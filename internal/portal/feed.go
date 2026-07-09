package portal

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"sweetty/internal/event"
	"sweetty/internal/util"
)

const (
	defaultLimit = 200
	maxLimit     = 1000
)

// srcOf returns the source IP an entry should be grouped under: the explicit
// src_ip when present, otherwise the host part of the remote "ip:port".
func srcOf(e event.Entry) string {
	if e.SrcIP != "" {
		return e.SrcIP
	}
	return util.HostOnly(e.IP)
}

// feedGeo is the portal-plane context attached to a feed event for display:
// where the source resolves to and what the sensor already knows about it (how
// many visits, whether it has been here before, the classifier's verdict). It
// is computed at read time from the resolver and the projections; the log line
// on disk stays exactly what the listener wrote.
type feedGeo struct {
	Country   string `json:"country,omitempty"`
	Org       string `json:"org,omitempty"`
	Scope     string `json:"scope,omitempty"`
	Visits    int    `json:"visits,omitempty"`
	Returning bool   `json:"returning,omitempty"`
	Kind      string `json:"kind,omitempty"`
}

// sourceContexts returns the display context for each distinct source in srcs.
// The store is folded first, so the answer reflects every event already on disk,
// including the one being enriched.
func (p *Portal) sourceContexts(srcs []string) map[string]*feedGeo {
	out := make(map[string]*feedGeo, len(srcs))
	p.store.mu.Lock()
	defer p.store.mu.Unlock()
	p.syncStoreLocked()
	o := &p.store.ov
	for _, src := range srcs {
		if src == "" || out[src] != nil {
			continue
		}
		loc := p.geo.Locate(src)
		g := &feedGeo{Country: loc.Country, Org: loc.Org, Scope: loc.Scope}
		if o.bySrc != nil {
			if row := o.bySrc[src]; row != nil {
				g.Visits = o.visitCnt[src]
				if sig := o.sigBySrc[src]; sig != nil {
					if kind, _, _ := verdict(*sig); kind != kindUnknown {
						g.Kind = kind
					}
					g.Returning = g.Visits >= 2 || (row.Scanned && (sig.commands > 0 || sig.sessions > 0))
				}
			}
		}
		out[src] = g
	}
	return out
}

// enrichFeedLine attaches the source context to one raw log line before it is
// streamed. The line is parsed into a generic map so fields this build does not
// know survive untouched; on any failure the raw line streams as-is, so
// enrichment can degrade but never block the feed.
func (p *Portal) enrichFeedLine(line string) string {
	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		return line
	}
	src, _ := m["src_ip"].(string)
	if src == "" {
		if ip, _ := m["ip"].(string); ip != "" {
			src = util.HostOnly(ip)
		}
	}
	if src == "" {
		return line
	}
	m["geo"] = p.sourceContexts([]string{src})[src]
	b, err := json.Marshal(m)
	if err != nil {
		return line
	}
	return string(b)
}

// enrichedEntry is a feed entry with its display context attached, for the
// backfill query, so the dashboard renders history and live pushes identically.
type enrichedEntry struct {
	event.Entry
	Geo *feedGeo `json:"geo,omitempty"`
}

func (p *Portal) enrichEntries(entries []event.Entry) []enrichedEntry {
	srcs := make([]string, 0, len(entries))
	for _, e := range entries {
		srcs = append(srcs, srcOf(e))
	}
	ctx := p.sourceContexts(srcs)
	out := make([]enrichedEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, enrichedEntry{Entry: e, Geo: ctx[srcOf(e)]})
	}
	return out
}

// scanEntries streams every log entry through each, in file (chronological)
// order, without ever materializing the file. Lines that are not valid JSON are
// skipped, so a truncated final write cannot abort the read. The drill-down
// endpoints scan rather than hold a projection: they are operator-initiated
// one-offs, so the per-request cost is a read, never a per-poll one, and the
// callback keeps only what its response needs.
func (p *Portal) scanEntries(each func(event.Entry)) error {
	f, err := os.Open(p.cfg.LogFile)
	if err != nil {
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	// Allow long lines: captured request bodies and headers can be large.
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e event.Entry
		if err := json.Unmarshal(line, &e); err != nil {
			continue
		}
		each(e)
	}
	return sc.Err()
}

// lastN keeps the newest n entries streamed into it, in chronological order, so
// a bounded transcript never costs more than n entries of memory no matter how
// large the history is.
type lastN struct {
	buf     []event.Entry
	start   int
	full    bool
	dropped bool
}

func newLastN(n int) *lastN { return &lastN{buf: make([]event.Entry, 0, n)} }

func (l *lastN) add(e event.Entry) {
	if len(l.buf) < cap(l.buf) {
		l.buf = append(l.buf, e)
		return
	}
	l.buf[l.start] = e
	l.start = (l.start + 1) % len(l.buf)
	l.full = true
	l.dropped = true
}

// ordered returns the kept entries oldest-first.
func (l *lastN) ordered() []event.Entry {
	if !l.full {
		return l.buf
	}
	out := make([]event.Entry, 0, len(l.buf))
	out = append(out, l.buf[l.start:]...)
	out = append(out, l.buf[:l.start]...)
	return out
}

// drilldownEntryCap bounds the transcript returned for one IP or session. Far
// above what the drawer renders usefully; the newest entries are kept, and the
// response says when older ones were dropped. The assessment still reads the
// full history, streamed.
const drilldownEntryCap = 5000

// logQuery serves the main feed: newest-first entries, optionally filtered by a
// src-IP prefix and an exact event type, capped at limit. The scan keeps only
// the newest limit matches, so the request never holds the whole log.
func (p *Portal) logQuery(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := parseLimit(q.Get("limit"))
	ipPrefix := q.Get("ip")
	eventType := q.Get("event")

	keep := newLastN(limit)
	err := p.scanEntries(func(e event.Entry) {
		if ipPrefix != "" && !strings.HasPrefix(srcOf(e), ipPrefix) {
			return
		}
		if eventType != "" && e.Event != eventType {
			return
		}
		keep.add(e)
	})
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"entries": []event.Entry{}, "count": 0})
		return
	}

	reversed := p.enrichEntries(reverse(keep.ordered()))
	writeJSON(w, http.StatusOK, map[string]any{"entries": reversed, "count": len(reversed)})
}

// byIP returns the newest entries attributable to one IP, by src_ip or by the
// host part of the remote address, in chronological order so the JS can build a
// transcript. The assessment (visits, phases, bot/human verdict) is folded over
// the source's complete history as the scan streams past, so a capped transcript
// never changes the verdict.
func (p *Portal) byIP(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")
	keep := newLastN(drilldownEntryCap)
	var an sourceAnalyzer
	_ = p.scanEntries(func(e event.Entry) {
		if srcOf(e) != ip && e.IP != ip && e.SrcIP != ip {
			return
		}
		an.observe(e)
		keep.add(e)
	})
	entries := keep.ordered()
	writeJSON(w, http.StatusOK, map[string]any{
		"ip": ip, "entries": entries, "count": len(entries),
		"capped": keep.dropped, "profile": an.assessment(),
	})
}

// bySession returns the newest entries for one connection id, in chronological
// order.
func (p *Portal) bySession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	keep := newLastN(drilldownEntryCap)
	_ = p.scanEntries(func(e event.Entry) {
		if e.Session != id {
			return
		}
		keep.add(e)
	})
	entries := keep.ordered()
	writeJSON(w, http.StatusOK, map[string]any{
		"session": id, "entries": entries, "count": len(entries), "capped": keep.dropped,
	})
}

const maxEventLineBytes = 1 << 20

// events streams new log lines over Server-Sent Events. It opens the log file,
// every 500ms emits any complete new lines as `log` events, and sends a keep-alive
// comment when idle. Each event carries an `id:` equal to the byte offset just past
// it; on an automatic reconnect the browser replays that as Last-Event-ID, and we
// resume from there so events written during the gap are backfilled rather than
// lost. A fresh connection (or a stale offset past a rotated log) starts at the end
// of the file and streams only new lines. It returns when the client disconnects.
func (p *Portal) events(w http.ResponseWriter, r *http.Request) {
	// Bound concurrent subscribers: each SSE stream holds a goroutine and an open fd
	// for its whole life (deliberately no WriteTimeout), so without a cap a client
	// opening many streams could exhaust both. Shed the excess rather than serve it.
	select {
	case p.sseGate <- struct{}{}:
		defer func() { <-p.sseGate }()
	default:
		writeString(w, http.StatusServiceUnavailable, "too many event streams")
		return
	}

	// The feed streams frame by frame, so the writer must flush mid-response.
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeString(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}

	f, err := os.Open(p.cfg.LogFile)
	if err != nil {
		writeString(w, http.StatusInternalServerError, "log unavailable")
		return
	}
	defer f.Close()
	offset, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		writeString(w, http.StatusInternalServerError, "log unavailable")
		return
	}
	// Resume from Last-Event-ID when it names a byte offset still within the file;
	// otherwise the end-of-file start above stands.
	if lid := r.Header.Get("Last-Event-ID"); lid != "" {
		if n, perr := strconv.ParseInt(lid, 10, 64); perr == nil && n >= 0 && n <= offset {
			if _, serr := f.Seek(n, io.SeekStart); serr == nil {
				offset = n
			}
		}
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	// Disable proxy buffering so events arrive as they are written.
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	reader := bufio.NewReader(f)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	// partial holds the bytes of a line that has been written to disk without its
	// terminating newline yet, carried across ticks until the line completes.
	var partial strings.Builder
	partialBytes := 0
	partialTooLong := false
	idleTicks := 0
	const idlePingEvery = 20 // ~10s of silence between keep-alive pings

	done := r.Context().Done()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			wrote := false
			for {
				chunk, err := reader.ReadSlice('\n')
				partialBytes += len(chunk)
				if !partialTooLong {
					if partial.Len()+len(chunk) > maxEventLineBytes {
						partialTooLong = true
						partial.Reset()
					} else {
						partial.Write(chunk)
					}
				}
				if err == bufio.ErrBufferFull {
					continue
				}
				if err != nil {
					// EOF (or short read): keep any partial line for next tick.
					break
				}
				offset += int64(partialBytes)
				partialBytes = 0
				if partialTooLong {
					partialTooLong = false
					partial.Reset()
					continue
				}
				raw := partial.String()
				// Advance the resumable offset past this complete line (newline
				// included) so the id we emit is exactly where a reconnect resumes.
				partial.Reset()
				line := strings.TrimRight(raw, "\r\n")
				if line == "" {
					continue
				}
				frame := "id: " + strconv.FormatInt(offset, 10) + "\nevent: log\ndata: " + p.enrichFeedLine(line) + "\n\n"
				if _, err := io.WriteString(w, frame); err != nil {
					return
				}
				wrote = true
			}
			if wrote {
				idleTicks = 0
				flusher.Flush()
				continue
			}
			idleTicks++
			if idleTicks >= idlePingEvery {
				idleTicks = 0
				if _, err := io.WriteString(w, ": ping\n\n"); err != nil {
					return
				}
				flusher.Flush()
			}
		}
	}
}

// parseLimit clamps a requested limit to [1, maxLimit], defaulting when unset or
// invalid.
func parseLimit(s string) int {
	if s == "" {
		return defaultLimit
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return defaultLimit
	}
	if n > maxLimit {
		return maxLimit
	}
	return n
}

// reverse returns a new slice with the entries in reverse order, newest first.
func reverse(in []event.Entry) []event.Entry {
	out := make([]event.Entry, len(in))
	for i, e := range in {
		out[len(in)-1-i] = e
	}
	return out
}
