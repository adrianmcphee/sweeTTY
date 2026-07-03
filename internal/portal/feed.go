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

	reversed := reverse(keep.ordered())
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
				chunk, err := reader.ReadString('\n')
				if len(chunk) > 0 {
					partial.WriteString(chunk)
				}
				if err != nil {
					// EOF (or short read): keep any partial line for next tick.
					break
				}
				raw := partial.String()
				// Advance the resumable offset past this complete line (newline
				// included) so the id we emit is exactly where a reconnect resumes.
				offset += int64(len(raw))
				partial.Reset()
				line := strings.TrimRight(raw, "\r\n")
				if line == "" {
					continue
				}
				frame := "id: " + strconv.FormatInt(offset, 10) + "\nevent: log\ndata: " + line + "\n\n"
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
