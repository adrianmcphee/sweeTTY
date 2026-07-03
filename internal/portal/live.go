package portal

import (
	"bufio"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// activeWindow bounds how long after its last event a session is still shown as
// live, so an orphan left by a hard restart (which never got its SESSION_END) does
// not linger in the live rail forever.
const activeWindow = 15 * time.Minute

// liveSession is one currently-open connection, for the console's live rail.
type liveSession struct {
	ID         string `json:"id"`
	IP         string `json:"ip"`
	Protocol   string `json:"protocol,omitempty"`
	Country    string `json:"country,omitempty"`
	Org        string `json:"org,omitempty"`
	StartedMs  int64  `json:"started_ms"`
	LastSeenMs int64  `json:"last_seen_ms"`
	Commands   int    `json:"commands"`
	Recorded   bool   `json:"recorded"`
}

// recordedSet returns the set of session ids that have a cast on disk, so the live
// rail and the drawer can tell which sessions can be watched or replayed.
func (p *Portal) recordedSet() map[string]bool {
	set := map[string]bool{}
	if p.cfg.RecordDir == "" {
		return set
	}
	ents, err := os.ReadDir(p.cfg.RecordDir)
	if err != nil {
		return set
	}
	for _, e := range ents {
		if id, ok := strings.CutSuffix(e.Name(), ".cast"); ok && safeID(id) {
			set[id] = true
		}
	}
	return set
}

// activeSessions lists connections that have started but not ended and whose last
// event is recent, newest-activity-first, so the console can surface a live rail and
// offer to watch them. It reads the incremental projection over the same log as
// everything else (store.go); nothing new is stored. This is the dashboard's
// hottest poll, so it must never cost a full log read.
func (p *Portal) activeSessions(w http.ResponseWriter, _ *http.Request) {
	p.store.mu.Lock()
	defer p.store.mu.Unlock()
	p.syncStoreLocked()

	now := time.Now().UnixMilli()
	cutoff := now - activeWindow.Milliseconds()
	p.store.live.sweep(now - liveSweepFactor*activeWindow.Milliseconds())
	recorded := p.recordedSet()
	out := []liveSession{}
	for _, id := range p.store.live.order {
		a := p.store.live.byID[id]
		if a == nil || !a.started || a.lastMs < cutoff {
			continue
		}
		ls := liveSession{
			ID: id, IP: a.ip, Protocol: a.proto,
			StartedMs: a.firstMs, LastSeenMs: a.lastMs,
			Commands: a.cmds, Recorded: recorded[id],
		}
		if p.geo != nil && a.ip != "" {
			loc := p.geo.Locate(a.ip)
			ls.Country = loc.Country
			ls.Org = loc.Org
		}
		out = append(out, ls)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].LastSeenMs > out[j].LastSeenMs })
	writeJSON(w, http.StatusOK, map[string]any{"sessions": out, "count": len(out)})
}

// watch streams a live session's terminal output over Server-Sent Events by tailing
// its cast file as the honeypot writes it. It streams from the START of the cast, so
// a watcher joining mid-session sees everything the attacker has seen so far, then
// follows new frames as they land, exactly the way the event feed tails the log.
//
// It is strictly read-only: it shows the bytes the attacker saw and offers no way to
// send anything back, so watching stays inside the deception boundary (the honeypot
// still executes nothing and the operator never interacts with the session).
func (p *Portal) watch(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if p.cfg.RecordDir == "" || !safeID(id) {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// Bound concurrent watchers: each holds a goroutine and an open fd for its whole
	// life (deliberately no WriteTimeout), so shed the excess rather than serve it.
	select {
	case p.watchGate <- struct{}{}:
		defer func() { <-p.watchGate }()
	default:
		writeString(w, http.StatusServiceUnavailable, "too many watchers")
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeString(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	f, err := os.Open(filepath.Join(p.cfg.RecordDir, id+".cast"))
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	defer f.Close()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	reader := bufio.NewReader(f)
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	var partial strings.Builder
	idle := 0
	const idlePingEvery = 40 // ~10s of silence between keep-alive pings
	done := r.Context().Done()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			wrote := false
			for {
				chunk, rerr := reader.ReadString('\n')
				if len(chunk) > 0 {
					partial.WriteString(chunk)
				}
				if rerr != nil {
					break // EOF or short read: keep the partial line for the next tick
				}
				raw := strings.TrimRight(partial.String(), "\r\n")
				partial.Reset()
				if raw == "" {
					continue
				}
				// Each cast line is a self-contained JSON array; the browser skips the
				// header line and renders the [t,"o",data] output frames.
				if _, werr := io.WriteString(w, "event: frame\ndata: "+raw+"\n\n"); werr != nil {
					return
				}
				wrote = true
			}
			if wrote {
				idle = 0
				flusher.Flush()
				continue
			}
			idle++
			if idle >= idlePingEvery {
				idle = 0
				if _, werr := io.WriteString(w, ": ping\n\n"); werr != nil {
					return
				}
				flusher.Flush()
			}
		}
	}
}
