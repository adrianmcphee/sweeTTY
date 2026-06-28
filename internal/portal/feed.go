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

	"github.com/gin-gonic/gin"

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

// readEntries reads the whole log file and returns every entry that passes keep,
// in file (chronological) order. Lines that are not valid JSON are skipped, so a
// truncated final write cannot abort the read.
func (p *Portal) readEntries(keep func(event.Entry) bool) ([]event.Entry, error) {
	f, err := os.Open(p.cfg.LogFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []event.Entry
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
		if keep == nil || keep(e) {
			out = append(out, e)
		}
	}
	return out, sc.Err()
}

// logQuery serves the main feed: newest-first entries, optionally filtered by a
// src-IP prefix and an exact event type, capped at limit.
func (p *Portal) logQuery(c *gin.Context) {
	limit := parseLimit(c.Query("limit"))
	ipPrefix := c.Query("ip")
	eventType := c.Query("event")

	entries, err := p.readEntries(func(e event.Entry) bool {
		if ipPrefix != "" && !strings.HasPrefix(srcOf(e), ipPrefix) {
			return false
		}
		if eventType != "" && e.Event != eventType {
			return false
		}
		return true
	})
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"entries": []event.Entry{}, "count": 0})
		return
	}

	// Newest first, then cap. Reversing after the cap would drop the newest, so
	// reverse first and take the head.
	reversed := reverse(entries)
	if len(reversed) > limit {
		reversed = reversed[:limit]
	}
	c.JSON(http.StatusOK, gin.H{"entries": reversed, "count": len(reversed)})
}

// byIP returns every entry attributable to one IP, by src_ip or by the host part
// of the remote address, in chronological order so the JS can build a transcript.
func (p *Portal) byIP(c *gin.Context) {
	ip := c.Param("ip")
	entries, err := p.readEntries(func(e event.Entry) bool {
		return srcOf(e) == ip || e.IP == ip || e.SrcIP == ip
	})
	if err != nil {
		entries = nil
	}
	c.JSON(http.StatusOK, gin.H{"ip": ip, "entries": entries, "count": len(entries)})
}

// bySession returns every entry for one connection id, in chronological order.
func (p *Portal) bySession(c *gin.Context) {
	id := c.Param("id")
	entries, err := p.readEntries(func(e event.Entry) bool {
		return e.Session == id
	})
	if err != nil {
		entries = nil
	}
	c.JSON(http.StatusOK, gin.H{"session": id, "entries": entries, "count": len(entries)})
}

// events streams new log lines over Server-Sent Events. It opens the log file,
// every 500ms emits any complete new lines as `log` events, and sends a keep-alive
// comment when idle. Each event carries an `id:` equal to the byte offset just past
// it; on an automatic reconnect the browser replays that as Last-Event-ID, and we
// resume from there so events written during the gap are backfilled rather than
// lost. A fresh connection (or a stale offset past a rotated log) starts at the end
// of the file and streams only new lines. It returns when the client disconnects.
func (p *Portal) events(c *gin.Context) {
	// Bound concurrent subscribers: each SSE stream holds a goroutine and an open fd
	// for its whole life (deliberately no WriteTimeout), so without a cap a client
	// opening many streams could exhaust both. Shed the excess rather than serve it.
	select {
	case p.sseGate <- struct{}{}:
		defer func() { <-p.sseGate }()
	default:
		c.String(http.StatusServiceUnavailable, "too many event streams")
		return
	}

	f, err := os.Open(p.cfg.LogFile)
	if err != nil {
		c.String(http.StatusInternalServerError, "log unavailable")
		return
	}
	defer f.Close()
	offset, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		c.String(http.StatusInternalServerError, "log unavailable")
		return
	}
	// Resume from Last-Event-ID when it names a byte offset still within the file;
	// otherwise the end-of-file start above stands.
	if lid := c.GetHeader("Last-Event-ID"); lid != "" {
		if n, perr := strconv.ParseInt(lid, 10, 64); perr == nil && n >= 0 && n <= offset {
			if _, serr := f.Seek(n, io.SeekStart); serr == nil {
				offset = n
			}
		}
	}

	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	// Disable proxy buffering so events arrive as they are written.
	c.Header("X-Accel-Buffering", "no")
	c.Writer.WriteHeader(http.StatusOK)
	c.Writer.Flush()

	reader := bufio.NewReader(f)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	// partial holds the bytes of a line that has been written to disk without its
	// terminating newline yet, carried across ticks until the line completes.
	var partial strings.Builder
	idleTicks := 0
	const idlePingEvery = 20 // ~10s of silence between keep-alive pings

	done := c.Request.Context().Done()
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
				if _, err := c.Writer.WriteString(frame); err != nil {
					return
				}
				wrote = true
			}
			if wrote {
				idleTicks = 0
				c.Writer.Flush()
				continue
			}
			idleTicks++
			if idleTicks >= idlePingEvery {
				idleTicks = 0
				if _, err := c.Writer.WriteString(": ping\n\n"); err != nil {
					return
				}
				c.Writer.Flush()
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
