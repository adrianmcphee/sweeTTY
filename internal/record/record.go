// Package record writes a session's terminal output as an asciinema v2 cast
// file, so an operator can replay exactly what an attacker saw. It records only
// output the honeypot itself produced, to an operator-configured directory; it
// is the same category of telemetry as the JSON event log, written to a path the
// operator chose, never to an attacker-controlled path. Recording is off unless
// a directory is configured.
package record

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// maxCastBytes caps how large a single session's cast may grow. A session that
// elicits huge output (a large find, download theatre, expansion) would otherwise
// write an unbounded file, and once the disk fills the event log itself starts
// dropping writes, blinding the sensor it exists to feed. Retention and file count
// are the deployment's job (the instance template ages casts out); this bounds the
// one-session runaway.
const maxCastBytes = 16 << 20

// Recorder appends asciinema v2 events for one session. The zero value and a nil
// Recorder are safe no-ops, so callers need not branch on whether recording is
// enabled.
type Recorder struct {
	mu      sync.Mutex
	f       *os.File
	start   time.Time
	written int
	capped  bool
}

// New creates <dir>/<id>.cast and writes the v2 header. The directory is created
// if absent with owner-only permissions. A returned error means recording could
// not start; the caller should carry on without a recorder.
func New(dir, id string, width, height int) (*Recorder, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, id+".cast"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	hdr, _ := json.Marshal(map[string]any{
		"version":   2,
		"width":     width,
		"height":    height,
		"timestamp": now.Unix(),
	})
	if _, err := f.Write(append(hdr, '\n')); err != nil {
		f.Close()
		return nil, err
	}
	return &Recorder{f: f, start: now}, nil
}

// Write appends one output event carrying b at the current offset from the start
// of the recording. It is safe to call concurrently and on a nil Recorder.
// Write records server output (bytes the attacker saw) as an "o" event.
func (r *Recorder) Write(b []byte) { r.event('o', b) }

// WriteInput records attacker input (bytes they sent) as an "i" event, so the
// replay and the live watch can show what a source typed even when the honeypot
// echoes nothing back, which is the common case for a bot that blasts credentials.
func (r *Recorder) WriteInput(b []byte) { r.event('i', b) }

func (r *Recorder) event(kind byte, b []byte) {
	if r == nil || len(b) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil || r.capped {
		return
	}
	data, err := json.Marshal(string(b))
	if err != nil {
		return
	}
	off := strconv.FormatFloat(time.Since(r.start).Seconds(), 'f', 6, 64)
	line := "[" + off + ", \"" + string(kind) + "\", " + string(data) + "]\n"
	if r.written+len(line) > maxCastBytes {
		// One last marker so a truncated replay is self-explanatory, then stop.
		r.f.WriteString("[" + off + ", \"o\", \"\\r\\n[recording truncated]\\r\\n\"]\n")
		r.capped = true
		return
	}
	n, _ := r.f.WriteString(line)
	r.written += n
}

// Close flushes and closes the cast file. It is safe on a nil Recorder.
func (r *Recorder) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return nil
	}
	err := r.f.Close()
	r.f = nil
	return err
}
