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

// Recorder appends asciinema v2 events for one session. The zero value and a nil
// Recorder are safe no-ops, so callers need not branch on whether recording is
// enabled.
type Recorder struct {
	mu    sync.Mutex
	f     *os.File
	start time.Time
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
func (r *Recorder) Write(b []byte) {
	if r == nil || len(b) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return
	}
	data, err := json.Marshal(string(b))
	if err != nil {
		return
	}
	off := strconv.FormatFloat(time.Since(r.start).Seconds(), 'f', 6, 64)
	r.f.WriteString("[" + off + ", \"o\", " + string(data) + "]\n")
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
