// Package record writes a session's terminal output as an asciinema v2 cast
// file, so an operator can replay exactly what an attacker saw. It records only
// output the honeypot itself produced, to an operator-configured directory; it
// is the same category of telemetry as the JSON event log, written to a path the
// operator chose, never to an attacker-controlled path. Recording is opt-in and
// is disabled unless the configuration explicitly enables it.
package record

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// maxCastBytes caps how large a single session's cast may grow. A session that
// elicits huge output (a large find, download theatre, expansion) would otherwise
// write an unbounded file, and once the disk fills the event log itself starts
// dropping writes, blinding the sensor it exists to feed. Retention and file count
// are the deployment's job (the instance template ages casts out); this bounds the
// one-session runaway. Directory-wide limits provide a second line of defence.
const (
	maxCastBytes    int64 = 16 << 20
	maxCastFiles          = 4096
	maxCastDirBytes int64 = 1 << 30
)

type dirQuota struct {
	mu    sync.Mutex
	init  bool
	files int
	bytes int64
}

var quotaState struct {
	sync.Mutex
	byDir map[string]*dirQuota
}

func quotaFor(dir string) *dirQuota {
	clean := filepath.Clean(dir)
	quotaState.Lock()
	defer quotaState.Unlock()
	if quotaState.byDir == nil {
		quotaState.byDir = map[string]*dirQuota{}
	}
	q := quotaState.byDir[clean]
	if q == nil {
		q = &dirQuota{}
		quotaState.byDir[clean] = q
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if !q.init {
		if ents, err := os.ReadDir(clean); err == nil {
			for _, e := range ents {
				if e.IsDir() || !strings.HasSuffix(e.Name(), ".cast") {
					continue
				}
				if fi, err := e.Info(); err == nil {
					q.files++
					q.bytes += fi.Size()
				}
			}
		}
		q.init = true
	}
	return q
}

func (q *dirQuota) reserveFile(bytes int64) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.files >= maxCastFiles || bytes > maxCastDirBytes-q.bytes {
		return false
	}
	q.files++
	q.bytes += bytes
	return true
}

func (q *dirQuota) reserveBytes(bytes int64) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if bytes < 0 || bytes > maxCastDirBytes-q.bytes {
		return false
	}
	q.bytes += bytes
	return true
}

func (q *dirQuota) releaseBytes(bytes int64) {
	if bytes <= 0 {
		return
	}
	q.mu.Lock()
	q.bytes -= bytes
	q.mu.Unlock()
}

// Recorder appends asciinema v2 events for one session. The zero value and a nil
// Recorder are safe no-ops, so callers need not branch on whether recording is
// enabled.
type Recorder struct {
	mu      sync.Mutex
	f       *os.File
	quota   *dirQuota
	start   time.Time
	written int64
	capped  bool
}

// New creates <dir>/<id>.cast and writes the v2 header. The directory is created
// if absent with owner-only permissions. A returned error means recording could
// not start; the caller should carry on without a recorder.
func New(dir, id string, width, height int) (*Recorder, error) {
	if !validID(id) {
		return nil, fmt.Errorf("invalid recording id")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	q := quotaFor(dir)
	path := filepath.Join(dir, id+".cast")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
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
	header := append(hdr, '\n')
	if !q.reserveFile(int64(len(header))) {
		f.Close()
		os.Remove(path)
		return nil, fmt.Errorf("recording directory quota exceeded")
	}
	n, err := f.Write(header)
	if err != nil || n != len(header) {
		q.releaseBytes(int64(n))
		q.mu.Lock()
		q.files--
		q.mu.Unlock()
		f.Close()
		os.Remove(path)
		if err == nil {
			err = os.ErrInvalid
		}
		return nil, err
	}
	return &Recorder{f: f, quota: q, start: now, written: int64(len(header))}, nil
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
	if r.written+int64(len(line)) > maxCastBytes {
		// One last marker so a truncated replay is self-explanatory, then stop.
		marker := "[" + off + ", \"o\", \"\\r\\n[recording truncated]\\r\\n\"]\n"
		if r.written+int64(len(marker)) <= maxCastBytes && r.quota.reserveBytes(int64(len(marker))) {
			if n, _ := r.f.WriteString(marker); n != len(marker) {
				r.quota.releaseBytes(int64(len(marker) - n))
			}
		}
		r.capped = true
		return
	}
	if !r.quota.reserveBytes(int64(len(line))) {
		r.capped = true
		return
	}
	n, err := r.f.WriteString(line)
	if n < len(line) {
		r.quota.releaseBytes(int64(len(line) - n))
	}
	r.written += int64(n)
	if err != nil || n != len(line) {
		r.capped = true
	}
}

func validID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
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
