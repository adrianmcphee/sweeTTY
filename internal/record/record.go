// Package record writes a session's terminal output as an asciinema v2 cast
// file, so an operator can replay exactly what an attacker saw. It records only
// output the honeypot itself produced, to an operator-configured directory; it
// is the same category of telemetry as the JSON event log, written to a path the
// operator chose, never to an attacker-controlled path. Recording runs whenever
// a directory is configured; the config layer defaults one in, and "record":
// false removes it.
package record

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// maxCastBytes caps how large a single session's cast may grow. A session that
// elicits huge output (a large find, download theatre, expansion) would otherwise
// write an unbounded file, and once the disk fills the event log itself starts
// dropping writes, blinding the sensor it exists to feed. This bounds the
// one-session runaway.
//
// The directory-wide limits are a ring, not a cliff: when the directory is full,
// the oldest finished casts are evicted to make room, so recording never stops
// and the newest data always wins. A sensor whose sessions silently go
// unrecorded loses data it can never get back; a bounded directory of old casts
// is merely storage. Time-based retention stays the deployment's job (the
// instance template ages casts out); the ring bounds space.
const (
	maxCastBytes           int64 = 16 << 20
	defaultMaxCastFiles          = 65536
	defaultMaxCastDirBytes int64 = 4 << 30
)

var limits = struct {
	sync.Mutex
	files int
	bytes int64
}{files: defaultMaxCastFiles, bytes: defaultMaxCastDirBytes}

// SetLimits overrides the recording directory's ring size. Zero or negative
// leaves the corresponding built-in default in place. Call it once at startup,
// before the first recording.
func SetLimits(files int, bytes int64) {
	limits.Lock()
	defer limits.Unlock()
	if files > 0 {
		limits.files = files
	}
	if bytes > 0 {
		limits.bytes = bytes
	}
}

func currentLimits() (int, int64) {
	limits.Lock()
	defer limits.Unlock()
	return limits.files, limits.bytes
}

type dirQuota struct {
	mu     sync.Mutex
	dir    string
	init   bool
	files  int
	bytes  int64
	active map[string]bool // ids being written now; never evicted
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
		q = &dirQuota{dir: clean, active: map[string]bool{}}
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

// reserveFile admits a new cast (one file slot plus its header bytes), marking
// its id active so eviction never removes a cast that is still being written.
// A full ring evicts the oldest finished casts rather than refusing.
func (q *dirQuota) reserveFile(id string, bytes int64) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	maxFiles, maxBytes := currentLimits()
	if q.files >= maxFiles || bytes > maxBytes-q.bytes {
		if !q.evictLocked(1, bytes) {
			return false
		}
	}
	q.files++
	q.bytes += bytes
	q.active[id] = true
	return true
}

// releaseFile undoes a reserveFile whose cast never materialised (create or
// header write failed): the slot, the written bytes, and the active mark.
func (q *dirQuota) releaseFile(id string, bytes int64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.files--
	if bytes > 0 {
		q.bytes -= bytes
	}
	delete(q.active, id)
}

func (q *dirQuota) reserveBytes(bytes int64) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if bytes < 0 {
		return false
	}
	_, maxBytes := currentLimits()
	if bytes > maxBytes-q.bytes && !q.evictLocked(0, bytes) {
		return false
	}
	q.bytes += bytes
	return true
}

func (q *dirQuota) finish(id string) {
	q.mu.Lock()
	delete(q.active, id)
	q.mu.Unlock()
}

// evictLocked frees room for needFiles slots and needBytes bytes by deleting the
// oldest casts that are not being written, and reports whether the need now fits.
// It rescans the directory first, so the counters resync with anything deleted
// behind us (the deployment's time-based retention removes casts too). It frees a
// little beyond the need, so a full ring does not rescan on every admission.
func (q *dirQuota) evictLocked(needFiles int, needBytes int64) bool {
	maxFiles, maxBytes := currentLimits()
	ents, err := os.ReadDir(q.dir)
	if err != nil {
		return false
	}
	type cast struct {
		name string
		size int64
		mod  int64
	}
	var victims []cast
	files, bytes := 0, int64(0)
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".cast") {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		files++
		bytes += fi.Size()
		if !q.active[strings.TrimSuffix(e.Name(), ".cast")] {
			victims = append(victims, cast{e.Name(), fi.Size(), fi.ModTime().UnixNano()})
		}
	}
	sort.Slice(victims, func(i, j int) bool { return victims[i].mod < victims[j].mod })
	wantFiles := maxFiles - needFiles - maxFiles/64
	wantBytes := maxBytes - needBytes - maxBytes/64
	for _, c := range victims {
		if files <= wantFiles && bytes <= wantBytes {
			break
		}
		if os.Remove(filepath.Join(q.dir, c.name)) == nil {
			files--
			bytes -= c.size
		}
	}
	q.files, q.bytes = files, bytes
	return q.files+needFiles <= maxFiles && needBytes <= maxBytes-q.bytes
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
	id      string
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
	now := time.Now()
	hdr, _ := json.Marshal(map[string]any{
		"version":   2,
		"width":     width,
		"height":    height,
		"timestamp": now.Unix(),
	})
	header := append(hdr, '\n')
	// Reserve (and mark the id active) before the file exists, so a concurrent
	// eviction rescan never sees an unaccounted cast and never removes this one.
	if !q.reserveFile(id, int64(len(header))) {
		return nil, fmt.Errorf("recording directory quota exceeded")
	}
	path := filepath.Join(dir, id+".cast")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		q.releaseFile(id, int64(len(header)))
		return nil, err
	}
	n, err := f.Write(header)
	if err != nil || n != len(header) {
		f.Close()
		os.Remove(path)
		q.releaseFile(id, int64(len(header)))
		if err == nil {
			err = os.ErrInvalid
		}
		return nil, err
	}
	return &Recorder{f: f, id: id, quota: q, start: now, written: int64(len(header))}, nil
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

// Close flushes and closes the cast file, releasing the eviction protection its
// active mark held. It is safe on a nil Recorder.
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
	r.quota.finish(r.id)
	return err
}
