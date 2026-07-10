package record

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestCastIsValidAsciinema proves the file opens with a v2 header and that each
// output event is a well-formed [offset, "o", data] triple carrying the bytes
// written, so a standard asciinema player can replay it.
func TestCastIsValidAsciinema(t *testing.T) {
	dir := t.TempDir()
	r, err := New(dir, "sess123", 80, 24)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	r.Write([]byte("login: "))
	time.Sleep(5 * time.Millisecond)
	r.Write([]byte("root\r\n"))
	if err := r.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	f, err := os.Open(filepath.Join(dir, "sess123.cast"))
	if err != nil {
		t.Fatalf("open cast: %v", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)

	if !sc.Scan() {
		t.Fatal("cast has no header line")
	}
	var hdr struct {
		Version       int `json:"version"`
		Width, Height int
		Timestamp     int64
	}
	if err := json.Unmarshal(sc.Bytes(), &hdr); err != nil {
		t.Fatalf("header is not JSON: %v", err)
	}
	if hdr.Version != 2 || hdr.Width != 80 || hdr.Height != 24 {
		t.Fatalf("header = %+v, want version 2, 80x24", hdr)
	}

	var got strings.Builder
	var lastOff float64 = -1
	events := 0
	for sc.Scan() {
		var ev []json.RawMessage
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil || len(ev) != 3 {
			t.Fatalf("event line is not a 3-tuple: %q (%v)", sc.Text(), err)
		}
		var off float64
		var kind, data string
		json.Unmarshal(ev[0], &off)
		json.Unmarshal(ev[1], &kind)
		json.Unmarshal(ev[2], &data)
		if kind != "o" {
			t.Fatalf("event kind = %q, want o", kind)
		}
		if off < lastOff {
			t.Fatalf("event offsets are not monotonic: %v then %v", lastOff, off)
		}
		lastOff = off
		got.WriteString(data)
		events++
	}
	if events != 2 {
		t.Fatalf("recorded %d events, want 2", events)
	}
	if got.String() != "login: root\r\n" {
		t.Fatalf("replayed output = %q, want the two writes concatenated", got.String())
	}
}

// TestNilRecorderIsSafe proves the no-op behaviour callers rely on.
func TestNilRecorderIsSafe(t *testing.T) {
	var r *Recorder
	r.Write([]byte("x")) // must not panic
	if err := r.Close(); err != nil {
		t.Fatalf("nil Close: %v", err)
	}
}

func TestRecorderRejectsUnsafeAndDuplicateIDs(t *testing.T) {
	dir := t.TempDir()
	if _, err := New(dir, "../escape", 80, 24); err == nil {
		t.Fatal("recording accepted a path-traversal id")
	}
	r, err := New(dir, "same", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := New(dir, "same", 80, 24); err == nil {
		t.Fatal("recording silently replaced an existing cast")
	}
}

// withLimits shrinks the ring for a test and restores the defaults afterwards.
func withLimits(t *testing.T, files int, bytes int64) {
	t.Helper()
	limits.Lock()
	prevFiles, prevBytes := limits.files, limits.bytes
	limits.files, limits.bytes = files, bytes
	limits.Unlock()
	t.Cleanup(func() {
		limits.Lock()
		limits.files, limits.bytes = prevFiles, prevBytes
		limits.Unlock()
	})
}

// TestRingEvictsOldestWhenFull proves a full recordings directory keeps
// recording by deleting the oldest finished cast rather than refusing: the ring
// favours new data over old, and the sensor never goes blind.
func TestRingEvictsOldestWhenFull(t *testing.T) {
	withLimits(t, 2, 1<<20)
	dir := t.TempDir()
	old := time.Now().Add(-time.Hour)
	for i, id := range []string{"aaa", "bbb"} {
		r, err := New(dir, id, 80, 24)
		if err != nil {
			t.Fatalf("new %s: %v", id, err)
		}
		r.Write([]byte("x"))
		r.Close()
		// Distinct mtimes so eviction order is deterministic, oldest first.
		ts := old.Add(time.Duration(i) * time.Minute)
		if err := os.Chtimes(filepath.Join(dir, id+".cast"), ts, ts); err != nil {
			t.Fatal(err)
		}
	}
	r, err := New(dir, "ccc", 80, 24)
	if err != nil {
		t.Fatalf("full ring refused a new cast instead of evicting: %v", err)
	}
	r.Close()
	if _, err := os.Stat(filepath.Join(dir, "aaa.cast")); !os.IsNotExist(err) {
		t.Error("oldest cast survived eviction")
	}
	for _, id := range []string{"bbb", "ccc"} {
		if _, err := os.Stat(filepath.Join(dir, id+".cast")); err != nil {
			t.Errorf("cast %s missing after eviction: %v", id, err)
		}
	}
}

// TestRingNeverEvictsActiveCast proves a cast still being written is not an
// eviction candidate: with the ring fully occupied by live recordings, a new
// cast is refused rather than destroying one mid-session.
func TestRingNeverEvictsActiveCast(t *testing.T) {
	withLimits(t, 1, 1<<20)
	dir := t.TempDir()
	open, err := New(dir, "live1", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(dir, "next1", 80, 24); err == nil {
		t.Fatal("a live cast was evicted to admit a new one")
	}
	open.Close()
	r, err := New(dir, "next1", 80, 24)
	if err != nil {
		t.Fatalf("closed cast not evicted: %v", err)
	}
	r.Close()
	if _, err := os.Stat(filepath.Join(dir, "live1.cast")); !os.IsNotExist(err) {
		t.Error("finished cast survived eviction in a size-1 ring")
	}
}

// TestRingEvictsForBytes proves the byte bound also evicts: growth of a current
// cast pushes the oldest finished cast out instead of capping the recording.
func TestRingEvictsForBytes(t *testing.T) {
	withLimits(t, 1000, 4096)
	dir := t.TempDir()
	payload := []byte(strings.Repeat("a", 3000)) // printable, so the JSON event stays ~payload-sized
	r1, err := New(dir, "old1", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	r1.Write(payload)
	r1.Close()
	ts := time.Now().Add(-time.Hour)
	os.Chtimes(filepath.Join(dir, "old1.cast"), ts, ts)

	r2, err := New(dir, "new1", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	r2.Write(payload)
	r2.Close()
	if _, err := os.Stat(filepath.Join(dir, "old1.cast")); !os.IsNotExist(err) {
		t.Error("oldest cast not evicted when bytes ran out")
	}
	data, err := os.ReadFile(filepath.Join(dir, "new1.cast"))
	if err != nil || !strings.Contains(string(data), `"o"`) {
		t.Errorf("new cast did not keep recording after byte eviction: %v", err)
	}
}

func TestNewCountsEachCastOnceAgainstDirectoryQuota(t *testing.T) {
	dir := t.TempDir()
	r, err := New(dir, "one", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	q := quotaFor(dir)
	q.mu.Lock()
	files := q.files
	q.mu.Unlock()
	if files != 1 {
		t.Fatalf("directory quota counted %d files after one cast, want 1", files)
	}
}

// TestCastSizeIsCapped proves one session cannot write an unbounded cast file. A
// runaway session that elicits huge output would otherwise fill the disk, at which
// point the JSON event log itself starts dropping writes and the sensor goes blind.
func TestCastSizeIsCapped(t *testing.T) {
	dir := t.TempDir()
	r, err := New(dir, "big", 80, 24)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	chunk := make([]byte, 1<<20)
	for range int(maxCastBytes/int64(len(chunk))) + 8 {
		r.Write(chunk)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	fi, err := os.Stat(filepath.Join(dir, "big.cast"))
	if err != nil {
		t.Fatal(err)
	}
	// Allow a small margin for the header and the truncation marker line.
	if fi.Size() > maxCastBytes+4096 {
		t.Fatalf("cast grew to %d bytes, past the %d cap", fi.Size(), maxCastBytes)
	}
}

// TestWriteInputRecordsIEvents proves attacker input is captured as "i" events
// alongside the "o" output, so a replay/watch shows what a source typed even when
// the honeypot echoes nothing.
func TestWriteInputRecordsIEvents(t *testing.T) {
	dir := t.TempDir()
	r, err := New(dir, "inp", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	r.Write([]byte("login: "))
	r.WriteInput([]byte("root\r\n"))
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(dir, "inp.cast"))
	s := string(data)
	if !strings.Contains(s, `"o"`) || !strings.Contains(s, "login") {
		t.Errorf("output not recorded as o event:\n%s", s)
	}
	if !strings.Contains(s, `"i"`) || !strings.Contains(s, "root") {
		t.Errorf("input not recorded as i event:\n%s", s)
	}
}
