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

func TestDirectoryQuotaAccountingIsBounded(t *testing.T) {
	q := &dirQuota{files: maxCastFiles - 1, bytes: maxCastDirBytes - 4}
	if !q.reserveFile(4) || q.reserveFile(1) {
		t.Fatal("directory quota admitted an over-cap file")
	}
	if q.reserveBytes(1) {
		t.Fatal("directory quota admitted bytes beyond its cap")
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
