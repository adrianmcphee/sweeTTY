package server

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sweetty/internal/event"
)

// writeStub is a banner-first protocol that immediately writes a line, so the
// recorder has output to capture without any client input.
type writeStub struct{}

func (writeStub) Name() string      { return "writestub" }
func (writeStub) ClientFirst() bool { return false }
func (writeStub) Handle(s *Session) { s.Write("hello world\r\n") }

// TestSessionRecordingWritesCast proves that with a record directory configured,
// a real session produces a cast file that captures the bytes the attacker saw,
// through the tee'd connection and every IO helper.
func TestSessionRecordingWritesCast(t *testing.T) {
	recDir := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "rec.log")
	lg, err := event.New(logPath)
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	defer lg.Close()

	srv := New(0, lg, writeStub{})
	srv.RecordDir = recDir
	if err := srv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, port, _ := net.SplitHostPort(srv.Addr())
	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", port))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	// Banner-first: the server writes immediately. Read it, then close.
	buf := make([]byte, 64)
	conn.SetReadDeadline(time.Now().Add(time.Second))
	conn.Read(buf)
	conn.Close()

	// Poll for the cast file to appear and capture the output.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		ents, _ := os.ReadDir(recDir)
		for _, e := range ents {
			if !strings.HasSuffix(e.Name(), ".cast") {
				continue
			}
			data, _ := os.ReadFile(filepath.Join(recDir, e.Name()))
			if strings.Contains(string(data), "hello world") {
				if !strings.Contains(string(data), "\"version\": 2") && !strings.Contains(string(data), "\"version\":2") {
					t.Fatalf("cast %s has no v2 header:\n%s", e.Name(), data)
				}
				return // success
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("no cast file capturing the session output appeared")
}
