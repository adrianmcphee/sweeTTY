package server

import (
	"bufio"
	"net"
	"testing"
	"time"
)

// TestReadLineIsBounded proves a connection that streams bytes with no newline is
// returned in a bounded chunk rather than growing the buffer until the process
// OOMs. Without the cap this test would hang or exhaust memory.
func TestReadLineIsBounded(t *testing.T) {
	client, srv := net.Pipe()
	defer client.Close()
	defer srv.Close()
	s := &Session{conn: srv, reader: bufio.NewReader(srv), IdleTimeout: 2 * time.Second}

	// Flood ~800KB with no newline; net.Pipe blocks the writer until ReadLine reads,
	// so this drives exactly the unbounded-line path.
	go func() {
		buf := make([]byte, 8192)
		for i := range buf {
			buf[i] = 'A'
		}
		for range 100 {
			if _, err := client.Write(buf); err != nil {
				return
			}
		}
	}()

	done := make(chan struct{})
	var line string
	var ok bool
	go func() {
		line, ok = s.ReadLine()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("ReadLine did not return on an unbounded no-newline flood (OOM/hang risk)")
	}
	if !ok {
		t.Fatal("ReadLine reported not-ok for a bounded line")
	}
	if len(line) > maxLineBytes {
		t.Fatalf("ReadLine returned %d bytes, exceeding the %d cap", len(line), maxLineBytes)
	}
}
