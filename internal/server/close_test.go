package server

import (
	"net"
	"path/filepath"
	"testing"
	"time"

	"sweetty/internal/event"
)

// TestServerCloseStopsAccepting proves Close shuts the listener so no new
// connection is admitted - the primitive a clean SIGTERM shutdown relies on to stop
// accepting before the process flushes its log and exits.
func TestServerCloseStopsAccepting(t *testing.T) {
	lg, err := event.New(filepath.Join(t.TempDir(), "close.log"))
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	defer lg.Close()

	srv := New(0, lg, scanStub{})
	if err := srv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := srv.Addr()
	if addr == "" {
		t.Fatal("no bound address")
	}

	if err := srv.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	time.Sleep(20 * time.Millisecond) // let the accept loop observe net.ErrClosed

	if c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond); err == nil {
		c.Close()
		t.Fatal("a connection was accepted after Close: the listener is still open")
	}
}
