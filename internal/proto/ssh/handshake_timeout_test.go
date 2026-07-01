package ssh

import (
	"testing"
	"time"

	"sweetty/internal/fakehost"
	"sweetty/internal/persona"
	"sweetty/internal/testharness"
)

// TestHandshakeSlowlorisTimesOut proves the interactive SSH handshake is bounded.
// The handshake runs on the bare TCP conn, which carries no per-read deadline of
// its own; a client that opens the socket and then never completes the SSH banner
// exchange must be dropped at handshakeTimeout instead of pinning the goroutine,
// its fd, and a connection-limiter slot forever.
func TestHandshakeSlowlorisTimesOut(t *testing.T) {
	old := handshakeTimeout
	handshakeTimeout = 150 * time.Millisecond
	defer func() { handshakeTimeout = old }()

	p := persona.Generate()
	fs, err := fakehost.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	h, err := testharness.New(New(fs, p, ""))
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	// The server sends its identification banner, then blocks reading ours. Send
	// nothing: the deadline must tear the connection down. A closed server side
	// surfaces as a read that returns (EOF/reset) rather than hanging past the
	// deadline; without the fix this read blocks indefinitely.
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 256)
		for {
			if _, err := h.Client.Read(buf); err != nil {
				close(done)
				return
			}
		}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("idle handshake was not dropped at handshakeTimeout: connection still open")
	}
}
