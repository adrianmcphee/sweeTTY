package http_test

// Go-live stability pin: a client that streams headers without ever sending the
// terminating blank line must not hang the handler or grow the captured map until
// the process OOMs. The header loop is bounded, so the server stops reading and
// responds.

import (
	"strings"
	"testing"
	"time"

	"sweetty/internal/persona"
	httpproto "sweetty/internal/proto/http"
	"sweetty/internal/testharness"
)

func TestHTTPHeaderFloodIsBounded(t *testing.T) {
	h, err := testharness.New(httpproto.New(nil, persona.Generate(), "nginx-static"))
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	var b strings.Builder
	b.WriteString("GET / HTTP/1.1\r\n")
	for range 500 { // far past the 100-header cap, with no terminating blank line
		b.WriteString("X-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n")
	}
	// Send in the background: the server stops reading at the header cap and responds,
	// leaving the rest of the flood unconsumed (which blocks the synchronous pipe
	// writer until the test ends). If the loop were unbounded it would block forever
	// waiting for the terminating blank line.
	go h.Send(b.String())

	resp, ok := h.ReadUntil("HTTP/1.1", 3*time.Second)
	if !ok {
		t.Fatalf("server did not respond to a header flood (unbounded read): %q", resp)
	}
}

func TestHTTPHeaderBytesAreBounded(t *testing.T) {
	h, err := testharness.New(httpproto.New(nil, persona.Generate(), "nginx-static"))
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	var b strings.Builder
	b.WriteString("GET / HTTP/1.1\r\n")
	b.WriteString("X-Pad: " + strings.Repeat("a", 70000) + "\r\n")
	b.WriteString("X-Pad: " + strings.Repeat("b", 70000) + "\r\n\r\n")
	go h.Send(b.String())
	resp, ok := h.ReadUntil("HTTP/1.1", 3*time.Second)
	if !ok || !strings.HasPrefix(resp, "HTTP/1.1 431") {
		t.Fatalf("oversized header bytes were not rejected: %q", resp)
	}
}
