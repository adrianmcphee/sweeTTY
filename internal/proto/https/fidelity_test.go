package https_test

// Bot-fidelity pin for the HTTPS surface. Like SSH, the TLS port deliberately never
// completes a handshake: it captures the ClientHello and holds the socket open,
// writing nothing. The machine-observable consequence is an all-zero JARM and an
// nmap "tcpwrapped" label - a conscious trade (terminating real TLS would expose
// Go's own JARM/JA3S, which would not match nginx+OpenSSL anyway). This test pins
// the zero-bytes-written behaviour so it can never regress into Go's default TLS
// stack, and confirms the ClientHello is still classified and captured.

import (
	"testing"
	"time"

	"sweetty/internal/persona"
	"sweetty/internal/proto/https"
	"sweetty/internal/testharness"
)

func TestHTTPSNeverWritesBytesAndCapturesHello(t *testing.T) {
	p := persona.Generate()
	h, err := testharness.New(https.New(p))
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	// A minimal ClientHello-shaped record: handshake content type 0x16, TLS major
	// 0x03. A trailing newline lets the line-based capture return promptly.
	hello := []byte{0x16, 0x03, 0x01, 0x00, 0x2a, 0x01, 0x00, 0x00, 0x26, 0x03, 0x03, '\n'}
	h.SendBytes(hello)

	// A real TLS server answers with a ServerHello immediately; SweeTTY sends
	// nothing. Anything on the wire here means the all-zero-JARM trade regressed.
	if out := h.ReadFor(400 * time.Millisecond); out != "" {
		t.Fatalf("the HTTPS tarpit wrote %d bytes; it must never speak TLS (all-zero JARM is the deliberate trade): %q", len(out), out)
	}

	e, ok := h.WaitEvent("TLS_HELLO", 2*time.Second)
	if !ok {
		t.Fatal("the ClientHello was not captured")
	}
	if e.Data == "" {
		t.Fatal("TLS_HELLO captured no data")
	}
}
