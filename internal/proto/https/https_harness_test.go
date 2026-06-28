package https_test

import (
	"strings"
	"testing"
	"time"

	"sweetty/internal/persona"
	"sweetty/internal/proto/https"
	"sweetty/internal/testharness"
)

// TestTLSHelloCaptured drives the HTTPS banner-and-tarpit over the harness: a
// ClientHello-shaped opening record is captured and classified as a TLS hello
// with a non-empty hex dump, before the service falls into its long tarpit. The
// test asserts on the captured event and closes, so it never waits out the
// multi-minute hold.
func TestTLSHelloCaptured(t *testing.T) {
	p := persona.Generate()
	h, err := testharness.New(https.New(p))
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	// A TLS record header: handshake content type (0x16), TLS version (0x03 0x01),
	// then a record length, followed by filler standing in for the ClientHello
	// body. None of the bytes is CR, LF, or NUL, so the line read captures them
	// intact up to the terminating newline.
	hello := []byte{0x16, 0x03, 0x01, 0x00, 0x2c}
	filler := make([]byte, 32)
	for i := range filler {
		filler[i] = byte(0x40 + i)
	}
	payload := append(append(hello, filler...), '\n')
	h.SendBytes(payload)

	e, ok := h.WaitEvent("TLS_HELLO", 2*time.Second)
	if !ok {
		t.Fatal("no TLS_HELLO event")
	}
	if e.Data == "" {
		t.Fatal("TLS_HELLO captured no data")
	}
	if !strings.Contains(e.Data, "tls_hello=true") {
		t.Fatalf("opening record not classified as a ClientHello: %q", e.Data)
	}
}
