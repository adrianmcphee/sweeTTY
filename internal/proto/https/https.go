// Package https implements a TLS banner-and-tarpit service. It never completes a
// TLS handshake; it captures the client's first bytes, notes whether they look
// like a TLS ClientHello, and then holds the connection open. Because no TLS
// session is ever negotiated, no HTTP request is served and nothing is fetched,
// executed, or written.
package https

import (
	"fmt"
	"time"

	"sweetty/internal/persona"
	"sweetty/internal/server"
	"sweetty/internal/util"
)

// captureTimeout bounds the wait for the client's opening bytes before the
// service falls into the tarpit.
const captureTimeout = 15 * time.Second

// maxHelloBytes caps the capture buffer for the client's opening record.
const maxHelloBytes = 128

// tarpit is how long the connection is held open after capture, doing nothing.
const tarpit = 4 * time.Minute

// Protocol is the HTTPS banner-and-tarpit. It carries the instance persona so
// captured events correlate to the rest of the host's identity.
type Protocol struct {
	persona *persona.Persona
}

// New returns an HTTPS protocol bound to the given persona.
func New(p *persona.Persona) server.Protocol {
	return &Protocol{persona: p}
}

// Name reports the protocol label used in logs and startup output.
func (pr *Protocol) Name() string { return "https" }

// ClientFirst is true: a TLS client sends its ClientHello before the server
// responds.
func (pr *Protocol) ClientFirst() bool { return true }

// DecodesInput reports that this service records its own input: the wire carries
// a binary TLS ClientHello, not keystrokes, so the server must not raw-tee it
// into the cast (the bytes render as mojibake in the replay and live watch, and
// the JSON marshal destroys invalid UTF-8 anyway). Handle records a readable
// classification frame instead; the faithful bytes stay in the TLS_HELLO event.
func (pr *Protocol) DecodesInput() bool { return true }

// Handle captures the client's opening bytes, classifies them as a probable TLS
// ClientHello or not, then tarpits the connection.
func (pr *Protocol) Handle(s *server.Session) {
	s.Persona = pr.persona

	// Stop the raw input tee before the first read; anything the client dribbles
	// during the tarpit stays out of the cast for the same reason.
	s.RecordInputDecoded()

	// Bound the single capture read via the session's idle timeout.
	s.IdleTimeout = captureTimeout

	line, _ := s.ReadLine()
	buf := []byte(line)
	if len(buf) > maxHelloBytes {
		buf = buf[:maxHelloBytes]
	}

	// A TLS record opens with the handshake content type (0x16) followed by a
	// TLS major version of 0x03; that pair is the cheap, reliable ClientHello
	// tell. HexDump itself returns only the first 32 bytes.
	isHello := len(buf) >= 2 && buf[0] == 0x16 && buf[1] == 0x03
	s.LogRaw("TLS_HELLO", fmt.Sprintf("tls_hello=%v hex=%s", isHello, util.HexDump(buf)))

	// Give the cast what the client sent in a form a terminal can show: the
	// classification and a hex dump, in place of the raw record the tee would
	// have written.
	if len(buf) > 0 {
		kind := "non-TLS opening bytes"
		if isHello {
			kind = "TLS ClientHello"
		}
		dump := util.HexDump(buf)
		if len(buf) > 32 {
			dump += " ..."
		}
		s.RecordInput([]byte(kind + "  " + dump + "\r\n"))
	}

	// Tarpit: never negotiate TLS, just hold the socket open doing nothing, but
	// release as soon as the client disconnects so a storm cannot pin resources for
	// the full hold.
	s.HoldOpen(tarpit)
}
