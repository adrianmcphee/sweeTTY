package server

// Protocol is implemented by every fake service. Handle owns the connection for
// its whole lifetime. Name is used in logs and startup output. ClientFirst
// reports whether the client is expected to send data before the server speaks:
// true for request/response protocols (HTTP), false for banner-first protocols
// (telnet, SSH, FTP). The server uses it to decide how to detect bare-connect
// port scans without misclassifying a client that is simply waiting for a banner.
type Protocol interface {
	Name() string
	ClientFirst() bool
	Handle(s *Session)
}

// inputDecoder is an optional Protocol capability: a protocol that strips its own
// transport framing from attacker input (telnet removing IAC negotiation) and tees
// the cleaned keystrokes into the recorder itself. For such a protocol the server
// does not raw-tee read-ahead it buffered, so the cast shows what was typed rather
// than the wire framing around it.
type inputDecoder interface {
	DecodesInput() bool
}

// decodesInput reports whether p records its own cleaned input.
func decodesInput(p Protocol) bool {
	d, ok := p.(inputDecoder)
	return ok && d.DecodesInput()
}
