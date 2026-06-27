package ssh

import (
	"bytes"
	"io"
	"testing"

	gossh "golang.org/x/crypto/ssh"
)

// stubChannel is a minimal gossh.Channel for exercising cookedTTY in isolation: it
// replays a fixed input on Read and captures everything written (the echo).
type stubChannel struct {
	in      []byte
	pos     int
	written bytes.Buffer
}

func (s *stubChannel) Read(p []byte) (int, error) {
	if s.pos >= len(s.in) {
		return 0, io.EOF
	}
	n := copy(p, s.in[s.pos:])
	s.pos += n
	return n, nil
}
func (s *stubChannel) Write(p []byte) (int, error)                    { return s.written.Write(p) }
func (s *stubChannel) Close() error                                   { return nil }
func (s *stubChannel) CloseWrite() error                              { return nil }
func (s *stubChannel) SendRequest(string, bool, []byte) (bool, error) { return false, nil }
func (s *stubChannel) Stderr() io.ReadWriter                          { return io.Discard.(io.ReadWriter) }

var _ gossh.Channel = (*stubChannel)(nil)

// TestCookedTTYEditsAndTerminatesLines proves the PTY line discipline: a backspace
// erases the mistyped character, a bare CR ends the line, and the reader sees a
// clean LF-terminated line, while the client gets the input echoed with the erase
// sequence.
func TestCookedTTYEditsAndTerminatesLines(t *testing.T) {
	// Type "whoamz", backspace the 'z', type 'i', press Enter (bare CR), then "exit"
	// + Enter, then the channel ends.
	stub := &stubChannel{in: []byte("whoamz\x7fi\rexit\r")}
	tty := &cookedTTY{ch: stub}

	got, err := io.ReadAll(tty)
	if err != nil {
		t.Fatalf("read cooked input: %v", err)
	}
	if want := "whoami\nexit\n"; string(got) != want {
		t.Errorf("cooked line stream = %q, want %q", got, want)
	}
	// The client saw its input echoed, including the destructive backspace.
	echo := stub.written.String()
	if !bytes.Contains([]byte(echo), []byte("\b \b")) {
		t.Errorf("backspace was not echoed as an erase sequence: %q", echo)
	}
	if !bytes.Contains([]byte(echo), []byte("whoam")) {
		t.Errorf("typed input was not echoed back: %q", echo)
	}
}

// TestCookedTTYSwallowsCRLF proves a CRLF pair from a client that sends both is read
// as a single line, not as a line plus a spurious empty one.
func TestCookedTTYSwallowsCRLF(t *testing.T) {
	stub := &stubChannel{in: []byte("id\r\n")}
	tty := &cookedTTY{ch: stub}
	got, err := io.ReadAll(tty)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if want := "id\n"; string(got) != want {
		t.Errorf("CRLF not coalesced: got %q, want %q", got, want)
	}
}

// TestCookedTTYCtrlDEndsSession proves Ctrl-D on an empty line is an EOF, the way a
// real shell exits on it.
func TestCookedTTYCtrlDEndsSession(t *testing.T) {
	stub := &stubChannel{in: []byte("\x04")}
	tty := &cookedTTY{ch: stub}
	if _, err := io.ReadAll(tty); err != nil {
		t.Fatalf("Ctrl-D should read as a clean EOF, got: %v", err)
	}
}
