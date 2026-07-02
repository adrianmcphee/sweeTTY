package term

import (
	"bytes"
	"io"
	"testing"
)

// newCooked wires a Cooked over a fixed input and a buffer that captures the echo,
// the two things every test here inspects.
func newCooked(in string) (*Cooked, *bytes.Buffer) {
	var echo bytes.Buffer
	return New(bytes.NewReader([]byte(in)), &echo), &echo
}

// TestEditsAndTerminatesLines proves the line discipline: backspace erases the
// mistyped character, a bare CR ends the line, the reader sees a clean LF-terminated
// line, and the client gets the input echoed with the erase sequence.
func TestEditsAndTerminatesLines(t *testing.T) {
	// Type "whoamz", backspace the 'z', type 'i', Enter (bare CR), then "exit" + Enter.
	tty, echo := newCooked("whoamz\x7fi\rexit\r")
	got, err := io.ReadAll(tty)
	if err != nil {
		t.Fatalf("read cooked input: %v", err)
	}
	if want := "whoami\nexit\n"; string(got) != want {
		t.Errorf("cooked line stream = %q, want %q", got, want)
	}
	if !bytes.Contains(echo.Bytes(), []byte("\b \b")) {
		t.Errorf("backspace was not echoed as an erase sequence: %q", echo.String())
	}
	if !bytes.Contains(echo.Bytes(), []byte("whoam")) {
		t.Errorf("typed input was not echoed back: %q", echo.String())
	}
}

// TestSwallowsCRLF proves a CR LF pair is read as one line, not a line plus an empty
// one, and TestSwallowsCRNUL the same for the telnet CR NUL Enter.
func TestSwallowsCRLF(t *testing.T) {
	tty, _ := newCooked("id\r\n")
	got, _ := io.ReadAll(tty)
	if want := "id\n"; string(got) != want {
		t.Errorf("CR LF not coalesced: got %q, want %q", got, want)
	}
}

func TestSwallowsCRNUL(t *testing.T) {
	// A macOS/BSD telnet client sends CR NUL for Enter; the NUL must be dropped.
	tty, _ := newCooked("root\r\x00admin\r\x00")
	got, _ := io.ReadAll(tty)
	if want := "root\nadmin\n"; string(got) != want {
		t.Errorf("CR NUL not handled: got %q, want %q", got, want)
	}
}

// TestCtrlDEndsSession proves Ctrl-D on an empty line reads as a clean EOF.
func TestCtrlDEndsSession(t *testing.T) {
	tty, _ := newCooked("\x04")
	if _, err := io.ReadAll(tty); err != nil {
		t.Fatalf("Ctrl-D should read as a clean EOF, got: %v", err)
	}
}

// TestSetEchoHidesPassword proves that with echo off the characters are still
// collected into the line (so the password is captured) but never echoed, while the
// terminating newline still shows so the cursor advances past the hidden entry.
func TestSetEchoHidesPassword(t *testing.T) {
	tty, echo := newCooked("s3cret\r")
	tty.SetEcho(false)
	got, _ := io.ReadAll(tty)
	if want := "s3cret\n"; string(got) != want {
		t.Errorf("password not collected: got %q, want %q", got, want)
	}
	if bytes.Contains(echo.Bytes(), []byte("s3cret")) {
		t.Errorf("password was echoed with echo off: %q", echo.String())
	}
	if !bytes.Contains(echo.Bytes(), []byte("\r\n")) {
		t.Errorf("the Enter after a hidden password should still advance the cursor: %q", echo.String())
	}
}

// TestOnLineRecordsSubmittedLines proves the record hook receives exactly the
// submitted lines (with their newline), so a caller can log what was typed even when
// echo is suppressed.
func TestOnLineRecordsSubmittedLines(t *testing.T) {
	var rec bytes.Buffer
	tty, _ := newCooked("ls -la\rwhoami\r")
	tty.OnLine(func(b []byte) { rec.Write(b) })
	io.ReadAll(tty)
	if want := "ls -la\nwhoami\n"; rec.String() != want {
		t.Errorf("recorded input = %q, want %q", rec.String(), want)
	}
}
