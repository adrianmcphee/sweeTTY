// Package term is an in-process line discipline for the honeypot's fake interactive
// shells. The honeypot has no real PTY and executes nothing; this emulates just
// enough of a terminal, entirely in memory, that a client which put its own terminal
// in raw mode (SSH with a PTY, telnet in character mode) sees a convincing login: it
// echoes printable input, turns Enter into a submitted line, handles backspace and
// Ctrl-C / Ctrl-D, and can suppress echo so a password is never shown. It touches no
// operating-system facility; it only shuffles bytes.
package term

import "io"

// maxLine bounds one edited input line. Without it a newline-free flood grows the
// line and pending buffers until the process OOMs, since this path bypasses the line
// reader's own ceiling. It matches that reader's 64KB limit.
const maxLine = 64 * 1024

// Cooked reads raw keystrokes from r and writes echoes to w. For SSH those are the
// same channel; for telnet, r is the IAC-stripped input stream and w is the wire.
// The zero value is not usable; construct with New.
type Cooked struct {
	r       io.Reader
	w       io.Writer
	echo    bool         // echo printable input and backspace erases; off hides a password
	record  func([]byte) // tees each submitted line into a recorder, if set
	pending []byte       // cooked bytes ready to hand to the line reader
	line    []byte       // the line currently being edited
	prevCR  bool         // last byte was CR, so swallow a following LF or NUL
	eof     bool
}

// New builds a cooked terminal reading from r and echoing to w, with echo on.
func New(r io.Reader, w io.Writer) *Cooked {
	return &Cooked{r: r, w: w, echo: true}
}

// SetEcho turns local echo on or off. Turning it off hides a password the way a real
// login does: the character is still collected into the line, just not shown.
func (t *Cooked) SetEcho(on bool) { t.echo = on }

// OnLine registers a hook that receives each submitted line (with its trailing
// newline), so a caller can record what was typed even when echo is off. SSH records
// through its connection wrapper instead and leaves this nil.
func (t *Cooked) OnLine(fn func([]byte)) { t.record = fn }

func (t *Cooked) Write(p []byte) (int, error) { return t.w.Write(p) }

// Close closes the underlying writer if it is a Closer, so an SSH channel is torn
// down when the shell ends.
func (t *Cooked) Close() error {
	if c, ok := t.w.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

func (t *Cooked) Read(p []byte) (int, error) {
	for len(t.pending) == 0 {
		if t.eof {
			return 0, io.EOF
		}
		var buf [256]byte
		n, err := t.r.Read(buf[:])
		if n > 0 {
			t.cook(buf[:n])
		}
		if err != nil && len(t.pending) == 0 {
			return 0, err
		}
	}
	n := copy(p, t.pending)
	t.pending = t.pending[n:]
	return n, nil
}

// cook processes raw input bytes into echoed, line-edited output appended to
// t.pending as complete lines.
func (t *Cooked) cook(in []byte) {
	for _, c := range in {
		cr := t.prevCR
		t.prevCR = false
		switch {
		case c == '\r':
			t.endLine()
			t.prevCR = true
		case c == '\n':
			if cr {
				continue // swallow the LF of a CR LF pair
			}
			t.endLine()
		case c == 0:
			// NUL: the pair byte of a telnet CR NUL Enter, or an NVT no-op. Drop it so
			// it never reaches the shell as a phantom byte.
			continue
		case c == 0x7f || c == 0x08: // DEL / backspace
			if len(t.line) > 0 {
				t.line = t.line[:len(t.line)-1]
				if t.echo {
					io.WriteString(t.w, "\b \b")
				}
			}
		case c == 0x03: // Ctrl-C: abandon the current line
			io.WriteString(t.w, "^C\r\n")
			t.line = t.line[:0]
			t.emit([]byte{'\n'})
		case c == 0x04: // Ctrl-D: EOF on an empty line, ignored mid-line
			if len(t.line) == 0 {
				t.eof = true
				return
			}
		case c >= 0x20: // printable; other control bytes are ignored
			t.line = append(t.line, c)
			if t.echo {
				t.w.Write([]byte{c})
			}
			// Flush an over-long line so memory is released, the way a real terminal
			// eventually wraps and submits, since this path never returns to the line
			// reader's own ceiling.
			if len(t.line) >= maxLine {
				t.endLine()
			}
		}
	}
}

// endLine echoes a newline (always, even for a hidden password, so the cursor
// advances) and hands the buffered line to the reader.
func (t *Cooked) endLine() {
	io.WriteString(t.w, "\r\n")
	t.emit(t.line)
	t.emit([]byte{'\n'})
	t.line = t.line[:0]
}

// emit appends cooked bytes for the reader and tees them to the record hook.
func (t *Cooked) emit(b []byte) {
	t.pending = append(t.pending, b...)
	if t.record != nil && len(b) > 0 {
		t.record(b)
	}
}
