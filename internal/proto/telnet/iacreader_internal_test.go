package telnet

import (
	"bytes"
	"io"
	"testing"
)

// TestIACReaderCRVariantsEndLine pins the fix for the interactive-client bug: a real
// telnet client ends a line with CR LF, CR NUL, or a bare CR depending on its mode,
// and every one of them must reach the shell as a single clean newline. Before this,
// the reader broke lines only on LF, so a macOS/BSD telnet client (which sends CR NUL
// for Enter) never submitted a line and the login prompt just piled up carriage
// returns.
func TestIACReaderCRVariantsEndLine(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
	}{
		{"CR LF", []byte("root\r\nadmin\r\n")},
		{"CR NUL", []byte("root\r\x00admin\r\x00")},
		{"bare CR", []byte("root\radmin\r")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &iacReader{src: bytes.NewReader(tc.in)}
			got, err := io.ReadAll(r)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if string(got) != "root\nadmin\n" {
				t.Fatalf("cleaned stream = %q, want %q", got, "root\nadmin\n")
			}
		})
	}
}

// TestIACReaderRecordsCleanedInput verifies the recorder tap sees the keystrokes the
// attacker typed, not the telnet framing around them: option negotiation, the NUL
// that pairs a CR, and the CR itself must all be gone, leaving a clean newline. This
// is what keeps the live watch and the replay readable instead of showing raw IAC
// option bytes as input.
func TestIACReaderRecordsCleanedInput(t *testing.T) {
	in := []byte{iac, will, optNaws}         // IAC WILL NAWS: a client option offer
	in = append(in, []byte("root\r\x00")...) // then "root" + a CR NUL Enter

	var rec bytes.Buffer
	r := &iacReader{
		src:    bytes.NewReader(in),
		record: func(b []byte) { rec.Write(b) },
	}
	if _, err := io.ReadAll(r); err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := rec.String(); got != "root\n" {
		t.Fatalf("recorded input = %q, want %q", got, "root\n")
	}
	if bytes.IndexByte(rec.Bytes(), iac) >= 0 || bytes.IndexByte(rec.Bytes(), 0) >= 0 {
		t.Fatalf("recorded input still carries telnet framing: % x", rec.Bytes())
	}
}

// TestIACReaderDropsBareNUL confirms a NUL that is not part of a CR pair is dropped
// (a telnet NVT no-op), so it never reaches the shell as a phantom byte.
func TestIACReaderDropsBareNUL(t *testing.T) {
	r := &iacReader{src: bytes.NewReader([]byte("a\x00b\r\n"))}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "ab\n" {
		t.Fatalf("cleaned stream = %q, want %q", got, "ab\n")
	}
}
