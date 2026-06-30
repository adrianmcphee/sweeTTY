package shell

import "testing"

// TestDecodeEchoEscapes pins the escape interpretation echo -e performs, above all
// \xHH, which is how a BusyBox echo-loader writes a dropper one byte at a time.
func TestDecodeEchoEscapes(t *testing.T) {
	cases := []struct{ in, want string }{
		{`\x50\x6f\x72\x74`, "Port"},
		{`\x7f\x45\x4c\x46`, "\x7fELF"},
		{`a\tb\nc`, "a\tb\nc"},
		{`no escapes here`, "no escapes here"},
		{`\\x41`, `\x41`}, // an escaped backslash, then the literal text x41
		{`\x4`, "\x04"},   // a single trailing hex digit still decodes
		{`\0101`, "A"},    // octal \0NNN form (\0101 == 'A')
	}
	for _, c := range cases {
		if got := decodeEchoEscapes(c.in); got != c.want {
			t.Errorf("decodeEchoEscapes(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestEchoInterpretsEscapesOnlyWithDashE proves -e (or -ne) turns on escape
// interpretation while a plain echo leaves the text literal, matching bash.
func TestEchoInterpretsEscapesOnlyWithDashE(t *testing.T) {
	sh := &Shell{}
	if got := sh.cmdEcho([]string{"echo", "-ne", `\x50\x6f`}); got != "Po" {
		t.Errorf("echo -ne decode = %q, want %q", got, "Po")
	}
	if got := sh.cmdEcho([]string{"echo", `\x50\x6f`}); got != `\x50\x6f`+"\n" {
		t.Errorf("echo without -e must not decode, got %q", got)
	}
	if got := sh.cmdEcho([]string{"echo", "-e", `a\nb`}); got != "a\nb\n" {
		t.Errorf("echo -e = %q, want %q", got, "a\nb\n")
	}
}
