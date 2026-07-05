package ssh_test

// Bot-fidelity pins for the SSH tarpit surface. The tarpit presents a real OpenSSH
// banner and then deliberately never completes the handshake: no session can be
// established, but a scanner sees a banner with no KEXINIT. The interactive SSH
// service is covered by the handshake tests.

import (
	"regexp"
	"testing"
	"time"

	"sweetty/internal/persona"
	"sweetty/internal/proto/ssh"
	"sweetty/internal/testharness"
)

// TestSSHBannerExactWire asserts the identification string is byte-exact: the
// OpenSSH form, the persona version, a trailing CRLF, and nothing else. A drift to
// LF-only or a stray byte would distinguish the box from real OpenSSH on the most
// scanned port.
func TestSSHBannerExactWire(t *testing.T) {
	p := persona.Generate()
	h, err := testharness.New(ssh.NewTarpit(p))
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	want := "SSH-2.0-" + p.OpenSSHVer + "\r\n"
	if got := h.ReadFor(500 * time.Millisecond); got != want {
		t.Fatalf("SSH identification string is not byte-exact:\n got %q\nwant %q", got, want)
	}
}

// TestSSHEmitsBannerThenSilenceBeforeKex pins the deliberate no-KEX trade: after a
// client completes the identification exchange and sends a KEXINIT, a real OpenSSH
// server replies with its own KEXINIT immediately; SweeTTY sends nothing. The
// silence is the intended design, but the client packet is still captured, so
// silence is not inertness.
func TestSSHEmitsBannerThenSilenceBeforeKex(t *testing.T) {
	p := persona.Generate()
	h, err := testharness.New(ssh.NewTarpit(p))
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	if got := h.ReadFor(500 * time.Millisecond); got != "SSH-2.0-"+p.OpenSSHVer+"\r\n" {
		t.Fatalf("unexpected banner: %q", got)
	}

	h.SendLine("SSH-2.0-OpenSSH_9.6")
	kex := make([]byte, 32)
	for i := range kex {
		kex[i] = byte(0x14 + i) // 0x14 = SSH_MSG_KEXINIT
	}
	h.SendBytes(append(kex, '\n'))

	if extra := h.ReadFor(400 * time.Millisecond); extra != "" {
		t.Fatalf("server sent bytes after the client KEXINIT; the deliberate no-KEX trade regressed into a partial handshake: %q", extra)
	}
	if !h.HasEvent("SSH_KEX") {
		t.Fatal("the client KEXINIT was not captured: silence must not mean inertness")
	}
}

// TestSSHBannerPoolMatchesOpenSSHGrammar proves every advertised version is a
// well-formed OpenSSH+Ubuntu package string and that it actually varies per
// instance, so a malformed pool entry (a tell) is caught and the value is not a
// fixed constant readable from the source.
func TestSSHBannerPoolMatchesOpenSSHGrammar(t *testing.T) {
	re := regexp.MustCompile(`^OpenSSH_\d+\.\d+p\d+ Ubuntu-\S+$`)
	seen := map[string]bool{}
	for range 200 {
		v := persona.Generate().OpenSSHVer
		seen[v] = true
		if !re.MatchString(v) {
			t.Fatalf("OpenSSH version %q does not match the OpenSSH+Ubuntu package grammar", v)
		}
	}
	if len(seen) < 2 {
		t.Fatalf("the OpenSSH version never varied across 200 personas: %v", seen)
	}
}
