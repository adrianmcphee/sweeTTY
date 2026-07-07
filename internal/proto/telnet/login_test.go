package telnet_test

import (
	"strings"
	"testing"
	"time"
)

// The post-login banner must read like a real Ubuntu serial console: the welcome
// line carries the release exactly once (not "Welcome to Ubuntu Ubuntu ..."), and
// the stock Ubuntu MOTD header triplet (Documentation/Management/Support) is present
// - a lone Documentation line is impossible on a real box.
func TestUbuntuWelcomeAndMOTD(t *testing.T) {
	h, p := setup(t, "ubuntu")
	if _, ok := h.ReadUntil("login:", 2*time.Second); !ok {
		t.Fatal("never saw login prompt")
	}
	h.SendLine("root")
	h.ReadUntil("Password:", 2*time.Second)
	h.SendLine(p.RootPassword) // the real credential, so the box lets us in
	out := h.ReadFor(900 * time.Millisecond)

	if strings.Contains(out, "Welcome to Ubuntu Ubuntu") {
		t.Errorf("welcome double-prints Ubuntu: %q", out)
	}
	if !strings.Contains(out, "Welcome to "+p.PrettyName) {
		t.Errorf("welcome missing the release %q: %q", p.PrettyName, out)
	}
	for _, line := range []string{"* Documentation:", "* Management:", "* Support:"} {
		if !strings.Contains(out, line) {
			t.Errorf("MOTD missing %q: %q", line, out)
		}
	}
}

// `quit` is not a bash builtin: a real shell answers "command not found" and stays
// alive, where the old code treated it as logout. Proving it both errors AND leaves
// the session running pins the fix.
func TestQuitIsNotABuiltin(t *testing.T) {
	h, p := setup(t, "ubuntu")
	login(t, h, p, "root")
	if out := run(h, "quit"); !strings.Contains(out, "command not found") {
		t.Errorf("quit should be command-not-found, got: %q", out)
	}
	if out := run(h, "whoami"); !strings.Contains(out, "root") {
		t.Errorf("session ended after `quit` (it should not have): %q", out)
	}
}

// agetty re-prompts on a blank login name rather than accepting it. An empty entry
// must not produce a CREDENTIAL event or a shell; the real name that follows is the
// only one captured.
func TestEmptyUsernameRePrompts(t *testing.T) {
	h, _ := setup(t, "ubuntu")
	if _, ok := h.ReadUntil("login:", 2*time.Second); !ok {
		t.Fatal("never saw login prompt")
	}
	// A blank entry must draw a fresh "login:" prompt rather than advancing to the
	// password (drain it before sending again - the harness pipe is unbuffered).
	h.SendLine("")
	if _, ok := h.ReadUntil("login:", 2*time.Second); !ok {
		t.Fatal("a blank username did not re-prompt with login:")
	}
	h.SendLine("root")
	if _, ok := h.ReadUntil("Password:", 2*time.Second); !ok {
		t.Fatal("never reached the password prompt after the blank username")
	}
	h.SendLine("x")
	h.ReadFor(400 * time.Millisecond)

	e, ok := h.FindEvent("CREDENTIAL")
	if !ok {
		t.Fatal("no CREDENTIAL captured")
	}
	if e.Username != "root" {
		t.Errorf("captured username = %q, want root (a blank entry must not be logged)", e.Username)
	}
	for _, ev := range h.Entries() {
		if ev.Event == "CREDENTIAL" && strings.TrimSpace(ev.Username) == "" {
			t.Errorf("a blank username produced a CREDENTIAL event: %+v", ev)
		}
	}
}

// A client that vanishes at the password prompt must not yield a phantom empty
// CREDENTIAL or a shell - the read failure has to be honored.
func TestPasswordDisconnectLogsNoCredential(t *testing.T) {
	h, _ := setup(t, "ubuntu")
	if _, ok := h.ReadUntil("login:", 2*time.Second); !ok {
		t.Fatal("never saw login prompt")
	}
	h.SendLine("root")
	if _, ok := h.ReadUntil("Password:", 2*time.Second); !ok {
		t.Fatal("never saw password prompt")
	}
	h.Close() // vanish mid-password
	time.Sleep(250 * time.Millisecond)

	if _, ok := h.FindEvent("CREDENTIAL"); ok {
		t.Error("phantom CREDENTIAL logged after a mid-password disconnect")
	}
}

// The box validates like real telnetd/login: the persona's per-instance password is
// accepted and lands a root shell, logged as accepted.
func TestCorrectPasswordIsAccepted(t *testing.T) {
	h, p := setup(t, "ubuntu")
	login(t, h, p, "root")
	if out := run(h, "whoami"); !strings.Contains(out, "root") {
		t.Fatalf("the correct password did not reach a root shell: %q", out)
	}
	e, ok := h.FindEvent("CREDENTIAL")
	if !ok || e.Note != "accepted" {
		t.Fatalf("correct password was not logged as accepted: %+v", e)
	}
}

// A wrong password draws "Login incorrect" and re-prompts (login(1) allows three
// tries), never granting a shell - so telnet and SSH agree on what a wrong password
// does, and a scanner cannot tell them apart by waving a bad credential through.
func TestWrongPasswordRePromptsLoginIncorrect(t *testing.T) {
	h, p := setup(t, "ubuntu")
	if _, ok := h.ReadUntil("login:", 2*time.Second); !ok {
		t.Fatal("never saw login prompt")
	}
	h.SendLine("root")
	h.ReadUntil("Password:", 2*time.Second)
	h.SendLine(p.RootPassword + "-nope")
	if _, ok := h.ReadUntil("Login incorrect", 2*time.Second); !ok {
		t.Fatal("a wrong password did not produce 'Login incorrect'")
	}
	if _, ok := h.ReadUntil("login:", 2*time.Second); !ok {
		t.Fatal("the prompt did not return to login: after a wrong password")
	}
	if e, ok := h.FindEvent("CREDENTIAL"); !ok || e.Note != "rejected" {
		t.Fatalf("wrong password not logged as rejected: %+v", e)
	}
}
