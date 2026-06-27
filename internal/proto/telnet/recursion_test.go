package telnet_test

// Go-live stability pin: a self-referential shell payload must not recurse until
// the goroutine stack overflows. A stack overflow is a fatal runtime error that
// recover() cannot catch, so without a depth guard one telnet session would take
// the entire multi-port sensor (and the portal) down in seconds. The shell must
// instead bottom out with a believable "maximum nesting level" error and keep
// serving.

import (
	"strings"
	"testing"
	"time"
)

func TestSelfReferentialExecDoesNotCrash(t *testing.T) {
	h, p := setup(t, "ubuntu")
	login(t, h, p, "root")

	// X expands to a command that re-runs X: unbounded recursion through sh -c.
	run(h, `X='sh -c "$X"'`)
	run(h, `sh -c "$X"`)

	// The session must still be alive and responsive afterwards — if the process
	// had crashed, the harness pipe would be dead and this would read nothing.
	out := run(h, "echo still-alive")
	if !strings.Contains(out, "still-alive") {
		t.Fatalf("shell did not survive a self-referential exec payload: %q", out)
	}
}

// TestPivotIsSingleHop proves the NAS pivot cannot pivot onward: an attacker who
// lands on the backup host and then sshes back to it again does not nest another
// shell. Without the single-hop bound, repeating the pivot would stack newShell().
// loop() frames until the goroutine stack overflows — a crash that bypasses the
// per-shell exec-depth guard.
func TestPivotIsSingleHop(t *testing.T) {
	h, p := setup(t, "ubuntu")
	login(t, h, p, "root")

	// Hop 1: pivot onto the NAS.
	h.SendLine("ssh deploy@" + p.BackupIP)
	h.ReadUntil("(yes/no", 3*time.Second)
	h.SendLine("yes")
	h.ReadUntil("password", 3*time.Second)
	h.SendLine("Summer2026!")
	h.ReadFor(700 * time.Millisecond)
	if out := run(h, "hostname"); !strings.Contains(out, p.BackupHost) {
		t.Fatalf("first pivot did not land on the NAS (%q): %q", p.BackupHost, out)
	}

	// Hop 2: from the NAS, ssh to the backup again. It still walks the auth dialogue
	// (capturing credentials, which is good), but must fail to connect rather than
	// nest another shell.
	h.SendLine("ssh deploy@" + p.BackupIP)
	h.ReadUntil("(yes/no", 3*time.Second)
	h.SendLine("yes")
	h.ReadUntil("password", 3*time.Second)
	h.SendLine("pw2")
	out := h.ReadFor(700 * time.Millisecond)
	if !strings.Contains(out, "timed out") {
		t.Fatalf("the NAS pivoted onward instead of failing to connect (unbounded pivot recursion): %q", out)
	}
	// Still on the single NAS shell and responsive.
	if out := run(h, "hostname"); !strings.Contains(out, p.BackupHost) {
		t.Fatalf("shell not responsive on the NAS after the refused onward pivot: %q", out)
	}
}

func TestBase64DecodedCommandDoesNotCrash(t *testing.T) {
	h, p := setup(t, "ubuntu")
	login(t, h, p, "root")

	// A file whose bytes decode to a command that base64-decodes the same file:
	// the base64 auto-exec path would recurse without the depth guard.
	run(h, `echo YmFzaCAtYyAnYmFzZTY0IC1kIC90bXAvbG9vcCc= > /tmp/loop`)
	h.SendLine("base64 -d /tmp/loop")
	h.ReadFor(700 * time.Millisecond)

	out := run(h, "echo still-alive")
	if !strings.Contains(out, "still-alive") {
		t.Fatalf("shell did not survive a base64-decoded command payload: %q", out)
	}
}
