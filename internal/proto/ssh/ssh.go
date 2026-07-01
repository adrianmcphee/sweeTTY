// Package ssh implements an interactive SSH service. It completes a real SSH
// handshake using the instance's persistent per-instance host key, presents the
// persona's OpenSSH identification string, validates credentials against the
// persona (so only this instance's random password, or the primary user's, logs
// in), and hands an authenticated session to the same shell engine the telnet
// service uses. It executes nothing an attacker sends: the shell is the tarpit
// shell, downloads fetch nothing, and mutations land only in the per-session VFS
// overlay.
//
// Completing the handshake is a deliberate reversal of the earlier
// banner-and-tarpit design. The cost is that a real handshake exposes this Go SSH
// stack's algorithm fingerprint (its KEX/cipher/MAC list, i.e. its HASSH), which a
// determined fingerprinter can tell apart from a genuine OpenSSH server even though
// the banner matches. The gain is the whole point of an SSH honeypot: full capture
// of credentials, commands, payloads, and the post-login behaviour of a bot that
// believes it is in. The pure banner-and-tarpit remains available as NewTarpit for
// ports where zero crypto fingerprint matters more than interaction.
package ssh

import (
	"encoding/binary"
	"errors"
	"io"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"sweetty/internal/fakehost"
	"sweetty/internal/persona"
	"sweetty/internal/server"
	"sweetty/internal/shell"
	"sweetty/internal/util"
	"sweetty/internal/vfs"
)

// captureTimeout bounds how long the tarpit waits for the client's banner and
// KEXINIT before it stops reading and holds the connection, so a silent client
// cannot stall the capture phase.
const captureTimeout = 15 * time.Second

// maxKexBytes caps the tarpit key-exchange capture buffer. Only the leading bytes
// carry fingerprintable structure.
const maxKexBytes = 512

// tarpitHold is how long the tarpit holds a connection open after capture.
const tarpitHold = 5 * time.Minute

// maxAuthTries bounds password guesses per connection, matching a typical sshd
// MaxAuthTries, so a single connection cannot brute-force indefinitely (every
// attempt is still captured).
const maxAuthTries = 6

// handshakeTimeout bounds the SSH transport handshake and authentication. The
// interactive path runs the handshake on the bare TCP conn, which has no per-read
// deadline of its own, so without this a client that opens the socket and then
// dribbles or sends nothing pins a goroutine, an fd, and a connection-limiter slot
// forever. Held long enough that a slow-but-real client still completes. A var,
// not a const, only so a test can shorten it.
var handshakeTimeout = 30 * time.Second

// sessionDeadline is the absolute ceiling on one interactive SSH connection once
// the handshake is done, mirroring the line protocols' session-lifetime clamp. It
// stops a client that completes auth but never opens a channel, or opens a channel
// but never requests a shell, from stalling a goroutine indefinitely.
const sessionDeadline = 60 * time.Minute

// startTimeout bounds how long an accepted channel waits for its first shell or
// exec request before the session is abandoned.
const startTimeout = 2 * time.Minute

// errAuthFailed is the generic rejection returned to every failed auth attempt, so
// the client cannot distinguish a wrong password from an unknown user.
var errAuthFailed = errors.New("permission denied")

// Protocol is the interactive SSH service. It carries the instance persona (for the
// banner, host key, and credential policy) and the virtual filesystem the shell
// runs over.
type Protocol struct {
	fs    *vfs.FS
	p     *persona.Persona
	style string
}

// New returns an interactive SSH service over fs, wearing the given persona. style
// selects the shell prompt flavour; only "ubuntu" is used today and an empty style
// defaults to it.
func New(fs *vfs.FS, p *persona.Persona, style string) server.Protocol {
	return &Protocol{fs: fs, p: p, style: style}
}

// Name reports the protocol label used in logs and startup output.
func (pr *Protocol) Name() string { return "ssh" }

// ClientFirst is false: an SSH server sends its identification string first.
func (pr *Protocol) ClientFirst() bool { return false }

// Handle completes the SSH handshake, authenticates against the persona, and serves
// the shell over each session channel.
func (pr *Protocol) Handle(s *server.Session) {
	s.Persona = pr.p

	signer, err := hostSigner(pr.p)
	if err != nil {
		// No usable host key (an older persona generated before the seed existed).
		// Degrade to the banner-and-tarpit so the port still behaves like an SSH
		// service and still captures the client banner and KEXINIT, rather than
		// starting with an unstable, regenerated host key.
		s.LogRaw("SSH_NOTE", "no host key in persona; serving banner-and-tarpit")
		tarpit(s, pr.p)
		return
	}

	cfg := &gossh.ServerConfig{
		ServerVersion: "SSH-2.0-" + pr.p.OpenSSHVer,
		MaxAuthTries:  maxAuthTries,
		PasswordCallback: func(conn gossh.ConnMetadata, password []byte) (*gossh.Permissions, error) {
			return pr.authPassword(s, conn.User(), string(password))
		},
		KeyboardInteractiveCallback: func(conn gossh.ConnMetadata, challenge gossh.KeyboardInteractiveChallenge) (*gossh.Permissions, error) {
			// Real Ubuntu sshd answers keyboard-interactive via PAM with a single
			// "Password:" prompt. Mirror that so a bot using this method still hands us
			// a credential and still meets the realistic accept/reject.
			answers, err := challenge("", "", []string{"Password: "}, []bool{false})
			if err != nil || len(answers) == 0 {
				return nil, errAuthFailed
			}
			return pr.authPassword(s, conn.User(), answers[0])
		},
		PublicKeyCallback: func(conn gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
			// Real Ubuntu offers publickey first. We hold no private half of any key, so
			// this always fails, exactly like a server the attacker has no authorized key
			// on, but we record the key they tried for attribution. It is an auth attempt,
			// so it is logged as a credential, not a command.
			s.LogPublicKey(conn.User(), key.Type(), gossh.FingerprintSHA256(key))
			return nil, errAuthFailed
		},
	}
	// Order the key-exchange, cipher, and MAC lists toward what OpenSSH 8.9 offers,
	// rather than shipping the Go crypto library's own default ordering. The banner
	// claims OpenSSH, so a raw Go algorithm list is an easy nmap ssh2-enum-algos tell;
	// this narrows the gap to the residual algorithms x/crypto does not implement
	// (sntrup, umac), which stays the documented, accepted price of completing a real
	// handshake. Only names x/crypto supports are listed, so the handshake still works.
	cfg.KeyExchanges = []string{
		"curve25519-sha256", "curve25519-sha256@libssh.org",
		"ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
		"diffie-hellman-group14-sha256",
	}
	cfg.Ciphers = []string{
		"chacha20-poly1305@openssh.com",
		"aes128-gcm@openssh.com", "aes256-gcm@openssh.com",
		"aes128-ctr", "aes192-ctr", "aes256-ctr",
	}
	cfg.MACs = []string{
		"hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com",
		"hmac-sha2-256", "hmac-sha2-512",
	}
	cfg.AddHostKey(signer)

	// Deadline the handshake on the bare conn: gossh reads the client banner and
	// runs key exchange here with no read deadline of its own, so an idle or
	// dribbling client would otherwise pin this goroutine forever.
	raw := s.RawConn()
	raw.SetDeadline(time.Now().Add(handshakeTimeout))
	sshConn, chans, reqs, err := gossh.NewServerConn(raw, cfg)
	if err != nil {
		// Handshake closed or every auth attempt failed. Credentials are already
		// logged in the callbacks; the library has closed the connection.
		return
	}
	defer sshConn.Close()
	// Handshake done: swap the tight handshake deadline for the absolute session
	// ceiling, so a completed connection that then goes idle (no channel, no shell
	// request) still cannot hold the goroutine and slot open without bound.
	raw.SetDeadline(time.Now().Add(sessionDeadline))
	s.Username = sshConn.User()

	go gossh.DiscardRequests(reqs)
	// Session channels are served one at a time over the shared session IO; attackers
	// open one, and serial handling avoids two channels racing the same Rebind.
	for nc := range chans {
		if nc.ChannelType() != "session" {
			nc.Reject(gossh.UnknownChannelType, "")
			continue
		}
		pr.serveSession(s, nc)
	}
}

// authPassword logs the attempt with its verdict and accepts only a credential the
// persona recognises.
func (pr *Protocol) authPassword(s *server.Session, user, pass string) (*gossh.Permissions, error) {
	ok, bruteForced := pr.p.AcceptFrom(s.SrcIP, user, pass)
	s.LogCredentialResult(user, pass, ok, bruteForced)
	if ok {
		return &gossh.Permissions{}, nil
	}
	return nil, errAuthFailed
}

// serveSession accepts one session channel, redirects the session IO onto it, and
// runs the shell (for a "shell" request) or a one-shot command (for "exec").
func (pr *Protocol) serveSession(s *server.Session, nc gossh.NewChannel) {
	ch, reqs, err := nc.Accept()
	if err != nil {
		return
	}
	defer ch.Close()

	user := pr.shellUser(s.Username)
	style := pr.style
	if style == "" {
		style = "ubuntu"
	}
	pivot := pr.pivot()

	// Channel requests (pty-req, env, shell, exec, window-change) are drained in a
	// goroutine so out-of-band requests during a long command never stall the SSH
	// mux. The first shell/exec request, and whether a PTY was asked for, is reported
	// back over start.
	type startReq struct {
		exec bool
		pty  bool
		cmd  string
	}
	start := make(chan startReq, 1)
	go func() {
		defer close(start)
		// This goroutine parses attacker-controlled channel-request payloads. A panic
		// in a bare goroutine is not caught by the parent's recover and would crash the
		// whole multi-port process, so guard it the way every other input handler is.
		defer func() {
			if r := recover(); r != nil {
				s.LogRaw("SSH_NOTE", "recovered from a panic in the channel-request handler")
			}
		}()
		var pty, started bool
		for req := range reqs {
			switch req.Type {
			case "pty-req":
				// Accept the PTY so the client believes it has an interactive terminal,
				// and remember it so the shell input gets terminal cooking.
				pty = true
				req.Reply(true, nil)
			case "env":
				if name, val, ok := parseEnvReq(req.Payload); ok {
					s.LogCommandNote("export "+name+"="+val, "ssh-env")
				}
				req.Reply(true, nil)
			case "shell":
				req.Reply(!started, nil)
				if !started {
					started = true
					start <- startReq{pty: pty}
				}
			case "exec":
				cmd := sshStringOnly(req.Payload)
				req.Reply(!started, nil)
				if !started {
					started = true
					start <- startReq{exec: true, pty: pty, cmd: cmd}
				}
			case "subsystem":
				// sftp and friends: decline cleanly (subsystem disabled) rather than
				// emit a malformed session. The request is still observed.
				name := sshStringOnly(req.Payload)
				s.LogCommandNote("subsystem "+name, "ssh-subsystem")
				req.Reply(false, nil)
			default:
				if req.WantReply {
					req.Reply(false, nil)
				}
			}
		}
	}()

	var sr startReq
	var ok bool
	select {
	case sr, ok = <-start:
		if !ok {
			// The client closed the channel without ever asking for a shell or command.
			return
		}
	case <-time.After(startTimeout):
		// Channel accepted but no shell/exec request ever arrived: abandon it rather
		// than block this goroutine on the range over reqs indefinitely.
		return
	}

	// An interactive shell on a PTY needs server-side line discipline (echo, Enter,
	// erase), because the client put its terminal in raw mode and sends bare
	// keystrokes. An exec command, or a shell with no PTY, reads the channel raw.
	if sr.pty && !sr.exec {
		s.Rebind(&cookedTTY{ch: ch})
	} else {
		s.Rebind(ch)
	}

	exitCode := 0
	if sr.exec {
		s.LogCommandNote(sr.cmd, "ssh-exec")
		exitCode = shell.RunOnce(s, pr.fs, pr.p, user, style, pivot, sr.cmd)
	} else {
		shell.Run(s, pr.fs, pr.p, user, style, pivot)
	}
	sendExitStatus(ch, uint32(exitCode))
}

// cookedTTY gives the interactive SSH shell a minimal terminal line discipline. A
// client that requested a PTY puts its local terminal in raw mode and sends each
// keystroke unprocessed, expecting the server to echo input and turn Enter (a bare
// CR) into a line. Real sshd delegates this to the kernel PTY; SweeTTY has no PTY,
// so it cooks here: it echoes printable input, handles backspace, treats CR or LF
// as end-of-line (emitting a clean LF to the shell's line reader), and surfaces
// Ctrl-D on an empty line as EOF. Without this an attacker would type into a shell
// that echoes nothing and never accepts a command, which is both unusable and an
// obvious tell.
// maxCookedLine bounds one edited input line in the SSH cooked path, matching the
// line reader's own 64KB ceiling that this path bypasses. Without it a newline-free
// flood grows the line and pending buffers until the process OOMs.
const maxCookedLine = 64 * 1024

type cookedTTY struct {
	ch      gossh.Channel
	pending []byte // cooked bytes ready to hand to the line reader
	line    []byte // the line currently being edited
	prevCR  bool   // last byte was CR, so swallow a following LF
	eof     bool
}

func (t *cookedTTY) Write(p []byte) (int, error) { return t.ch.Write(p) }
func (t *cookedTTY) Close() error                { return t.ch.Close() }

func (t *cookedTTY) Read(p []byte) (int, error) {
	for len(t.pending) == 0 {
		if t.eof {
			return 0, io.EOF
		}
		var buf [256]byte
		n, err := t.ch.Read(buf[:])
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
func (t *cookedTTY) cook(in []byte) {
	for _, c := range in {
		cr := t.prevCR
		t.prevCR = false
		switch {
		case c == '\r':
			t.endLine()
			t.prevCR = true
		case c == '\n':
			if cr {
				continue // swallow the LF of a CRLF pair
			}
			t.endLine()
		case c == 0x7f || c == 0x08: // DEL / backspace
			if len(t.line) > 0 {
				t.line = t.line[:len(t.line)-1]
				t.ch.Write([]byte("\b \b"))
			}
		case c == 0x03: // Ctrl-C: abandon the current line
			t.ch.Write([]byte("^C\r\n"))
			t.line = t.line[:0]
			t.pending = append(t.pending, '\n')
		case c == 0x04: // Ctrl-D: EOF on an empty line, ignored mid-line
			if len(t.line) == 0 {
				t.eof = true
				return
			}
		case c >= 0x20: // printable; other control bytes are ignored
			t.line = append(t.line, c)
			t.ch.Write([]byte{c})
			// A newline-free stream would otherwise grow t.line (and t.pending)
			// without bound, since this path never returns to the line reader's
			// maxLineBytes ceiling. Flush an over-long line so memory is released,
			// the way a real terminal eventually wraps and submits.
			if len(t.line) >= maxCookedLine {
				t.endLine()
			}
		}
	}
}

// endLine echoes a newline and hands the buffered line to the reader.
func (t *cookedTTY) endLine() {
	t.ch.Write([]byte("\r\n"))
	t.pending = append(t.pending, t.line...)
	t.pending = append(t.pending, '\n')
	t.line = t.line[:0]
}

// shellUser maps the authenticated SSH user to the account the shell runs as. Only
// root and the persona's primary user can authenticate (see persona.Accept), so any
// other value is a defensive fallback to root.
func (pr *Protocol) shellUser(authed string) string {
	if authed == pr.p.Username {
		return pr.p.Username
	}
	return "root"
}

// pivot builds the NAS pivot resolver shared with the telnet shell.
func (pr *Protocol) pivot() shell.PivotResolver {
	p := pr.p
	return func(target string) (*shell.Pivot, bool) {
		if target != p.BackupIP && target != p.BackupHost {
			return nil, false
		}
		fs, np, ok := fakehost.NAS(p)
		if !ok {
			return nil, false
		}
		return &shell.Pivot{FS: fs, P: np}, true
	}
}

// ---- tarpit (banner + capture, no handshake) ----

// tarpitProtocol is the original banner-and-tarpit SSH service: it presents the
// OpenSSH identification string, captures the client banner and first KEXINIT for
// fingerprinting, and holds the connection open without ever completing a handshake.
// It exposes zero server-side crypto fingerprint, the trade being that no session
// can be established.
type tarpitProtocol struct{ p *persona.Persona }

// NewTarpit returns the banner-and-tarpit SSH service.
func NewTarpit(p *persona.Persona) server.Protocol { return &tarpitProtocol{p: p} }

func (t *tarpitProtocol) Name() string      { return "ssh" }
func (t *tarpitProtocol) ClientFirst() bool { return false }
func (t *tarpitProtocol) Handle(s *server.Session) {
	s.Persona = t.p
	tarpit(s, t.p)
}

// tarpit speaks the server identification string, records the client's banner and
// first packet, then holds the connection open doing nothing.
func tarpit(s *server.Session, p *persona.Persona) {
	s.Write("SSH-2.0-" + p.OpenSSHVer + "\r\n")
	s.IdleTimeout = captureTimeout

	banner, _ := s.ReadLine()
	s.LogRaw("SSH_CLIENT", banner)

	kex, _ := s.ReadLine()
	buf := []byte(kex)
	if len(buf) > maxKexBytes {
		buf = buf[:maxKexBytes]
	}
	s.LogRaw("SSH_KEX", util.HexDump(buf))

	s.HoldOpen(tarpitHold)
}

// ---- helpers ----

// hostSigner builds the SSH signer from the instance's persistent host key.
func hostSigner(p *persona.Persona) (gossh.Signer, error) {
	key, err := p.SSHHostKey()
	if err != nil {
		return nil, err
	}
	return gossh.NewSignerFromKey(key)
}

// sshStringOnly returns the first SSH wire string in an SSH request payload (an
// exec command, a subsystem name), or "" if the payload is malformed.
func sshStringOnly(payload []byte) string {
	s, _, _ := sshString(payload)
	return s
}

// parseEnvReq parses an SSH "env" request payload (two SSH strings: name, value).
func parseEnvReq(payload []byte) (name, val string, ok bool) {
	name, rest, ok := sshString(payload)
	if !ok {
		return "", "", false
	}
	val, _, ok = sshString(rest)
	if !ok {
		return "", "", false
	}
	return name, val, true
}

// sshString reads one length-prefixed SSH string from b, returning it and the
// remainder. RFC 4251: a 4-byte big-endian length followed by that many bytes.
func sshString(b []byte) (string, []byte, bool) {
	if len(b) < 4 {
		return "", b, false
	}
	n := binary.BigEndian.Uint32(b)
	b = b[4:]
	if uint32(len(b)) < n {
		return "", b, false
	}
	return string(b[:n]), b[n:], true
}

// sendExitStatus sends the channel's exit status, the way a shell reports its exit
// code before the channel closes.
func sendExitStatus(ch gossh.Channel, code uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], code)
	ch.SendRequest("exit-status", false, b[:])
}
