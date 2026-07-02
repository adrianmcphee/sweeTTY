// Package telnet presents a fake Linux shell over telnet. It performs just enough
// option negotiation to look like real telnetd (it suppresses client echo around
// the password prompt and strips inbound IAC sequences), captures the login
// credentials, and hands off to the shell engine backed by the virtual
// filesystem. It executes nothing an attacker sends.
package telnet

import (
	"errors"
	"io"
	"strings"
	"time"

	"sweetty/internal/fakehost"
	"sweetty/internal/persona"
	"sweetty/internal/server"
	"sweetty/internal/shell"
	"sweetty/internal/util"
	"sweetty/internal/vfs"
)

// maxSubnegLen caps the bytes consumed while scanning one telnet subnegotiation for
// its terminating IAC SE. Real subnegotiations are tiny; a longer one is malformed.
const maxSubnegLen = 256

// maxNegotiations bounds how many option-negotiation triplets a single Read may
// consume before giving up. Each triplet makes the reader write a reply while
// producing no data byte, so a peer that streams IAC DO x IAC DO x ... can hold
// the loop spinning and force a 1:1 write reflection. A real client negotiates a
// handful of options at startup; far past that is a flood, and ending the read
// stops it well before the idle deadline would.
const maxNegotiations = 512

// loginAttempts is how many username/password tries the login prompt allows before
// dropping the connection, matching login(1)'s default LOGIN_RETRIES of 3.
const loginAttempts = 3

// errOversizedSubneg ends a read whose subnegotiation never terminates, so a peer
// cannot pin the IAC reader on the raw socket with an unbounded IAC SB stream.
var errOversizedSubneg = errors.New("telnet: oversized subnegotiation")

// errNegotiationFlood ends a read that is nothing but option negotiation, so a
// peer cannot pin the reader reflecting replies without ever sending input.
var errNegotiationFlood = errors.New("telnet: option-negotiation flood")

// Telnet option bytes.
const (
	iac  = 0xff
	se   = 0xf0
	sb   = 0xfa
	will = 0xfb
	wont = 0xfc
	do   = 0xfd
	dont = 0xfe

	optEcho       = 0x01
	optSGA        = 0x03
	optTType      = 0x18
	optNaws       = 0x1f
	optTSpeed     = 0x20
	optXDisploc   = 0x23
	optNewEnviron = 0x27
)

type Protocol struct {
	fs    *vfs.FS
	p     *persona.Persona
	style string
}

// New builds a telnet honeypot over fs, wearing the given persona and shell style
// ("ubuntu" for a Linux login shell, or "cisco" for an IOS-style CLI).
func New(fs *vfs.FS, p *persona.Persona, style string) server.Protocol {
	return &Protocol{fs: fs, p: p, style: style}
}

func (t *Protocol) Name() string      { return "telnet" }
func (t *Protocol) ClientFirst() bool { return false }

// DecodesInput reports that telnet strips IAC negotiation from attacker input and
// records the cleaned keystrokes itself, so the server must not raw-tee the wire.
func (t *Protocol) DecodesInput() bool { return true }

func (t *Protocol) Handle(s *server.Session) {
	s.Persona = t.p
	// Open with a burst like a real netkit/inetutils telnetd: query the client for
	// its terminal type, speed, X display and environment, offer to suppress
	// go-ahead, and ask for the window size. A lone DO NAWS is a near-unique
	// honeypot tell. The server still drives ECHO itself around the password, so it
	// is deliberately absent here (that would force char-at-a-time and contradict
	// the line-mode password takeover below). From here we strip any IAC the client
	// sends so it never lands in captured input.
	s.WriteBytesRaw([]byte{
		iac, do, optTType,
		iac, do, optTSpeed,
		iac, do, optXDisploc,
		iac, do, optNewEnviron,
		iac, will, optSGA,
		iac, do, optNaws,
	})
	// Record what the attacker types, not the telnet framing around it: stop the raw
	// input tee, strip IAC through the reader (chained onto the current buffered
	// reader so any bytes a PROXY-header parse read ahead are kept), and tee the
	// cleaned bytes into the recorder. Negotiation replies go straight to the wire so
	// they stay out of the cast too.
	s.RecordInputDecoded()
	s.ReplaceReader(&iacReader{
		src:     s.Reader(),
		respond: func(b []byte) { s.WriteBytesRaw(b) },
		record:  s.RecordInput,
	})

	if t.style == "cisco" {
		t.cisco(s)
		return
	}

	t.banner(s)
	// Real telnetd hands off to login(1): up to three attempts, each captured and
	// validated against this box's per-instance credentials, with "Login incorrect"
	// on a miss. This matches the SSH service (which also validates via persona.Accept)
	// so the two protocols cannot be told apart by whether a wrong password works.
	for attempt := 0; attempt < loginAttempts; attempt++ {
		user, ok := t.readUsername(s)
		if !ok {
			return
		}
		s.Username = user

		// Take over echo so the password is not shown, then return it to the client.
		s.WriteBytesRaw([]byte{iac, will, optEcho})
		pass, ok := s.Prompt("Password: ")
		s.WriteBytesRaw([]byte{iac, wont, optEcho})
		if !ok {
			return // client vanished mid-password: no phantom credential, no shell
		}
		s.Write("\r\n")

		accepted, bruteForced := t.p.AcceptFrom(s.SrcIP, user, pass)
		s.LogCredentialResult(user, pass, accepted, bruteForced)
		if !server.FastMode() {
			time.Sleep(util.RandomDelay(700, 1400)) // simulate a PAM auth check
		}
		if accepted {
			shell.Run(s, t.fs, t.p, loginUser(t.p, user), t.style, nasResolver(t.p))
			return
		}
		s.Write("Login incorrect\r\n\r\n")
	}
	// Three strikes: real telnetd drops the connection.
}

// readUsername prompts like agetty — "<hostname> login: " — until the client
// supplies a non-empty login name, re-prompting on a blank entry the way getty does.
// It returns the trimmed name and false if the client disconnected.
func (t *Protocol) readUsername(s *server.Session) (string, bool) {
	// login(1) does not re-prompt forever; cap blank entries so a client spamming
	// empty lines cannot loop us indefinitely.
	for attempts := 0; attempts < 64; attempts++ {
		u, ok := s.Prompt(t.p.Hostname + " login: ")
		if !ok {
			return "", false
		}
		if u = strings.TrimSpace(u); u != "" {
			return u, true
		}
	}
	return "", false
}

// loginUser maps the typed login name to the account the shell runs as. The persona
// has only root and its primary user (deploy); anything else lands on root, where
// most telnet logins aim. This keeps the prompt identity honest instead of always
// showing root@host no matter what name was typed.
func loginUser(p *persona.Persona, typed string) string {
	if typed == p.Username {
		return p.Username
	}
	return "root"
}

// nasResolver builds the shared pivot: `ssh <backup>` from the shell lands on the
// NAS host. The NAS data comes from fakehost so telnet and ssh resolve it
// identically; the closure adapts it to the shell's PivotResolver type.
func nasResolver(p *persona.Persona) shell.PivotResolver {
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

func (t *Protocol) banner(s *server.Session) {
	// agetty renders the default Ubuntu /etc/issue on a serial line: the release,
	// the hostname, then the tty. (A BusyBox banner over this full Ubuntu shell was
	// incoherent, so the appliance wears Ubuntu end to end.)
	v := strings.TrimPrefix(t.p.PrettyName, "Ubuntu ")
	s.SlowWrite("\r\nUbuntu "+v+" "+t.p.Hostname+" ttyS0\r\n\r\n", 12*time.Millisecond)
}

// cisco presents a minimal IOS-style CLI instead of a unix shell.
func (t *Protocol) cisco(s *server.Session) {
	s.Writeln("")
	s.Writeln("")
	s.Writeln("User Access Verification")
	s.Writeln("")
	user, ok := s.Prompt("Username: ")
	if !ok {
		return
	}
	s.WriteBytesRaw([]byte{iac, will, optEcho})
	pass, ok := s.Prompt("Password: ")
	s.WriteBytesRaw([]byte{iac, wont, optEcho})
	if !ok {
		return // client vanished mid-password: no phantom credential
	}
	s.Write("\r\n")
	s.LogCredential(strings.TrimSpace(user), pass)
	if !server.FastMode() {
		time.Sleep(util.RandomDelay(500, 1000))
	}
	host := t.p.Hostname
	for {
		line, ok := s.Prompt(host + ">")
		if !ok {
			return
		}
		cmd := strings.TrimSpace(line)
		if cmd == "" {
			continue
		}
		s.LogCommand(cmd)
		switch {
		case cmd == "exit" || cmd == "logout" || cmd == "quit":
			return
		case strings.HasPrefix(cmd, "en"):
			s.Writeln("% Access denied")
		case strings.HasPrefix(cmd, "show ver"):
			s.Writeln("Cisco IOS Software, C2900 Software, Version 15.7(3)M6, RELEASE SOFTWARE")
			s.Writeln(host + " uptime is 41 weeks, 2 days")
		case strings.HasPrefix(cmd, "show run"):
			s.Writeln("% Incomplete command.")
		default:
			s.Writeln("% Unknown command or computer name, or unable to find computer address")
		}
	}
}

// iacReader filters telnet IAC sequences out of the client byte stream so the
// shell sees clean input. IAC IAC becomes a literal 0xFF; option triplets and
// subnegotiations are consumed. A telnet client ends a line with CR followed by LF
// or NUL (BSD/macOS telnet sends CR NUL for Enter by default), so the reader treats
// CR as the line terminator and swallows the byte that pairs it; a bare NUL is a
// no-op and is dropped. Without this an interactive client's Enter never reaches the
// shell and the login prompt just accumulates carriage returns.
type iacReader struct {
	src     io.Reader
	one     [1]byte
	respond func([]byte) // sends a negotiation reply back to the client, if set
	record  func([]byte) // tees the cleaned (post-IAC-strip) input into the recorder, if set
	sawCR   bool         // last emitted byte was a CR turned into a newline; swallow a paired LF or NUL
}

// Read strips telnet framing and, when a recorder is attached, tees the cleaned
// bytes it hands to the shell, so the cast shows keystrokes rather than the IAC
// option negotiation that surrounds them on the wire.
func (r *iacReader) Read(p []byte) (int, error) {
	n, err := r.read(p)
	if n > 0 && r.record != nil {
		r.record(p[:n])
	}
	return n, err
}

// negotiate answers a client option request the way a real telnetd does, rather
// than swallowing it in silence (a near-unique honeypot tell). It mirrors the
// opening burst: acknowledgements of options the server itself requested (DO TTYPE/
// TSPEED/XDISPLOC/NEW-ENVIRON/NAWS) or offered (WILL SGA, plus ECHO which it drives
// around the password) draw no reply — answering would contradict the request and
// could loop — while every other DO is met with WONT and every other WILL with DONT.
func (r *iacReader) negotiate(cmd, opt byte) {
	if r.respond == nil {
		return
	}
	switch cmd {
	case do:
		// Acks of options the server itself offered (WILL) must not be answered.
		if opt == optEcho || opt == optSGA {
			return // the server drives ECHO and offered WILL SGA
		}
		r.respond([]byte{iac, wont, opt})
	case will:
		// Acks of options the server requested (DO) must not be answered, or the
		// reply would contradict the request and risk a negotiation loop.
		switch opt {
		case optNaws, optTType, optTSpeed, optXDisploc, optNewEnviron:
			return
		}
		r.respond([]byte{iac, dont, opt})
	}
	// WONT/DONT need no reply; answering them would risk a negotiation loop.
}

func (r *iacReader) readByte() (byte, error) {
	_, err := io.ReadFull(r.src, r.one[:])
	return r.one[0], err
}

func (r *iacReader) read(p []byte) (int, error) {
	n := 0
	negs := 0
	for n < len(p) {
		b, err := r.readByte()
		if err != nil {
			if n > 0 {
				return n, nil
			}
			return 0, err
		}
		// A CR just ended a line and was turned into a newline; telnet pairs it with
		// LF or NUL, so swallow whichever follows rather than start the next line with
		// a stray character. Any other byte is real input and falls through.
		if r.sawCR {
			r.sawCR = false
			if b == '\n' || b == 0 {
				continue
			}
		}
		if b == iac {
			c, err := r.readByte()
			if err != nil {
				if n > 0 {
					return n, nil
				}
				return 0, err
			}
			switch {
			case c == iac:
				p[n] = iac
				n++
			case c == will || c == wont || c == do || c == dont:
				opt, err := r.readByte() // consume the option byte
				if err != nil {
					if n > 0 {
						return n, nil
					}
					return 0, err
				}
				r.negotiate(c, opt)
				if negs++; negs > maxNegotiations {
					return n, errNegotiationFlood
				}
			case c == sb:
				// A real subnegotiation (NAWS, terminal type) is a handful of bytes.
				// Cap the scan so a peer that sends IAC SB and then a stream with no
				// terminating IAC SE cannot keep this loop reading the raw socket
				// forever; an oversized subnegotiation is malformed, so end the read.
				for sbLen := 0; ; sbLen++ {
					if sbLen > maxSubnegLen {
						return n, errOversizedSubneg
					}
					x, err := r.readByte()
					if err != nil {
						return n, err
					}
					if x == iac {
						y, err := r.readByte()
						if err != nil {
							return n, err
						}
						if y == se {
							break
						}
					}
				}
			}
			continue
		}
		switch b {
		case '\r':
			// The line terminator for a real telnet client. Hand the shell a clean
			// newline and remember the CR so the LF or NUL that pairs it is swallowed.
			p[n] = '\n'
			n++
			r.sawCR = true
			return n, nil
		case '\n':
			p[n] = '\n'
			n++
			return n, nil
		case 0:
			// Bare NUL is a telnet NVT no-op; drop it so it never reaches the shell as
			// a phantom byte or lands in captured input.
			continue
		default:
			p[n] = b
			n++
		}
	}
	return n, nil
}
