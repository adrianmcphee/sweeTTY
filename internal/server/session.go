package server

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"sweetty/internal/event"
	"sweetty/internal/persona"
	"sweetty/internal/util"
)

const (
	defaultIdleTimeout = 10 * time.Minute
	writeTimeout       = 30 * time.Second
	// maxSessionLifetime is an absolute ceiling on one connection, independent of
	// the per-read idle refresh. ReadLine re-arms the idle deadline on every line,
	// so a client that dribbles one byte just inside the idle window could otherwise
	// pin a goroutine, fd, and limiter slot forever. The cap is generous enough that
	// a genuinely engaged attacker in a multi-minute tarpit is never cut short, and
	// finite enough that an idle-dribbling slowloris is eventually reaped.
	maxSessionLifetime = 60 * time.Minute
)

// Session holds the per-connection state shared by every protocol and the IO
// helpers used to talk to the attacker.
type Session struct {
	conn     net.Conn
	reader   *bufio.Reader
	logger   *event.Logger
	port     int
	protocol Protocol

	IP        string           // remote "ip:port"
	SrcIP     string           // remote ip only
	DstIP     string           // local ip
	ID        string           // per-connection id, correlates every event
	Persona   *persona.Persona // attached identity, nil until a protocol sets it
	StartTime time.Time
	CmdCount  int
	Username  string

	IdleTimeout time.Duration
	// Deadline is the absolute time the connection must end by, regardless of
	// activity. Zero means no hard cap (the in-memory test harness path).
	Deadline time.Time
}

// readDeadline returns the deadline to arm before a read: the idle timeout from
// now, clamped so it never extends past the absolute session lifetime cap. This is
// what makes the per-line idle refresh unable to keep a slowloris alive forever.
func (s *Session) readDeadline() time.Time {
	d := time.Now().Add(s.IdleTimeout)
	if !s.Deadline.IsZero() && d.After(s.Deadline) {
		return s.Deadline
	}
	return d
}

// handle wraps the protocol with start/end logging and a panic guard, so a bug
// in any handler degrades to a logged panic and a clean session end rather than
// taking down the process.
func (s *Session) handle() {
	s.LogSessionStart()
	defer func() {
		if r := recover(); r != nil {
			s.LogRaw("PANIC", fmt.Sprint(r))
		}
		s.LogSessionEnd(time.Since(s.StartTime))
	}()
	s.protocol.Handle(s)
}

// Conn returns the raw connection, for protocols (like telnet) that need to
// install their own byte-level input handling.
func (s *Session) Conn() net.Conn { return s.conn }

// RawConn returns the underlying transport connection, unwrapping the session
// recorder if one is installed. The SSH protocol runs its handshake on this rather
// than on s.conn, so the encrypted handshake bytes are never fed to the asciinema
// recorder (which records the decrypted session after Rebind instead).
func (s *Session) RawConn() net.Conn {
	if rc, ok := s.conn.(*recordConn); ok {
		return rc.Conn
	}
	return s.conn
}

// Rebind redirects every session IO helper onto rw, an SSH channel established
// after the handshake, so the existing shell engine (written against the line-based
// Session helpers) runs unchanged over SSH. Reads and writes flow over the channel;
// deadlines, addresses, and connection lifetime still track the underlying
// transport, whose read deadline continues to reap an idle session because the SSH
// mux reads that same socket. If recording is enabled, the decrypted channel IO is
// teed into the same recorder, so the cast captures what the attacker saw rather
// than the ciphertext on the wire.
func (s *Session) Rebind(rw io.ReadWriteCloser) {
	var c net.Conn = &chanConn{rw: rw, base: s.RawConn()}
	if rc, ok := s.conn.(*recordConn); ok {
		c = &recordConn{Conn: c, rec: rc.rec}
	}
	s.conn = c
	s.reader = bufio.NewReader(c)
}

// chanConn adapts an SSH channel (an io.ReadWriteCloser with no addressing or
// deadlines of its own) to net.Conn, so the session IO helpers run over it
// unchanged. Reads and writes go to the channel; deadlines, addresses, and Close
// are delegated to the underlying transport. Delegating the read deadline is what
// lets an idle SSH session still be reaped: the SSH mux is blocked reading the same
// socket, so when the deadline the shell set on a ReadLine elapses, that read fails
// and tears the connection down.
type chanConn struct {
	rw   io.ReadWriteCloser
	base net.Conn
}

func (c *chanConn) Read(b []byte) (int, error)         { return c.rw.Read(b) }
func (c *chanConn) Write(b []byte) (int, error)        { return c.rw.Write(b) }
func (c *chanConn) Close() error                       { return c.rw.Close() }
func (c *chanConn) LocalAddr() net.Addr                { return c.base.LocalAddr() }
func (c *chanConn) RemoteAddr() net.Addr               { return c.base.RemoteAddr() }
func (c *chanConn) SetDeadline(t time.Time) error      { return c.base.SetDeadline(t) }
func (c *chanConn) SetReadDeadline(t time.Time) error  { return c.base.SetReadDeadline(t) }
func (c *chanConn) SetWriteDeadline(t time.Time) error { return c.base.SetWriteDeadline(t) }

// ReadN reads up to n bytes of raw input, for protocols that consume a body by
// length rather than by line (an HTTP request body). It refreshes the idle
// deadline first and returns what it managed to read.
func (s *Session) ReadN(n int) []byte {
	if n <= 0 {
		return nil
	}
	s.conn.SetReadDeadline(s.readDeadline())
	buf := make([]byte, n)
	read, _ := io.ReadFull(s.reader, buf)
	return buf[:read]
}

// ReplaceReader swaps the line reader, letting a protocol insert a filter (the
// telnet IAC stripper) so the higher-level ReadLine/Prompt see clean input.
func (s *Session) ReplaceReader(r io.Reader) { s.reader = bufio.NewReader(r) }

// ---- IO helpers ----

func (s *Session) Write(str string) {
	s.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	s.conn.Write([]byte(str))
}

func (s *Session) WriteBytes(b []byte) {
	s.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	s.conn.Write(b)
}

func (s *Session) Writeln(str string) { s.Write(str + "\r\n") }

// maxLineBytes caps a single captured line. Without a bound, a connection that
// streams bytes with no newline grows the read buffer until the process OOMs (and
// 25 such per source, inside the per-IP cap, kills the box). A flood is instead
// returned in bounded chunks the protocol disposes of quickly; no real
// credential, command, or request line approaches this size.
const maxLineBytes = 64 * 1024

// ReadLine reads one line, bounded by maxLineBytes, refreshing the idle deadline
// first so an active attacker is never reaped while a slow multi-minute operation
// runs elsewhere.
func (s *Session) ReadLine() (string, bool) {
	s.conn.SetReadDeadline(s.readDeadline())
	var b strings.Builder
	for {
		c, err := s.reader.ReadByte()
		if err != nil {
			return util.TrimCRLF(b.String()), false
		}
		b.WriteByte(c)
		if c == '\n' || b.Len() >= maxLineBytes {
			return util.TrimCRLF(b.String()), true
		}
	}
}

func (s *Session) Prompt(label string) (string, bool) {
	s.Write(label)
	return s.ReadLine()
}

// HoldOpen keeps a tarpit connection open for up to d, but returns as soon as the
// client disconnects, so the goroutine and file descriptor are freed promptly
// instead of being pinned for the full hold — the difference between a
// connect/disconnect storm costing a thread for milliseconds versus minutes. It
// reads and discards anything the client sends (the protocol has already captured
// what it needs) and makes the recorded SESSION_END duration the true connection
// time. FastMode returns immediately so tests never stall on a real tarpit.
func (s *Session) HoldOpen(d time.Duration) {
	if FastMode() {
		return
	}
	hold := time.Now().Add(d)
	if !s.Deadline.IsZero() && hold.After(s.Deadline) {
		hold = s.Deadline
	}
	s.conn.SetReadDeadline(hold)
	buf := make([]byte, 1024)
	for {
		if _, err := s.conn.Read(buf); err != nil {
			return // client gone, or the hold elapsed
		}
	}
}

// SlowWrite emits a string one rune at a time with a delay between each, so
// banners and output feel like a slow terminal. It stops on the first write
// error (client gone).
func (s *Session) SlowWrite(str string, delay time.Duration) {
	if FastMode() {
		s.Write(str)
		return
	}
	for _, r := range str {
		s.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
		if _, err := s.conn.Write([]byte(string(r))); err != nil {
			return
		}
		time.Sleep(delay)
	}
}

// SlowProgress draws a wget/curl-style progress bar that advances over total,
// updating in place with carriage returns and ending with a newline.
func (s *Session) SlowProgress(label string, total time.Duration) {
	if FastMode() {
		s.Write(fmt.Sprintf("\r%s %s 100%%\n", label, progressBar(100)))
		return
	}
	const steps = 50
	step := total / steps
	for i := 0; i <= steps; i++ {
		pct := i * 100 / steps
		s.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
		line := fmt.Sprintf("\r%s %s %3d%%", label, progressBar(pct), pct)
		if _, err := s.conn.Write([]byte(line)); err != nil {
			return
		}
		if i < steps {
			time.Sleep(step)
		}
	}
	s.Write("\n")
}

func progressBar(pct int) string {
	const width = 20
	filled := pct * width / 100
	if filled > width {
		filled = width
	}
	var b strings.Builder
	b.WriteByte('[')
	for i := 0; i < width; i++ {
		switch {
		case i < filled:
			b.WriteByte('=')
		case i == filled:
			b.WriteByte('>')
		default:
			b.WriteByte(' ')
		}
	}
	b.WriteByte(']')
	return b.String()
}

// ---- event helpers ----

// ev builds an event pre-filled with this session's identity.
func (s *Session) ev(name string) event.Entry {
	e := event.Entry{
		Event:    name,
		Session:  s.ID,
		IP:       s.IP,
		SrcIP:    s.SrcIP,
		DstIP:    s.DstIP,
		Port:     s.port,
		Protocol: s.protocol.Name(),
	}
	if s.Persona != nil {
		e.Persona = s.Persona.Hostname
	}
	return e
}

func (s *Session) LogSessionStart() { s.logger.Log(s.ev("SESSION_START")) }

func (s *Session) LogSessionEnd(d time.Duration) {
	e := s.ev("SESSION_END")
	e.DurationMs = d.Milliseconds()
	e.CmdCount = s.CmdCount
	e.Username = s.Username
	s.logger.Log(e)
}

func (s *Session) LogCredential(user, pass string) {
	e := s.ev("CREDENTIAL")
	e.Username = user
	e.Password = pass
	s.logger.Log(e)
}

// LogCredentialResult records a credential attempt together with whether it was
// accepted, for services (SSH) that actually validate the pair rather than waving
// every login through. The pair is captured either way; the verdict tells an
// analyst which attempts believed they succeeded.
func (s *Session) LogCredentialResult(user, pass string, accepted, bruteForced bool) {
	e := s.ev("CREDENTIAL")
	e.Username = user
	e.Password = pass
	switch {
	case bruteForced:
		// Let in not by the real credential but by the brute-force policy: the source
		// kept guessing and was eventually let in with the pair it tried.
		e.Note = "accepted (brute-forced)"
	case accepted:
		e.Note = "accepted"
	default:
		e.Note = "rejected"
	}
	s.logger.Log(e)
}

// LogHoneytoken records access to a planted bait (a fake vault or wallet, or the
// ascii-rendered portrait). It is a high-signal event: a legitimate user never
// runs these, so every hit is an attacker, attributed by source IP and session.
func (s *Session) LogHoneytoken(token, detail string) {
	e := s.ev("HONEYTOKEN")
	e.Note = token
	e.Command = detail
	s.logger.Log(e)
}

func (s *Session) LogCommand(cmd string) {
	e := s.ev("COMMAND")
	e.Command = cmd
	s.logger.Log(e)
}

func (s *Session) LogCommandNote(cmd, note string) {
	e := s.ev("COMMAND")
	e.Command = cmd
	e.Note = note
	s.logger.Log(e)
}

func (s *Session) LogDownload(cmd, url, host, filename string) {
	e := s.ev("DOWNLOAD_ATTEMPT")
	e.Command = cmd
	e.URL = url
	e.Host = host
	e.Filename = filename
	s.logger.Log(e)
}

func (s *Session) LogExec(detail, sha string) {
	e := s.ev("EXEC_ATTEMPT")
	e.Command = detail
	e.SHA256 = sha
	s.logger.Log(e)
}

func (s *Session) LogHTTPRequest(method, request, path string, headers map[string]string) {
	e := s.ev("HTTP_REQUEST")
	e.Method = method
	e.Request = request
	e.Path = path
	e.Headers = headers
	e.UserAgent = headers["user-agent"]
	s.logger.Log(e)
}

func (s *Session) LogHTTPPost(path, body, sha string) {
	e := s.ev("HTTP_POST")
	e.Path = path
	e.Body = body
	e.SHA256 = sha
	s.logger.Log(e)
}

func (s *Session) LogRaw(name, data string) {
	e := s.ev(name)
	e.Data = data
	s.logger.Log(e)
}
