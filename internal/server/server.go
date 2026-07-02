// Package server owns the TCP accept loop and the per-connection session: the IO
// helpers every fake protocol uses to talk to an attacker, and the event-logging
// helpers that turn session activity into structured events. A Protocol plugs its
// behavior in; the server handles binding, backpressure, scan detection, and the
// session lifecycle around it.
package server

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"sweetty/internal/event"
	"sweetty/internal/proxyproto"
	"sweetty/internal/record"
	"sweetty/internal/util"
)

// proxyHeaderTimeout bounds how long the accept loop waits for an HAProxy PROXY
// header before giving up, so a connection that announces nothing cannot hang a
// goroutine.
const proxyHeaderTimeout = 5 * time.Second

// scanGrace is a package var (not a const) so a test can lower it to exercise the
// bare-connect port-scan path quickly. Production never changes it.
var scanGrace = 8 * time.Second

// maxConnsPerIP caps concurrent connections from a single source so one aggressive
// brute-forcer cannot exhaust the box and blind capture. Set generously: an idle
// sensor has ample headroom (goroutines and FDs are cheap, the process-wide maxConns
// is the real backstop), and the busiest sources are the loaders worth holding onto,
// so this should shed only a genuine flood, not normal Mirai connection parallelism.
const maxConnsPerIP = 128

// maxConns bounds the total concurrent connections across every listener. The
// per-IP cap is defeated by a botnet spread over many source addresses, so this
// process-wide backstop protects file descriptors and goroutines (each connection
// is one of each, and the tarpits hold them for minutes). Sized well under a
// hardened LimitNOFILE.
const maxConns = 4096

// connLimiter is a process-wide concurrency cap. tryAcquire returns false when the
// cap is reached rather than blocking, so an over-cap connection is dropped fast.
type connLimiter struct{ ch chan struct{} }

func newConnLimiter(n int) *connLimiter { return &connLimiter{ch: make(chan struct{}, n)} }

func (l *connLimiter) tryAcquire() bool {
	select {
	case l.ch <- struct{}{}:
		return true
	default:
		return false
	}
}

func (l *connLimiter) release() { <-l.ch }

// globalConns is the shared cap every accepted connection acquires.
var globalConns = newConnLimiter(maxConns)

// fastMode is a test seam: when true, protocols skip their multi-minute tarpits
// and long time-wasters so the test harness runs quickly. It is atomic because the
// harness toggles it while server goroutines from earlier connections may still be
// reading it (e.g. in HoldOpen). Production never enables it.
var fastMode atomic.Bool

// FastMode reports whether the test seam is enabled.
func FastMode() bool { return fastMode.Load() }

// SetFastMode toggles the test seam; only the test harness calls it.
func SetFastMode(on bool) { fastMode.Store(on) }

// RunConn drives a single connection through a protocol, building the session
// exactly as the accept loop does but without the port-scan grace or the per-IP
// cap. It is the seam the test harness uses to exercise a protocol end to end
// over an in-memory pipe.
func RunConn(conn net.Conn, logger *event.Logger, p Protocol) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()
	sess := &Session{
		conn:        conn,
		reader:      bufio.NewReader(conn),
		logger:      logger,
		protocol:    p,
		IP:          remote,
		SrcIP:       util.HostOnly(remote),
		DstIP:       util.HostOnly(conn.LocalAddr().String()),
		ID:          util.Base58Gen(12),
		StartTime:   time.Now(),
		IdleTimeout: defaultIdleTimeout,
		Deadline:    time.Now().Add(maxSessionLifetime),
	}
	sess.handle()
}

type Server struct {
	port     int
	logger   *event.Logger
	protocol Protocol
	listener net.Listener

	// ProxyProtocol, when set, reads an HAProxy PROXY header at the front of each
	// connection and recovers the real attacker address from it. It is enabled for
	// the HAProxy edge topology, where the backend ports otherwise only ever see
	// the proxy's loopback address.
	ProxyProtocol bool

	// trustedProxyNets are the peer networks (beyond loopback, which is always
	// trusted) allowed to present a PROXY header. A header from any other peer is
	// ignored, so a direct attacker cannot forge the logged source IP or slip the
	// per-source cap by rotating a fake src. Set via SetTrustedProxies.
	trustedProxyNets []netip.Prefix

	// RecordDir, when non-empty, names the directory that per-session asciinema
	// cast recordings are written to, one <session-id>.cast per connection.
	RecordDir string

	mu       sync.Mutex
	conns    map[string]int // srcIP -> active connection count
	shedN    int            // connections shed (capped) since the last shed notice
	shedLast time.Time      // when the last shed notice was logged
}

// shedLogInterval rate-limits the "connection shed" notice so saturation is visible
// in the log without the hot shed path amplifying into a log-flood of its own.
const shedLogInterval = 10 * time.Second

// noteShed records that a connection was shed by a cap and reports whether a
// coalesced notice is due, with the count since the last one.
func (srv *Server) noteShed() (int, bool) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	srv.shedN++
	if time.Since(srv.shedLast) < shedLogInterval {
		return 0, false
	}
	srv.shedLast = time.Now()
	n := srv.shedN
	srv.shedN = 0
	return n, true
}

// recordConn tees everything written to the client into a session recorder, so
// the cast captures exactly the bytes the attacker saw regardless of which IO
// helper produced them. Reads and deadlines pass straight through.
type recordConn struct {
	net.Conn
	rec *record.Recorder
	// noInput suppresses teeing raw reads as input. A protocol that decodes its own
	// transport framing (telnet stripping IAC) sets this and tees the cleaned bytes
	// itself, so the cast shows keystrokes rather than wire negotiation.
	noInput bool
}

func (c *recordConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.rec.Write(b[:n])
	}
	return n, err
}

// Read tees the attacker's input into the cast as an "i" event, so the replay and
// live watch show what a source typed even when the honeypot echoes nothing back
// (the common case for a bot that blasts credentials at a login prompt).
func (c *recordConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 && !c.noInput {
		c.rec.WriteInput(b[:n])
	}
	return n, err
}

// New creates a server bound to no port yet; call Listen to start accepting.
func New(port int, logger *event.Logger, p Protocol) *Server {
	return &Server{port: port, logger: logger, protocol: p}
}

// SetTrustedProxies configures which peer networks (in CIDR form) may present a
// PROXY header, for a remote HAProxy that is not on loopback. Loopback is always
// trusted, which covers the default same-host edge. Invalid entries are logged and
// skipped rather than failing the listener.
func (srv *Server) SetTrustedProxies(cidrs []string) {
	srv.trustedProxyNets = nil
	for _, c := range cidrs {
		if pfx, err := netip.ParsePrefix(c); err == nil {
			srv.trustedProxyNets = append(srv.trustedProxyNets, pfx.Masked())
		} else {
			srv.logger.System("ignoring invalid proxy_trusted_cidrs entry %q: %v", c, err)
		}
	}
}

// peerTrusted reports whether the immediate peer may present a PROXY header.
// Loopback (the same-host HAProxy edge) and any configured trusted network qualify;
// a non-IP peer (the in-memory test pipe) is trusted so the harness still exercises
// the parser. Everything else is untrusted, so its header is ignored.
func (srv *Server) peerTrusted(conn net.Conn) bool {
	ap, err := netip.ParseAddrPort(conn.RemoteAddr().String())
	if err != nil {
		return true
	}
	ip := ap.Addr()
	if ip.IsLoopback() {
		return true
	}
	for _, n := range srv.trustedProxyNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Listen binds the port and starts accepting. It returns immediately; a bind
// failure is returned to the caller so the remaining ports can still start.
func (srv *Server) Listen() error {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", srv.port))
	if err != nil {
		return err
	}
	srv.listener = ln
	srv.conns = make(map[string]int)
	go srv.accept()
	return nil
}

// Addr returns the bound listen address, or "" before Listen has run. It exists
// so a test can discover the ephemeral port chosen for a ":0" bind.
func (srv *Server) Addr() string {
	if srv.listener != nil {
		return srv.listener.Addr().String()
	}
	return ""
}

// Close stops the accept loop by closing the listener (the loop returns on the
// resulting net.ErrClosed). In-flight sessions run until they end on their own;
// this just stops admitting new connections, for a clean shutdown.
func (srv *Server) Close() error {
	if srv.listener != nil {
		return srv.listener.Close()
	}
	return nil
}

func (srv *Server) accept() {
	var delay time.Duration
	for {
		conn, err := srv.listener.Accept()
		if err != nil {
			// A closed listener means a clean shutdown; stop. Any other error
			// (notably EMFILE under fd pressure) is treated as transient: back off
			// and keep accepting, so a momentary spike does not permanently kill the
			// listener while the process stays alive on select{}.
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if delay == 0 {
				delay = 5 * time.Millisecond
				srv.logger.System("accept on :%d erroring, backing off: %v", srv.port, err)
			} else if delay *= 2; delay > time.Second {
				delay = time.Second
			}
			time.Sleep(delay)
			continue
		}
		delay = 0
		go srv.handle(conn)
	}
}

func (srv *Server) handle(conn net.Conn) {
	defer conn.Close()
	// A panic anywhere in the connection-setup path (proxy-header parse, scan check,
	// recorder) runs before the session's own recover, so guard it here too: the
	// doctrine is to degrade to a logged failure, never take the process down.
	defer func() {
		if r := recover(); r != nil {
			srv.logger.System("recovered panic in connection handler on :%d: %v", srv.port, r)
		}
	}()

	// Process-wide cap: a botnet across many source IPs defeats the per-IP cap, so
	// bound total concurrent connections before doing any per-connection work. A
	// shed connection is logged (rate-limited) so saturation — which blinds capture
	// across all protocols — is never silent.
	if !globalConns.tryAcquire() {
		if n, ok := srv.noteShed(); ok {
			srv.logger.System("connection cap (%d) reached on :%d; shed %d connection(s) recently", maxConns, srv.port, n)
		}
		return
	}
	defer globalConns.release()

	remote := conn.RemoteAddr().String()
	dst := conn.LocalAddr().String()
	// Wrap the connection for recording up front, so both the bytes we send and the
	// bytes the attacker sends flow through one tap and the session's reader reads
	// through it. Teeing stays off until a recorder attaches below (after the scan
	// check), so the PROXY header and the scan peek are never recorded.
	rc := &recordConn{Conn: conn}
	conn = rc
	reader := bufio.NewReader(conn)

	// Behind an HAProxy edge, the connection opens with a PROXY header naming the
	// address the attacker really connected from. Recover it before anything else,
	// so logging, the per-source cap, and scan detection all key off the true
	// source rather than the proxy's loopback address. Only honor the header from a
	// trusted proxy peer: trusting it from any direct connection would let an
	// attacker forge the logged source and rotate a fake src past the per-IP cap.
	if srv.ProxyProtocol && srv.peerTrusted(conn) {
		conn.SetReadDeadline(time.Now().Add(proxyHeaderTimeout))
		hdr, ok, err := proxyproto.Parse(reader)
		conn.SetReadDeadline(time.Time{})
		if err != nil {
			return
		}
		if ok {
			remote, dst = hdr.Src, hdr.Dst
		}
	}
	src := util.HostOnly(remote)

	// Backpressure: cap concurrent connections per source so a single host
	// cannot exhaust file descriptors against the tarpits that invite many
	// connections. A shed connection is logged (rate-limited) so a noisy source is
	// visible rather than silently dropped.
	if !srv.acquire(src) {
		if n, ok := srv.noteShed(); ok {
			srv.logger.System("per-source cap (%d) reached on :%d; shed %d connection(s) recently", maxConnsPerIP, srv.port, n)
		}
		return
	}
	defer srv.release(src)

	p := srv.protocol
	if p.ClientFirst() {
		// Request/response protocol: a connection that sends nothing after any
		// PROXY header within the grace window is a bare-connect scan. Peek leaves
		// the byte buffered for the protocol once it arrives.
		conn.SetReadDeadline(time.Now().Add(scanGrace))
		_, err := reader.Peek(1)
		conn.SetReadDeadline(time.Time{})
		if err != nil {
			srv.logger.PortScan(remote, srv.port, p.Name())
			return
		}
	}

	id := util.Base58Gen(12)
	// Attach the recorder now (after the scan check, so bare-connect scans never
	// produce an empty cast). From here the recordConn tees both output and input.
	if srv.RecordDir != "" {
		if rec, err := record.New(srv.RecordDir, id, 80, 24); err == nil {
			rc.rec = rec
			defer rec.Close()
			// The PROXY-header parse and the scan peek read ahead through the bufio, so
			// the attacker's first input (a login burst, an HTTP request) can already be
			// buffered before the recorder attached, and reading it from the buffer would
			// never hit recordConn.Read. Tee whatever is buffered now so it is captured;
			// the PROXY header itself was already consumed, so it is not included. A
			// protocol that decodes its own input (telnet) reads this same buffer through
			// its IAC stripper and records the cleaned bytes itself, so raw-teeing here
			// would both duplicate it and reintroduce the wire framing; skip it for those.
			if n := reader.Buffered(); n > 0 && !decodesInput(p) {
				if b, err := reader.Peek(n); err == nil {
					rec.WriteInput(b)
				}
			}
		} else {
			srv.logger.System("session recording could not start: %v", err)
		}
	}

	sess := &Session{
		conn:        conn,
		reader:      reader,
		logger:      srv.logger,
		port:        srv.port,
		protocol:    p,
		IP:          remote,
		SrcIP:       src,
		DstIP:       util.HostOnly(dst),
		ID:          id,
		StartTime:   time.Now(),
		IdleTimeout: defaultIdleTimeout,
		Deadline:    time.Now().Add(maxSessionLifetime),
	}
	sess.handle()
}

func (srv *Server) acquire(src string) bool {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.conns[src] >= maxConnsPerIP {
		return false
	}
	srv.conns[src]++
	return true
}

func (srv *Server) release(src string) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.conns[src] <= 1 {
		delete(srv.conns, src)
	} else {
		srv.conns[src]--
	}
}
