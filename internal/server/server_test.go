package server

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sweetty/internal/event"
)

// scanStub is a ClientFirst protocol whose Handle never runs along the scan path:
// a bare connect that sends nothing is logged as a port scan before any session
// is ever built, so the stub records nothing of its own.
type scanStub struct{}

func (scanStub) Name() string      { return "scanstub" }
func (scanStub) ClientFirst() bool { return true }
func (scanStub) Handle(*Session)   {}

// TestBareConnectIsPortScan exercises Server.handle's scan-grace path (the one
// RunConn deliberately skips): a ClientFirst connection that sends nothing within
// the grace window is a bare-connect scan, logged as PORT_SCAN with no session.
func TestBareConnectIsPortScan(t *testing.T) {
	// Lower the grace window so the scan fires in milliseconds, and restore it.
	orig := scanGrace
	scanGrace = 80 * time.Millisecond
	defer func() { scanGrace = orig }()

	logPath := filepath.Join(t.TempDir(), "scan.log")
	lg, err := event.New(logPath)
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	defer lg.Close()

	stub := scanStub{}
	srv := New(0, lg, stub)
	if err := srv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := srv.Addr()
	if addr == "" {
		t.Fatal("server reported no bound address after Listen")
	}

	// Dial the loopback v4 address explicitly so the captured source IP is the
	// 127.0.0.1 the assertion expects rather than a v6-mapped form.
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split bound addr %q: %v", addr, err)
	}
	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", port))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	// Send nothing and outlast the grace window, then close: a bare-connect scan.
	time.Sleep(scanGrace + 150*time.Millisecond)
	conn.Close()

	// Poll the log so the test does not race the server's write of the scan line.
	var scans []event.Entry
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		scans = filterEvent(readLog(t, logPath), "PORT_SCAN")
		if len(scans) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if len(scans) != 1 {
		t.Fatalf("PORT_SCAN events = %d, want exactly 1", len(scans))
	}
	got := scans[0]
	if got.Protocol != stub.Name() {
		t.Fatalf("PORT_SCAN protocol = %q, want %q", got.Protocol, stub.Name())
	}
	if got.SrcIP != "127.0.0.1" {
		t.Fatalf("PORT_SCAN src_ip = %q, want 127.0.0.1", got.SrcIP)
	}
	for _, e := range readLog(t, logPath) {
		if e.Event == "SESSION_START" {
			t.Fatal("a bare-connect scan must not open a session")
		}
	}
}

// dialServer brings up a server with the given proxy-protocol setting on a
// loopback port and returns a connection to it.
func dialServer(t *testing.T, proxy bool) (*net.TCPConn, string) {
	t.Helper()
	logPath := filepath.Join(t.TempDir(), "p.log")
	lg, err := event.New(logPath)
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	t.Cleanup(func() { lg.Close() })
	srv := New(0, lg, scanStub{})
	srv.ProxyProtocol = proxy
	if err := srv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, port, err := net.SplitHostPort(srv.Addr())
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", port))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn.(*net.TCPConn), logPath
}

// waitFor polls the log until the first event of the given type appears.
func waitFor(t *testing.T, path, name string) event.Entry {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, e := range readLog(t, path) {
			if e.Event == name {
				return e
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("never saw a %s event in %s", name, path)
	return event.Entry{}
}

// TestProxyProtocolRecoversRealSource proves that with proxy-protocol enabled, a
// v1 PROXY header makes the session key off the attacker's real address rather
// than the proxy's loopback address. This is the whole point of the sensor
// behind an HAProxy edge.
func TestProxyProtocolRecoversRealSource(t *testing.T) {
	conn, logPath := dialServer(t, true)
	if _, err := conn.Write([]byte("PROXY TCP4 203.0.113.7 198.51.100.2 56324 443\r\nx")); err != nil {
		t.Fatalf("write: %v", err)
	}
	ss := waitFor(t, logPath, "SESSION_START")
	if ss.SrcIP != "203.0.113.7" {
		t.Fatalf("recovered src_ip = %q, want 203.0.113.7", ss.SrcIP)
	}
	if ss.DstIP != "198.51.100.2" {
		t.Fatalf("recovered dst_ip = %q, want 198.51.100.2", ss.DstIP)
	}
}

// TestProxyProtocolFallsBackWithoutHeader proves that an ordinary connection
// with no PROXY header still opens a session, keyed off the direct peer, so a
// direct probe of the backend port is not silently dropped.
func TestProxyProtocolFallsBackWithoutHeader(t *testing.T) {
	conn, logPath := dialServer(t, true)
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	ss := waitFor(t, logPath, "SESSION_START")
	if ss.SrcIP != "127.0.0.1" {
		t.Fatalf("fallback src_ip = %q, want the direct peer 127.0.0.1", ss.SrcIP)
	}
}

// TestProxyProtocolMalformedIsDropped proves a header that announces PROXY but
// does not parse is rejected before any session opens, rather than trusted.
func TestProxyProtocolMalformedIsDropped(t *testing.T) {
	conn, logPath := dialServer(t, true)
	if _, err := conn.Write([]byte("PROXY TCP4 999.0.0.1 1.2.3.4 1 2\r\nx")); err != nil {
		t.Fatalf("write: %v", err)
	}
	time.Sleep(300 * time.Millisecond)
	for _, e := range readLog(t, logPath) {
		if e.Event == "SESSION_START" {
			t.Fatal("a malformed PROXY header must not open a session")
		}
	}
}

// readLog parses every event written to the log file so far.
func readLog(t *testing.T, path string) []event.Entry {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	var out []event.Entry
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var e event.Entry
		if json.Unmarshal([]byte(line), &e) == nil {
			out = append(out, e)
		}
	}
	return out
}

// filterEvent returns the entries whose type matches name.
func filterEvent(entries []event.Entry, name string) []event.Entry {
	var out []event.Entry
	for _, e := range entries {
		if e.Event == name {
			out = append(out, e)
		}
	}
	return out
}

func TestProgressBar(t *testing.T) {
	if got := progressBar(0); got != "[>                   ]" {
		t.Fatalf("0%%: %q", got)
	}
	if got := progressBar(100); got != "[====================]" {
		t.Fatalf("100%%: %q", got)
	}
	if got := progressBar(50); got != "[==========>         ]" {
		t.Fatalf("50%%: %q", got)
	}
}
