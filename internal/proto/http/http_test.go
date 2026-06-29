package http

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"sweetty/internal/event"
	"sweetty/internal/persona"
	"sweetty/internal/server"
)

// testPersona returns a persona with fixed, known software versions so tests can
// assert on the exact strings rendered into responses.
func testPersona() *persona.Persona {
	return &persona.Persona{
		Hostname:  "web-prod-01",
		WPVer:     "6.5.2",
		ApacheVer: "2.4.58",
		PHPVer:    "8.2.15",
		TomcatVer: "10.1.18",
		NginxVer:  "1.24.0",
	}
}

func TestNameAndClientFirst(t *testing.T) {
	proto := New(testPersona(), "wordpress")
	if got := proto.Name(); got != "http" {
		t.Errorf("Name() = %q, want %q", got, "http")
	}
	if !proto.ClientFirst() {
		t.Error("ClientFirst() = false, want true")
	}
}

// TestRootResponseByStyle checks that GET / for each style returns the right
// Server header and the persona's version string.
func TestRootResponseByStyle(t *testing.T) {
	p := testPersona()
	cases := []struct {
		style      string
		status     string
		serverHdr  string
		wantInBody []string
	}{
		{"wordpress", "HTTP/1.1 200 OK\r\n", "Server: Apache/" + p.ApacheVer + " (Ubuntu)", []string{"WordPress " + p.WPVer, "X-Powered-By: PHP/" + p.PHPVer}},
		// Modern Tomcat sends no Server header and an EMPTY reason phrase.
		{"tomcat", "HTTP/1.1 200 \r\n", "", []string{"Apache Tomcat/" + p.TomcatVer}},
		// Real nginx sends a bare "nginx/<ver>" Server header (no distro suffix).
		{"nginx-static", "HTTP/1.1 200 OK\r\n", "Server: nginx/" + p.NginxVer + "\r\n", []string{"Welcome to nginx!"}},
	}
	for _, c := range cases {
		pr := New(p, c.style).(*Protocol)
		resp, delay := pr.respond(nil, "GET", "/", "")
		if delay != 0 {
			t.Errorf("%s: GET / delay = %v, want 0", c.style, delay)
		}
		if !strings.HasPrefix(resp, c.status) {
			t.Errorf("%s: GET / status line = %q, want prefix %q", c.style, firstLine(resp), c.status)
		}
		if c.serverHdr != "" {
			if !strings.Contains(resp, c.serverHdr) {
				t.Errorf("%s: missing %q in response", c.style, c.serverHdr)
			}
		} else {
			for _, line := range strings.Split(resp, "\r\n") {
				if strings.HasPrefix(line, "Server:") {
					t.Errorf("%s: expected no Server header, got %q", c.style, line)
				}
			}
		}
		for _, want := range c.wantInBody {
			if !strings.Contains(resp, want) {
				t.Errorf("%s: response missing %q", c.style, want)
			}
		}
		if !strings.Contains(resp, "Connection: close\r\n") {
			t.Errorf("%s: missing Connection: close", c.style)
		}
		assertContentLength(t, c.style, resp)
	}
}

func TestWordPressRoutes(t *testing.T) {
	pr := New(testPersona(), "wordpress").(*Protocol)

	resp, delay := pr.respond(nil, "GET", "/wp-login.php", "")
	if !strings.HasPrefix(resp, "HTTP/1.1 200") || !strings.Contains(resp, `name="log"`) {
		t.Errorf("GET /wp-login.php should be the login form: %q", firstLine(resp))
	}
	if delay != loginPageDelay {
		t.Errorf("login page delay = %v, want %v", delay, loginPageDelay)
	}

	resp, delay = pr.respond(nil, "POST", "/wp-login.php", "")
	if !strings.HasPrefix(resp, "HTTP/1.1 302") || !strings.Contains(resp, "Location: /wp-login.php?error=") {
		t.Errorf("POST /wp-login.php should be a 302 with error Location: %q", firstLine(resp))
	}
	if delay != loginPostDelay {
		t.Errorf("login post delay = %v, want %v", delay, loginPostDelay)
	}

	resp, _ = pr.respond(nil, "GET", "/xmlrpc.php", "")
	if !strings.HasPrefix(resp, "HTTP/1.1 405") || !strings.Contains(resp, "Allow: POST") {
		t.Errorf("GET /xmlrpc.php should be 405 with Allow: POST: %q", firstLine(resp))
	}

	resp, delay = pr.respond(nil, "POST", "/xmlrpc.php", "")
	if !strings.HasPrefix(resp, "HTTP/1.1 200") || !strings.Contains(resp, "<methodResponse>") || !strings.Contains(resp, "<fault>") {
		t.Errorf("POST /xmlrpc.php should be an XML-RPC fault: %q", firstLine(resp))
	}
	if delay != xmlrpcPostDelay {
		t.Errorf("xmlrpc delay = %v, want %v", delay, xmlrpcPostDelay)
	}

	resp, _ = pr.respond(nil, "GET", "/wp-admin/", "")
	if !strings.HasPrefix(resp, "HTTP/1.1 302") || !strings.Contains(resp, "Location: /wp-login.php") {
		t.Errorf("GET /wp-admin/ should redirect to login: %q", firstLine(resp))
	}

	resp, _ = pr.respond(nil, "GET", "/readme.html", "")
	if !strings.Contains(resp, "Version 6.5.2") {
		t.Errorf("GET /readme.html should show Version 6.5.2: %q", firstLine(resp))
	}

	resp, _ = pr.respond(nil, "GET", "/robots.txt", "")
	if !strings.Contains(resp, "Disallow: /wp-admin/") || !strings.Contains(resp, "admin-ajax.php") {
		t.Errorf("robots.txt content wrong: %q", resp)
	}

	resp, delay = pr.respond(nil, "GET", "/does-not-exist", "")
	if !strings.HasPrefix(resp, "HTTP/1.1 404") || delay != notFoundDelay {
		t.Errorf("unknown path should be 404 with %v delay: %q delay=%v", notFoundDelay, firstLine(resp), delay)
	}
}

func TestTomcatRoutes(t *testing.T) {
	pr := New(testPersona(), "tomcat").(*Protocol)
	for _, path := range []string{"/manager/html", "/host-manager/html"} {
		resp, delay := pr.respond(nil, "GET", path, "")
		if !strings.HasPrefix(resp, "HTTP/1.1 401") {
			t.Errorf("%s should be 401: %q", path, firstLine(resp))
		}
		if !strings.Contains(resp, `WWW-Authenticate: Basic realm="Tomcat Manager Application"`) {
			t.Errorf("%s missing manager realm challenge", path)
		}
		if delay != managerAuthDelay {
			t.Errorf("%s delay = %v, want %v", path, delay, managerAuthDelay)
		}
	}
	resp, _ := pr.respond(nil, "GET", "/whatever", "")
	if !strings.HasPrefix(resp, "HTTP/1.1 404") || !strings.Contains(resp, "Apache Tomcat/10.1.18") {
		t.Errorf("tomcat 404 wrong: %q", firstLine(resp))
	}
}

func TestNginxRoutes(t *testing.T) {
	pr := New(testPersona(), "nginx-static").(*Protocol)
	resp, _ := pr.respond(nil, "GET", "/missing", "")
	if !strings.HasPrefix(resp, "HTTP/1.1 404") || !strings.Contains(resp, "nginx/1.24.0") {
		t.Errorf("nginx 404 should carry the version: %q", firstLine(resp))
	}
}

func TestHTTPResponseHelper(t *testing.T) {
	resp := nginxResponse(302, "Found", "", "", map[string]string{"Location": "/x", "Server": "nginx/1.0"})
	if !strings.HasPrefix(resp, "HTTP/1.1 302 Found\r\n") {
		t.Fatalf("status line wrong: %q", firstLine(resp))
	}
	for _, want := range []string{"Location: /x\r\n", "Server: nginx/1.0\r\n", "Content-Length: 0\r\n", "Connection: close\r\n"} {
		if !strings.Contains(resp, want) {
			t.Errorf("response missing %q", want)
		}
	}
	if strings.Contains(resp, "Content-Type:") {
		t.Error("empty content type should not emit a Content-Type header")
	}
	assertContentLength(t, "helper", resp)
}

func TestParseRequestLine(t *testing.T) {
	method, path := parseRequestLine("post /wp-login.php?x=1 HTTP/1.1")
	if method != "POST" || path != "/wp-login.php?x=1" {
		t.Errorf("parseRequestLine = %q,%q", method, path)
	}
	if _, path := parseRequestLine("GET"); path != "/" {
		t.Errorf("missing path should default to /, got %q", path)
	}
	if route := pathOnly("/a?b=1#c"); route != "/a" {
		t.Errorf("pathOnly = %q, want /a", route)
	}
}

// TestPostIsLoggedWithSHA drives a real listener end to end and verifies that a
// POST body is captured and logged with the correct sha256. This is the only
// path that exercises Handle, since the session type cannot be built directly.
func TestPostIsLoggedWithSHA(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "events.log")
	lg, err := event.New(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer lg.Close()

	pr := New(testPersona(), "wordpress").(*Protocol)
	pr.sleep = func(time.Duration) {} // skip the 3s login delay
	port := startServer(t, pr, lg)

	body := "log=admin&pwd=hunter2&wp-submit=Log+In"
	sum := sha256.Sum256([]byte(body))
	want := hex.EncodeToString(sum[:])

	raw := "POST /wp-login.php HTTP/1.1\r\nHost: web-prod-01\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
	resp := roundtrip(t, port, raw)
	if !strings.HasPrefix(resp, "HTTP/1.1 302") {
		t.Fatalf("POST login want 302, got %q", firstLine(resp))
	}

	var post *event.Entry
	for _, e := range readLog(t, logPath) {
		if e.Event == "HTTP_POST" {
			ec := e
			post = &ec
		}
	}
	if post == nil {
		t.Fatal("no HTTP_POST event was logged")
	}
	if post.SHA256 != want {
		t.Errorf("logged sha256 = %q, want %q", post.SHA256, want)
	}
	if post.Body != body {
		t.Errorf("logged body = %q, want %q", post.Body, body)
	}
	if post.Path != "/wp-login.php" {
		t.Errorf("logged path = %q, want /wp-login.php", post.Path)
	}
}

// ---- test helpers ----

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimRight(s[:i], "\r")
	}
	return s
}

// assertContentLength confirms the Content-Length header matches the actual body.
func assertContentLength(t *testing.T, label, resp string) {
	t.Helper()
	i := strings.Index(resp, "\r\n\r\n")
	if i < 0 {
		t.Fatalf("%s: response has no header terminator", label)
	}
	body := resp[i+4:]
	marker := "Content-Length: "
	j := strings.Index(resp, marker)
	if j < 0 {
		t.Fatalf("%s: no Content-Length header", label)
	}
	end := strings.Index(resp[j:], "\r\n")
	got, err := strconv.Atoi(resp[j+len(marker) : j+end])
	if err != nil {
		t.Fatalf("%s: bad Content-Length: %v", label, err)
	}
	if got != len(body) {
		t.Errorf("%s: Content-Length = %d, actual body = %d", label, got, len(body))
	}
}

// startServer binds a fresh listener through the server package and returns its
// port. It discovers a free port, then retries on the rare bind race.
func startServer(t *testing.T, proto server.Protocol, lg *event.Logger) int {
	t.Helper()
	for i := 0; i < 20; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			continue
		}
		port := ln.Addr().(*net.TCPAddr).Port
		ln.Close()
		srv := server.New(port, lg, proto)
		if err := srv.Listen(); err == nil {
			return port
		}
	}
	t.Fatal("could not start a test server")
	return 0
}

// roundtrip sends a raw request, half-closes the write side so a body read sees
// EOF, then returns the full response.
func roundtrip(t *testing.T, port int, raw string) string {
	t.Helper()
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte(raw)); err != nil {
		t.Fatal(err)
	}
	conn.(*net.TCPConn).CloseWrite()
	data, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return string(data)
}

func readLog(t *testing.T, path string) []event.Entry {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []event.Entry
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var e event.Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("bad log line %q: %v", line, err)
		}
		out = append(out, e)
	}
	return out
}
