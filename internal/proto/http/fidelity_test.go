package http_test

// Bot-fidelity pins for the HTTP surface, checked against wire output captured from
// the real daemons in Docker. nginx emits a bare "nginx/<ver>" Server header before
// Date and serves its exact 615-byte default index with Last-Modified/ETag/
// Accept-Ranges; a non-GET/HEAD method is 405 with NO Allow header (the
// nginx-vs-Apache differential); Apache emits Date before Server; modern Tomcat
// sends no Server header; HEAD returns no body. The exact per-stack header ORDER
// and the Tomcat/WordPress-login byte sets remain documented backlog.

import (
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"sweetty/internal/persona"
	httpproto "sweetty/internal/proto/http"
	"sweetty/internal/testharness"
)

// headerLines returns the response header lines (without the status line) up to the
// blank line, and the body that follows.
func headerLines(resp string) ([]string, string) {
	i := strings.Index(resp, "\r\n\r\n")
	if i < 0 {
		return nil, ""
	}
	head := strings.Split(resp[:i], "\r\n")
	if len(head) > 0 {
		head = head[1:] // drop the status line
	}
	return head, resp[i+4:]
}

func headerIndex(lines []string, name string) int {
	for i, l := range lines {
		if strings.HasPrefix(l, name+":") {
			return i
		}
	}
	return -1
}

func fetch(t *testing.T, style, request string) string {
	t.Helper()
	p := persona.Generate()
	h, err := testharness.New(httpproto.New(nil, p, style))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.Close)
	h.Send(request)
	return h.ReadFor(600 * time.Millisecond)
}

func TestNginxServerHeaderIsBareAndBeforeDate(t *testing.T) {
	lines, _ := headerLines(fetch(t, "nginx-static", "GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	srv := headerIndex(lines, "Server")
	date := headerIndex(lines, "Date")
	if srv < 0 || date < 0 {
		t.Fatalf("missing Server/Date header: %v", lines)
	}
	if srv > date {
		t.Errorf("nginx must emit Server before Date; got Date first: %v", lines)
	}
	// Real nginx (even the Ubuntu/Debian package) sends a bare "nginx/<ver>" with no
	// distro suffix, matching the token its error pages echo. A suffix would be a tell.
	if strings.Contains(lines[srv], "(") {
		t.Errorf("nginx Server header must be a bare nginx/<ver> with no distro suffix: %q", lines[srv])
	}
}

// TestNginxServesExactDefaultIndex pins the byte-exact 615-byte default index and
// the static signature headers (Last-Modified/ETag/Accept-Ranges) against the
// captured real artifact, so a content-hash or header check cannot distinguish it.
func TestNginxServesExactDefaultIndex(t *testing.T) {
	want, err := os.ReadFile("testdata/nginx-index.html")
	if err != nil {
		t.Fatal(err)
	}
	lines, body := headerLines(fetch(t, "nginx-static", "GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	if body != string(want) {
		t.Errorf("nginx index body is not the real %d-byte artifact (got %d bytes)", len(want), len(body))
	}
	for _, hdr := range []string{"Last-Modified", "ETag", "Accept-Ranges"} {
		if headerIndex(lines, hdr) < 0 {
			t.Errorf("nginx static 200 omits %s, a header real nginx always sends: %v", hdr, lines)
		}
	}
}

// TestNginxNonGetMethodIs405WithoutAllow proves a non-GET/HEAD method on a static
// path is 405 - and, crucially, with NO Allow header (Apache sends one; nginx does
// not), instead of the old "any method returns 200".
func TestNginxNonGetMethodIs405WithoutAllow(t *testing.T) {
	resp := fetch(t, "nginx-static", "POST / HTTP/1.1\r\nHost: x\r\n\r\n")
	if !strings.HasPrefix(resp, "HTTP/1.1 405") {
		t.Fatalf("POST to a static path should be 405, got: %q", resp[:min(len(resp), 40)])
	}
	lines, body := headerLines(resp)
	if headerIndex(lines, "Allow") >= 0 {
		t.Errorf("nginx 405 must not carry an Allow header (that is the Apache behaviour): %v", lines)
	}
	if !strings.Contains(body, "405 Not Allowed") {
		t.Errorf("nginx 405 body is not the default page: %q", body)
	}
}

// TestWordPressFrontPageHasRestApiLink proves the WordPress front page carries the
// REST-API discovery Link header (rel="https://api.w.org/") and Vary, after
// X-Powered-By - the signature a real WP front page always emits and whose absence
// (while the body screams WordPress) is a classic mock tell.
func TestWordPressFrontPageHasRestApiLink(t *testing.T) {
	lines, _ := headerLines(fetch(t, "wordpress", "GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	link := headerIndex(lines, "Link")
	if link < 0 || !strings.Contains(lines[link], `rel="https://api.w.org/"`) {
		t.Fatalf("WordPress front page missing the REST-API discovery Link header: %v", lines)
	}
	if headerIndex(lines, "Vary") < 0 {
		t.Errorf("WordPress front page missing Vary: %v", lines)
	}
	// Link must come after X-Powered-By, as captured.
	if xp := headerIndex(lines, "X-Powered-By"); xp < 0 || link < xp {
		t.Errorf("Link must follow X-Powered-By: %v", lines)
	}
}

// TestWordPressLoginSignatureHeaders pins the wp-login.php fingerprint headers
// (captured from a real WordPress): the wordpress_test_cookie probe, the legacy
// 1984 Expires, no-store Cache-Control, and the security headers, in the captured
// relative order (Cache-Control before Set-Cookie, Vary last).
func TestWordPressLoginSignatureHeaders(t *testing.T) {
	lines, _ := headerLines(fetch(t, "wordpress", "GET /wp-login.php HTTP/1.1\r\nHost: x\r\n\r\n"))
	want := []string{"Expires", "Cache-Control", "Set-Cookie", "X-Frame-Options", "Content-Security-Policy", "Referrer-Policy"}
	last := -1
	for _, name := range want {
		i := headerIndex(lines, name)
		if i < 0 {
			t.Errorf("wp-login.php missing the %s signature header: %v", name, lines)
			continue
		}
		if i < last {
			t.Errorf("wp-login.php header %s is out of the captured order: %v", name, lines)
		}
		last = i
	}
	if sc := headerIndex(lines, "Set-Cookie"); sc < 0 || !strings.Contains(lines[sc], "wordpress_test_cookie") {
		t.Errorf("wp-login.php Set-Cookie must be the wordpress_test_cookie probe: %v", lines)
	}
}

// TestPerStackHeaderOrder pins the stack-specific intra-block ordering the per-stack
// emitter exists to produce, matching the captures: Tomcat emits Date LAST (after
// Content-Length) and no Server; nginx emits Content-Type/Content-Length BEFORE its
// signature headers; Apache emits Content-Type AFTER Content-Length.
func TestPerStackHeaderOrder(t *testing.T) {
	// Tomcat: Date last, no Server.
	tc, _ := headerLines(fetch(t, "tomcat", "GET /nope HTTP/1.1\r\nHost: x\r\n\r\n"))
	if d, cl := headerIndex(tc, "Date"), headerIndex(tc, "Content-Length"); d < 0 || cl < 0 || d < cl {
		t.Errorf("Tomcat must emit Date after Content-Length (Date last): %v", tc)
	}
	if headerIndex(tc, "Server") >= 0 {
		t.Errorf("Tomcat must not emit a Server header: %v", tc)
	}

	// nginx: Content-Length before the signature headers (Last-Modified/ETag).
	ng, _ := headerLines(fetch(t, "nginx-static", "GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	if cl, lm := headerIndex(ng, "Content-Length"), headerIndex(ng, "Last-Modified"); cl < 0 || lm < 0 || cl > lm {
		t.Errorf("nginx must emit Content-Length before Last-Modified: %v", ng)
	}

	// Apache: Content-Type after Content-Length.
	wp, _ := headerLines(fetch(t, "wordpress", "GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	if cl, ct := headerIndex(wp, "Content-Length"), headerIndex(wp, "Content-Type"); cl < 0 || ct < 0 || cl > ct {
		t.Errorf("Apache must emit Content-Type after Content-Length: %v", wp)
	}
}

func TestApacheEmitsDateBeforeServer(t *testing.T) {
	lines, _ := headerLines(fetch(t, "wordpress", "GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	srv := headerIndex(lines, "Server")
	date := headerIndex(lines, "Date")
	if srv < 0 || date < 0 {
		t.Fatalf("missing Server/Date header: %v", lines)
	}
	if date > srv {
		t.Errorf("Apache must emit Date before Server; got Server first: %v", lines)
	}
}

// TestTomcatEmptyReasonAndDefault404 pins the strong Tomcat fingerprints captured
// from tomcat:9.0: an empty HTTP reason phrase, a lowercase charset, and the exact
// default 404 page shape (UTF-8 en-dash, self-closing <hr/>, the precise
// description, no "Message" line).
func TestTomcatEmptyReasonAndDefault404(t *testing.T) {
	resp := fetch(t, "tomcat", "GET /nope HTTP/1.1\r\nHost: x\r\n\r\n")
	if !strings.HasPrefix(resp, "HTTP/1.1 404 \r\n") {
		t.Errorf("Tomcat must use an empty reason phrase (\"HTTP/1.1 404 \"): %q", resp[:min(len(resp), 24)])
	}
	lines, body := headerLines(resp)
	if headerIndex(lines, "Server") >= 0 {
		t.Errorf("modern Tomcat sends no Server header: %v", lines)
	}
	if !strings.Contains(body, "HTTP Status 404 – Not Found") {
		t.Errorf("Tomcat 404 should use the UTF-8 en-dash title: %q", body)
	}
	if !strings.Contains(body, `<hr class="line" />`) || strings.Contains(body, "<b>Message</b>") {
		t.Errorf("Tomcat 404 body shape wrong (self-closing hr, no Message line): %q", body)
	}
	if ctIdx := headerIndex(lines, "Content-Type"); ctIdx < 0 || !strings.Contains(lines[ctIdx], "charset=utf-8") {
		t.Errorf("Tomcat Content-Type should be lowercase charset=utf-8: %v", lines)
	}
}

// TestUnknownMethodIsPerDaemon pins the captured per-daemon response to an unknown
// method: Apache returns 501 Not Implemented WITH an Allow header (and reflects the
// method), while nginx returns 405 with NO Allow header. Both beat the old
// 200-for-any-method.
func TestUnknownMethodIsPerDaemon(t *testing.T) {
	// Apache/WordPress: 501 + Allow.
	resp := fetch(t, "wordpress", "FOO / HTTP/1.1\r\nHost: x\r\n\r\n")
	if !strings.HasPrefix(resp, "HTTP/1.1 501 Not Implemented\r\n") {
		t.Errorf("Apache unknown method should be 501: %q", resp[:min(len(resp), 32)])
	}
	lines, body := headerLines(resp)
	if headerIndex(lines, "Allow") < 0 {
		t.Errorf("Apache 501 must carry an Allow header: %v", lines)
	}
	if !strings.Contains(body, "FOO not supported") {
		t.Errorf("Apache 501 body should reflect the method: %q", body)
	}

	// nginx: 405, no Allow (the differential).
	ng := fetch(t, "nginx-static", "FOO / HTTP/1.1\r\nHost: x\r\n\r\n")
	if !strings.HasPrefix(ng, "HTTP/1.1 405") {
		t.Errorf("nginx unknown method should be 405: %q", ng[:min(len(ng), 32)])
	}
	if nl, _ := headerLines(ng); headerIndex(nl, "Allow") >= 0 {
		t.Errorf("nginx 405 must not carry Allow: %v", nl)
	}
}

func TestTomcatSendsNoServerHeader(t *testing.T) {
	lines, _ := headerLines(fetch(t, "tomcat", "GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	if i := headerIndex(lines, "Server"); i >= 0 {
		t.Errorf("modern Tomcat sends no Server header, but one was emitted: %q", lines[i])
	}
}

func TestHeadReturnsHeadersOnly(t *testing.T) {
	get := fetch(t, "nginx-static", "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	_, getBody := headerLines(get)
	if len(getBody) == 0 {
		t.Fatal("GET / returned an empty body; cannot compare HEAD")
	}

	head := fetch(t, "nginx-static", "HEAD / HTTP/1.1\r\nHost: x\r\n\r\n")
	lines, headBody := headerLines(head)
	if headBody != "" {
		t.Fatalf("HEAD returned a body (%d bytes); RFC 7231 forbids it", len(headBody))
	}
	// The Content-Length must still describe what the matching GET would return.
	wantCL := "Content-Length: " + strconv.Itoa(len(getBody))
	if headerIndex(lines, "Content-Length") < 0 || !slices.Contains(lines, wantCL) {
		t.Fatalf("HEAD must keep the GET Content-Length (%q): %v", wantCL, lines)
	}
}
