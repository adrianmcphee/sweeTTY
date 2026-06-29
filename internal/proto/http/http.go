// Package http implements an HTTP honeypot persona. It speaks just enough of
// HTTP/1.1 to look like a real web stack to a scanner or a bot: it parses the
// request line and headers, logs them, captures any POST body (with a sha256 of
// the bytes), and answers with a static page rendered from the instance persona.
//
// Every response is a fixed template filled in from the persona's randomized
// software versions, so two instances advertise different stacks and neither
// matches this source. The service never fetches, proxies, executes, or writes
// anything: it only records the request and returns a canned page, then closes
// the connection. That keeps the persona inert no matter what an attacker sends.
package http

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"html"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"sweetty/internal/persona"
	"sweetty/internal/server"
)

// Per-route latencies. Real PHP login handlers and manager-app auth checks take
// a beat; reproducing that both adds realism and slows brute-force clients.
const (
	loginPageDelay   = 200 * time.Millisecond
	loginPostDelay   = 3 * time.Second
	xmlrpcPostDelay  = 2 * time.Second
	notFoundDelay    = 500 * time.Millisecond
	managerAuthDelay = 2 * time.Second
)

// maxBodyBytes caps how much of a POST body is read and stored, so a large
// upload cannot exhaust memory. The full byte count is still taken from
// Content-Length; only the captured payload is bounded.
const maxBodyBytes = 65536

// maxHeaders caps how many request header lines are read, so a client that streams
// headers forever cannot grow the captured map until the process OOMs. Each line
// is independently bounded by the session's maxLineBytes.
const maxHeaders = 100

// httpDate is the layout for the Date header. HTTP fixes the timezone to GMT.
const httpDate = "Mon, 02 Jan 2006 15:04:05 GMT"

// Protocol is the HTTP honeypot. It carries the instance persona so the
// advertised server software and versions match the rest of the host's identity,
// and a style that selects which web stack to impersonate. sleep is the latency
// source, indirected so tests can run without the per-route delays.
type Protocol struct {
	persona *persona.Persona
	style   string
	sleep   func(time.Duration)

	// wp* track WordPress login pressure per source so the admin "gives" only
	// after persistent credential-stuffing, never to a one-shot bot. Guarded by mu
	// because one Protocol serves every connection on the listener concurrently.
	mu       sync.Mutex
	wpTries  map[string]int
	wpBroken map[string]bool
}

// New returns an HTTP protocol bound to the given persona and style. The style
// is one of "wordpress", "tomcat", or "nginx-static"; any other value falls back
// to a plain static server.
func New(p *persona.Persona, style string) server.Protocol {
	return &Protocol{
		persona:  p,
		style:    style,
		sleep:    time.Sleep,
		wpTries:  make(map[string]int),
		wpBroken: make(map[string]bool),
	}
}

// Name reports the protocol label used in logs and startup output.
func (pr *Protocol) Name() string { return "http" }

// ClientFirst is true: an HTTP client sends its request before the server speaks.
func (pr *Protocol) ClientFirst() bool { return true }

// Handle reads one request, logs it (and any POST body with its sha256), then
// writes a single static response and returns. The response carries
// Connection: close, so the connection ends after one exchange.
func (pr *Protocol) Handle(s *server.Session) {
	s.Persona = pr.persona

	requestLine, ok := s.ReadLine()
	if requestLine == "" && !ok {
		return
	}
	method, path := parseRequestLine(requestLine)

	// Bound the header block: an attacker can otherwise stream headers forever,
	// growing the map until the process OOMs. A real client sends a few dozen.
	headers := make(map[string]string)
	for range maxHeaders {
		line, lok := s.ReadLine()
		if line == "" {
			break // blank line terminates the header block
		}
		if k, v, found := splitHeader(line); found {
			headers[strings.ToLower(k)] = v
		}
		if !lok {
			break
		}
	}
	s.LogHTTPRequest(method, requestLine, path, headers)

	var body string
	if method == "POST" {
		body = readBody(s, atoiSafe(headers["content-length"]))
		sum := sha256.Sum256([]byte(body))
		s.LogHTTPPost(path, body, hex.EncodeToString(sum[:]))
	}

	resp, delay := pr.respond(s, method, path, body)
	if method == "HEAD" {
		resp = headersOnly(resp)
	}
	if delay > 0 {
		pr.sleep(delay)
	}
	s.Write(resp)
}

// headersOnly strips the body from a response for a HEAD request, keeping the
// header block including the Content-Length the matching GET would have returned,
// as RFC 7231 requires. Returning a body for HEAD is a tell no real httpd commits.
func headersOnly(resp string) string {
	if i := strings.Index(resp, "\r\n\r\n"); i >= 0 {
		return resp[:i+4]
	}
	return resp
}

// ---- request parsing ----

// parseRequestLine splits "METHOD path HTTP/x.y" into method and path. The
// method is upper-cased; a missing path defaults to "/".
func parseRequestLine(line string) (method, path string) {
	fields := strings.Fields(line)
	if len(fields) > 0 {
		method = strings.ToUpper(fields[0])
	}
	if len(fields) > 1 {
		path = fields[1]
	}
	if path == "" {
		path = "/"
	}
	return method, path
}

// splitHeader splits one header line at the first colon.
func splitHeader(line string) (key, value string, ok bool) {
	i := strings.IndexByte(line, ':')
	if i < 0 {
		return "", "", false
	}
	return strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:]), true
}

// atoiSafe parses a non-negative integer, returning 0 for anything malformed.
func atoiSafe(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// readBody reads up to contentLength bytes of the request body using the only
// input surface the session exposes, line reads. Lines are rejoined with CRLF
// (HTTP's terminator, which the reader strips) and the result is bounded by both
// Content-Length and maxBodyBytes. The capture stops early on end of input.
func readBody(s *server.Session, contentLength int) string {
	if contentLength <= 0 {
		return ""
	}
	if contentLength > maxBodyBytes {
		contentLength = maxBodyBytes
	}
	return string(s.ReadN(contentLength))
}

// pathOnly strips the query string and fragment from a request target.
func pathOnly(target string) string {
	if i := strings.IndexAny(target, "?#"); i >= 0 {
		return target[:i]
	}
	return target
}

// ---- response building ----

// canonicalHeaderOrder is the order the per-route extra headers are emitted in,
// after the Server/Date pair. Real servers emit a fixed order; a naive map
// iteration would emit them alphabetically, which no daemon does and which (being
// identical across all three personas) reveals one engine behind them. Server is
// placed explicitly below, since its position relative to Date differs by server.
var canonicalHeaderOrder = []string{
	"X-Powered-By", "Link", "Expires", "Cache-Control", "Set-Cookie",
	"X-Frame-Options", "Content-Security-Policy", "Referrer-Policy",
	"Location", "WWW-Authenticate", "Allow",
	"Last-Modified", "ETag", "Accept-Ranges", "Vary",
}

// hdr is one response header, kept ordered (a map cannot express the per-stack
// order a scanner fingerprints).
type hdr struct{ k, v string }

// httpHead assembles a response from an explicit ordered header list. Each stack
// builder below places Date/Server/Content-Type/Content-Length/Connection in its
// own order; Connection: close and an explicit Content-Length are kept on every
// stack (one-request-per-connection) as a documented accepted trade — real nginx
// keep-alive and Apache chunked framing are deliberately not reproduced.
func httpHead(status int, reason string, headers []hdr, body string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", status, reason)
	for _, h := range headers {
		fmt.Fprintf(&b, "%s: %s\r\n", h.k, h.v)
	}
	b.WriteString("\r\n")
	b.WriteString(body)
	return b.String()
}

func httpNow() string { return time.Now().UTC().Format(httpDate) }

func contentLength(body string) hdr { return hdr{"Content-Length", strconv.Itoa(len(body))} }

func contentType(ct string) []hdr {
	if ct == "" {
		return nil
	}
	return []hdr{{"Content-Type", ct}}
}

// orderedExtras returns the per-route extra headers (everything the stack builders
// do not place themselves) in canonical order.
func orderedExtras(extra map[string]string) []hdr {
	var out []hdr
	emitted := map[string]bool{"Server": true}
	for _, k := range canonicalHeaderOrder {
		if v, ok := extra[k]; ok {
			out = append(out, hdr{k, v})
			emitted[k] = true
		}
	}
	rest := make([]string, 0)
	for k := range extra {
		if !emitted[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	for _, k := range rest {
		out = append(out, hdr{k, extra[k]})
	}
	return out
}

// nginxResponse: Server, Date, Content-Type, Content-Length, <extras>, Connection.
func nginxResponse(status int, reason, ct, body string, extra map[string]string) string {
	hs := []hdr{{"Server", extra["Server"]}, {"Date", httpNow()}}
	hs = append(hs, contentType(ct)...)
	hs = append(hs, contentLength(body))
	hs = append(hs, orderedExtras(extra)...)
	hs = append(hs, hdr{"Connection", "close"})
	return httpHead(status, reason, hs, body)
}

// apacheResponse: Date, Server, <extras>, Content-Length, Content-Type, Connection
// (Apache emits Date before Server and Content-Type after Content-Length).
func apacheResponse(status int, reason, ct, body string, extra map[string]string) string {
	hs := []hdr{{"Date", httpNow()}}
	if s := extra["Server"]; s != "" {
		hs = append(hs, hdr{"Server", s})
	}
	hs = append(hs, orderedExtras(extra)...)
	hs = append(hs, contentLength(body))
	hs = append(hs, contentType(ct)...)
	hs = append(hs, hdr{"Connection", "close"})
	return httpHead(status, reason, hs, body)
}

// tomcatResponse: Content-Type, Content-Language, Content-Length, Date (LAST),
// <extras>, Connection. Modern Tomcat sends no Server header and emits Date last.
func tomcatResponse(status int, reason, ct, body string, extra map[string]string) string {
	hs := contentType(ct)
	hs = append(hs, hdr{"Content-Language", "en"}, contentLength(body), hdr{"Date", httpNow()})
	hs = append(hs, orderedExtras(extra)...)
	hs = append(hs, hdr{"Connection", "close"})
	return httpHead(status, reason, hs, body)
}

// withHeader returns a copy of base with one extra header set, so a route can add
// a Location or WWW-Authenticate without mutating the shared base header set.
func withHeader(base map[string]string, key, value string) map[string]string {
	m := make(map[string]string, len(base)+1)
	for k, v := range base {
		m[k] = v
	}
	m[key] = value
	return m
}

// respond routes a request to the active style and returns the full response
// plus the latency to apply before sending it.
func (pr *Protocol) respond(s *server.Session, method, path, body string) (string, time.Duration) {
	switch pr.style {
	case "tomcat":
		return pr.respondTomcat(method, path)
	case "wordpress":
		return pr.respondWordPress(s, sessionIP(s), method, path, body)
	default:
		return pr.respondNginx(method, path)
	}
}

// sessionIP returns the source IP used to gate the WordPress trap, tolerating a
// nil session so the stateless responders stay unit-testable without a live
// connection.
func sessionIP(s *server.Session) string {
	if s == nil {
		return ""
	}
	return s.SrcIP
}

// ---- WordPress ----

func (pr *Protocol) wpHeaders() map[string]string {
	return map[string]string{
		"Server":       "Apache/" + pr.persona.ApacheVer + " (Ubuntu)",
		"X-Powered-By": "PHP/" + pr.persona.PHPVer,
	}
}

func (pr *Protocol) respondWordPress(s *server.Session, srcIP, method, path, body string) (string, time.Duration) {
	base := pr.wpHeaders()
	if method != "GET" && method != "HEAD" && method != "POST" {
		// Apache answers a method it does not implement with 501 + an Allow header
		// (captured from httpd:2.4), not 200-for-everything.
		h := withHeader(base, "Allow", "POST,OPTIONS,HEAD,GET,TRACE")
		return apacheResponse(501, "Not Implemented", "text/html; charset=iso-8859-1", apache501Body(method), h), 0
	}
	route := pathOnly(path)

	switch {
	case route == "/":
		// The REST-API discovery Link header (rel="https://api.w.org/") is THE
		// WordPress fingerprint, plus Vary: Accept-Encoding — both present on a real
		// WP front page and a tell by their absence.
		h := withHeader(base, "Link", "<http://"+pr.persona.Hostname+"/index.php?rest_route=/>; rel=\"https://api.w.org/\"")
		h["Vary"] = "Accept-Encoding"
		return apacheResponse(200, "OK", "text/html; charset=UTF-8", wpFrontPage(pr.persona), h), 0

	case route == "/wp-login.php":
		if method == "POST" {
			// Capture the guessed credential, then decide whether this source has
			// done enough "work" to be let in. A real WordPress returns 302 either
			// way; what differs is the destination and the logged-in cookie.
			user, pass := parseWPLogin(body)
			accepted := pr.wpLetIn(srcIP)
			if s != nil {
				s.LogCredentialResult(user, pass, accepted, accepted)
			}
			if accepted {
				h := withHeader(base, "Location", "/wp-admin/")
				h["Set-Cookie"] = wpLoggedInCookie(pr.persona)
				return apacheResponse(302, "Found", "", "", h), loginPostDelay
			}
			h := withHeader(base, "Location", "/wp-login.php?error=invalid_credentials")
			return apacheResponse(302, "Found", "", "", h), loginPostDelay
		}
		// The wp-login signature, captured from a real WordPress: the legacy 1984
		// Expires, the no-store Cache-Control, the wordpress_test_cookie probe, and
		// the security headers — the trio scanners key on for the login page.
		h := withHeader(base, "Expires", "Wed, 11 Jan 1984 05:00:00 GMT")
		h["Cache-Control"] = "no-cache, must-revalidate, max-age=0, no-store, private"
		h["Set-Cookie"] = "wordpress_test_cookie=WP%20Cookie%20check; path=/; HttpOnly"
		h["X-Frame-Options"] = "SAMEORIGIN"
		h["Content-Security-Policy"] = "frame-ancestors 'self';"
		h["Referrer-Policy"] = "strict-origin-when-cross-origin"
		h["Vary"] = "Accept-Encoding"
		return apacheResponse(200, "OK", "text/html; charset=UTF-8", wpLoginPage(pr.persona), h), loginPageDelay

	case route == "/xmlrpc.php":
		if method == "POST" {
			return apacheResponse(200, "OK", "text/xml; charset=UTF-8", xmlrpcFault(), base), xmlrpcPostDelay
		}
		h := withHeader(base, "Allow", "POST")
		return apacheResponse(405, "Method Not Allowed", "text/plain; charset=UTF-8",
			"XML-RPC server accepts POST requests only.", h), 0

	case strings.HasPrefix(route, "/wp-admin"):
		// A source that has broken in lands in the dashboard; everyone else is
		// bounced to the login like a real wp-admin guard.
		if pr.wpBrokenIn(srcIP) {
			return apacheResponse(200, "OK", "text/html; charset=UTF-8", wpSecretsPage(pr.persona), base), loginPageDelay
		}
		h := withHeader(base, "Location", "/wp-login.php?redirect_to=%2Fwp-admin%2F&reauth=1")
		return apacheResponse(302, "Found", "", "", h), 0

	case route == "/readme.html":
		return apacheResponse(200, "OK", "text/html; charset=UTF-8", wpReadme(pr.persona), base), 0

	case route == "/robots.txt":
		return apacheResponse(200, "OK", "text/plain; charset=UTF-8", wpRobots(), base), 0

	default:
		return apacheResponse(404, "Not Found", "text/html; charset=UTF-8", wp404(pr.persona), base), notFoundDelay
	}
}

// ---- WordPress break-in trap ----

//go:embed secrets.html
var jtArtDoc string

// jtArtBody is the colour-ASCII payload carved out of the embedded libcaca
// document, without its <html>/<head> wrapper, ready to drop into the dashboard.
var jtArtBody = extractArtBody(jtArtDoc)

func extractArtBody(doc string) string {
	i := strings.Index(doc, "<body>")
	j := strings.LastIndex(doc, "</body>")
	if i >= 0 && j > i {
		return doc[i+len("<body>") : j]
	}
	return doc
}

const (
	// wpBreakInAfter is how many wp-login POSTs one source must send before the
	// door gives. Persistent credential-stuffing earns the reveal; a drive-by bot
	// that tries once and leaves never sees it, so the payoff only follows work.
	wpBreakInAfter = 5
	// wpTrackCap bounds the per-source tables so a spray from many forged source
	// IPs cannot grow them without limit (the host is assumed hostile).
	wpTrackCap = 50000
)

// wpLetIn records one login attempt from srcIP and reports whether the door now
// opens. It opens once a source reaches wpBreakInAfter attempts and stays open
// for that source thereafter.
func (pr *Protocol) wpLetIn(srcIP string) bool {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	if pr.wpBroken[srcIP] {
		return true
	}
	if _, seen := pr.wpTries[srcIP]; !seen && len(pr.wpTries) >= wpTrackCap {
		return false // table full: do not begin tracking a brand-new source
	}
	pr.wpTries[srcIP]++
	if pr.wpTries[srcIP] >= wpBreakInAfter {
		delete(pr.wpTries, srcIP)
		pr.wpBroken[srcIP] = true
		return true
	}
	return false
}

// wpBrokenIn reports whether srcIP has already been let into wp-admin.
func (pr *Protocol) wpBrokenIn(srcIP string) bool {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	return pr.wpBroken[srcIP]
}

// parseWPLogin pulls the username and password from a wp-login POST body (the
// standard log/pwd form fields), tolerating anything malformed.
func parseWPLogin(body string) (user, pass string) {
	v, err := url.ParseQuery(body)
	if err != nil {
		return "", ""
	}
	return v.Get("log"), v.Get("pwd")
}

// wpLoggedInCookie mints a WordPress-shaped logged-in cookie. A real install
// embeds a per-site hash in the cookie name; we derive a stable one from the
// persona so it is consistent across a source's requests.
func wpLoggedInCookie(p *persona.Persona) string {
	sum := sha256.Sum256([]byte("wp-logged-in:" + p.Hostname))
	return "wordpress_logged_in_" + hex.EncodeToString(sum[:])[:32] +
		"=admin%7C9999999999%7Chash; path=/; HttpOnly"
}

// wpSecretsPage is the dashboard a broken-in attacker lands on: just enough
// wp-admin chrome to read as real, wrapped around the reveal.
func wpSecretsPage(p *persona.Persona) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en-US">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Dashboard &lsaquo; %s &mdash; WordPress</title>
<style>
body{margin:0;background:#1d2327;color:#f0f0f1;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;font-size:13px}
#wpwrap{padding:20px}
h1{font-weight:400;font-size:23px;margin:0 0 8px}
.caca{overflow:auto}
</style>
</head>
<body class="wp-admin wp-core-ui">
<div id="wpwrap">
<h1>Dashboard</h1>
<p>Howdy, admin. You did the work. Here are the secrets.</p>
<div class="caca">%s</div>
</div>
</body>
</html>`, html.EscapeString(p.Hostname), jtArtBody)
}

func wpFrontPage(p *persona.Persona) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en-US">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="WordPress %s">
<title>%s | Just another WordPress site</title>
<link rel="stylesheet" id="wp-block-library-css" href="/wp-includes/css/dist/block-library/style.min.css?ver=%s" media="all">
</head>
<body class="home blog wp-embed-responsive">
<header class="site-header">
<h1 class="site-title"><a href="/" rel="home">%s</a></h1>
<p class="site-description">Just another WordPress site</p>
</header>
<main id="main" class="site-main">
<article class="post-1 post type-post status-publish">
<h2 class="entry-title"><a href="/?p=1" rel="bookmark">Hello world!</a></h2>
<div class="entry-content"><p>Welcome to WordPress. This is your first post. Edit or delete it, then start writing!</p></div>
</article>
</main>
<footer class="site-footer"><p>Proudly powered by <a href="https://wordpress.org/">WordPress</a></p></footer>
</body>
</html>
`, p.WPVer, p.Hostname, p.WPVer, p.Hostname)
}

func wpLoginPage(p *persona.Persona) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en-US">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex, follow">
<title>Log In | %s</title>
<link rel="stylesheet" href="/wp-admin/css/login.min.css?ver=%s" media="all">
</head>
<body class="login no-js login-action-login wp-core-ui locale-en-us">
<div id="login">
<h1><a href="https://wordpress.org/">Powered by WordPress</a></h1>
<form name="loginform" id="loginform" action="/wp-login.php" method="post">
<p><label for="user_login">Username or Email Address</label>
<input type="text" name="log" id="user_login" class="input" value="" size="20" autocapitalize="off" autocomplete="username"></p>
<div class="user-pass-wrap">
<label for="user_pass">Password</label>
<input type="password" name="pwd" id="user_pass" class="input password-input" value="" size="20" autocomplete="current-password"></div>
<p class="forgetmenot"><input name="rememberme" type="checkbox" id="rememberme" value="forever"> <label for="rememberme">Remember Me</label></p>
<p class="submit">
<input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Log In">
<input type="hidden" name="redirect_to" value="/wp-admin/">
<input type="hidden" name="testcookie" value="1"></p>
</form>
<p id="nav"><a href="/wp-login.php?action=lostpassword">Lost your password?</a></p>
<p id="backtoblog"><a href="/">Go to %s</a></p>
</div>
</body>
</html>
`, p.Hostname, p.WPVer, p.Hostname)
}

func wpReadme(p *persona.Persona) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>WordPress ReadMe</title>
</head>
<body>
<h1 id="logo">WordPress</h1>
<p style="text-align: center;">Semantic Personal Publishing Platform</p>
<h2>Version %s</h2>
<p>Using WordPress, you can build great websites quickly.</p>
<h3>Installation: Famous 5-minute install</h3>
<ol>
<li>Unzip the package in an empty directory and upload everything.</li>
<li>Open wp-admin/install.php in your browser.</li>
</ol>
</body>
</html>
`, p.WPVer)
}

func wpRobots() string {
	return "User-agent: *\nDisallow: /wp-admin/\nAllow: /wp-admin/admin-ajax.php\n"
}

// apache501Body is Apache's default 501 page, captured from httpd:2.4, with the
// offending method reflected (and HTML-escaped, as Apache does).
func apache501Body(method string) string {
	return `<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html><head>
<title>501 Not Implemented</title>
</head><body>
<h1>Not Implemented</h1>
<p>` + html.EscapeString(method) + ` not supported for current URL.<br />
</p>
</body></html>
`
}

func wp404(p *persona.Persona) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en-US">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="WordPress %s">
<title>Page not found | %s</title>
</head>
<body class="error404">
<header class="site-header"><h1 class="site-title"><a href="/" rel="home">%s</a></h1></header>
<main id="main" class="site-main">
<h2 class="page-title">Oops! That page can't be found.</h2>
<p>It looks like nothing was found at this location. Maybe try a search?</p>
</main>
</body>
</html>
`, p.WPVer, p.Hostname, p.Hostname)
}

func xmlrpcFault() string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <fault>
    <value>
      <struct>
        <member>
          <name>faultCode</name>
          <value><int>-32700</int></value>
        </member>
        <member>
          <name>faultString</name>
          <value><string>parse error. not well formed</string></value>
        </member>
      </struct>
    </value>
  </fault>
</methodResponse>
`
}

// ---- Tomcat ----

func (pr *Protocol) respondTomcat(method, path string) (string, time.Duration) {
	// Captured from tomcat:9.0: modern Tomcat sends no Server header, an EMPTY reason
	// phrase ("HTTP/1.1 404 " — the empty statusText below yields the bare-code
	// status line, a strong fingerprint), and a lowercase charset=utf-8.
	base := map[string]string{}
	const ct = "text/html;charset=utf-8"
	route := pathOnly(path)

	switch {
	case route == "/":
		return tomcatResponse(200, "", ct, tomcatHome(pr.persona), base), 0

	case strings.HasPrefix(route, "/manager") || strings.HasPrefix(route, "/host-manager"):
		h := withHeader(base, "WWW-Authenticate", `Basic realm="Tomcat Manager Application"`)
		return tomcatResponse(401, "", ct, tomcat401(), h), managerAuthDelay

	default:
		return tomcatResponse(404, "", ct, tomcat404(pr.persona), base), 0
	}
}

func tomcatHome(p *persona.Persona) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Apache Tomcat/%s</title>
<link href="/manager/images/tomcat.css" rel="stylesheet" type="text/css">
</head>
<body>
<div id="wrapper">
<div id="navigation" class="curved"><h1>Apache Tomcat/%s</h1></div>
<div id="asf-box"><h1>Apache Tomcat/%s</h1></div>
<div id="upgrade"><p>If you're seeing this, you've successfully installed Tomcat. Congratulations!</p></div>
<div id="actions">
<a href="/manager/html">Manager App</a>
<a href="/host-manager/html">Host Manager</a>
<a href="/docs/">Server Status</a>
</div>
</div>
</body>
</html>
`, p.TomcatVer, p.TomcatVer, p.TomcatVer)
}

func tomcat401() string {
	return `<!doctype html><html lang="en"><head><title>401 Unauthorized</title>` +
		`<style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1 {background-color:#525D76;color:white;}</style>` +
		`</head><body><h1>401 Unauthorized</h1><hr class="line">` +
		`<p>You are not authorized to view this page. If you have not changed any configuration files, ` +
		`please examine the file conf/tomcat-users.xml in your installation.</p></body></html>`
}

func tomcat404(p *persona.Persona) string {
	// The exact default Tomcat 404 captured from tomcat:9.0: a UTF-8 EN DASH in the
	// title/h1 (not an ASCII hyphen), the full CSS block, a self-closing <hr/>, no
	// "Message" line, and the precise description text.
	return fmt.Sprintf(`<!doctype html><html lang="en"><head><title>HTTP Status 404 – Not Found</title>`+
		`<style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style>`+
		`</head><body><h1>HTTP Status 404 – Not Found</h1><hr class="line" /><p><b>Type</b> Status Report</p>`+
		`<p><b>Description</b> The origin server did not find a current representation for the target resource or is not willing to disclose that one exists.</p>`+
		`<hr class="line" /><h3>Apache Tomcat/%s</h3></body></html>`, p.TomcatVer)
}

// ---- nginx static ----

// nginx default-index header values, captured authentically: the package file's
// mtime and the derived ETag (hex(mtime)-hex(size)). They are fixed artifacts of
// the 615-byte page, so they are constants tied to nginxDefaultIndex.
const (
	nginxIndexLastModified = "Tue, 11 Apr 2023 01:45:34 GMT"
	nginxIndexETag         = `"6434bbbe-267"`
)

func (pr *Protocol) respondNginx(method, path string) (string, time.Duration) {
	// nginx — even the Ubuntu/Debian package — emits a bare "nginx/<ver>" Server
	// header with no distro suffix, matching the token its error pages echo in the
	// <hr> signature line. (Apache, by contrast, does add "(Ubuntu)".)
	base := map[string]string{"Server": "nginx/" + pr.persona.NginxVer}
	if method != "GET" && method != "HEAD" {
		// A disallowed or unknown method on a static file is 405 — and nginx sends
		// NO Allow header here, a key differential from Apache.
		return nginxResponse(405, "Not Allowed", "text/html", nginxErrorPage(pr.persona, "405 Not Allowed"), base), 0
	}
	if pathOnly(path) == "/" {
		h := withHeader(base, "Last-Modified", nginxIndexLastModified)
		h["ETag"] = nginxIndexETag
		h["Accept-Ranges"] = "bytes"
		return nginxResponse(200, "OK", "text/html", nginxDefaultIndex, h), 0
	}
	return nginxResponse(404, "Not Found", "text/html", nginxErrorPage(pr.persona, "404 Not Found"), base), 0
}

// nginxDefaultIndex is the exact 615-byte default index page nginx ships, captured
// verbatim from nginx:1.24.0. It carries no version, so it is identical across the
// version pool; testdata/nginx-index.html is the golden copy a test diffs against.
const nginxDefaultIndex = `<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
html { color-scheme: light dark; }
body { width: 35em; margin: 0 auto;
font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>
`

// nginxErrorPage renders nginx's default error page for a "<code> <reason>" title.
// The version token in the <hr> signature line matches the bare Server header.
func nginxErrorPage(p *persona.Persona, title string) string {
	return fmt.Sprintf(`<html>
<head><title>%s</title></head>
<body>
<center><h1>%s</h1></center>
<hr><center>nginx/%s</center>
</body>
</html>
`, title, title, p.NginxVer)
}
