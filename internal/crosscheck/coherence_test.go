package crosscheck_test

import (
	"strings"
	"testing"
	"time"

	"sweetty/internal/fakehost"
	"sweetty/internal/persona"
	"sweetty/internal/proto/ftp"
	httpproto "sweetty/internal/proto/http"
	"sweetty/internal/proto/ssh"
	"sweetty/internal/proto/telnet"
	"sweetty/internal/server"
	"sweetty/internal/testharness"
)

// firstResponse connects to a protocol over the harness, optionally sends a
// request, and returns the server's opening bytes.
func firstResponse(t *testing.T, proto server.Protocol, request string) string {
	t.Helper()
	h, err := testharness.New(proto)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.Close)
	if request != "" {
		h.Send(request)
	}
	return h.ReadFor(600 * time.Millisecond)
}

// TestEveryServiceTellsOnePersonaStory drives ssh, ftp, all three http stacks and
// telnet from a SINGLE persona and asserts every advertised version and the host
// identity come from it. A refactor that made one service read a different field,
// or pinned a version, desyncs the banners a scan platform correlates and fails
// here — the property no per-service test can prove on its own.
func TestEveryServiceTellsOnePersonaStory(t *testing.T) {
	p := persona.GenerateProfile("full") // a profile that exposes every service

	fs, err := fakehost.Load(p)
	if err != nil {
		t.Fatalf("load fakehost: %v", err)
	}

	// SSH: the interactive service sends this persona's OpenSSH identification string
	// before any key exchange, so the opening bytes carry the persona version.
	if sshResp := firstResponse(t, ssh.New(fs, p, ""), ""); !strings.Contains(sshResp, "SSH-2.0-"+p.OpenSSHVer) {
		t.Errorf("ssh banner does not carry persona OpenSSH %q: %q", p.OpenSSHVer, sshResp)
	}

	// FTP: the banner is the persona's daemon, carrying its version (Pure-FTPd
	// deliberately hides the version, so only assert the version when it is shown).
	ftpResp := firstResponse(t, ftp.New(p), "")
	if !strings.HasPrefix(ftpResp, "220") {
		t.Errorf("ftp banner is not a 220 greeting: %q", ftpResp)
	}
	if p.FTPSoftware != "pure-ftpd" && !strings.Contains(ftpResp, p.FTPVer) {
		t.Errorf("ftp banner does not carry persona FTP version %q: %q", p.FTPVer, ftpResp)
	}

	get := "GET / HTTP/1.1\r\nHost: x\r\n\r\n"

	// HTTP / WordPress on Apache: the Apache, PHP and WordPress versions all come
	// from this one persona, and Apache carries the Ubuntu tag.
	wp := firstResponse(t, httpproto.New(p, "wordpress"), get)
	for _, want := range []string{"Apache/" + p.ApacheVer + " (Ubuntu)", "PHP/" + p.PHPVer, "WordPress " + p.WPVer} {
		if !strings.Contains(wp, want) {
			t.Errorf("wordpress response missing %q (cross-service desync): %q", want, firstLine(wp))
		}
	}

	// HTTP / nginx static: nginx version with the Ubuntu tag.
	if ng := firstResponse(t, httpproto.New(p, "nginx-static"), get); !strings.Contains(ng, "Server: nginx/"+p.NginxVer+"\r\n") {
		t.Errorf("nginx response does not carry the bare persona nginx token %q: %q", p.NginxVer, firstLine(ng))
	}

	// HTTP / Tomcat: the body version is the persona's Tomcat.
	if tc := firstResponse(t, httpproto.New(p, "tomcat"), get); !strings.Contains(tc, "Apache Tomcat/"+p.TomcatVer) {
		t.Errorf("tomcat response does not carry persona Tomcat %q", p.TomcatVer)
	}

	// Telnet: a logged-in `uname -a` names the same kernel and host as everything else.
	if una := telnetUname(t, p); !strings.Contains(una, p.KernelRel) || !strings.Contains(una, p.Hostname) {
		t.Errorf("telnet uname -a disagrees with the persona kernel %q / host %q: %q", p.KernelRel, p.Hostname, una)
	}
}

// telnetUname logs into the telnet shell and runs uname -a.
func telnetUname(t *testing.T, p *persona.Persona) string {
	t.Helper()
	fs, err := fakehost.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	h, err := testharness.New(telnet.New(fs, p, "ubuntu"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.Close)
	h.ReadUntil("login:", 2*time.Second)
	h.SendLine("root")
	h.ReadUntil("Password:", 2*time.Second)
	h.SendLine(p.RootPassword)        // the box validates like sshd; use the real credential
	h.ReadFor(400 * time.Millisecond) // welcome + first prompt
	h.SendLine("uname -a")
	return h.ReadFor(500 * time.Millisecond)
}

func firstLine(s string) string {
	if i := strings.Index(s, "\r\n"); i >= 0 {
		return s[:i]
	}
	return s
}
