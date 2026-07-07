package ftp

import (
	"strings"
	"testing"

	"sweetty/internal/persona"
)

func TestNewNameAndClientFirst(t *testing.T) {
	proto := New(persona.Generate())
	if got := proto.Name(); got != "ftp" {
		t.Errorf("Name() = %q, want %q", got, "ftp")
	}
	if proto.ClientFirst() {
		t.Error("ClientFirst() = true, want false")
	}
}

func TestBanner(t *testing.T) {
	// vsftpd greets with its version in parens; ProFTPD greets with the version,
	// the ServerName, and the connecting address - never "Server ready.".
	vsftpd := &Protocol{persona: &persona.Persona{FTPSoftware: "vsftpd", FTPVer: "3.0.5"}}
	if got, want := vsftpd.banner(), "220 (vsFTPd 3.0.5)\r\n"; got != want {
		t.Errorf("vsftpd banner = %q, want %q", got, want)
	}

	proftpd := &Protocol{persona: &persona.Persona{FTPSoftware: "proftpd", FTPVer: "1.3.7a", Hostname: "ftp-prod-02", HostIP: "10.0.0.5"}}
	if got, want := proftpd.banner(), "220 ProFTPD 1.3.7a Server (ftp-prod-02) [::ffff:10.0.0.5]\r\n"; got != want {
		t.Errorf("proftpd banner = %q, want %q", got, want)
	}

	pure := &Protocol{persona: &persona.Persona{FTPSoftware: "pure-ftpd", FTPVer: "1.0.49"}}
	got := pure.banner()
	if !strings.HasPrefix(got, "220---------- Welcome to Pure-FTPd") {
		t.Errorf("pure-ftpd banner = %q, missing welcome prefix", got)
	}
	if strings.Contains(got, "[TLS]") {
		t.Errorf("pure-ftpd banner advertises [TLS] it cannot honour: %q", got)
	}
	if !strings.HasSuffix(got, "\r\n") {
		t.Errorf("pure-ftpd banner = %q, must end with CRLF", got)
	}
}

func TestSplitCommand(t *testing.T) {
	cmd, arg := splitCommand("USER Admin")
	if cmd != "USER" || arg != "Admin" {
		t.Errorf("splitCommand = %q,%q, want USER,Admin", cmd, arg)
	}
	cmd, arg = splitCommand("quit")
	if cmd != "QUIT" || arg != "" {
		t.Errorf("splitCommand = %q,%q, want QUIT,empty", cmd, arg)
	}
}
