package ftp_test

// Bot-fidelity pins for the per-daemon FTP behaviour, against the real wire output
// captured from vsftpd and Pure-FTPd (and ProFTPD's documented default). The
// daemons differ in exactly the places a honeypot-aware client probes: FEAT
// (Pure-FTPd/ProFTPD advertise MLST, vsftpd does not), pre-login SYST (vsftpd gates
// it 530, the others answer 215), and the unhandled-command reply (vsftpd and
// Pure-FTPd answer 530 to everything pre-login - NOT 500 - with their own text,
// while ProFTPD answers 500 to a genuinely unknown verb). PASS-before-USER is 503.

import (
	"strings"
	"testing"
	"time"

	"sweetty/internal/persona"
	"sweetty/internal/proto/ftp"
	"sweetty/internal/testharness"
)

func ftpHarness(t *testing.T, software string) *testharness.Harness {
	t.Helper()
	p := &persona.Persona{FTPSoftware: software, FTPVer: "3.0.5", Hostname: "ftp-prod-02", HostIP: "10.0.0.5"}
	h, err := testharness.New(ftp.New(p))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.Close)
	if _, ok := h.ReadUntil("220", 2*time.Second); !ok {
		t.Fatal("no FTP banner")
	}
	return h
}

// expect sends a command and asserts the reply contains want.
func expect(t *testing.T, h *testharness.Harness, send, want, what string) {
	t.Helper()
	h.SendLine(send)
	out, ok := h.ReadUntil(want, 2*time.Second)
	if !ok {
		t.Errorf("%s: sent %q, wanted %q, got %q", what, send, want, out)
	}
}

func TestFTPVsftpdBehaviour(t *testing.T) {
	h := ftpHarness(t, "vsftpd")
	// vsftpd answers 530 to everything pre-login, including an unknown verb, and
	// gates SYST behind login. FEAT has UTF8 but no MLST.
	h.SendLine("FEAT")
	feat, _ := h.ReadUntil("211 End", 2*time.Second)
	if !strings.Contains(feat, "UTF8") || strings.Contains(feat, "MLST") {
		t.Errorf("vsftpd FEAT wrong (want UTF8, no MLST): %q", feat)
	}
	expect(t, h, "SYST", "530", "vsftpd gates SYST pre-login")
	expect(t, h, "WHARRGARBL", "530", "vsftpd answers 530 to an unknown verb (not 500)")
	expect(t, h, "PASS x", "503", "PASS before USER is 503")
}

func TestFTPPureFTPdBehaviour(t *testing.T) {
	h := ftpHarness(t, "pure-ftpd")
	h.SendLine("FEAT")
	feat, _ := h.ReadUntil("211 End", 2*time.Second)
	if !strings.Contains(feat, "MLST") {
		t.Errorf("pure-ftpd FEAT should advertise MLST: %q", feat)
	}
	if strings.Contains(feat, "AUTH TLS") {
		t.Errorf("pure-ftpd FEAT must not advertise AUTH TLS (the tarpit does no TLS): %q", feat)
	}
	expect(t, h, "SYST", "215", "pure-ftpd answers SYST pre-login")
	expect(t, h, "WHARRGARBL", "530", "pure-ftpd answers 530 to an unknown verb")
}

func TestFTPProFTPdBehaviour(t *testing.T) {
	h := ftpHarness(t, "proftpd")
	h.SendLine("FEAT")
	feat, _ := h.ReadUntil("211 End", 2*time.Second)
	if !strings.Contains(feat, "MLST") {
		t.Errorf("proftpd FEAT should advertise MLST: %q", feat)
	}
	expect(t, h, "SYST", "215", "proftpd answers SYST pre-login")
	// ProFTPD answers 500 to a genuinely unknown verb.
	expect(t, h, "WHARRGARBL", "500", "proftpd answers 500 to an unknown verb")
}
