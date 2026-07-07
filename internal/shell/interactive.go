package shell

import (
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/fs"
	mrand "math/rand/v2"
	"path"
	"strconv"
	"strings"
	"time"

	"sweetty/internal/persona"
	"sweetty/internal/server"
	"sweetty/internal/util"
)

// revealArt holds the colour-ANSI renderings served as the payoff when an
// attacker views or grabs a bait image (the terminal image viewers, cat/base64
// on a bait file, the fake vault command). They are operator-replaceable assets:
// drop any number of your own .txt renderings into internal/shell/reveal/ and
// rebuild; one is chosen at random per view. The shipped art is upper-half-block
// (U+2580) rendering in 256-colour ANSI, each cell carrying two vertically
// stacked pixels of real colour so the portrait reads as a photo rather than
// glyph noise. 256-colour renders on essentially any terminal an attacker
// connects with (including ones without truecolour, such as Apple Terminal).
// Nothing in the name hints at the gag.
//
//go:embed reveal
var revealArt embed.FS

//go:embed loot
var lootArt embed.FS

func randomReveal() string {
	entries, err := fs.ReadDir(revealArt, "reveal")
	if err != nil {
		return ""
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".txt") {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		return ""
	}
	data, _ := fs.ReadFile(revealArt, "reveal/"+names[mrand.IntN(len(names))])
	return string(data)
}

// hasImageExt reports whether p names a file a terminal image viewer would accept.
func hasImageExt(p string) bool {
	low := strings.ToLower(p)
	return strings.HasSuffix(low, ".png") || strings.HasSuffix(low, ".jpg") ||
		strings.HasSuffix(low, ".jpeg") || strings.HasSuffix(low, ".gif") ||
		strings.HasSuffix(low, ".bmp")
}

// isLootImage reports whether abs is one of this instance's planted bait images:
// an image file under the per-instance loot directory. Every way an attacker can
// view or grab one (cat, base64, an ASCII viewer) routes through the reveal so the
// payoff is the same regardless of the tool, and so no read ever yields a "real"
// secret to walk away with.
func (sh *Shell) isLootImage(abs string) bool {
	return sh.p != nil && sh.p.LootPath != "" &&
		strings.HasPrefix(abs, sh.p.LootPath+"/") && hasImageExt(abs)
}

// revealForLoot records the grab as a honeytoken hit and returns the colour-ANSI
// reveal art, LF-terminated; emit() translates newlines to CRLF on the way out.
func (sh *Shell) revealForLoot(kind, abs, cmd string) string {
	sh.s.LogHoneytoken(kind+":"+path.Base(abs), cmd)
	return strings.TrimRight(randomReveal(), "\n") + "\n"
}

// lootImageBytes returns the real image handed over when a bait file is base64'd
// off the box: a Justin Timberlake photo, chosen by the bait's name (the
// crypto/wallet/key stash gets the full-length shot), so an attacker who copies
// the blob and decodes it locally opens a picture of JT rather than any real
// secret. Returns nil if the asset is missing so the caller can fall back to the
// ANSI reveal.
func lootImageBytes(abs string) []byte {
	name := strings.ToLower(path.Base(abs))
	pick := ""
	for _, kw := range []string{"wallet", "seed", "key", "crypto", "coin", "btc"} {
		if strings.Contains(name, kw) {
			pick = "jt4"
			break
		}
	}
	if pick == "" {
		// Spread the generic stash across the headshots deterministically by name, so
		// a given bait file always yields the same picture (coherent on repeated
		// reads) while different files vary.
		gens := []string{"jt3", "jt5", "jt6"}
		var h uint32
		for _, c := range []byte(name) {
			h = h*131 + uint32(c)
		}
		pick = gens[h%uint32(len(gens))]
	}
	b, err := lootArt.ReadFile("loot/" + pick + ".jpg")
	if err != nil {
		return nil
	}
	return b
}

// isInteractive reports whether a command takes over the terminal IO (reads more
// input, streams output, or runs a time-waster) rather than producing a string.
func isInteractive(name string) bool {
	switch name {
	case "top", "htop", "find", "wget", "curl", "vi", "vim", "vim.basic", "nano",
		"crontab", "passwd", "su", "tftp", "ftpget", "ftpput",
		"ssh", "scp", "sftp", "gcc", "cc", "g++", "make",
		"apt", "apt-get", "aptitude", "python", "python2", "python3", "perl",
		"ruby", "sh", "bash", "openssl", "nc", "ncat", "telnet", "mysql",
		"tcpdump", "strace", "ltrace", "tar", "rsync", "pip", "pip3",
		"jp2a", "catimg", "chafa", "img2txt", "asciiview", "aview", "cacaview",
		"vault", "passwords", "pass", "wallet", "balance", "balances",
		"secrets", "keepass", "lpass", "gopass", "bw":
		return true
	}
	return false
}

func (sh *Shell) runInteractive(args []string) int {
	if len(args) == 0 {
		return 0
	}
	switch args[0] {
	case "wget":
		return sh.iWget(args)
	case "curl":
		return sh.iCurl(args)
	case "ssh":
		return sh.iSSH(args)
	case "scp", "sftp":
		return sh.iScp(args)
	case "tftp":
		return sh.iTftp(args)
	case "ftpget", "ftpput":
		return sh.iFtp(args)
	case "su":
		return sh.iSu(args)
	case "sh", "bash":
		return sh.iShExec(args)
	case "python", "python2", "python3", "perl", "ruby":
		return sh.iInterp(args)
	case "gcc", "cc", "g++", "make":
		return sh.iCompile(args)
	case "apt", "apt-get", "aptitude":
		return sh.iApt(args)
	case "pip", "pip3":
		return sh.iPip(args)
	case "rsync":
		return sh.iRsync(args)
	case "passwd":
		return sh.iPasswd(args)
	case "vi", "vim", "vim.basic", "nano":
		return sh.iEditor(args)
	case "crontab":
		return sh.iCrontab(args)
	case "find":
		return sh.iFind(args)
	case "top", "htop":
		return sh.iTop(args)
	case "mysql":
		return sh.iMysql(args)
	case "tar":
		return sh.iTar(args)
	case "jp2a", "catimg", "chafa", "img2txt", "asciiview", "aview", "cacaview":
		return sh.iAsciiView(args)
	case "vault", "passwords", "pass", "wallet", "balance", "balances",
		"secrets", "keepass", "lpass", "gopass", "bw":
		return sh.iVault(args)
	default:
		sh.pause(time.Second)
		sh.s.Writeln(args[0] + ": terminated")
		return 1
	}
}

// pause sleeps unless the test harness has enabled fast mode.
func (sh *Shell) pause(d time.Duration) {
	// Skip the realism sleep in fast mode (tests) and when driving a non-terminal
	// capture (an HTTP RCE): no one is watching a live terminal there, and the
	// accumulated pauses would push the response past a scanner's timeout.
	if server.FastMode() || (sh.s != nil && sh.s.Capturing()) {
		return
	}
	time.Sleep(d)
}

func wgetURL(args []string) string {
	if u := util.ExtractURL(args); u != "" {
		return u
	}
	for _, a := range args[1:] {
		if !strings.HasPrefix(a, "-") {
			return a
		}
	}
	return ""
}

func (sh *Shell) iWget(args []string) int {
	url := wgetURL(args)
	if url == "" {
		sh.s.Writeln("wget: missing URL")
		return 1
	}
	host := util.ExtractHost(url)
	file := path.Base(url)
	if file == "" || file == "/" || file == "." {
		file = "index.html"
	}
	// Honour -O <name> / -O<name>; -O- (or -O -) means "to stdout", which in the
	// classic `wget -O- url | sh` loader is the pipe's job, so nothing lands.
	toStdout := false
	for i := 1; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-O" && i+1 < len(args):
			file = args[i+1]
		case strings.HasPrefix(a, "-O") && len(a) > 2:
			file = a[2:]
		}
	}
	if file == "-" {
		toStdout = true
	}
	ip := fakeResolveIP(host)
	size := fakeDownloadSize(url)
	dur := downloadDur(size)
	sh.s.LogDownload(strings.Join(args, " "), url, host, file)
	sh.s.Writeln("--" + time.Now().Format("2006-01-02 15:04:05") + "--  " + url)
	sh.s.Writeln("Resolving " + host + " (" + host + ")... " + ip)
	sh.s.Writeln("Connecting to " + host + " (" + host + ")|" + ip + "|:80... connected.")
	sh.s.Writeln("HTTP request sent, awaiting response... 200 OK")
	sh.s.Writeln(fmt.Sprintf("Length: %d (%s) [application/octet-stream]", size, humanBytes(size)))
	if toStdout {
		// Output "goes to stdout"; in a pipe the next stage consumes it. We emit
		// nothing and never connect - the download intent is already captured.
		sh.pause(dur)
		return 0
	}
	sh.s.Writeln("Saving to: '" + file + "'")
	sh.s.Writeln("")
	sh.s.SlowProgress(file+"  "+humanBytes(size), dur)
	sh.s.Writeln("")
	sh.s.Writeln(fmt.Sprintf("%s (%s) - '%s' saved [%d/%d]",
		time.Now().Format("2006-01-02 15:04:05"), downloadRate(size, dur), file, size, size))
	// The fetch "succeeds": an inert payload lands in the overlay so the file
	// survives ls/cat/file and a follow-up chmod +x && ./run (captured as exec).
	// Nothing was actually fetched; no outbound connection is ever made.
	_ = sh.fs.WriteFile(sh.fs.Resolve(file), droppedPayload(file))
	return 0
}

func (sh *Shell) iCurl(args []string) int {
	url := wgetURL(args)
	host := util.ExtractHost(url)
	toFile := false
	name := ""
	for i := 1; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-O":
			toFile, name = true, path.Base(url)
		case a == "-o" && i+1 < len(args):
			toFile, name = true, args[i+1]
		case strings.HasPrefix(a, "-o") && len(a) > 2:
			toFile, name = true, a[2:]
		}
	}
	if url != "" {
		sh.s.LogDownload(strings.Join(args, " "), url, host, path.Base(url))
	}
	if toFile {
		if name == "" || name == "." || name == "/" {
			name = "index.html"
		}
		size := fakeDownloadSize(url)
		dur := downloadDur(size)
		sh.s.SlowProgress("  % Total    % Received % Xferd  Average Speed", dur)
		sh.s.Writeln(fmt.Sprintf("100 %d  100 %d    0     0  %dk      0 --:--:-- --:--:-- --:--:-- %dk",
			size, size, size/1024, size/1024))
		// Lands like wget: an inert payload in the overlay, no outbound connection.
		_ = sh.fs.WriteFile(sh.fs.Resolve(name), droppedPayload(name))
		return 0
	}
	sh.pause(2 * time.Second)
	sh.s.Writeln("curl: (56) Recv failure: Connection reset by peer")
	return 56
}

func (sh *Shell) iSSH(args []string) int {
	target, user := "", "root"
	for _, a := range args[1:] {
		if !strings.HasPrefix(a, "-") {
			target = a
			break
		}
	}
	host := target
	if at := strings.IndexByte(target, '@'); at >= 0 {
		user = target[:at]
		host = target[at+1:]
	}
	if host == "" {
		sh.s.Writeln("usage: ssh [user@]hostname")
		return 255
	}
	sh.s.Writeln("The authenticity of host '" + host + " (" + host + ")' can't be established.")
	sh.s.Writeln("ED25519 key fingerprint is " + sh.p.SSHKeyFP + ".")
	sh.s.Writeln("This key is not known by any other names.")
	ans, ok := sh.s.Prompt("Are you sure you want to continue connecting (yes/no/[fingerprint])? ")
	if !ok {
		return 255
	}
	if strings.TrimSpace(ans) != "yes" {
		sh.s.Writeln("Host key verification failed.")
		return 255
	}
	sh.s.Writeln("Warning: Permanently added '" + host + "' (ED25519) to the list of known hosts.")
	pass, _ := sh.s.ReadPassword(user + "@" + host + "'s password: ")
	sh.s.Writeln("")
	sh.s.LogCredential(user, pass)
	if sh.pivot != nil {
		if piv, ok := sh.pivot(host); ok {
			// The pivoted (NAS) shell gets no resolver, so it cannot pivot onward.
			// Without this single-hop bound an attacker could ssh to the backup host
			// from the backup host repeatedly, nesting newShell().loop() frames until
			// the goroutine stack overflows - a fatal crash that bypasses the
			// per-shell exec-depth guard.
			nested := newShell(sh.s, piv.FS, piv.P, "root", sh.style, nil)
			defer nested.fs.Release()
			nested.welcome()
			nested.loop()
			return 0
		}
	}
	sh.pause(2 * time.Second)
	sh.s.Writeln("ssh: connect to host " + host + " port 22: Connection timed out")
	return 255
}

// iScp simulates a successful scp transfer. It never connects anywhere - every
// byte of this is local theatre - so an attacker exfiltrating to their own box
// sees it "work" while no data ever leaves, and the destination, credential, and
// source are captured as exfil intent. The same applies to rsync below; faking
// success keeps them productive and revealing instead of bailing on a tarpit.
func (sh *Shell) iScp(args []string) int {
	remote, local := "", ""
	for _, a := range args[1:] {
		if strings.HasPrefix(a, "-") {
			continue
		}
		if strings.Contains(a, ":") {
			remote = a
		} else {
			local = a
		}
	}
	if remote == "" {
		sh.s.Writeln("usage: scp [options] source target")
		return 1
	}
	host := remote
	if at := strings.IndexByte(remote, '@'); at >= 0 {
		host = remote[at+1:]
	}
	host = strings.SplitN(host, ":", 2)[0]
	pass, _ := sh.s.ReadPassword(remoteUser(remote, sh.user) + "@" + host + "'s password: ")
	sh.s.LogCredential("scp:"+host, pass)
	sh.s.LogCommandNote("scp "+local+" -> "+remote, "exfil")
	sh.pause(900 * time.Millisecond)
	name := path.Base(local)
	if name == "" || name == "." {
		name = "archive.tar"
	}
	sh.s.Writeln(name + "                                100%   85KB   4.2MB/s   00:00")
	return 0
}

func (sh *Shell) iRsync(args []string) int {
	remote, local := "", ""
	for _, a := range args[1:] {
		if strings.HasPrefix(a, "-") {
			continue
		}
		if strings.Contains(a, ":") {
			remote = a
		} else {
			local = a
		}
	}
	// Pushing to a remote over ssh may prompt for a password; capture it.
	if strings.Contains(remote, ":") {
		host := remote
		if at := strings.IndexByte(remote, '@'); at >= 0 {
			host = remote[at+1:]
		}
		host = strings.SplitN(host, ":", 2)[0]
		pass, _ := sh.s.ReadPassword(remoteUser(remote, sh.user) + "@" + host + "'s password: ")
		sh.s.LogCredential("rsync:"+host, pass)
		sh.s.LogCommandNote("rsync "+local+" -> "+remote, "exfil")
	}
	sh.pause(900 * time.Millisecond)
	sh.s.Writeln("sending incremental file list")
	src := strings.TrimPrefix(path.Clean(local), "/")
	if src == "" || src == "." {
		src = "data"
	}
	sh.s.Writeln(src + "/")
	sh.pause(400 * time.Millisecond)
	sh.s.Writeln("")
	sh.s.Writeln("sent 4,231,109 bytes  received 4,096 bytes  2,823,470.00 bytes/sec")
	sh.s.Writeln("total size is 4,225,560  speedup is 1.00")
	return 0
}

// remoteUser returns the user in a user@host[:path] spec, or def if none is given.
func remoteUser(remote, def string) string {
	if at := strings.IndexByte(remote, '@'); at >= 0 {
		return remote[:at]
	}
	return def
}

func (sh *Shell) iShExec(args []string) int {
	for i := 1; i < len(args); i++ {
		if args[i] == "-c" && i+1 < len(args) {
			inner := args[i+1]
			sh.s.LogExec(args[0]+" -c: "+inner, "")
			sh.runLine(inner)
			return sh.last
		}
	}
	if len(args) > 1 && !strings.HasPrefix(args[1], "-") {
		// `sh dropper` runs a file the attacker assembled in place: capture its
		// reconstructed content as a dropper indicator before logging the exec.
		sh.captureDropper(args[1], args[0]+" "+args[1])
		sh.s.LogExec(args[0]+" "+args[1], "")
		sh.pause(1500 * time.Millisecond)
		sh.s.Writeln("Killed")
		return 137
	}
	return 0
}

// fakeResolveIP returns a stable, plausible routable IP for a host, derived from
// its name so the same host always resolves the same way and different hosts differ.
// It stays out of the reserved ranges a real resolver never returns for an internet
// host: resolving an attacker's own C2 to a TEST-NET address is an obvious tell.
func fakeResolveIP(host string) string {
	h := fnv32(host)
	firsts := []int{45, 104, 138, 159, 172, 185, 193, 194} // common hosting first octets
	return fmt.Sprintf("%d.%d.%d.%d",
		firsts[int(h)%len(firsts)], int(h>>8)%256, int(h>>16)%256, int(h>>24)%254+1)
}

// fakeDownloadSize returns a stable, plausible payload size for a URL, so two
// fetches are never byte-identical and the size varies with what is being pulled.
func fakeDownloadSize(url string) int { return 24000 + int(fnv32(url)%940000) }

// downloadDur is how long the fake transfer appears to take: proportional to size
// but short and capped, because a small file that stalls for minutes while claiming
// a fast rate is itself the tell (a real 85K fetch is near-instant).
func downloadDur(size int) time.Duration {
	d := time.Duration(size/400000) * time.Second
	if d < 300*time.Millisecond {
		d = 300 * time.Millisecond
	}
	if d > 5*time.Second {
		d = 5 * time.Second
	}
	return d
}

// downloadRate reports a transfer rate consistent with the size and duration shown,
// so the reported speed cannot contradict the elapsed time.
func downloadRate(size int, d time.Duration) string {
	bps := float64(size) / d.Seconds()
	if bps >= 1<<20 {
		return fmt.Sprintf("%.2f MB/s", bps/(1<<20))
	}
	return fmt.Sprintf("%.0f KB/s", bps/1024)
}

func humanBytes(n int) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1fM", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%dK", n/1024)
	default:
		return strconv.Itoa(n)
	}
}

func fnv32(s string) uint32 {
	h := uint32(2166136261)
	for i := 0; i < len(s); i++ {
		h = (h ^ uint32(s[i])) * 16777619
	}
	return h
}

// interpVersion answers a version probe (--version / -V / -v) for a scripting
// interpreter with a version string from the same Ubuntu release as the persona,
// so `python3 --version` and friends do not segfault the way a payload run does.
// A prober enumerates the toolchain in the first minute; an interpreter that is
// "installed" yet fails even a version check is a conclusive tell.
func interpVersion(p *persona.Persona, args []string) (string, bool) {
	probe := false
	for _, a := range args[1:] {
		if a == "--version" || a == "-V" || a == "-v" {
			probe = true
		}
	}
	if !probe {
		return "", false
	}
	switch {
	case strings.HasPrefix(args[0], "python"):
		return "Python " + p.PythonVersion(), true
	case args[0] == "perl":
		return "\nThis is perl 5, version " + p.PerlSubversion() + ", subversion 0 (v5." + p.PerlSubversion() + ".0) built for x86_64-linux-gnu-thread-multi\n\n" +
			"Copyright 1987-2022, Larry Wall\n", true
	case args[0] == "ruby":
		return "ruby " + p.RubyVersion() + " (2021-07-07 revision 0db68f0233) [x86_64-linux-gnu]", true
	case args[0] == "node" || args[0] == "nodejs":
		return p.NodeVersion(), true
	case args[0] == "php":
		return "PHP " + p.PHPVersion() + " (cli) (built: Feb 25 2022 16:14:04) (NTS)", true
	}
	return "", false
}

func (sh *Shell) iInterp(args []string) int {
	if v, ok := interpVersion(sh.p, args); ok {
		sh.s.Writeln(v)
		return 0
	}
	full := strings.Join(args, " ")
	code := ""
	for i := 1; i < len(args); i++ {
		if (args[i] == "-c" || args[i] == "-e") && i+1 < len(args) {
			code = args[i+1]
		}
	}
	exec := strings.Contains(code, "urllib") || strings.Contains(code, "requests") ||
		strings.Contains(code, "socket") || strings.Contains(full, "http://") ||
		strings.Contains(full, "https://") || strings.Contains(code, "exec") ||
		strings.Contains(code, "system")
	if exec {
		sh.s.LogExec(full, "")
	} else {
		sh.s.LogDownload(full, util.ExtractURL(args), "", "")
	}
	sh.pause(2 * time.Second)
	sh.s.Writeln(args[0] + ": Segmentation fault (core dumped)")
	return 139
}

// iTftp emulates the tftp client BusyBox loaders reach for as a fetch fallback when
// wget/curl are absent. It logs the fetch as a download attempt, so the staging
// host surfaces on the Payloads page, and reports the silent success a real `-g`
// transfer gives, fetching nothing.
func (sh *Shell) iTftp(args []string) int {
	var host string
	for _, a := range args[1:] {
		if !strings.HasPrefix(a, "-") {
			host = a // the host trails the flags; the last bare token wins
		}
	}
	sh.s.LogDownload(strings.Join(args, " "), "", host, "")
	sh.pause(time.Second)
	return 0
}

// iFtp emulates ftpget/ftpput, the other BusyBox fetch verbs. ftpget HOST LOCAL
// REMOTE pulls a stage; we log the attempt with the host and report silent success.
func (sh *Shell) iFtp(args []string) int {
	host := ""
	if len(args) > 1 && !strings.HasPrefix(args[1], "-") {
		host = args[1]
	}
	sh.s.LogDownload(strings.Join(args, " "), "", host, "")
	sh.pause(time.Second)
	return 0
}

// iSu emulates su: it prompts for a password and captures it (loaders try su with a
// known password such as the Hajime/zyad markers), then returns to the shell as the
// requested user. The session is already root, so this is a silent success and
// nothing actually escalates.
func (sh *Shell) iSu(args []string) int {
	target := "root"
	for i := 1; i < len(args); i++ {
		if !strings.HasPrefix(args[i], "-") {
			target = args[i]
			break
		}
	}
	pass, _ := sh.s.ReadPassword("Password: ")
	sh.s.LogCredential(target, pass)
	sh.pause(time.Second)
	return 0
}

func (sh *Shell) cmdBase64(args []string, stdin string) (string, int) {
	decode := false
	var file string
	for _, a := range args[1:] {
		switch {
		case a == "-d" || a == "--decode" || a == "-D":
			decode = true
		case strings.HasPrefix(a, "-"):
			// ignore other flags such as -w0
		default:
			file = a
		}
	}
	// Reading a file serves its exact bytes, so base64 is a faithful exfil channel
	// that (unlike cat) does not corrupt binary over the terminal. The exception is
	// a bait image: there it serves the reveal art instead, so an attacker who
	// base64s one and decodes it locally reconstructs the colour-ANSI payoff rather
	// than walking away with a "real" secret.
	var data []byte
	if file != "" {
		abs := sh.fs.Resolve(file)
		b, err := sh.fs.ReadFile(abs)
		if err != nil {
			return "base64: " + file + ": No such file or directory\n", 1
		}
		data = b
		if sh.isLootImage(abs) {
			// base64 is the exfil channel: hand over the real bytes of a Justin
			// Timberlake photo, so an attacker who copies the blob and decodes it
			// locally opens a picture of JT instead of any real secret. The grab is
			// still logged as a honeytoken; the on-box paths (cat, image viewers, the
			// vault command) keep rendering the ANSI reveal immediately.
			sh.s.LogHoneytoken("loot-grab:"+path.Base(abs), "base64 "+file)
			if img := lootImageBytes(abs); img != nil {
				data = img
			} else {
				data = []byte(strings.TrimRight(randomReveal(), "\n") + "\n")
			}
		}
	} else {
		data = []byte(stdin)
	}
	if !decode {
		return base64.StdEncoding.EncodeToString(data) + "\n", 0
	}
	clean := strings.Join(strings.Fields(string(data)), "")
	raw, err := base64.StdEncoding.DecodeString(clean)
	if err != nil {
		return "base64: invalid input\n", 1
	}
	sum := sha256.Sum256(raw)
	preview := string(raw)
	if len(preview) > 1024 {
		preview = preview[:1024]
	}
	sh.s.LogExec("base64 -d: "+preview, hex.EncodeToString(sum[:]))
	if looksLikeCommand(string(raw)) {
		sh.runLine(strings.TrimSpace(string(raw)))
		return "", 0
	}
	return string(raw), 0
}

func looksLikeCommand(s string) bool {
	s = strings.TrimSpace(s)
	for _, p := range []string{"wget", "curl", "sh ", "bash", "/bin/", "chmod", "nc ", "python", "rm "} {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func (sh *Shell) iCompile(args []string) int {
	for _, a := range args[1:] {
		if a == "--version" || a == "-dumpversion" || (a == "-v" && args[0] != "make") {
			switch args[0] {
			case "make":
				sh.s.Writeln("GNU Make 4.3\nBuilt for x86_64-pc-linux-gnu\nCopyright (C) 1988-2020 Free Software Foundation, Inc.")
			case "cc", "gcc":
				sh.s.Writeln("gcc (Ubuntu " + sh.p.GCCPackage() + ") " + sh.p.GCCVersion() + "\nCopyright (C) 2021 Free Software Foundation, Inc.")
			case "g++":
				sh.s.Writeln("g++ (Ubuntu " + sh.p.GCCPackage() + ") " + sh.p.GCCVersion() + "\nCopyright (C) 2021 Free Software Foundation, Inc.")
			default:
				sh.s.Writeln(args[0] + " (Ubuntu " + sh.p.GCCPackage() + ") " + sh.p.GCCVersion())
			}
			return 0
		}
		if a == "-v" && args[0] == "make" {
			sh.s.Writeln("GNU Make 4.3\nBuilt for x86_64-pc-linux-gnu")
			return 0
		}
	}
	sh.s.LogCommandNote(strings.Join(args, " "), "compile-attempt")
	lines := []string{
		"In file included from main.c:3:",
		"main.c: In function 'main':",
		"main.c:23:5: warning: implicit declaration of function 'strlcpy' [-Wimplicit-function-declaration]",
		"net.c:44:12: warning: unused variable 'sock' [-Wunused-variable]",
	}
	for _, l := range lines {
		sh.pause(900 * time.Millisecond)
		sh.s.Writeln(l)
	}
	sh.pause(2 * time.Second)
	sh.s.Writeln("/usr/bin/ld: cannot find -lpthread: No such file or directory")
	sh.s.Writeln("collect2: error: ld returned 1 exit status")
	return 1
}

// iApt fakes a working apt. Installs "succeed" and leave a stub binary in
// /usr/bin (so which/ls/dpkg stay coherent), updates and upgrades complete - the
// box behaves like a healthy, root-owned host so an attacker keeps tooling up and
// revealing what they reach for. Nothing is fetched; no outbound connection is
// made.
func (sh *Shell) iApt(args []string) int {
	sub := ""
	var pkgs []string
	for _, a := range args[1:] {
		if strings.HasPrefix(a, "-") {
			continue
		}
		if sub == "" {
			sub = a
			continue
		}
		pkgs = append(pkgs, a)
	}
	switch sub {
	case "install", "reinstall":
		sh.s.LogCommandNote(strings.Join(args, " "), "apt-install")
		sh.s.Writeln("Reading package lists... Done")
		sh.s.Writeln("Building dependency tree... Done")
		sh.s.Writeln("Reading state information... Done")
		if len(pkgs) == 0 {
			sh.s.Writeln("0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.")
			return 0
		}
		sh.s.Writeln("The following NEW packages will be installed:")
		sh.s.Writeln("  " + strings.Join(pkgs, " "))
		sh.s.Writeln(fmt.Sprintf("0 upgraded, %d newly installed, 0 to remove and 0 not upgraded.", len(pkgs)))
		sh.pause(800 * time.Millisecond)
		for _, pkg := range pkgs {
			sh.s.Writeln("Get:1 http://archive.ubuntu.com/ubuntu " + sh.p.OSCodename() + "/universe amd64 " + pkg + " amd64 1.0-1 [1,024 kB]")
		}
		sh.s.Writeln("Fetched 1,024 kB in 1s (980 kB/s)")
		sh.pause(600 * time.Millisecond)
		for _, pkg := range pkgs {
			sh.s.Writeln("Selecting previously unselected package " + pkg + ".")
			sh.s.Writeln("Unpacking " + pkg + " (1.0-1) ...")
			sh.s.Writeln("Setting up " + pkg + " (1.0-1) ...")
			_ = sh.fs.WriteFile(sh.fs.Resolve("/usr/bin/"+pkg), elfStub())
		}
		sh.s.Writeln("Processing triggers for man-db (" + sh.p.ManDBVersion() + ") ...")
		return 0
	case "update":
		sh.s.Writeln("Hit:1 http://archive.ubuntu.com/ubuntu " + sh.p.OSCodename() + " InRelease")
		sh.s.Writeln("Get:2 http://archive.ubuntu.com/ubuntu " + sh.p.OSCodename() + "-updates InRelease [119 kB]")
		sh.pause(700 * time.Millisecond)
		sh.s.Writeln("Fetched 119 kB in 1s (140 kB/s)")
		sh.s.Writeln("Reading package lists... Done")
		sh.s.Writeln("Building dependency tree... Done")
		sh.s.Writeln("All packages are up to date.")
		return 0
	case "upgrade", "full-upgrade", "dist-upgrade":
		sh.s.Writeln("Reading package lists... Done")
		sh.s.Writeln("Building dependency tree... Done")
		sh.s.Writeln("Calculating upgrade... Done")
		sh.s.Writeln("0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.")
		return 0
	case "remove", "purge", "autoremove":
		sh.s.LogCommandNote(strings.Join(args, " "), "apt-remove")
		sh.s.Writeln("Reading package lists... Done")
		sh.s.Writeln("Building dependency tree... Done")
		for _, pkg := range pkgs {
			sh.s.Writeln("Removing " + pkg + " (1.0-1) ...")
			_ = sh.fs.Remove(sh.fs.Resolve("/usr/bin/" + pkg))
		}
		return 0
	default:
		sh.s.Writeln("E: Invalid operation " + sub)
		return 100
	}
}

// iPip fakes a working pip/pip3. Installs report success; nothing is fetched and
// no outbound connection is made.
func (sh *Shell) iPip(args []string) int {
	sub := ""
	var pkgs []string
	for _, a := range args[1:] {
		if strings.HasPrefix(a, "-") {
			continue
		}
		if sub == "" {
			sub = a
			continue
		}
		pkgs = append(pkgs, a)
	}
	if sub != "install" || len(pkgs) == 0 {
		return 0
	}
	sh.s.LogCommandNote(strings.Join(args, " "), "pip-install")
	for _, pkg := range pkgs {
		sh.s.Writeln("Collecting " + pkg)
		sh.s.Writeln("  Downloading " + pkg + "-1.0.0-py3-none-any.whl (48 kB)")
	}
	sh.pause(800 * time.Millisecond)
	sh.s.Writeln("Installing collected packages: " + strings.Join(pkgs, ", "))
	sh.s.Writeln("Successfully installed " + strings.Join(pkgs, "-1.0.0 ") + "-1.0.0")
	return 0
}

// elfStub is a minimal, inert ELF64 header: enough for `file` to call a dropped
// file an executable and for cat to look binary, with no runnable code in it.
func elfStub() []byte {
	return append([]byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0}, make([]byte, 112)...)
}

// droppedPayload returns plausible inert bytes to "save" for a fetched file, so a
// landed download survives ls/cat/file and a follow-up `./run`. Script extensions
// get a tiny script; everything else gets the ELF stub.
func droppedPayload(name string) []byte {
	low := strings.ToLower(name)
	if strings.HasSuffix(low, ".sh") || strings.HasSuffix(low, ".py") ||
		strings.HasSuffix(low, ".pl") || strings.HasSuffix(low, ".rb") {
		return []byte("#!/bin/sh\n# fetched\n")
	}
	return elfStub()
}

func (sh *Shell) iPasswd(args []string) int {
	user := sh.user
	if len(args) > 1 && !strings.HasPrefix(args[1], "-") {
		user = args[1]
	}
	sh.s.Writeln("Changing password for " + user + ".")
	cur, _ := sh.s.ReadPassword("Current password: ")
	sh.s.LogCredential(user, cur)
	n1, _ := sh.s.ReadPassword("New password: ")
	n2, _ := sh.s.ReadPassword("Retype new password: ")
	sh.s.LogCommandNote("passwd new="+n1+" retype="+n2, "password-change")
	sh.pause(time.Second)
	sh.s.Writeln("passwd: password updated successfully")
	return 0
}

func (sh *Shell) iEditor(args []string) int {
	target := "file"
	if len(args) > 1 && !strings.HasPrefix(args[len(args)-1], "-") {
		target = args[len(args)-1]
	}
	body, saved := sh.runEditor(target)
	sh.s.LogCommandNote("editor("+target+"): "+strings.ReplaceAll(body, "\n", "\\n"), "editor-input")
	// A saved edit to a named, non-system file persists in the overlay, so a later
	// cat shows it back - the attacker's change "sticks" for the session.
	if saved && target != "file" {
		if abs := sh.fs.Resolve(target); !inSystemBin(abs) {
			content := body
			if content != "" {
				content += "\n"
			}
			_ = sh.fs.WriteFile(abs, []byte(content))
		}
	}
	return 0
}

// runEditor drives the fake vi/nano screen, capturing every line typed until a
// write-and-quit (:wq/:x/ZZ) or a quit-without-saving (:q). It returns the
// captured body (the quit command itself excluded) and whether it was saved.
func (sh *Shell) runEditor(target string) (string, bool) {
	sh.s.Write("\r\n\r\n")
	for i := 0; i < 6; i++ {
		sh.s.Writeln("~")
	}
	sh.s.Writeln("~                              VIM - Vi IMproved")
	sh.s.Writeln("~")
	sh.s.Writeln("\"" + target + "\" [New File]")
	sh.s.IdleTimeout = 5 * time.Minute
	var typed []string
	for {
		line, ok := sh.s.ReadLine()
		if !ok {
			return strings.Join(typed, "\n"), false
		}
		switch strings.TrimSpace(line) {
		case ":wq", ":x", "ZZ", ":wq!":
			sh.s.Writeln("\"" + target + "\" written")
			return strings.Join(typed, "\n"), true
		case ":q!", ":q":
			return strings.Join(typed, "\n"), false
		default:
			typed = append(typed, line)
		}
	}
}

// iCrontab fakes a working crontab. An install via -e or a file persists in the
// session, so crontab -l echoes the attacker's entry straight back - their
// persistence "took". It is captured as a high-signal persistence event.
func (sh *Shell) iCrontab(args []string) int {
	for i := 1; i < len(args); i++ {
		switch {
		case args[i] == "-l":
			if strings.TrimSpace(sh.cron) == "" {
				sh.s.Writeln("no crontab for " + sh.user)
				return 0
			}
			for _, line := range strings.Split(strings.TrimRight(sh.cron, "\n"), "\n") {
				sh.s.Writeln(line)
			}
			return 0
		case args[i] == "-r":
			sh.cron = ""
			return 0
		case args[i] == "-e":
			body, saved := sh.runEditor("/tmp/crontab." + sh.user)
			if saved {
				sh.cron = body
				sh.s.LogCommandNote("crontab installed:\\n"+strings.ReplaceAll(body, "\n", "\\n"), "persistence")
			}
			return 0
		case args[i] == "-u" && i+1 < len(args):
			i++ // skip the target user
		case !strings.HasPrefix(args[i], "-"):
			// crontab <file>: install the crontab from a file.
			if data, err := sh.fs.ReadFile(sh.fs.Resolve(args[i])); err == nil {
				sh.cron = string(data)
				sh.s.LogCommandNote("crontab installed from "+args[i]+":\\n"+strings.ReplaceAll(string(data), "\n", "\\n"), "persistence")
			}
			return 0
		}
	}
	sh.s.Writeln("no crontab for " + sh.user)
	return 0
}

func (sh *Shell) iFind(args []string) int {
	start := "."
	for _, a := range args[1:] {
		if !strings.HasPrefix(a, "-") {
			start = a
			break
		}
	}
	abs := sh.fs.Resolve(start)
	count := 0
	deadline := time.Now().Add(5 * time.Minute)
	sh.walkFind(abs, &count, deadline)
	return 0
}

func (sh *Shell) walkFind(dir string, count *int, deadline time.Time) {
	if *count > 5000 || time.Now().After(deadline) {
		return
	}
	sh.s.Writeln(dir)
	*count++
	entries, err := sh.fs.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		// Re-check the bound on every entry, not just at recursion entry: a single
		// wide directory would otherwise run its whole loop (one 40-160ms pause each)
		// and overshoot the 5-minute cap by minutes.
		if *count > 5000 || time.Now().After(deadline) {
			return
		}
		if !server.FastMode() {
			sh.pause(util.RandomDelay(40, 160))
		}
		child := dir + "/" + e.Name()
		child = strings.ReplaceAll(child, "//", "/")
		if e.IsDir() {
			sh.walkFind(child, count, deadline)
		} else {
			sh.s.Writeln(child)
			*count++
		}
	}
}

func (sh *Shell) iTop(args []string) int {
	up := uptimeOf(sh.p)
	days := int(up.Hours()) / 24
	// Tasks and the load average must agree with what ps and uptime/w report, or the
	// three contradict each other. Task total is the process-table length (the same
	// list ps aux prints); load reuses uptime's formula; memory reuses free's totals.
	total, used, free, buff, avail := memNumbers(sh.p)
	toMiB := func(kib int) float64 { return float64(kib) / 1024 }
	tasks := len(procTable(sh.p))
	sh.s.Writeln(fmt.Sprintf("top - %s up %d days, %2d:%02d,  1 user,  load average: 0.%02d, 0.%02d, 0.%02d",
		time.Now().Format("15:04:05"), days, int(up.Hours())%24, int(up.Minutes())%60,
		8+days%30, 12+days%20, 5+days%15))
	sh.s.Writeln(fmt.Sprintf("Tasks: %3d total,   1 running, %3d sleeping,   0 stopped,   0 zombie", tasks, tasks-1))
	sh.s.Writeln("%Cpu(s):  2.3 us,  0.7 sy,  0.0 ni, 96.8 id,  0.2 wa,  0.0 hi,  0.0 si")
	sh.s.Writeln(fmt.Sprintf("MiB Mem : %8.1f total, %8.1f free, %8.1f used, %8.1f buff/cache",
		toMiB(total), toMiB(free), toMiB(used), toMiB(buff)))
	sh.s.Writeln(fmt.Sprintf("MiB Swap:   2048.0 total,   1964.0 free,     84.0 used. %8.1f avail Mem", toMiB(avail)))
	sh.s.Writeln("")
	sh.s.Writeln("    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND")
	sh.s.Writeln("    611 mysql     20   0 1820400 184220  18120 S   3.0   4.6   8:42.11 mysqld")
	sh.s.Writeln("    880 www-data  20   0  294500  43120  29800 S   0.7   1.1   0:33.40 php-fpm")
	sh.s.Writeln("    720 www-data  20   0  209360  25240  16080 S   0.3   0.6   0:11.02 nginx")
	sh.pause(2 * time.Second)
	sh.s.Writeln("")
	return 0
}

func (sh *Shell) iMysql(args []string) int {
	for _, a := range args[1:] {
		if strings.HasPrefix(a, "-p") && len(a) > 2 {
			sh.s.LogCredential("mysql", a[2:])
		}
	}
	if hasFlag(args, "-p") {
		pass, _ := sh.s.ReadPassword("Enter password: ")
		sh.s.LogCredential("mysql", pass)
	}
	sh.pause(time.Second)
	sh.s.Writeln("ERROR 2002 (HY000): Can't connect to MySQL server on '" + sh.p.DBIP + "' (110)")
	return 1
}

func (sh *Shell) iTar(args []string) int {
	create := false
	extract := false
	for _, a := range args[1:] {
		if strings.HasPrefix(a, "-") || len(a) <= 4 {
			if strings.Contains(a, "c") {
				create = true
			}
			if strings.Contains(a, "x") {
				extract = true
			}
		}
	}
	if extract {
		sh.pause(2 * time.Second)
		sh.s.Writeln("tar: Error opening archive: Failed to open the archive")
		return 1
	}
	if create {
		sh.pause(2 * time.Second)
	}
	return 0
}

// iAsciiView renders an image file to the terminal as ASCII art. It is the
// natural thing an attacker reaches for when cat just dumps binary, and on a
// bait image it returns the embedded portrait.
func (sh *Shell) iAsciiView(args []string) int {
	var img string
	for _, a := range args[1:] {
		if !strings.HasPrefix(a, "-") {
			img = a
		}
	}
	if img == "" {
		sh.s.Writeln(args[0] + ": no input file specified")
		return 1
	}
	if _, err := sh.fs.Stat(sh.fs.Resolve(img)); err != nil {
		sh.s.Writeln(args[0] + ": " + img + ": No such file or directory")
		return 1
	}
	low := strings.ToLower(img)
	if !(strings.HasSuffix(low, ".jpg") || strings.HasSuffix(low, ".jpeg") ||
		strings.HasSuffix(low, ".png") || strings.HasSuffix(low, ".gif") ||
		strings.HasSuffix(low, ".bmp")) {
		sh.s.Writeln(args[0] + ": " + img + ": unrecognized image format")
		return 1
	}
	sh.s.LogHoneytoken("ascii-view:"+path.Base(img), strings.Join(args, " "))
	for _, line := range strings.Split(strings.TrimRight(randomReveal(), "\n"), "\n") {
		sh.s.Writeln(line)
	}
	return 0
}

// iVault is a honeytoken: a fake password vault / wallet that an attacker runs
// expecting credentials or balances. Running it is captured as a high-signal
// event, and the "secret" it reveals is the embedded portrait.
func (sh *Shell) iVault(args []string) int {
	sh.s.LogHoneytoken("vault:"+args[0], strings.Join(args, " "))
	switch args[0] {
	case "wallet", "balance", "balances", "bw":
		sh.s.Writeln("Connecting to wallet daemon at 127.0.0.1:8332 ...")
		sh.pause(700 * time.Millisecond)
		sh.s.Writeln("Decrypting keystore ...")
	default:
		sh.s.Writeln("Unlocking vault ...")
		sh.pause(700 * time.Millisecond)
		sh.s.Writeln("Master password accepted. Rendering entry ...")
	}
	sh.pause(900 * time.Millisecond)
	sh.s.Writeln("")
	for _, line := range strings.Split(strings.TrimRight(randomReveal(), "\n"), "\n") {
		sh.s.Writeln(line)
	}
	return 0
}

func hasFlag(args []string, flag string) bool {
	for _, a := range args[1:] {
		if a == flag {
			return true
		}
	}
	return false
}
