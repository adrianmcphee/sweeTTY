// Package shell is the fake interactive shell presented over telnet (and any
// other protocol that wants a Linux prompt). It is backed by the virtual
// filesystem, so ls/cat/cd/find never disagree, and it is driven by the instance
// persona, so identity and system output are this host's own. It is a tarpit, not
// a sandbox: it records what an attacker tries (commands, downloads, payloads)
// and executes none of it. Downloads fetch nothing, mutations land only in the
// per-session overlay, and no real host resource is ever read.
package shell

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"sweetty/internal/persona"
	"sweetty/internal/server"
	"sweetty/internal/vfs"
)

// Pivot is a reachable internal host an attacker can ssh into from this shell.
type Pivot struct {
	FS *vfs.FS
	P  *persona.Persona
}

// PivotResolver maps a target host (name or IP) to a pivot, or reports none.
type PivotResolver func(target string) (*Pivot, bool)

// Shell is one interactive session over one host's filesystem.
type Shell struct {
	s         *server.Session
	fs        *vfs.Session
	p         *persona.Persona
	user      string
	style     string
	env       map[string]string
	last      int
	quit      bool
	pivot     PivotResolver
	execDepth int       // re-entry depth for sh -c / base64-decoded commands
	cron      string    // crontab installed this session, so crontab -l echoes what -e/<file> set
	login     time.Time // when this session logged in, so w/who/last/ps show it live from the real source
	// capture, when non-nil, receives command output instead of the terminal, so
	// $(...) and backticks can run a sub-command and read back its stdout.
	capture *strings.Builder
	// expandBudget is the bytes still allowed for one top-level line's variable and
	// command-substitution expansion; subCount counts substitutions in that line.
	// Both bound the amplification a single line can drive (see maxExpandBytes).
	expandBudget int
	subCount     int
}

// maxExpandBytes caps the total bytes one command line may accumulate through
// variable and command substitution, and maxCmdSubs caps how many substitutions
// it may run. Every leaf buffer is already bounded (a file at 2 MiB, a command's
// output at maxCmdOutput), but a single 64 KiB line can hold thousands of
// $(cat big) or $VAR$VAR... repetitions whose results all live in memory at once.
// Without an aggregate cap that multiplies into gigabytes and OOM-kills the whole
// multi-port process, which recover() cannot catch. The cap is shared across the
// line and all its nested substitutions, and reset per top-level line.
const (
	maxExpandBytes = 8 << 20
	maxCmdSubs     = 256
)

// maxExecDepth bounds how deeply a command may re-enter the shell (via `sh -c`,
// `bash -c`, or a base64-decoded command that runs). Without it a self-referential
// payload such as `X='sh -c "$X"'; sh -c "$X"` recurses until the goroutine stack
// overflows — a fatal runtime error that recover() cannot catch and that would take
// the whole multi-port sensor down from one telnet session.
const maxExecDepth = 25

// Run starts an interactive shell on base as user, in the given prompt style.
func Run(s *server.Session, base *vfs.FS, p *persona.Persona, user, style string, pivot PivotResolver) {
	sh := newShell(s, base, p, user, style, pivot)
	defer sh.fs.Release()
	sh.welcome()
	sh.loop()
}

// RunOnce executes a single command line non-interactively, the way `ssh host
// "<cmd>"` runs one command and exits, and returns its exit code so the caller can
// report it as the channel's exit status. It shares the whole interactive machinery
// (parsing, the per-session VFS overlay, download and exec capture) but skips the
// welcome banner and the prompt loop. The caller is responsible for logging the
// command (the SSH exec path tags it as such); this only runs it.
func RunOnce(s *server.Session, base *vfs.FS, p *persona.Persona, user, style string, pivot PivotResolver, line string) int {
	line = strings.TrimSpace(line)
	if line == "" {
		return 0
	}
	sh := newShell(s, base, p, user, style, pivot)
	defer sh.fs.Release()
	sh.s.CmdCount++
	sh.runLine(line)
	if sh.last < 0 {
		return 0
	}
	return sh.last
}

// RunOnceCaptured runs one command line and returns its terminal output as a
// string instead of writing it to the session connection, plus the exit code. The
// side-effect capture (credentials, commands, download attempts, droppers, exec
// attempts) still fires through the logger. It is how a protocol that is not a live
// terminal, an HTTP RCE handler, can drive the same inert shell to record an
// attacker's injected command and produce coherent output without the shell writing
// raw bytes into the HTTP response. It executes nothing real, exactly like RunOnce.
func RunOnceCaptured(s *server.Session, base *vfs.FS, p *persona.Persona, user, style string, pivot PivotResolver, line string) (string, int) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", 0
	}
	sh := newShell(s, base, p, user, style, pivot)
	defer sh.fs.Release()
	sh.s.CmdCount++
	out := s.CaptureOutput(func() { sh.runLine(line) })
	if sh.last < 0 {
		return out, 0
	}
	return out, sh.last
}

func newShell(s *server.Session, base *vfs.FS, p *persona.Persona, user, style string, pivot PivotResolver) *Shell {
	home := "/root"
	if user != "root" {
		home = "/home/" + user
	}
	return &Shell{
		s: s, fs: base.NewSession(home), p: p, user: user, style: style,
		env: defaultEnv(p, user, home), pivot: pivot,
		expandBudget: maxExpandBytes,
		login:        time.Now(),
	}
}

func defaultEnv(p *persona.Persona, user, home string) map[string]string {
	path := "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	if user != "root" {
		path = "/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games"
	}
	return map[string]string{
		"PATH": path, "HOME": home, "USER": user, "LOGNAME": user,
		"SHELL": "/bin/bash", "TERM": "xterm-256color", "HOSTNAME": p.Hostname,
		"PWD": home, "SHLVL": "1", "LANG": "en_US.UTF-8",
	}
}

func (sh *Shell) prompt() string {
	cwd := sh.fs.Cwd()
	home := sh.env["HOME"]
	disp := cwd
	if cwd == home {
		disp = "~"
	} else if home != "/" && strings.HasPrefix(cwd, home+"/") {
		disp = "~" + cwd[len(home):]
	}
	sym := "$"
	if sh.user == "root" {
		sym = "#"
	}
	return fmt.Sprintf("%s@%s:%s%s ", sh.user, sh.p.Hostname, disp, sym)
}

func (sh *Shell) welcome() {
	// PrettyName already begins with "Ubuntu", so do not prepend it again.
	sh.s.SlowWrite("\r\nWelcome to "+sh.p.PrettyName+" (GNU/Linux "+sh.p.KernelRel+" "+sh.p.Arch+")\r\n\r\n", 8*time.Millisecond)
	// The stock 22.04 MOTD header is an invariant triplet; one lone line is a tell.
	sh.s.Writeln(" * Documentation:  https://help.ubuntu.com")
	sh.s.Writeln(" * Management:     https://landscape.canonical.com")
	sh.s.Writeln(" * Support:        https://ubuntu.com/pro")
	sh.s.Writeln("")
	// The previous login must match what `last` reports as the most recent completed
	// session (its second line): ~26h ago from the same source, and relative to now
	// so it advances across reconnects rather than freezing at a boot-relative constant.
	lastWhen := time.Now().Add(-26 * time.Hour)
	sh.s.Writeln("Last login: " + lastWhen.Format("Mon Jan  2 15:04:05 2006") + " from " + sh.p.GatewayIP)
}

func (sh *Shell) loop() {
	sh.s.IdleTimeout = 10 * time.Minute
	for !sh.quit {
		line, ok := sh.s.Prompt(sh.prompt())
		if !ok {
			return
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		sh.s.CmdCount++
		sh.s.LogCommand(line)
		sh.runLine(line)
	}
}

func (sh *Shell) runLine(line string) {
	if sh.execDepth == 0 {
		// Fresh top-level line: refill the shared expansion budget. Nested lines run
		// by $(...) do not reset it, so a line and all its substitutions share one cap.
		sh.expandBudget = maxExpandBytes
		sh.subCount = 0
	}
	if sh.execDepth >= maxExecDepth {
		// Bottom out the way a crashed process does, matching the recover() fallback
		// below — not with a synthetic "maximum nesting level" string, which no real
		// bash emits for sh -c recursion and which would be a honeypot fingerprint.
		sh.s.Writeln("Segmentation fault (core dumped)")
		sh.last = 139
		return
	}
	sh.execDepth++
	defer func() { sh.execDepth-- }()
	defer func() {
		if r := recover(); r != nil {
			sh.s.Writeln("Segmentation fault (core dumped)")
		}
	}()
	stmts := parse(line)
	run := true
	for _, st := range stmts {
		if run {
			sh.runStatement(st)
			if sh.quit {
				return
			}
		}
		switch st.chain {
		case "&&":
			run = sh.last == 0
		case "||":
			run = sh.last != 0
		default:
			run = true
		}
	}
}

func (sh *Shell) runStatement(st statement) {
	if len(st.stages) == 0 {
		return
	}
	// Statement of only assignments sets session env, prints nothing.
	if len(st.stages) == 1 && len(st.stages[0].args) == 0 {
		for k, v := range st.stages[0].assigns {
			sh.env[k] = sh.expand(v) // so VAR=$(cmd) and VAR=$OTHER store the value
		}
		sh.last = 0
		return
	}
	// A pipeline ending in a shell is an execution attempt on the producing stage.
	lastStage := st.stages[len(st.stages)-1]
	if len(st.stages) > 1 && len(lastStage.args) > 0 {
		if b := lastStage.args[0]; b == "sh" || b == "bash" {
			sh.s.LogExec("pipe-to-"+b+": "+stageString(st), "")
			sh.runInteractive(sh.expandStage(st.stages[0]))
			sh.last = 0
			return
		}
	}
	// Single interactive command takes over IO.
	if len(st.stages) == 1 {
		args := sh.expandStage(st.stages[0])
		if len(args) > 0 && isInteractive(args[0]) {
			sh.last = sh.runInteractive(args)
			return
		}
	}
	// Plain pipeline of filters.
	stdin := ""
	code := 0
	for i, stg := range st.stages {
		args := sh.expandStage(stg)
		if len(args) == 0 {
			continue
		}
		var out string
		// apply per-command env assignments transiently (ignored value-wise here)
		out, code = sh.runCommand(args, stdin)
		if i == len(st.stages)-1 {
			sh.emit(stg, out)
		} else {
			stdin = out
		}
	}
	sh.last = code
}

func (sh *Shell) emit(stg stage, out string) {
	if stg.outNull {
		return
	}
	if stg.outFile != "" {
		abs := sh.fs.Resolve(stg.outFile)
		data := []byte(out)
		// `>>` appends: concatenate onto any existing content so an echo-loader that
		// builds a dropper across many appends accumulates it, rather than each write
		// overwriting the last. A fresh copy avoids aliasing the overlay's bytes.
		if stg.appendT {
			if existing, err := sh.fs.ReadFile(abs); err == nil && len(existing) > 0 {
				data = append(append(make([]byte, 0, len(existing)+len(out)), existing...), out...)
			}
		}
		if err := sh.fs.WriteFile(abs, data); errors.Is(err, vfs.ErrNoSpace) {
			// A full overlay reports the same thing a real full disk would, so the
			// tarpit stays believable while the amplification attack dead-ends.
			sh.s.Write("-bash: " + stg.outFile + ": No space left on device\r\n")
		}
		return
	}
	// Inside a $(...) or backtick substitution, output is collected into a buffer
	// the substitution reads back, not written to the terminal (and not CRLF-translated).
	if sh.capture != nil {
		sh.capture.WriteString(sh.takeBudget(out))
		return
	}
	if out == "" {
		return
	}
	if !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	sh.s.Write(strings.ReplaceAll(out, "\n", "\r\n"))
}

func (sh *Shell) expandStage(stg stage) []string {
	out := make([]string, 0, len(stg.args))
	for _, a := range stg.args {
		out = append(out, sh.expand(a))
	}
	return out
}

// takeBudget clamps s to the line's remaining expansion budget and debits it, so
// the total bytes one line accumulates through substitution cannot exceed
// maxExpandBytes however the substitutions are nested or repeated.
func (sh *Shell) takeBudget(s string) string {
	if sh.expandBudget <= 0 {
		return ""
	}
	if len(s) > sh.expandBudget {
		s = s[:sh.expandBudget]
	}
	sh.expandBudget -= len(s)
	return s
}

func (sh *Shell) expand(w string) string {
	if !strings.ContainsAny(w, "$`") {
		return w
	}
	var b strings.Builder
	for i := 0; i < len(w); i++ {
		c := w[i]
		if c == '`' {
			j := i + 1
			for j < len(w) && w[j] != '`' {
				j++
			}
			b.WriteString(sh.cmdSub(w[i+1 : j]))
			i = j // the loop's i++ moves past the closing backtick (or the end)
			continue
		}
		if c != '$' {
			b.WriteByte(c)
			continue
		}
		// $$ is this shell's PID, and it must equal the -bash row ps prints for the
		// session, or `echo $$` contradicts ps.
		if i+1 < len(w) && w[i+1] == '$' {
			b.WriteString(strconv.Itoa(shellPID))
			i++
			continue
		}
		// $((expr)) is arithmetic, checked before $(...) command substitution.
		if i+2 < len(w) && w[i+1] == '(' && w[i+2] == '(' {
			depth := 2
			j := i + 3
			for j < len(w) && depth > 0 {
				switch w[j] {
				case '(':
					depth++
				case ')':
					depth--
				}
				if depth == 0 {
					break
				}
				j++
			}
			// j is at the first ')' of the closing '))'; evaluate the inner expression.
			b.WriteString(strconv.Itoa(sh.evalArith(w[i+3 : j])))
			i = j + 1 // move past both ')'; the loop's i++ steps off the second
			continue
		}
		if i+1 < len(w) && w[i+1] == '(' {
			depth := 1
			j := i + 2
			for j < len(w) {
				if w[j] == '(' {
					depth++
				} else if w[j] == ')' {
					depth--
					if depth == 0 {
						break
					}
				}
				j++
			}
			b.WriteString(sh.cmdSub(w[i+2 : j]))
			i = j // at the matching ')'; the loop's i++ moves past it
			continue
		}
		if i+1 < len(w) && w[i+1] == '?' {
			b.WriteString(strconv.Itoa(sh.last))
			i++
			continue
		}
		if i+1 < len(w) && w[i+1] == '{' {
			if j := strings.IndexByte(w[i+2:], '}'); j >= 0 {
				b.WriteString(sh.takeBudget(sh.getenv(w[i+2 : i+2+j])))
				i = i + 2 + j
				continue
			}
		}
		j := i + 1
		for j < len(w) && (w[j] == '_' || isAlnum(w[j])) {
			j++
		}
		if j > i+1 {
			b.WriteString(sh.takeBudget(sh.getenv(w[i+1 : j])))
			i = j - 1
			continue
		}
		b.WriteByte('$')
	}
	return b.String()
}

// cmdSleep actually pauses, because a `sleep 5` that returns instantly (so
// `time sleep 5` shows 0s) is a plain tell. The delay is capped and interruptible
// via pause, so it cannot be turned into a resource-holding lever by an attacker.
func (sh *Shell) cmdSleep(args []string) string {
	secs := 0.0
	for _, a := range args[1:] {
		if strings.HasPrefix(a, "-") {
			continue
		}
		mult := 1.0
		switch {
		case strings.HasSuffix(a, "m"):
			mult, a = 60, strings.TrimSuffix(a, "m")
		case strings.HasSuffix(a, "h"):
			mult, a = 3600, strings.TrimSuffix(a, "h")
		case strings.HasSuffix(a, "s"):
			a = strings.TrimSuffix(a, "s")
		}
		if v, err := strconv.ParseFloat(a, 64); err == nil {
			secs += v * mult
		}
		break
	}
	if secs <= 0 {
		return ""
	}
	d := time.Duration(secs * float64(time.Second))
	if d > maxSleep {
		d = maxSleep
	}
	sh.pause(d)
	return ""
}

// maxSleep caps how long a sleep will actually block, so the realistic pause never
// becomes a way to pin the session's goroutine for an attacker-chosen duration.
const maxSleep = 10 * time.Second

// evalArith evaluates a bash $((...)) integer expression: + - * / % with
// parentheses and unary sign, bare names and $names resolved from the environment
// (unset is 0), so echo $((1+1)) and echo $((count*2)) behave like bash rather than
// falling through to a "command not found" for the leading $(( token.
func (sh *Shell) evalArith(expr string) int {
	a := &arith{sh: sh, s: expr}
	return a.parseAdd()
}

type arith struct {
	sh  *Shell
	s   string
	pos int
}

func (a *arith) ws() {
	for a.pos < len(a.s) && a.s[a.pos] == ' ' {
		a.pos++
	}
}

func (a *arith) parseAdd() int {
	v := a.parseMul()
	for {
		a.ws()
		if a.pos < len(a.s) && (a.s[a.pos] == '+' || a.s[a.pos] == '-') {
			op := a.s[a.pos]
			a.pos++
			r := a.parseMul()
			if op == '+' {
				v += r
			} else {
				v -= r
			}
			continue
		}
		return v
	}
}

func (a *arith) parseMul() int {
	v := a.parseUnary()
	for {
		a.ws()
		if a.pos < len(a.s) && (a.s[a.pos] == '*' || a.s[a.pos] == '/' || a.s[a.pos] == '%') {
			op := a.s[a.pos]
			a.pos++
			r := a.parseUnary()
			switch {
			case op == '*':
				v *= r
			case r == 0:
				v = 0 // bash errors on divide-by-zero; 0 is a harmless stand-in here
			case op == '/':
				v /= r
			default:
				v %= r
			}
			continue
		}
		return v
	}
}

func (a *arith) parseUnary() int {
	a.ws()
	if a.pos < len(a.s) {
		switch a.s[a.pos] {
		case '-':
			a.pos++
			return -a.parseUnary()
		case '+':
			a.pos++
			return a.parseUnary()
		}
	}
	return a.parsePrimary()
}

func (a *arith) parsePrimary() int {
	a.ws()
	if a.pos < len(a.s) && a.s[a.pos] == '(' {
		a.pos++
		v := a.parseAdd()
		a.ws()
		if a.pos < len(a.s) && a.s[a.pos] == ')' {
			a.pos++
		}
		return v
	}
	if a.pos < len(a.s) && a.s[a.pos] == '$' {
		a.pos++ // $name inside arithmetic behaves like name
	}
	start := a.pos
	for a.pos < len(a.s) && a.s[a.pos] >= '0' && a.s[a.pos] <= '9' {
		a.pos++
	}
	if a.pos > start {
		n, _ := strconv.Atoi(a.s[start:a.pos])
		return n
	}
	for a.pos < len(a.s) && (a.s[a.pos] == '_' || isAlnum(a.s[a.pos])) {
		a.pos++
	}
	if a.pos > start {
		if v, err := strconv.Atoi(a.sh.getenv(a.s[start:a.pos])); err == nil {
			return v
		}
	}
	return 0
}

func (sh *Shell) getenv(name string) string {
	if v, ok := sh.env[name]; ok {
		return v
	}
	return ""
}

// cmdSub runs the inner text of a $(...) or `...` substitution and returns its
// captured stdout the way bash does: trailing newlines stripped, embedded newlines
// folded to spaces (an approximation of unquoted word-splitting that suits the
// recon one-liners attackers run).
func (sh *Shell) cmdSub(inner string) string {
	sh.subCount++
	if sh.subCount > maxCmdSubs || sh.expandBudget <= 0 {
		return ""
	}
	out := sh.runCaptured(inner)
	out = strings.Trim(out, "\n")
	return strings.ReplaceAll(out, "\n", " ")
}

// runCaptured runs a command line with its terminal output redirected into a
// buffer and returns it, for command substitution. It is bounded by the same
// exec-depth guard as any sub-shell so a self-referential $(...) cannot recurse
// without limit.
func (sh *Shell) runCaptured(line string) string {
	if sh.execDepth >= maxExecDepth {
		return ""
	}
	prev := sh.capture
	var buf strings.Builder
	sh.capture = &buf
	sh.runLine(line)
	sh.capture = prev
	return buf.String()
}

func isAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z'
}

func stageString(st statement) string {
	var parts []string
	for _, s := range st.stages {
		parts = append(parts, strings.Join(s.args, " "))
	}
	return strings.Join(parts, " | ")
}

// binDirs are the absolute directories a bare command resolves under, so an
// attacker's /bin/uname or /usr/bin/nproc dispatches to the same handler as uname.
var binDirs = map[string]bool{
	"/bin/": true, "/sbin/": true, "/usr/bin/": true, "/usr/sbin/": true,
	"/usr/local/bin/": true, "/usr/local/sbin/": true,
}

// busyboxAppletList is the applet set this BusyBox advertises. Running `busybox X`
// for a listed applet re-dispatches to the shell's handler; an unlisted name gets
// "applet not found", which is exactly the response a Mirai-class loader probes for
// with `busybox <random>` to confirm BusyBox is present.
var busyboxAppletList = []string{
	"[", "[[", "ash", "awk", "base64", "basename", "cat", "chmod", "chown", "cp",
	"cut", "date", "dd", "df", "dmesg", "echo", "egrep", "env", "false", "fgrep",
	"free", "ftpget", "ftpput", "grep", "gunzip", "gzip", "head", "hostname", "id",
	"ifconfig", "kill", "killall", "ln", "login", "ls", "md5sum", "mkdir", "mount",
	"mv", "nc", "netstat", "nproc", "passwd", "ping", "printf", "ps", "pwd",
	"reboot", "rm", "rmdir", "route", "sed", "sh", "sleep", "sort", "tail", "tar",
	"telnet", "tftp", "top", "touch", "tr", "true", "uname", "uniq", "uptime", "wc",
	"wget", "which", "whoami",
}

var busyboxApplets = func() map[string]bool {
	m := make(map[string]bool, len(busyboxAppletList))
	for _, a := range busyboxAppletList {
		m[a] = true
	}
	return m
}()

// cmdBusybox is the BusyBox multicall entry. No applet prints the banner; a known
// applet re-dispatches to the shell's command for it (so `busybox uname -m` works
// the way a real device's busybox does); an unknown applet returns "applet not
// found" (the Mirai busybox-presence check).
func (sh *Shell) cmdBusybox(args []string) (string, int) {
	if len(args) == 1 {
		return sh.busyboxBanner(), 0
	}
	applet := args[1]
	if i := strings.LastIndexByte(applet, '/'); i >= 0 {
		applet = applet[i+1:]
	}
	if applet == "--list" || applet == "--list-full" {
		return strings.Join(busyboxAppletList, "\n") + "\n", 0
	}
	if busyboxApplets[applet] {
		return sh.runCommand(append([]string{applet}, args[2:]...), "")
	}
	return applet + ": applet not found\n", 127
}

// cmdNproc reports the online CPU count, kept coherent with /proc/cpuinfo by
// counting its processor entries, so the loader's `nproc` and its
// `grep -c "^processor" /proc/cpuinfo` fallback agree.
func (sh *Shell) cmdNproc() string {
	n := 0
	if data, err := sh.fs.ReadFile("/proc/cpuinfo"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "processor") {
				n++
			}
		}
	}
	if n == 0 {
		n = 1
	}
	return strconv.Itoa(n) + "\n"
}

func (sh *Shell) busyboxBanner() string {
	return "BusyBox v" + sh.p.BusyBoxVer + " (Ubuntu 1:" + sh.p.BusyBoxVer + "-2ubuntu1) multi-call binary.\n" +
		"BusyBox is copyright (C) 1998-2022 Erik Andersen, Rob Landley, Denys Vlasenko\n" +
		"and others. Licensed under GPLv2. See source distribution for detailed\n" +
		"copyright notices.\n\n" +
		"Usage: busybox [function [arguments]...]\n" +
		"   or: busybox --list[-full]\n" +
		"   or: function [arguments]...\n\n" +
		"\tBusyBox is a multi-call binary that combines many common Unix\n" +
		"\tutilities into a single executable.  Most people will create a\n" +
		"\tlink to busybox for each function they wish to use and BusyBox\n" +
		"\twill act like whatever it was invoked as.\n\n" +
		"Currently defined functions:\n\t" + strings.Join(busyboxAppletList, ", ") + "\n"
}

// cmdTest implements the [ / test builtin: it evaluates a condition and returns an
// exit code (0 true, 1 false) with no output, so chains like `[ -f X ] && cmd`
// work. It covers the predicates loader recon uses: -f/-d/-e/-s/-r/-w/-x file
// tests, -z/-n string tests, =/!= and -eq..-ge comparisons, a bare non-empty
// string, and a leading ! negation.
func (sh *Shell) cmdTest(args []string) (string, int) {
	a := args[1:]
	if args[0] == "[" {
		if len(a) == 0 || a[len(a)-1] != "]" {
			return "-bash: [: missing `]'\n", 2
		}
		a = a[:len(a)-1]
	}
	neg := false
	if len(a) > 0 && a[0] == "!" {
		neg = true
		a = a[1:]
	}
	res := sh.evalTest(a)
	if neg {
		res = !res
	}
	if res {
		return "", 0
	}
	return "", 1
}

func (sh *Shell) evalTest(a []string) bool {
	switch len(a) {
	case 1:
		return a[0] != "" // [ STR ] is true when STR is non-empty
	case 2:
		op, operand := a[0], a[1]
		switch op {
		case "-f":
			n, err := sh.fs.Stat(operand)
			return err == nil && !n.IsDir()
		case "-d":
			n, err := sh.fs.Stat(operand)
			return err == nil && n.IsDir()
		case "-e", "-r", "-w", "-x":
			return sh.fs.Exists(operand)
		case "-s":
			n, err := sh.fs.Stat(operand)
			return err == nil && n.Size() > 0
		case "-z":
			return operand == ""
		case "-n":
			return operand != ""
		}
	case 3:
		l, op, r := a[0], a[1], a[2]
		switch op {
		case "=", "==":
			return l == r
		case "!=":
			return l != r
		case "-eq", "-ne", "-lt", "-le", "-gt", "-ge":
			li, le := strconv.Atoi(l)
			ri, re := strconv.Atoi(r)
			if le != nil || re != nil {
				return false
			}
			switch op {
			case "-eq":
				return li == ri
			case "-ne":
				return li != ri
			case "-lt":
				return li < ri
			case "-le":
				return li <= ri
			case "-gt":
				return li > ri
			case "-ge":
				return li >= ri
			}
		}
	}
	return false
}

// runCommand dispatches a non-interactive command and returns its stdout and an
// exit code.
func (sh *Shell) runCommand(args []string, stdin string) (string, int) {
	base := args[0]
	// Resolve an absolute /bin, /sbin, /usr/bin, ... path to its command name, the
	// way the loaders' /bin/uname, /usr/bin/nproc, /bin/busybox fallbacks expect.
	if i := strings.LastIndexByte(base, '/'); i >= 0 && binDirs[base[:i+1]] {
		base = base[i+1:]
		args = append([]string{base}, args[1:]...)
	}
	switch base {
	case "exit", "logout":
		// `quit` is deliberately absent: it is not a bash builtin, so it must fall
		// through to the "command not found" path the way a real shell handles it.
		sh.quit = true
		return "logout\n", 0
	case "ls", "dir":
		return sh.cmdLs(args), 0
	case "cat":
		return sh.cmdCat(args)
	case "[", "test":
		return sh.cmdTest(args)
	case "busybox":
		return sh.cmdBusybox(args)
	case "nproc":
		return sh.cmdNproc(), 0
	case "pwd":
		return sh.fs.Cwd() + "\n", 0
	case "cd":
		return sh.cmdCd(args)
	case "echo":
		return sh.cmdEcho(args), 0
	case "whoami":
		return sh.user + "\n", 0
	case "id":
		return sh.cmdId(args), 0
	case "groups":
		return sh.cmdGroups(args)
	case "ping", "ping6":
		return sh.cmdPing(args)
	case "dig", "nslookup", "host":
		return sh.cmdResolve(args)
	case "du":
		return sh.cmdDu(args)
	case "md5sum", "sha1sum", "sha256sum":
		return sh.cmdHashsum(args)
	case "hostname":
		return sh.p.Hostname + "\n", 0
	case "uname":
		return sh.cmdUname(args), 0
	case "head", "tail":
		return sh.cmdHeadTail(args, stdin, base == "tail")
	case "wc":
		return sh.cmdWc(args, stdin)
	case "grep", "egrep", "fgrep":
		return sh.cmdGrep(args, stdin)
	case "which":
		return sh.cmdWhich(args)
	case "env", "printenv":
		return sh.cmdEnv(), 0
	case "stat":
		return sh.cmdStat(args)
	case "file":
		return sh.cmdFile(args), 0
	case "touch", "mkdir", "rm", "rmdir", "cp", "mv", "chmod", "chown", "ln":
		return sh.cmdMutate(args)
	case "export", "unset", "set", "alias", "umask", "complete", "shopt":
		return "", 0
	case "history":
		return sh.cmdHistory(args)
	case "ps":
		return sh.cmdPs(args), 0
	case "free":
		return freeStr(sh.p), 0
	case "df":
		return dfStr(sh.p), 0
	case "uptime":
		return uptimeStr(sh.p), 0
	case "w":
		return wStr(sh.p, sh.user, sh.s.SrcIP, sh.login), 0
	case "who":
		return sh.user + "     pts/0        " + sh.login.Format("Jan _2 15:04") + " (" + sh.s.SrcIP + ")\n", 0
	case "last":
		return lastStr(sh.p, sh.user, sh.s.SrcIP, sh.login), 0
	case "date":
		return time.Now().Format("Mon Jan  2 15:04:05 MST 2006") + "\n", 0
	case "ifconfig":
		return ifconfigStr(sh.p), 0
	case "ip":
		return sh.cmdIP(args), 0
	case "netstat":
		return netstatStr(sh.p), 0
	case "ss":
		return ssStr(sh.p), 0
	case "lscpu":
		return lscpuStr(sh.p), 0
	case "lsblk":
		return lsblkStr(sh.p), 0
	case "mount":
		return mountStr(sh.p), 0
	case "dmesg":
		return dmesgStr(sh.p), 0
	case "systemctl", "service":
		return sh.cmdService(args), 0
	case "dpkg":
		return sh.cmdDpkg(args), 0
	case "sleep":
		return sh.cmdSleep(args), 0
	case "true", ":", "clear", "kill", "killall", "sync", "reset":
		return "", 0
	case "chpasswd", "useradd", "usermod", "userdel", "adduser", "groupadd", "groupdel":
		// Account-management and persistence commands a loader runs after break-in
		// (chpasswd to change root's password, useradd to plant an account). They
		// report the silent success their real counterparts give, so the loader
		// believes it persisted; nothing changes (the overlay is per-session and the
		// real account database is never touched).
		return "", 0
	case "enable", "system", "shell", "linuxshell":
		// Mirai-class loaders fire these "menu escape" tokens the instant they log in,
		// to break out of a restricted IoT CLI into a raw shell. On the appliance persona
		// the escape "succeeds" silently — the device-authentic CLI-to-shell transition —
		// so the loader believes it reached a shell and goes on to its busybox probe,
		// recon, and payload pull, every step of which we already capture. The token
		// itself does nothing: no exec, no fetch, no write, no state change; it is the
		// safest possible builtin. On a server persona, which is already a bash shell and
		// where these are not real commands, they stay "command not found" — coherent.
		if sh.p.IsAppliance() {
			return "", 0
		}
		return "-bash: " + base + ": command not found\n", 127
	case "false":
		return "", 1
	case "sudo":
		if len(args) > 1 {
			return sh.runCommand(args[1:], stdin)
		}
		return "", 0
	case "base64":
		return sh.cmdBase64(args, stdin)
	case "cut":
		return sh.cmdCut(args, stdin), 0
	case "sort":
		return sh.cmdSort(args, stdin), 0
	case "uniq":
		return sh.cmdUniq(args, stdin), 0
	case "tr":
		return sh.cmdTr(args, stdin), 0
	case "awk", "gawk", "mawk":
		return sh.cmdAwk(args, stdin), 0
	case "sed":
		return sh.cmdSed(args, stdin), 0
	case "tee":
		return sh.cmdTee(args, stdin), 0
	case "xargs":
		// xargs builds and runs a command from stdin; running nothing, it passes the
		// input on so a pipe does not break, and the intent is already logged upstream.
		return stdin, 0
	default:
		if strings.HasPrefix(base, "./") || strings.HasPrefix(base, "/") {
			// A dropped or downloaded file that is then run: capture the exec and let
			// it appear to launch and silently background, the way a real dropper does.
			// Scoped away from the coreutils stub dirs so a full path to a real tool
			// (e.g. /bin/ls) is not mistaken for a payload.
			abs := sh.fs.Resolve(base)
			if !inSystemBin(abs) {
				if n, err := sh.fs.Stat(abs); err == nil && !n.IsDir() {
					// The file is the reconstructed payload: capture its content as a
					// dropper indicator, then log the exec attempt.
					if content, rerr := sh.fs.ReadFile(abs); rerr == nil && len(content) > 0 {
						sh.s.LogDropper(abs, strings.Join(args, " "), content)
					}
					sh.s.LogExec(strings.Join(args, " "), "dropped-exec")
					return "", 0
				}
			}
			return "-bash: " + base + ": No such file or directory\n", 127
		}
		return "-bash: " + base + ": command not found\n", 127
	}
}

// captureDropper records the reconstructed content of a file an attacker built on
// the box and is now executing, when it exists in the overlay and is not a system
// tool stub. With nothing fetched over the wire, that content is the actual payload
// and the best indicator the honeypot gets.
func (sh *Shell) captureDropper(path, command string) {
	abs := sh.fs.Resolve(path)
	if inSystemBin(abs) {
		return
	}
	if content, err := sh.fs.ReadFile(abs); err == nil && len(content) > 0 {
		sh.s.LogDropper(abs, command, content)
	}
}

// inSystemBin reports whether abs sits in one of the conventional executable
// directories, where coreutils stubs live. A run of something there is a tool
// invocation, not a dropped payload.
func inSystemBin(abs string) bool {
	for _, d := range []string{"/usr/bin/", "/bin/", "/sbin/", "/usr/sbin/", "/usr/local/bin/", "/usr/local/sbin/"} {
		if strings.HasPrefix(abs, d) {
			return true
		}
	}
	return false
}
