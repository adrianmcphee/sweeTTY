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
	execDepth int    // re-entry depth for sh -c / base64-decoded commands
	cron      string // crontab installed this session, so crontab -l echoes what -e/<file> set
	// capture, when non-nil, receives command output instead of the terminal, so
	// $(...) and backticks can run a sub-command and read back its stdout.
	capture *strings.Builder
}

// maxExecDepth bounds how deeply a command may re-enter the shell (via `sh -c`,
// `bash -c`, or a base64-decoded command that runs). Without it a self-referential
// payload such as `X='sh -c "$X"'; sh -c "$X"` recurses until the goroutine stack
// overflows — a fatal runtime error that recover() cannot catch and that would take
// the whole multi-port sensor down from one telnet session.
const maxExecDepth = 25

// Run starts an interactive shell on base as user, in the given prompt style.
func Run(s *server.Session, base *vfs.FS, p *persona.Persona, user, style string, pivot PivotResolver) {
	sh := newShell(s, base, p, user, style, pivot)
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
	sh.s.CmdCount++
	sh.runLine(line)
	if sh.last < 0 {
		return 0
	}
	return sh.last
}

func newShell(s *server.Session, base *vfs.FS, p *persona.Persona, user, style string, pivot PivotResolver) *Shell {
	home := "/root"
	if user != "root" {
		home = "/home/" + user
	}
	return &Shell{
		s: s, fs: base.NewSession(home), p: p, user: user, style: style,
		env: defaultEnv(p, user, home), pivot: pivot,
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
		if err := sh.fs.WriteFile(sh.fs.Resolve(stg.outFile), []byte(out)); errors.Is(err, vfs.ErrNoSpace) {
			// A full overlay reports the same thing a real full disk would, so the
			// tarpit stays believable while the amplification attack dead-ends.
			sh.s.Write("-bash: " + stg.outFile + ": No space left on device\r\n")
		}
		return
	}
	// Inside a $(...) or backtick substitution, output is collected into a buffer
	// the substitution reads back, not written to the terminal (and not CRLF-translated).
	if sh.capture != nil {
		sh.capture.WriteString(out)
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
				b.WriteString(sh.getenv(w[i+2 : i+2+j]))
				i = i + 2 + j
				continue
			}
		}
		j := i + 1
		for j < len(w) && (w[j] == '_' || isAlnum(w[j])) {
			j++
		}
		if j > i+1 {
			b.WriteString(sh.getenv(w[i+1 : j]))
			i = j - 1
			continue
		}
		b.WriteByte('$')
	}
	return b.String()
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
	case "pwd":
		return sh.fs.Cwd() + "\n", 0
	case "cd":
		return sh.cmdCd(args)
	case "echo":
		return sh.cmdEcho(args), 0
	case "whoami":
		return sh.user + "\n", 0
	case "id":
		if sh.user == "root" {
			return "uid=0(root) gid=0(root) groups=0(root)\n", 0
		}
		return fmt.Sprintf("uid=%d(%s) gid=%d(%s) groups=%d(%s)\n", sh.p.UserUID, sh.user, sh.p.UserUID, sh.user, sh.p.UserUID, sh.user), 0
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
		return wStr(sh.p, sh.user), 0
	case "who":
		return sh.user + "     pts/0        " + time.Now().Format("Jan _2 15:04") + " (" + sh.p.GatewayIP + ")\n", 0
	case "last":
		return lastStr(sh.p, sh.user), 0
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
	case "sleep", "true", ":", "clear", "kill", "killall", "sync", "reset":
		return "", 0
	case "false":
		return "", 1
	case "sudo":
		if len(args) > 1 {
			return sh.runCommand(args[1:], stdin)
		}
		return "", 0
	case "base64":
		return sh.cmdBase64(args, stdin)
	case "cut", "sort", "uniq", "tr", "awk", "sed", "tee", "xargs":
		// minimal stdin passthroughs so pipes do not break
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
					sh.s.LogExec(strings.Join(args, " "), "dropped-exec")
					return "", 0
				}
			}
			return "-bash: " + base + ": No such file or directory\n", 127
		}
		return "-bash: " + base + ": command not found\n", 127
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
