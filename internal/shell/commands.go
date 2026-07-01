package shell

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"sweetty/internal/persona"
	"sweetty/internal/vfs"
)

func (sh *Shell) cmdLs(args []string) string {
	long, all := false, false
	var paths []string
	for _, a := range args[1:] {
		if strings.HasPrefix(a, "-") && len(a) > 1 {
			if strings.Contains(a, "l") {
				long = true
			}
			if strings.Contains(a, "a") {
				all = true
			}
			continue
		}
		paths = append(paths, a)
	}
	if len(paths) == 0 {
		paths = []string{"."}
	}
	var b strings.Builder
	for idx, pth := range paths {
		abs := sh.fs.Resolve(pth)
		n, err := sh.fs.Stat(abs)
		if err != nil {
			b.WriteString("ls: cannot access '" + pth + "': No such file or directory\n")
			continue
		}
		if len(paths) > 1 {
			if idx > 0 {
				b.WriteString("\n")
			}
			b.WriteString(pth + ":\n")
		}
		if !n.IsDir() {
			if long {
				b.WriteString(lsLongLine(n))
			} else {
				b.WriteString(n.Name() + "\n")
			}
			continue
		}
		entries, _ := sh.fs.ReadDir(abs)
		var visible []*vfs.Node
		for _, e := range entries {
			if !all && strings.HasPrefix(e.Name(), ".") {
				continue
			}
			visible = append(visible, e)
		}
		if long {
			// Real `ls -l` always prints a `total` header; its absence, and the empty
			// listing an empty dir like /tmp produced, are tells. Approximate the block
			// count at four 1K-blocks per entry (a believable value; attackers do not
			// verify the arithmetic, only its presence).
			count := len(visible)
			if all {
				count += 2 // . and ..
			}
			b.WriteString(fmt.Sprintf("total %d\n", count*4))
			if all {
				b.WriteString(lsLongNamed(n, "."))
				parent := n
				if pn, perr := sh.fs.Stat(parentPath(abs)); perr == nil {
					parent = pn
				}
				b.WriteString(lsLongNamed(parent, ".."))
			}
			for _, e := range visible {
				b.WriteString(lsLongLine(e))
			}
		} else {
			var names []string
			if all {
				names = append(names, ".", "..") // real ls -a always lists these
			}
			for _, e := range visible {
				names = append(names, e.Name())
			}
			if len(names) > 0 {
				b.WriteString(strings.Join(names, "  ") + "\n")
			}
		}
	}
	return b.String()
}

func lsLongLine(n *vfs.Node) string {
	mode := n.Mode().String()
	if n.IsLink() {
		mode = "l" + mode[1:]
	}
	name := n.Name()
	if n.IsLink() && n.LinkTarget() != "" {
		name += " -> " + n.LinkTarget()
	}
	return fmt.Sprintf("%s %2d %-8s %-8s %8d %s %s\n",
		mode, n.LinkCount(), n.Uname(), n.Gname(), n.Size(), n.Mtime().Format("Jan _2 15:04"), name)
}

// lsLongNamed renders a long-format ls line for a node under a forced display name,
// used for the "." and ".." entries that real ls -a always lists.
func lsLongNamed(n *vfs.Node, name string) string {
	return fmt.Sprintf("%s %2d %-8s %-8s %8d %s %s\n",
		n.Mode().String(), n.LinkCount(), n.Uname(), n.Gname(), n.Size(), n.Mtime().Format("Jan _2 15:04"), name)
}

// fakeInode derives a stable, plausible inode number from a path, so repeated stat
// calls on the same file agree and different files differ, the way real inodes do.
func fakeInode(path string) int {
	h := uint32(2166136261)
	for i := 0; i < len(path); i++ {
		h = (h ^ uint32(path[i])) * 16777619
	}
	return int(h%8000000) + 100000
}

// parentPath returns the parent directory of an absolute path ("/tmp" -> "/").
func parentPath(abs string) string {
	abs = strings.TrimRight(abs, "/")
	if abs == "" {
		return "/"
	}
	if i := strings.LastIndexByte(abs, '/'); i > 0 {
		return abs[:i]
	}
	return "/"
}

// maxCmdOutput caps how many bytes a single command (cat being the worst case,
// since it can be handed the same file thousands of times on one 64KB line) will
// accumulate before it stops. Without this, `cat seed seed seed ...` builds a
// multi-gigabyte string in memory before the redirect even runs, OOM-killing the
// whole process. A real attacker never needs more than this from one command.
const maxCmdOutput = 4 << 20

// procDynamic returns synthesized content for the handful of /proc files that must
// stay live and coherent with the rest of the persona, rather than being frozen
// embedded text. /proc/uptime in particular must derive from the boot epoch (so it
// agrees with `uptime`) and carry an idle time consistent with the CPU count (a
// static idle/uptime ratio silently implies the wrong number of cores). It returns
// false for any path it does not synthesize, so the caller falls back to the VFS.
func (sh *Shell) procDynamic(abs string) (string, bool) {
	switch abs {
	case "/proc/uptime":
		up := uptimeOf(sh.p).Seconds()
		// Idle is summed across cores: on a 2-core box (matching lscpu, nproc, and
		// /proc/cpuinfo) roughly 2 x uptime, less the small fraction actually spent busy.
		idle := up * 2 * 0.985
		return fmt.Sprintf("%.2f %.2f\n", up, idle), true
	case "/proc/meminfo":
		// Render from the same numbers free and top use, so the three agree on
		// MemTotal/MemFree/MemAvailable and the swap figures rather than contradicting.
		total, _, free, buff, avail := memNumbers(sh.p)
		buffers := 121680
		cached := buff - buffers
		return fmt.Sprintf(`MemTotal:       %8d kB
MemFree:        %8d kB
MemAvailable:   %8d kB
Buffers:        %8d kB
Cached:         %8d kB
SwapCached:            0 kB
SwapTotal:      %8d kB
SwapFree:       %8d kB
`, total, free, avail, buffers, cached, swapTotalKiB, swapFreeKiB), true
	}
	return "", false
}

// readFile reads a path for display, consulting the dynamic /proc synthesizer first
// so cat, head, tail, and grep all read the same live content, then falling back to
// the virtual filesystem.
func (sh *Shell) readFile(abs string) ([]byte, error) {
	if dyn, ok := sh.procDynamic(abs); ok {
		return []byte(dyn), nil
	}
	return sh.fs.ReadFile(abs)
}

func (sh *Shell) cmdCat(args []string) (string, int) {
	var files []string
	for _, a := range args[1:] {
		if strings.HasPrefix(a, "-") {
			continue
		}
		files = append(files, a)
	}
	if len(files) == 0 {
		return "", 0 // a real cat reads stdin until EOF; the honeypot just returns
	}
	var b strings.Builder
	code := 0
	for _, f := range files {
		if b.Len() >= maxCmdOutput {
			break
		}
		abs := sh.fs.Resolve(f)
		n, err := sh.fs.Stat(abs)
		if err != nil {
			if errors.Is(err, vfs.ErrNotDir) {
				b.WriteString("cat: " + f + ": Not a directory\n")
			} else {
				b.WriteString("cat: " + f + ": No such file or directory\n")
			}
			code = 1
			continue
		}
		if n.IsDir() {
			b.WriteString("cat: " + f + ": Is a directory\n")
			code = 1
			continue
		}
		if sh.isLootImage(abs) {
			// catting a bait image dumps the colour-ANSI reveal straight to the
			// terminal — the payoff for whoever followed the trail to the stash.
			b.WriteString(sh.revealForLoot("loot-view", abs, "cat "+f))
			continue
		}
		if dyn, ok := sh.procDynamic(abs); ok {
			if room := maxCmdOutput - b.Len(); len(dyn) > room {
				dyn = dyn[:room]
			}
			b.WriteString(dyn)
			continue
		}
		content := n.Content()
		if room := maxCmdOutput - b.Len(); len(content) > room {
			content = content[:room]
		}
		b.Write(content)
	}
	return b.String(), code
}

func (sh *Shell) cmdCd(args []string) (string, int) {
	target := sh.env["HOME"]
	if len(args) > 1 {
		target = args[1]
	}
	abs := sh.fs.Resolve(target)
	if err := sh.fs.Chdir(abs); err != nil {
		if errors.Is(err, vfs.ErrNotDir) {
			return "-bash: cd: " + target + ": Not a directory\n", 1
		}
		return "-bash: cd: " + target + ": No such file or directory\n", 1
	}
	sh.env["OLDPWD"] = sh.env["PWD"]
	sh.env["PWD"] = sh.fs.Cwd()
	return "", 0
}

func (sh *Shell) cmdEcho(args []string) string {
	rest := args[1:]
	nl := true
	escape := false
	for len(rest) > 0 && (rest[0] == "-n" || rest[0] == "-e" || rest[0] == "-ne" || rest[0] == "-en" || rest[0] == "-E") {
		if strings.Contains(rest[0], "n") {
			nl = false
		}
		if strings.ContainsRune(rest[0], 'e') {
			escape = true
		}
		if rest[0] == "-E" {
			escape = false
		}
		rest = rest[1:]
	}
	out := strings.Join(rest, " ")
	if escape {
		out = decodeEchoEscapes(out)
	}
	if nl {
		out += "\n"
	}
	return out
}

// decodeEchoEscapes interprets the backslash escapes that echo -e expands, most
// importantly \xHH, so a BusyBox echo-loader that writes a dropper byte by byte
// (echo -ne '\x7f\x45\x4c\x46' >> bin) reconstructs the real bytes in the overlay
// rather than the literal text "\x7f...". Without this the dropped file is wrong
// and its content cannot be recovered as an indicator.
func decodeEchoEscapes(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch s[i] {
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case 'r':
			b.WriteByte('\r')
		case 'a':
			b.WriteByte(7)
		case 'b':
			b.WriteByte(8)
		case 'f':
			b.WriteByte(12)
		case 'v':
			b.WriteByte(11)
		case 'e':
			b.WriteByte(27)
		case '\\':
			b.WriteByte('\\')
		case 'x':
			h, n := 0, 0
			for n < 2 && i+1 < len(s) && isHexDigit(s[i+1]) {
				i++
				h = h*16 + hexDigitVal(s[i])
				n++
			}
			if n == 0 {
				b.WriteString("\\x")
			} else {
				b.WriteByte(byte(h))
			}
		case '0':
			o, n := 0, 0
			for n < 3 && i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '7' {
				i++
				o = o*8 + int(s[i]-'0')
				n++
			}
			b.WriteByte(byte(o))
		default:
			b.WriteByte('\\')
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func hexDigitVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	default:
		return int(c-'A') + 10
	}
}

func (sh *Shell) cmdUname(args []string) string {
	if len(args) == 1 {
		return "Linux\n"
	}
	// Collect the requested fields across all flags (loaders combine them, e.g.
	// `uname -s -v -n -m`); -a is everything. Emit in uname(1)'s canonical order
	// (s n r v m p), space-joined, regardless of the flag order given.
	var s, n, r, v, m, pr, all bool
	for _, a := range args[1:] {
		if !strings.HasPrefix(a, "-") {
			continue
		}
		for _, c := range a[1:] {
			switch c {
			case 'a':
				all = true
			case 's':
				s = true
			case 'n':
				n = true
			case 'r':
				r = true
			case 'v':
				v = true
			case 'm':
				m = true
			case 'p', 'i':
				pr = true
			}
		}
	}
	if all {
		return sh.p.Uname() + "\n"
	}
	var parts []string
	if s {
		parts = append(parts, "Linux")
	}
	if n {
		parts = append(parts, sh.p.Hostname)
	}
	if r {
		parts = append(parts, sh.p.KernelRel)
	}
	if v {
		parts = append(parts, sh.p.KernelVer)
	}
	if m {
		parts = append(parts, sh.p.Arch)
	}
	if pr {
		parts = append(parts, sh.p.Arch) // processor / hw platform: report the arch
	}
	if len(parts) == 0 {
		return "Linux\n"
	}
	return strings.Join(parts, " ") + "\n"
}

func (sh *Shell) cmdHeadTail(args []string, stdin string, tail bool) (string, int) {
	n := 10
	byteMode := false
	bc := 0
	var file string
	for i := 1; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-c" && i+1 < len(args):
			byteMode = true
			bc, _ = strconv.Atoi(args[i+1])
			i++
		case strings.HasPrefix(a, "-c"):
			byteMode = true
			bc, _ = strconv.Atoi(a[2:])
		case a == "-n" && i+1 < len(args):
			n, _ = strconv.Atoi(args[i+1])
			i++
		case strings.HasPrefix(a, "-n"):
			n, _ = strconv.Atoi(a[2:])
		case len(a) > 1 && a[0] == '-' && allDigits(a[1:]):
			// The obsolete but universally supported -NUM form: `head -1`, `tail -20`.
			// Without this it fell through to the unknown-flag case and silently used
			// the default of 10 lines, so `head -1 /etc/passwd` returned ten lines: a
			// coherence tell on a command an attacker runs constantly.
			n, _ = strconv.Atoi(a[1:])
		case strings.HasPrefix(a, "-"):
			continue
		default:
			file = a
		}
	}
	data := stdin
	if file != "" {
		b, err := sh.readFile(sh.fs.Resolve(file))
		if err != nil {
			verb := "head"
			if tail {
				verb = "tail"
			}
			return verb + ": cannot open '" + file + "' for reading: No such file or directory\n", 1
		}
		data = string(b)
	}
	if byteMode {
		// Byte mode emits exactly bc bytes with no added newline, unlike line mode.
		if bc < 0 {
			bc = -bc
		}
		if bc > len(data) {
			bc = len(data)
		}
		if tail {
			return data[len(data)-bc:], 0
		}
		return data[:bc], 0
	}
	lines := strings.Split(strings.TrimRight(data, "\n"), "\n")
	if n < 0 {
		n = -n
	}
	if n > len(lines) {
		n = len(lines)
	}
	if tail {
		lines = lines[len(lines)-n:]
	} else {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n") + "\n", 0
}

// allDigits reports whether s is non-empty and all ASCII digits, used to recognise
// the `-NUM` line-count shorthand for head/tail.
func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func (sh *Shell) cmdWc(args []string, stdin string) (string, int) {
	mode := ""
	var file string
	for _, a := range args[1:] {
		if strings.HasPrefix(a, "-") {
			mode = a
		} else {
			file = a
		}
	}
	data := stdin
	if file != "" {
		b, err := sh.readFile(sh.fs.Resolve(file))
		if err != nil {
			return "wc: " + file + ": No such file or directory\n", 1
		}
		data = string(b)
	}
	lines := strings.Count(data, "\n")
	words := len(strings.Fields(data))
	bytesN := len(data)
	switch {
	case strings.Contains(mode, "l"):
		return fmt.Sprintf("%d %s\n", lines, file), 0
	case strings.Contains(mode, "w"):
		return fmt.Sprintf("%d %s\n", words, file), 0
	case strings.Contains(mode, "c"):
		return fmt.Sprintf("%d %s\n", bytesN, file), 0
	default:
		return fmt.Sprintf("%7d %7d %7d %s\n", lines, words, bytesN, file), 0
	}
}

func (sh *Shell) cmdGrep(args []string, stdin string) (string, int) {
	var pattern, file string
	invert := false
	for i := 1; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			if strings.Contains(a, "v") {
				invert = true
			}
			continue
		}
		if pattern == "" {
			pattern = a
		} else {
			file = a
		}
	}
	data := stdin
	if file != "" {
		b, err := sh.readFile(sh.fs.Resolve(file))
		if err != nil {
			return "grep: " + file + ": No such file or directory\n", 2
		}
		data = string(b)
	}
	var out []string
	for _, line := range strings.Split(data, "\n") {
		match := strings.Contains(line, pattern)
		if match != invert && line != "" {
			out = append(out, line)
		}
	}
	if len(out) == 0 {
		return "", 1
	}
	return strings.Join(out, "\n") + "\n", 0
}

func (sh *Shell) cmdWhich(args []string) (string, int) {
	var out []string
	code := 0
	for _, a := range args[1:] {
		if strings.HasPrefix(a, "-") {
			continue
		}
		found := false
		for _, dir := range []string{"/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin"} {
			if sh.fs.Exists(dir + "/" + a) {
				out = append(out, dir+"/"+a)
				found = true
				break
			}
		}
		if !found {
			code = 1
		}
	}
	if len(out) == 0 {
		return "", code
	}
	return strings.Join(out, "\n") + "\n", code
}

func (sh *Shell) cmdEnv() string {
	keys := []string{"PATH", "HOME", "USER", "LOGNAME", "SHELL", "TERM", "HOSTNAME", "PWD", "SHLVL", "LANG"}
	var b strings.Builder
	for _, k := range keys {
		if v, ok := sh.env[k]; ok {
			b.WriteString(k + "=" + v + "\n")
		}
	}
	return b.String()
}

func (sh *Shell) cmdStat(args []string) (string, int) {
	var out []string
	code := 0
	for _, a := range args[1:] {
		if strings.HasPrefix(a, "-") {
			continue
		}
		abs := sh.fs.Resolve(a)
		n, err := sh.fs.Stat(abs)
		if err != nil {
			out = append(out, "stat: cannot statx '"+a+"': No such file or directory")
			code = 1
			continue
		}
		typ := "regular file"
		if n.IsDir() {
			typ = "directory"
		} else if n.IsLink() {
			typ = "symbolic link"
		}
		out = append(out, fmt.Sprintf("  File: %s\n  Size: %-10d Blocks: %-8d IO Block: 4096   %s\nDevice: 801h/2049d\tInode: %-11d Links: %d\nAccess: (%04o/%s)  Uid: (%5d/%8s)   Gid: (%5d/%8s)\nModify: %s",
			a, n.Size(), (n.Size()+511)/512, typ, fakeInode(abs), n.LinkCount(), n.Mode().Perm(), n.Mode().String(), n.Uid(), n.Uname(), n.Gid(), n.Gname(), n.Mtime().Format("2006-01-02 15:04:05.000000000 -0700")))
	}
	return strings.Join(out, "\n") + "\n", code
}

func (sh *Shell) cmdFile(args []string) string {
	var out []string
	for _, a := range args[1:] {
		if strings.HasPrefix(a, "-") {
			continue
		}
		abs := sh.fs.Resolve(a)
		n, err := sh.fs.Stat(abs)
		if err != nil {
			out = append(out, a+": cannot open `"+a+"' (No such file or directory)")
			continue
		}
		out = append(out, a+": "+describeFile(n, a))
	}
	return strings.Join(out, "\n") + "\n"
}

func describeFile(n *vfs.Node, name string) string {
	if n.IsDir() {
		return "directory"
	}
	if n.IsLink() {
		return "symbolic link to " + n.LinkTarget()
	}
	low := strings.ToLower(name)
	switch {
	case strings.HasSuffix(low, ".jpg") || strings.HasSuffix(low, ".jpeg"):
		return "JPEG image data, JFIF standard 1.01, resolution (DPI), density 72x72, segment length 16, baseline, precision 8, 1920x1080, components 3"
	case strings.HasSuffix(low, ".png"):
		return "PNG image data, 1920 x 1080, 8-bit/color RGBA, non-interlaced"
	case strings.HasSuffix(low, ".gif"):
		return "GIF image data, version 89a, 800 x 600"
	case strings.HasSuffix(low, ".gz"), strings.HasSuffix(low, ".tgz"):
		return "gzip compressed data, original size modulo 2^32"
	case strings.HasSuffix(low, ".zip"):
		return "Zip archive data, at least v2.0 to extract"
	case strings.HasSuffix(low, ".tar"):
		return "POSIX tar archive"
	case strings.HasSuffix(low, ".sh"):
		return "POSIX shell script, ASCII text executable"
	case strings.HasSuffix(low, ".pdf"):
		return "PDF document, version 1.5"
	}
	c := n.Content()
	if len(c) >= 4 && string(c[:4]) == "\x7fELF" {
		return "ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked"
	}
	if isPrintable(c) {
		return "ASCII text"
	}
	return "data"
}

func isPrintable(b []byte) bool {
	for _, c := range b {
		if c == '\n' || c == '\t' || c == '\r' {
			continue
		}
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

func (sh *Shell) cmdMutate(args []string) (string, int) {
	var targets []string
	for _, a := range args[1:] {
		if strings.HasPrefix(a, "-") {
			continue
		}
		targets = append(targets, a)
	}
	switch args[0] {
	case "touch":
		for _, t := range targets {
			abs := sh.fs.Resolve(t)
			if !sh.fs.Exists(abs) {
				sh.fs.WriteFile(abs, nil)
			}
		}
	case "mkdir":
		for _, t := range targets {
			sh.fs.Mkdir(sh.fs.Resolve(t))
		}
	case "rm", "rmdir":
		for _, t := range targets {
			sh.fs.Remove(sh.fs.Resolve(t))
		}
	case "cp":
		if len(targets) >= 2 {
			if data, err := sh.fs.ReadFile(sh.fs.Resolve(targets[0])); err == nil {
				sh.fs.WriteFile(sh.fs.Resolve(targets[len(targets)-1]), data)
			}
		}
	case "mv":
		if len(targets) >= 2 {
			src := sh.fs.Resolve(targets[0])
			dst := sh.fs.Resolve(targets[len(targets)-1])
			if data, err := sh.fs.ReadFile(src); err == nil {
				sh.fs.WriteFile(dst, data)
				sh.fs.Remove(src)
			}
		}
	}
	return "", 0
}

func (sh *Shell) cmdHistory(args []string) (string, int) {
	if len(args) > 1 && args[1] == "-c" {
		sh.s.LogCommandNote("history -c", "anti-forensics")
		return "", 0
	}
	lines := []string{
		"ls -la /var/www/html", "cat /var/www/html/wp-config.php",
		"mysql -u " + sh.p.WPDBUser + " -p -h " + sh.p.DBIP + " " + sh.p.WPDBName,
		"systemctl status nginx", "df -h", "cd /home/" + sh.p.Username + "/scripts",
		"./backup.sh", "ssh " + sh.p.Username + "@" + sh.p.BackupIP, "free -m", "history",
	}
	var b strings.Builder
	for i, l := range lines {
		b.WriteString(fmt.Sprintf("%5d  %s\n", i+1, l))
	}
	return b.String(), 0
}

func (sh *Shell) cmdService(args []string) string {
	name := ""
	action := ""
	for _, a := range args[1:] {
		if a == "status" || a == "start" || a == "stop" || a == "restart" || a == "enable" || a == "disable" {
			action = a
			continue
		}
		if !strings.HasPrefix(a, "-") && name == "" {
			name = a
		}
	}
	if action == "status" || action == "" {
		return systemctlStatus(sh.p, name)
	}
	return ""
}

// systemctlStatus renders `systemctl status <name>`. Its Main PID is sourced from
// the shared process table, so it can never name a different PID than `ps aux`
// shows for the same daemon.
func systemctlStatus(p *persona.Persona, name string) string {
	up := time.Since(time.Unix(p.BootEpoch, 0))
	return fmt.Sprintf("● %s.service - %s\n     Loaded: loaded (/lib/systemd/system/%s.service; enabled; vendor preset: enabled)\n     Active: active (running) since boot; %s ago\n   Main PID: %d (%s)\n      Tasks: 3 (limit: 2294)\n     Memory: 12.4M\n",
		name, name, name, fmtDur(up), mainPID(p, name), name)
}

// mainPID returns the master/daemon PID for a service name from the shared process
// table (systemd's Main PID is the master row, not a worker), falling back to a
// stable synthetic pid for a service the table does not model.
func mainPID(p *persona.Persona, name string) int {
	key := name
	switch name {
	case "mysql", "mysqld", "mariadb":
		key = "mysqld"
	case "ssh", "sshd":
		key = "sshd"
	case "php-fpm", "php", "php8.1-fpm":
		key = "php-fpm"
	}
	for _, r := range procTable(p) {
		if strings.Contains(r.command, "worker") {
			continue
		}
		if strings.Contains(r.command, key) {
			return r.pid
		}
	}
	return 600 + len(name)
}

func (sh *Shell) cmdDpkg(args []string) string {
	for _, a := range args[1:] {
		if a == "-l" || a == "--list" {
			out := "Desired=Unknown/Install/Remove/Purge/Hold\n| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend\n|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)\n||/ Name           Version          Architecture Description\n+++-==============-================-============-=================================\nii  bash           5.1-6ubuntu1     amd64        GNU Bourne Again SHell\nii  coreutils      8.32-4.1ubuntu1  amd64        GNU core utilities\nii  curl           7.81.0-1ubuntu1  amd64        command line tool for transferring data\nii  nginx          1.18.0-6ubuntu14 amd64        small, powerful, scalable web server\nii  openssh-server 1:8.9p1-3ubuntu0 amd64        secure shell (SSH) server\n"
			if sh.p.Embedded() {
				// Ubuntu on arm64: every package is built for the board's arch.
				out = strings.ReplaceAll(out, "amd64", "arm64")
			}
			return out
		}
	}
	return ""
}

func (sh *Shell) cmdIP(args []string) string {
	if len(args) > 1 {
		switch args[1] {
		case "a", "addr", "address":
			return ipAddrStr(sh.p)
		case "r", "route":
			return ipRouteStr(sh.p)
		case "link", "l":
			return ipLinkStr(sh.p)
		}
	}
	return ipAddrStr(sh.p)
}

func fmtDur(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60
	if days > 0 {
		return fmt.Sprintf("%dd %dh", days, hours)
	}
	return fmt.Sprintf("%dh %dmin", hours, mins)
}
