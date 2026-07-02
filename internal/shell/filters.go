package shell

import (
	"sort"
	"strconv"
	"strings"
)

// This file implements the text filters attackers pipe recon through: cut, sort,
// uniq, tr, tee, and a useful subset of awk and sed. They were previously stubs
// that returned stdin unchanged, so `cat /etc/passwd | cut -d: -f1` printed the
// whole file and `tr a-z A-Z` did nothing, both obvious tells. Each honours a file
// argument or stdin the way grep/wc already do.

// filterInput returns the text a filter processes: the named files' contents if any
// non-flag file arguments are given, otherwise stdin.
func (sh *Shell) filterInput(files []string, stdin string) string {
	if len(files) == 0 {
		return stdin
	}
	var b strings.Builder
	for _, f := range files {
		if data, err := sh.readFile(sh.fs.Resolve(f)); err == nil {
			b.Write(data)
		}
	}
	return b.String()
}

// lines splits s into lines without a trailing empty element, so filters iterate the
// real lines and rejoin with a single trailing newline like the coreutils do.
func lines(s string) []string {
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func joinLines(ls []string) string {
	if len(ls) == 0 {
		return ""
	}
	return strings.Join(ls, "\n") + "\n"
}

// parseRanges parses a cut/sort field list like "1", "1,3", "2-", "1-3" into a
// predicate over 1-based indices.
func parseRanges(spec string) func(i int) bool {
	type rng struct{ lo, hi int }
	var rs []rng
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if i := strings.IndexByte(part, '-'); i >= 0 {
			lo, _ := strconv.Atoi(part[:i])
			hi := 1 << 30
			if i+1 < len(part) {
				hi, _ = strconv.Atoi(part[i+1:])
			}
			if lo == 0 {
				lo = 1
			}
			rs = append(rs, rng{lo, hi})
		} else if n, err := strconv.Atoi(part); err == nil {
			rs = append(rs, rng{n, n})
		}
	}
	return func(i int) bool {
		for _, r := range rs {
			if i >= r.lo && i <= r.hi {
				return true
			}
		}
		return false
	}
}

func (sh *Shell) cmdCut(args []string, stdin string) string {
	delim := "\t"
	spec := ""
	byChar := false
	var files []string
	for i := 1; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-d" && i+1 < len(args):
			i++
			delim = a2delim(args[i])
		case strings.HasPrefix(a, "-d"):
			delim = a2delim(a[2:])
		case a == "-f" && i+1 < len(args):
			i++
			spec = args[i]
		case strings.HasPrefix(a, "-f"):
			spec = a[2:]
		case a == "-c" && i+1 < len(args):
			i++
			spec, byChar = args[i], true
		case strings.HasPrefix(a, "-c"):
			spec, byChar = a[2:], true
		case strings.HasPrefix(a, "-"):
			// ignore other flags (-s and friends)
		default:
			files = append(files, a)
		}
	}
	want := parseRanges(spec)
	var out []string
	for _, line := range lines(sh.filterInput(files, stdin)) {
		if byChar {
			var sb strings.Builder
			for i, r := range []rune(line) {
				if want(i + 1) {
					sb.WriteRune(r)
				}
			}
			out = append(out, sb.String())
			continue
		}
		if !strings.Contains(line, delim) {
			out = append(out, line) // a line without the delimiter is passed through
			continue
		}
		parts := strings.Split(line, delim)
		var sel []string
		for i, p := range parts {
			if want(i + 1) {
				sel = append(sel, p)
			}
		}
		out = append(out, strings.Join(sel, delim))
	}
	return joinLines(out)
}

// a2delim maps a delimiter argument to its byte, honouring the common escaped tab.
func a2delim(s string) string {
	if s == "\\t" {
		return "\t"
	}
	if s == "" {
		return "\t"
	}
	return s
}

func (sh *Shell) cmdSort(args []string, stdin string) string {
	numeric, reverse, unique := false, false, false
	var files []string
	for _, a := range args[1:] {
		switch {
		case a == "-n" || a == "-rn" || a == "-nr":
			numeric = true
			if a != "-n" {
				reverse = true
			}
		case a == "-r":
			reverse = true
		case a == "-u":
			unique = true
		case strings.HasPrefix(a, "-"):
			// -k and other flags: sort the whole line
		default:
			files = append(files, a)
		}
	}
	ls := lines(sh.filterInput(files, stdin))
	sort.SliceStable(ls, func(i, j int) bool {
		if numeric {
			return leadingNum(ls[i]) < leadingNum(ls[j])
		}
		return ls[i] < ls[j]
	})
	if reverse {
		for i, j := 0, len(ls)-1; i < j; i, j = i+1, j-1 {
			ls[i], ls[j] = ls[j], ls[i]
		}
	}
	if unique {
		ls = dedupAdjacent(ls, false, nil)
	}
	return joinLines(ls)
}

// leadingNum reads the leading numeric value of a line for `sort -n`, treating a
// non-numeric prefix as zero the way sort does.
func leadingNum(s string) float64 {
	s = strings.TrimSpace(s)
	end := 0
	for end < len(s) && (s[end] == '-' || s[end] == '.' || (s[end] >= '0' && s[end] <= '9')) {
		end++
	}
	f, _ := strconv.ParseFloat(s[:end], 64)
	return f
}

func (sh *Shell) cmdUniq(args []string, stdin string) string {
	count := false
	var files []string
	for _, a := range args[1:] {
		switch {
		case a == "-c":
			count = true
		case strings.HasPrefix(a, "-"):
		default:
			files = append(files, a)
		}
	}
	ls := lines(sh.filterInput(files, stdin))
	var out []string
	i := 0
	for i < len(ls) {
		j := i + 1
		for j < len(ls) && ls[j] == ls[i] {
			j++
		}
		if count {
			out = append(out, strconv.Itoa(j-i)+" "+ls[i])
		} else {
			out = append(out, ls[i])
		}
		i = j
	}
	return joinLines(out)
}

// dedupAdjacent collapses runs of equal adjacent lines (sort -u semantics after a
// sort). The count/only-dup variants live in cmdUniq.
func dedupAdjacent(ls []string, _ bool, _ func(string) string) []string {
	var out []string
	for i, l := range ls {
		if i == 0 || l != ls[i-1] {
			out = append(out, l)
		}
	}
	return out
}

func (sh *Shell) cmdTr(args []string, stdin string) string {
	del := false
	var sets []string
	for _, a := range args[1:] {
		if strings.HasPrefix(a, "-") && len(a) > 1 && a != "-" {
			if strings.Contains(a, "d") {
				del = true
			}
			continue
		}
		sets = append(sets, a)
	}
	in := sh.filterInput(nil, stdin)
	if del && len(sets) >= 1 {
		set := expandTrSet(sets[0])
		return strings.Map(func(r rune) rune {
			if strings.ContainsRune(set, r) {
				return -1
			}
			return r
		}, in)
	}
	if len(sets) >= 2 {
		from, to := expandTrSet(sets[0]), expandTrSet(sets[1])
		fr, tr := []rune(from), []rune(to)
		return strings.Map(func(r rune) rune {
			for i, c := range fr {
				if c == r {
					if i < len(tr) {
						return tr[i]
					}
					return tr[len(tr)-1] // shorter SET2 repeats its last char
				}
			}
			return r
		}, in)
	}
	return in
}

// expandTrSet expands tr range shorthands (a-z, A-Z, 0-9) into the full character set.
func expandTrSet(s string) string {
	var b strings.Builder
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		if i+2 < len(rs) && rs[i+1] == '-' {
			for c := rs[i]; c <= rs[i+2]; c++ {
				b.WriteRune(c)
			}
			i += 2
			continue
		}
		b.WriteRune(rs[i])
	}
	return b.String()
}

func (sh *Shell) cmdTee(args []string, stdin string) string {
	var files []string
	for _, a := range args[1:] {
		if strings.HasPrefix(a, "-") {
			continue
		}
		files = append(files, a)
	}
	for _, f := range files {
		_ = sh.fs.WriteFile(sh.fs.Resolve(f), []byte(stdin))
	}
	return stdin // tee also copies to stdout
}

// cmdAwk handles the field-printing programs attackers actually pipe recon through:
// {print $N}, {print $N,$M}, {print}, and NF, with -F to set the field separator.
// Anything it does not recognise passes stdin through rather than erroring.
func (sh *Shell) cmdAwk(args []string, stdin string) string {
	fs := " "
	prog := ""
	var files []string
	for i := 1; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-F" && i+1 < len(args):
			i++
			fs = a2delim(args[i])
		case strings.HasPrefix(a, "-F"):
			fs = a2delim(a[2:])
		case prog == "" && strings.Contains(a, "{"):
			prog = a
		case strings.HasPrefix(a, "-"):
		default:
			files = append(files, a)
		}
	}
	inner := prog
	if i := strings.IndexByte(inner, '{'); i >= 0 {
		inner = inner[i+1:]
	}
	inner = strings.TrimSuffix(strings.TrimSpace(inner), "}")
	inner = strings.TrimSpace(inner)
	if !strings.HasPrefix(inner, "print") {
		return sh.filterInput(files, stdin) // unrecognised program: pass through
	}
	fieldSpec := strings.TrimSpace(strings.TrimPrefix(inner, "print"))
	in := sh.filterInput(files, stdin)
	var out []string
	for _, line := range lines(in) {
		var f []string
		if fs == " " {
			f = strings.Fields(line)
		} else {
			f = strings.Split(line, fs)
		}
		out = append(out, awkPrint(fieldSpec, line, f))
	}
	return joinLines(out)
}

// awkPrint renders one awk print statement: bare print echoes the line; $0 is the
// whole line; $N selects a field; comma-separated specs join with a space.
func awkPrint(spec, line string, fields []string) string {
	spec = strings.TrimSpace(spec)
	if spec == "" || spec == "$0" {
		return line
	}
	var parts []string
	for _, tok := range strings.Split(spec, ",") {
		tok = strings.TrimSpace(tok)
		switch {
		case tok == "NF":
			parts = append(parts, strconv.Itoa(len(fields)))
		case strings.HasPrefix(tok, "$"):
			n, err := strconv.Atoi(tok[1:])
			if err == nil && n >= 1 && n <= len(fields) {
				parts = append(parts, fields[n-1])
			} else if n == 0 {
				parts = append(parts, line)
			} else {
				parts = append(parts, "")
			}
		default:
			parts = append(parts, strings.Trim(tok, `"`))
		}
	}
	return strings.Join(parts, " ")
}

// cmdSed handles the substitution and delete programs attackers use: s/re/repl/[g]
// as a plain (non-regex) replace, and /pat/d line deletion. Unrecognised programs
// pass through.
func (sh *Shell) cmdSed(args []string, stdin string) string {
	var prog string
	var files []string
	quiet := false
	for i := 1; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-n":
			quiet = true
		case a == "-e" && i+1 < len(args):
			i++
			prog = args[i]
		case a == "-r" || a == "-E":
		case strings.HasPrefix(a, "-"):
		case prog == "":
			prog = a
		default:
			files = append(files, a)
		}
	}
	in := sh.filterInput(files, stdin)
	if strings.HasPrefix(prog, "s") && len(prog) > 1 {
		sep := prog[1]
		rest := strings.Split(prog[2:], string(sep))
		if len(rest) >= 2 {
			from, to := rest[0], rest[1]
			global := len(rest) >= 3 && strings.Contains(rest[2], "g")
			if global {
				return strings.ReplaceAll(in, from, to)
			}
			var out []string
			for _, line := range lines(in) {
				out = append(out, strings.Replace(line, from, to, 1))
			}
			return joinLines(out)
		}
	}
	if strings.HasPrefix(prog, "/") && strings.HasSuffix(prog, "/d") {
		pat := strings.TrimSuffix(strings.TrimPrefix(prog, "/"), "/d")
		var out []string
		for _, line := range lines(in) {
			if !strings.Contains(line, pat) {
				out = append(out, line)
			}
		}
		return joinLines(out)
	}
	if quiet {
		return ""
	}
	return in
}
