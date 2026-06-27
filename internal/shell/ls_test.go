package shell

import (
	"strconv"
	"strings"
	"testing"

	"sweetty/internal/fakehost"
	"sweetty/internal/persona"
)

// linkCountOf extracts the ls -l link-count column from the line ending in suffix.
func linkCountOf(t *testing.T, lsOut, suffix string) int {
	t.Helper()
	for _, l := range strings.Split(lsOut, "\n") {
		if strings.HasSuffix(l, suffix) {
			if f := strings.Fields(l); len(f) >= 2 {
				if n, err := strconv.Atoi(f[1]); err == nil {
					return n
				}
			}
		}
	}
	t.Fatalf("no link count for a line ending %q in:\n%s", suffix, lsOut)
	return 0
}

// TestLsLinkCounts pins real hard-link counts: a regular file has 1, an empty
// directory has 2 (its own "." and its entry in the parent), and a directory with
// subdirectories has more. A directory reporting 1 is impossible on a real
// filesystem and a tell.
func TestLsLinkCounts(t *testing.T) {
	p := persona.Generate()
	base, err := fakehost.Load(p)
	if err != nil {
		t.Fatalf("load fakehost: %v", err)
	}
	sh := &Shell{fs: base.NewSession("/root")}

	if got := linkCountOf(t, sh.cmdLs([]string{"ls", "-l", "/etc/passwd"}), "passwd"); got != 1 {
		t.Errorf("/etc/passwd link count = %d, want 1", got)
	}
	if got := linkCountOf(t, sh.cmdLs([]string{"ls", "-la", "/tmp"}), " ."); got != 2 {
		t.Errorf("empty /tmp link count = %d, want 2", got)
	}
	if got := linkCountOf(t, sh.cmdLs([]string{"ls", "-la", "/"}), " ."); got <= 2 {
		t.Errorf("/ link count = %d, want >2 (it has subdirectories)", got)
	}
}

// TestLsDotEntriesAndTotal pins two things real ls always does that an attacker
// checks within seconds: `ls -la` lists "." and ".." (so an empty directory like
// /tmp is not a blank, suspicious response), and `ls -l` prints a "total" header.
func TestLsDotEntriesAndTotal(t *testing.T) {
	p := persona.Generate()
	base, err := fakehost.Load(p)
	if err != nil {
		t.Fatalf("load fakehost: %v", err)
	}
	sh := &Shell{fs: base.NewSession("/root")}

	// /tmp is an empty synthetic directory: the case that previously printed nothing.
	la := sh.cmdLs([]string{"ls", "-la", "/tmp"})
	lines := strings.Split(strings.TrimRight(la, "\n"), "\n")
	if len(lines) == 0 || !strings.HasPrefix(lines[0], "total ") {
		t.Fatalf("ls -la /tmp did not start with a total header:\n%q", la)
	}
	var dot, dotdot bool
	for _, l := range lines {
		if strings.HasSuffix(l, " .") {
			dot = true
		}
		if strings.HasSuffix(l, " ..") {
			dotdot = true
		}
	}
	if !dot || !dotdot {
		t.Errorf("ls -la /tmp missing . (%v) or .. (%v):\n%q", dot, dotdot, la)
	}

	// Short -a on the empty dir lists exactly . and ..
	if got := strings.TrimSpace(sh.cmdLs([]string{"ls", "-a", "/tmp"})); got != ".  .." {
		t.Errorf("ls -a /tmp = %q, want \".  ..\"", got)
	}

	// -l on an empty dir still emits the total header (total 0).
	if got := sh.cmdLs([]string{"ls", "-l", "/tmp"}); !strings.HasPrefix(got, "total 0") {
		t.Errorf("ls -l /tmp = %q, want it to start with \"total 0\"", got)
	}

	// A populated directory still lists its real entries alongside . and ..
	laRoot := sh.cmdLs([]string{"ls", "-la", "/root"})
	if !strings.Contains(laRoot, ".bashrc") || !strings.Contains(laRoot, " .\n") {
		t.Errorf("ls -la /root lost real entries or dot entries:\n%q", laRoot)
	}
}
