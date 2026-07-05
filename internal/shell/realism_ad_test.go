package shell

import (
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"sweetty/internal/persona"
)

// TestInterpreterVersionProbe proves an interpreter answers a version probe instead
// of segfaulting. A prober enumerates the toolchain in the first minute; an
// interpreter that is installed yet fails even `--version` is a conclusive tell.
func TestInterpreterVersionProbe(t *testing.T) {
	p := persona.Generate()
	cases := map[string]string{
		"python3": "Python 3.",
		"perl":    "perl 5",
		"php":     "PHP " + p.PHPVersion(),
		"node":    "v",
	}
	for bin, want := range cases {
		got, ok := interpVersion(p, []string{bin, "--version"})
		if !ok || !strings.Contains(got, want) {
			t.Errorf("%s --version = %q (ok=%v), want to contain %q", bin, got, ok, want)
		}
	}
	if _, ok := interpVersion(p, []string{"python3", "-c", "print(1)"}); ok {
		t.Error("a -c run must not be treated as a version probe")
	}
}

// TestArithmeticAndPidExpansion proves $(( )) evaluates and $$ expands to the shell
// pid, which must equal the -bash row ps prints so `echo $$` and ps agree.
func TestArithmeticAndPidExpansion(t *testing.T) {
	sh := &Shell{env: map[string]string{"n": "5"}, expandBudget: maxExpandBytes}
	cases := map[string]string{
		"$((2+3*4))":   "14",
		"$((10/3))":    "3",
		"$(( n * 2 ))": "10",
		"$((2*(3+4)))": "14",
		"$$":           strconv.Itoa(shellPID),
	}
	for in, want := range cases {
		if got := sh.expand(in); got != want {
			t.Errorf("expand(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestDownloadResolvesRoutableAndVaries proves a fake fetch resolves to a plausible
// routable address (never a reserved/TEST-NET one an attacker would spot for their
// own C2) and that the size varies by URL rather than being a fixed constant.
func TestDownloadResolvesRoutableAndVaries(t *testing.T) {
	for _, host := range []string{"evil.example", "cdn.badhost.ru", "1.2.3.4"} {
		ip := fakeResolveIP(host)
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			t.Fatalf("resolved %q to unparseable %q", host, ip)
		}
		if addr.IsPrivate() || addr.IsLoopback() || !addr.IsGlobalUnicast() {
			t.Errorf("resolved %q to non-routable %q", host, ip)
		}
	}
	if fakeDownloadSize("http://a/x") == fakeDownloadSize("http://a/y") {
		t.Error("download size does not vary by URL")
	}
}

// TestMeminfoAgreesWithFree proves cat /proc/meminfo reports the same MemFree the
// free command shows, so the two cannot be caught contradicting each other.
func TestMeminfoAgreesWithFree(t *testing.T) {
	p := persona.Generate()
	sh := &Shell{p: p}
	_, _, free, _, _ := memNumbers(p)

	mi, ok := sh.procDynamic("/proc/meminfo")
	if !ok {
		t.Fatal("/proc/meminfo not synthesized")
	}
	if !strings.Contains(mi, "MemFree:") || !strings.Contains(mi, strconv.Itoa(free)) {
		t.Errorf("/proc/meminfo MemFree does not match free's %d:\n%s", free, mi)
	}
}

// TestProcessListLooksReal proves the process table carries kernel threads and a
// believable count, not a suspiciously clean userspace-only LAMP set. top derives
// its Tasks count from this same table, so the two always agree.
func TestProcessListLooksReal(t *testing.T) {
	p := persona.Generate()
	rows := procTable(p)
	if len(rows) < 40 {
		t.Errorf("process table has only %d rows; a real server shows far more", len(rows))
	}
	kthreads := 0
	for _, r := range rows {
		if strings.HasPrefix(r.command, "[") {
			kthreads++
		}
	}
	if kthreads < 10 {
		t.Errorf("only %d kernel threads; their absence is a tell", kthreads)
	}
}
