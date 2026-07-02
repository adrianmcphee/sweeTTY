package shell

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// TestProcFilesAreSynthesizedOrAcceptedStatic is the meta-guard behind the whole
// coherence doctrine: it fails the build if a new static /proc file is embedded
// without either a live synthesizer or a deliberate exemption. The cross-checks
// otherwise compare generators against generators and never against the embedded
// files, which is exactly where the drift lived (a frozen /proc/uptime that
// disagreed with `uptime`). A file with a volatile field (uptime, memory, load)
// must be synthesized in procDynamic; a genuinely static one (cpuinfo, the kernel
// version string) is listed here with intent.
func TestProcFilesAreSynthesizedOrAcceptedStatic(t *testing.T) {
	sh := userShell(t, "root", "/")

	acceptedStatic := map[string]bool{
		"cpuinfo": true, // fixed hardware description; no volatile field
		"version": true, // the kernel version string, fixed for a booted kernel
	}
	entries, err := sh.fs.ReadDir("/proc")
	if err != nil {
		t.Fatalf("read /proc: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if _, ok := sh.procDynamic("/proc/" + name); ok {
			continue // synthesized live: cannot drift
		}
		if acceptedStatic[name] {
			continue
		}
		t.Errorf("/proc/%s is a static embedded file with no synthesizer and no exemption; "+
			"it will drift from the live generators. Synthesize it in procDynamic or add it to "+
			"acceptedStatic with a reason.", name)
	}
}

// TestCatProcAgreesWithGenerators proves the wired commands agree end to end, not
// just the generator functions: cat /proc/uptime against uptime, and cat
// /proc/meminfo against free, through the real command dispatch.
func TestCatProcAgreesWithGenerators(t *testing.T) {
	sh := userShell(t, "root", "/")

	procUp, _ := sh.runCommand([]string{"cat", "/proc/uptime"}, "")
	secs, err := strconv.ParseFloat(strings.Fields(procUp)[0], 64)
	if err != nil {
		t.Fatalf("parse /proc/uptime %q: %v", procUp, err)
	}
	days := int(secs) / 86400
	uptimeOut, _ := sh.runCommand([]string{"uptime"}, "")
	if !strings.Contains(uptimeOut, fmt.Sprintf("up %d days", days)) {
		t.Errorf("cat /proc/uptime says %d days but `uptime` disagrees: %q", days, strings.TrimSpace(uptimeOut))
	}

	_, _, free, _, _ := memNumbers(sh.p)
	freeKiB := strconv.Itoa(free)
	meminfo, _ := sh.runCommand([]string{"cat", "/proc/meminfo"}, "")
	freeOut, _ := sh.runCommand([]string{"free"}, "")
	if !strings.Contains(meminfo, freeKiB) || !strings.Contains(freeOut, freeKiB) {
		t.Errorf("MemFree %s not shown by both /proc/meminfo and free:\nmeminfo=%q\nfree=%q", freeKiB, meminfo, freeOut)
	}
}
