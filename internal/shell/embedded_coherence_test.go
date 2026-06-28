package shell

import (
	"strings"
	"testing"

	"sweetty/internal/fakehost"
	"sweetty/internal/persona"
)

// The architecture is one fact sampled from many places: uname -m, lscpu,
// /proc/cpuinfo and /proc/version. A recon attacker who reads two of them and finds
// aarch64 against a Xeon has busted the box. This white-box invariant fails the
// instant any generator or template drifts off the persona's architecture, for both
// the embedded board and the x86 server, the same way coherence_test pins the disk
// and process stories.
func TestArchIsOneStoryAcrossSources(t *testing.T) {
	cases := []struct {
		profile   string
		wantArch  string // appears in lscpu + equals persona.Arch (uname -m)
		wantCPU   string // a CPU token that must appear in /proc/cpuinfo for this arch
		bannedCPU string // a CPU token that must never appear for this arch
		buildHost string // the build-host arch token that must appear in /proc/version
	}{
		{"legacy", "aarch64", "0xd08", "GenuineIntel", "arm64"}, // 0xd08 = ARM Cortex-A72
		{"web", "x86_64", "GenuineIntel", "0xd08", "amd64"},
	}
	for _, c := range cases {
		t.Run(c.profile, func(t *testing.T) {
			p := persona.GenerateProfile(c.profile)
			fs, err := fakehost.Load(p)
			if err != nil {
				t.Fatal(err)
			}
			sess := fs.NewSession("/")

			if p.Arch != c.wantArch {
				t.Fatalf("uname -m / persona arch = %q, want %q", p.Arch, c.wantArch)
			}

			ls := lscpuStr(p)
			if !strings.Contains(ls, c.wantArch) {
				t.Errorf("lscpu does not report %q:\n%s", c.wantArch, ls)
			}
			if strings.Contains(ls, c.bannedCPU) {
				t.Errorf("lscpu leaks the wrong arch token %q:\n%s", c.bannedCPU, ls)
			}

			cpuinfo, err := sess.ReadFile("/proc/cpuinfo")
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(cpuinfo), c.wantCPU) {
				t.Errorf("/proc/cpuinfo missing %q:\n%s", c.wantCPU, cpuinfo)
			}
			if strings.Contains(string(cpuinfo), c.bannedCPU) {
				t.Errorf("/proc/cpuinfo leaks %q on a %s box", c.bannedCPU, c.wantArch)
			}

			version, err := sess.ReadFile("/proc/version")
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(version), c.buildHost) {
				t.Errorf("/proc/version build host is not %q: %q", c.buildHost, version)
			}
			if !strings.Contains(string(version), p.KernelRel) {
				t.Errorf("/proc/version kernel %q disagrees with uname -r: %q", p.KernelRel, version)
			}
		})
	}
}
