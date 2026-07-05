package persona

import (
	"strings"
	"testing"
)

// The legacy profile wears an embedded device-class (a busybox/appliance telnet
// login on dvr/cam/iot/router/nas hostnames). Its hardware must read as a 64-bit
// ARM board, not an Intel server, or the very first `uname -m` contradicts the role.
// This is the persona-layer proof for VISION doctrine #1 (one coherent identity).
func TestLegacyProfileIsEmbeddedARM(t *testing.T) {
	for range 64 {
		p := GenerateProfile("legacy")
		if p.Arch != "aarch64" {
			t.Fatalf("legacy profile arch = %q, want aarch64", p.Arch)
		}
		if !p.Embedded() {
			t.Fatalf("legacy profile must report Embedded()")
		}
		if !strings.Contains(p.Uname(), "aarch64") || strings.Contains(p.Uname(), "x86_64") {
			t.Fatalf("uname -a is not coherently ARM: %q", p.Uname())
		}
	}
}

// Every server profile stays x86_64 and must never claim to be embedded. A wrong
// architecture on a web/db/ftp box is just as much a tell as a Xeon on a router.
func TestServerProfilesStayX86(t *testing.T) {
	for _, name := range []string{"web", "edge", "infra", "ftp", "full"} {
		for range 16 {
			p := GenerateProfile(name)
			if p.Arch != "x86_64" {
				t.Errorf("%s profile arch = %q, want x86_64", name, p.Arch)
			}
			if p.Embedded() {
				t.Errorf("%s profile must not report Embedded()", name)
			}
		}
	}
}

// osImage keeps the kernel release and OS pretty-name identical across arches
// (Ubuntu ships the same release on amd64 and arm64); only the architecture moves.
// A divergent kernel string would let a scanner separate the two fleets.
func TestOSImageOnlyArchDiffersByProfile(t *testing.T) {
	rel := osReleasePool[0]
	aArch, aRel, aVer, aPretty := osImage("legacy", rel)
	bArch, bRel, bVer, bPretty := osImage("web", rel)
	if aArch == bArch {
		t.Fatalf("legacy and server arch should differ, both %q", aArch)
	}
	if aArch != "aarch64" || bArch != "x86_64" {
		t.Fatalf("arches = %q / %q, want aarch64 / x86_64", aArch, bArch)
	}
	if aRel != bRel || aVer != bVer || aPretty != bPretty {
		t.Fatalf("kernel/os identity diverged across arches: rel %q/%q ver %q/%q pretty %q/%q",
			aRel, bRel, aVer, bVer, aPretty, bPretty)
	}
}
