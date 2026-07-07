package telnet_test

import (
	"strings"
	"testing"

	"sweetty/internal/fakehost"
	"sweetty/internal/persona"
	"sweetty/internal/proto/telnet"
	"sweetty/internal/testharness"
)

// The protocol-layer proof for the embedded persona: a real busybox-style telnet
// session on the legacy (IoT/router) profile must answer every architecture probe
// as a 64-bit ARM board. This is the path a Mirai-class loader actually walks -
// log in, fingerprint the CPU, then decide which payload to drop - so a Xeon
// surfacing on any of uname/lscpu/cpuinfo would mark the box as a decoy.
func TestEmbeddedDeviceSessionIsCoherentlyARM(t *testing.T) {
	p := persona.GenerateProfile("legacy")
	if p.Arch != "aarch64" {
		t.Fatalf("legacy persona is not aarch64: %q", p.Arch)
	}
	fs, err := fakehost.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	h, err := testharness.New(telnet.New(fs, p, "ubuntu"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.Close)

	login(t, h, p, "root")

	if out := run(h, "uname -m"); !strings.Contains(out, "aarch64") || strings.Contains(out, "x86_64") {
		t.Errorf("uname -m not coherently ARM: %q", out)
	}
	if out := run(h, "uname -a"); !strings.Contains(out, "aarch64") || strings.Contains(out, "x86_64") {
		t.Errorf("uname -a not coherently ARM: %q", out)
	}
	if out := run(h, "cat /proc/cpuinfo"); strings.Contains(out, "GenuineIntel") || strings.Contains(out, "Xeon") {
		t.Errorf("/proc/cpuinfo leaks Intel on an ARM device: %q", out)
	}
	if out := run(h, "lscpu"); !strings.Contains(out, "aarch64") {
		t.Errorf("lscpu not aarch64: %q", out)
	}

	// The disk and boot story must match the board, not a Xen x86 VM: an SD card,
	// not /dev/xvda, and a dmesg with no Intel/x86, no dpkg amd64 packages.
	if out := run(h, "df -h"); strings.Contains(out, "xvda") || !strings.Contains(out, "mmcblk") {
		t.Errorf("df does not show an SD card on the ARM board: %q", out)
	}
	if out := run(h, "lsblk"); strings.Contains(out, "xvda") || !strings.Contains(out, "mmcblk") {
		t.Errorf("lsblk does not show an SD card on the ARM board: %q", out)
	}
	if out := run(h, "dmesg"); strings.Contains(out, "Intel") || strings.Contains(out, "x86") || strings.Contains(out, "xen") {
		t.Errorf("dmesg leaks x86/Intel/Xen on the ARM board: %q", out)
	}
	if out := run(h, "dpkg -l"); strings.Contains(out, "amd64") {
		t.Errorf("dpkg shows amd64 packages on the ARM board: %q", out)
	}
}
