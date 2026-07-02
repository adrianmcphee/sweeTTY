package shell

import (
	"strings"
	"testing"
)

// TestStatDeviceMatchesBlockLayer proves stat's Device field is derived from the
// mount a path falls under, so it agrees with lsblk (major:minor) instead of always
// reporting sda1 (801h) on every persona.
func TestStatDeviceMatchesBlockLayer(t *testing.T) {
	p, _ := loadHost(t) // "full" profile: a cloud host on xvda (202)
	if got := deviceFor(p, "/etc/passwd"); got != "ca01h/51713d" {
		t.Errorf("root device = %q, want ca01h/51713d (xvda1, 202:1)", got)
	}
	if got := deviceFor(p, "/var/lib/mysql/ibdata1"); got != "ca11h/51729d" {
		t.Errorf("data device = %q, want ca11h/51729d (xvdb1, 202:17)", got)
	}
	if strings.Contains(lsblkStr(p), "sda") {
		t.Error("lsblk shows xvda but stat used sda: they must name the same device")
	}
}

// TestSystemctlUnknownUnitNotFound proves an unmodeled unit reports not-found with
// exit 4, instead of claiming every name is active and running.
func TestSystemctlUnknownUnitNotFound(t *testing.T) {
	p, _ := loadHost(t)
	if out, code := systemctlStatus(p, "definitely-not-a-real-service"); code != 4 || !strings.Contains(out, "could not be found") {
		t.Errorf("unknown unit: got (%q, %d), want not-found and exit 4", out, code)
	}
	// A modeled daemon still reports running.
	if out, code := systemctlStatus(p, "nginx"); code != 0 || !strings.Contains(out, "active (running)") {
		t.Errorf("nginx: got (%q, %d), want running and exit 0", out, code)
	}
}

// TestLinkLocalStableAndShared proves the eth0 link-local is a stable EUI-64 from
// the MAC, shown identically by ifconfig and ip addr, and does not drift between
// calls the way the old uptime-derived value did.
func TestLinkLocalStableAndShared(t *testing.T) {
	p, _ := loadHost(t)
	ll := linkLocalFromMAC(p.MAC)
	if !strings.HasPrefix(ll, "fe80::") {
		t.Fatalf("link-local %q is not fe80::", ll)
	}
	if !strings.Contains(ifconfigStr(p), ll) {
		t.Errorf("ifconfig does not show the EUI-64 link-local %s", ll)
	}
	if !strings.Contains(ipAddrStr(p), ll) {
		t.Errorf("ip addr does not show the eth0 link-local %s (it had none before)", ll)
	}
	// The link-local is a pure function of the MAC, so it is identical on every call
	// (the old value was rebuilt from uptime and changed second to second).
	if linkLocalFromMAC(p.MAC) != ll {
		t.Error("link-local is not stable for a fixed MAC")
	}
}
