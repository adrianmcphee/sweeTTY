package shell

// White-box coherence-invariant tests. Where the protocol-level tests in
// internal/proto/telnet drive one believable session and assert a few facts agree,
// these walk the synthetic generators programmatically and assert that every pair
// of them describing the same fact can never disagree. They run in milliseconds
// with no network or sleeps, and they are the layer that catches a single-source-
// of-truth violation (VISION doctrine #1) the moment it is introduced, the way
// internal/safety proves the no-capability boundary. A recon attacker's first
// moves (df -h; cat /etc/fstab, or ps; uptime) are exactly these seams.

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"sweetty/internal/fakehost"
	"sweetty/internal/persona"
	"sweetty/internal/vfs"
)

// loadHost builds a generated persona and its rendered virtual filesystem, the
// same pair every protocol wears at runtime.
func loadHost(t *testing.T) (*persona.Persona, *vfs.FS) {
	t.Helper()
	p := persona.GenerateProfile("full")
	fs, err := fakehost.Load(p)
	if err != nil {
		t.Fatalf("load fakehost: %v", err)
	}
	return p, fs
}

// realDevMounts maps each /dev/* device to its mountpoint as reported by a
// df/mount/lsblk-style block of text, skipping pseudo filesystems (tmpfs, proc,
// sysfs, udev, devtmpfs). The two parsers below feed it.
func dfMounts(out string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 6 || !strings.HasPrefix(f[0], "/dev/") {
			continue
		}
		m[f[0]] = f[len(f)-1] // Filesystem ... Mounted-on (last column)
	}
	return m
}

func mountMounts(out string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		// "<dev> on <path> type <fstype> (...)"
		if len(f) < 4 || !strings.HasPrefix(f[0], "/dev/") || f[1] != "on" {
			continue
		}
		m[f[0]] = f[2]
	}
	return m
}

func lsblkMounts(out string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] == "NAME" {
			continue
		}
		// A partition line ends in its mountpoint when it has one.
		last := f[len(f)-1]
		if strings.HasPrefix(last, "/") && strings.Contains(line, "part") {
			// derive the bare device name from the tree-drawing prefix (└─xvda1).
			dev := strings.TrimLeft(f[0], "└─├│ ")
			m["/dev/"+dev] = last
		}
	}
	return m
}

// TestDiskStoryIsCoherent is the headline single-source-of-truth proof for the
// block layer. df, mount and lsblk must agree on the device->mountpoint map; every
// mountpoint they advertise must exist as a real directory in the VFS (so a
// `cd`/`ls` into it does not contradict `df -h`); and the set of persistent mounts
// must match /etc/fstab. A box that advertises /var/lib/mysql in df but has no such
// directory, or lists /boot in fstab that the block layer never shows, is busted by
// one recon command.
func TestDiskStoryIsCoherent(t *testing.T) {
	p, fs := loadHost(t)
	sess := fs.NewSession("/")

	df := dfMounts(dfStr(p))
	mnt := mountMounts(mountStr(p))
	lsblk := lsblkMounts(lsblkStr(p))
	if len(df) == 0 || len(mnt) == 0 || len(lsblk) == 0 {
		t.Fatalf("a generator reported no real-device mounts: df=%v mount=%v lsblk=%v", df, mnt, lsblk)
	}

	// (1) df, mount and lsblk agree on the device->mountpoint map.
	for dev, mp := range df {
		if mnt[dev] != mp {
			t.Errorf("mount disagrees with df for %s: df=%q mount=%q", dev, mp, mnt[dev])
		}
		if lsblk[dev] != mp {
			t.Errorf("lsblk disagrees with df for %s: df=%q lsblk=%q", dev, mp, lsblk[dev])
		}
	}
	if len(mnt) != len(df) || len(lsblk) != len(df) {
		t.Errorf("generators report different numbers of real-device mounts: df=%d mount=%d lsblk=%d", len(df), len(mnt), len(lsblk))
	}

	// (2) every advertised mountpoint exists as a directory in the VFS.
	for dev, mp := range df {
		n, err := sess.Stat(mp)
		if err != nil {
			t.Errorf("%s is mounted on %q in df but that path does not exist in the filesystem: %v", dev, mp, err)
			continue
		}
		if !n.IsDir() {
			t.Errorf("mountpoint %q (%s) exists but is not a directory", mp, dev)
		}
	}

	// (3) the persistent (non-swap) mounts in /etc/fstab match the block layer.
	fstab, err := sess.ReadFile("/etc/fstab")
	if err != nil {
		t.Fatalf("read /etc/fstab: %v", err)
	}
	want := map[string]bool{}
	for _, mp := range df {
		want[mp] = true
	}
	got := map[string]bool{}
	for _, line := range strings.Split(string(fstab), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		mp, fstype := f[1], f[2]
		if fstype == "swap" || mp == "none" || mp == "swap" {
			continue
		}
		got[mp] = true
	}
	for mp := range want {
		if !got[mp] {
			t.Errorf("/etc/fstab does not list mountpoint %q that the block layer mounts", mp)
		}
	}
	for mp := range got {
		if !want[mp] {
			t.Errorf("/etc/fstab lists mountpoint %q that the block layer (df/mount/lsblk) never shows", mp)
		}
	}
}

// TestProcessStartCoherentWithUptime proves ps cannot contradict uptime. The
// long-running daemons must show a START derived from the (randomized) boot epoch,
// not a hardcoded date: a box that has been "up 9 days" while init shows it started
// three weeks ago is a one-glance tell.
func TestProcessStartCoherentWithUptime(t *testing.T) {
	p, _ := loadHost(t)
	bootDate := time.Unix(p.BootEpoch, 0).Format("Jan02")

	ps := psStr(p, true, time.Now())
	// init (PID 1) is the canonical boot daemon; its START must be the boot date.
	initLine := ""
	for _, line := range strings.Split(ps, "\n") {
		if strings.Contains(line, "/sbin/init") {
			initLine = line
		}
	}
	if initLine == "" {
		t.Fatalf("ps aux did not list /sbin/init:\n%s", ps)
	}
	if !strings.Contains(initLine, bootDate) {
		t.Errorf("init START is not the boot date %q (ps must derive START from BootEpoch, not a literal):\n%s", bootDate, initLine)
	}
	// A hardcoded month/day that disagrees with the boot epoch is the exact bug.
	if !strings.Contains(ps, bootDate) {
		t.Errorf("no process shows the boot date %q; ps START is not derived from uptime/BootEpoch", bootDate)
	}
}

// TestSystemctlMainPidMatchesPs proves `systemctl status <svc>` and `ps aux` name
// the same Main PID for a daemon. A skeptic who runs both and sees two PIDs for
// nginx has caught the box.
func TestSystemctlMainPidMatchesPs(t *testing.T) {
	p, _ := loadHost(t)
	ps := psStr(p, true, time.Now())
	pidRe := regexp.MustCompile(`Main PID:\s*(\d+)`)
	for _, svc := range []string{"nginx", "mysql", "ssh"} {
		status, code := systemctlStatus(p, svc)
		if code != 0 {
			t.Errorf("systemctl status %s should be a known running unit, got exit %d", svc, code)
			continue
		}
		m := pidRe.FindStringSubmatch(status)
		if m == nil {
			t.Errorf("systemctl status %s has no Main PID:\n%s", svc, status)
			continue
		}
		want := m[1]
		if !psListsMainPID(ps, svc, want) {
			t.Errorf("systemctl says %s Main PID=%s but ps aux does not show that pid as the %s master:\n%s", svc, want, svc, ps)
		}
	}
}

// psListsMainPID reports whether ps shows pid as a master/daemon process for the
// given service keyword (the systemd Main PID is the master, not a worker).
func psListsMainPID(ps, svc, pid string) bool {
	key := svc
	switch svc {
	case "mysql":
		key = "mysqld"
	case "ssh":
		key = "sshd"
	}
	for _, line := range strings.Split(ps, "\n") {
		if !strings.Contains(line, key) || strings.Contains(line, "worker") {
			continue
		}
		f := strings.Fields(line)
		if len(f) > 1 && f[1] == pid {
			return true
		}
	}
	return false
}

// TestListenersMatchPersonaServices proves the ports netstat/ss advertise as
// externally listening are exactly the services this instance exposes. A 0.0.0.0
// LISTEN on a port the persona does not serve (or a served port absent from
// netstat) is a contradiction a scanner cross-checks against what actually answered.
func TestListenersMatchPersonaServices(t *testing.T) {
	p, _ := loadHost(t)
	want := map[int]bool{}
	for _, s := range p.Services {
		if s.Protocol == "https" || s.Protocol == "http" || s.Protocol == "ssh" || s.Protocol == "telnet" || s.Protocol == "ftp" {
			want[s.Port] = true
		}
	}
	for _, gen := range []struct {
		name, out string
	}{{"netstat", netstatStr(p)}, {"ss", ssStr(p)}} {
		got := externalListenPorts(gen.out)
		for port := range want {
			if !got[port] {
				t.Errorf("%s does not show a listener on :%d, a service this persona exposes", gen.name, port)
			}
		}
		for port := range got {
			if !want[port] {
				t.Errorf("%s advertises a 0.0.0.0 listener on :%d that persona.Services does not expose", gen.name, port)
			}
		}
	}
}

// externalListenPorts returns the set of ports in LISTEN state bound to 0.0.0.0
// (externally reachable) in a netstat/ss block. Loopback-bound listeners (internal
// daemons like mysqld on 127.0.0.1) are intentionally excluded.
func externalListenPorts(out string) map[int]bool {
	ports := map[int]bool{}
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "LISTEN") {
			continue
		}
		for _, f := range strings.Fields(line) {
			if strings.HasPrefix(f, "0.0.0.0:") {
				if n, err := strconv.Atoi(strings.TrimPrefix(f, "0.0.0.0:")); err == nil {
					ports[n] = true
				}
			}
		}
	}
	return ports
}
