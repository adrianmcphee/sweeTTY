package shell

import (
	"strconv"
	"strings"
	"testing"

	"sweetty/internal/fakehost"
	"sweetty/internal/persona"
)

// The embedded board's disk story must be its own coherent thing: a single SD card,
// no Xen data disk, and no x86/Intel/vmlinuz boot residue. df, mount and lsblk have
// to agree on the device->mountpoint map (the same invariant TestDiskStoryIsCoherent
// pins for the x86 server), every advertised mountpoint must exist in the VFS, and
// used + available can never exceed the filesystem size.
func TestEmbeddedDiskStoryIsCoherent(t *testing.T) {
	p := persona.GenerateProfile("legacy")
	fs, err := fakehost.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	sess := fs.NewSession("/")

	df := dfMounts(dfStr(p))
	mnt := mountMounts(mountStr(p))
	lsblk := lsblkMounts(lsblkStr(p))
	if len(df) == 0 {
		t.Fatalf("embedded df reports no real-device mount:\n%s", dfStr(p))
	}
	for dev, mp := range df {
		if mnt[dev] != mp {
			t.Errorf("mount disagrees with df for %s: df=%q mount=%q", dev, mp, mnt[dev])
		}
		if lsblk[dev] != mp {
			t.Errorf("lsblk disagrees with df for %s: df=%q lsblk=%q", dev, mp, lsblk[dev])
		}
		if !strings.Contains(dev, "mmcblk") {
			t.Errorf("embedded root device is not an SD card: %q", dev)
		}
		if n, err := sess.Stat(mp); err != nil || !n.IsDir() {
			t.Errorf("mountpoint %q (%s) missing or not a directory: %v", mp, dev, err)
		}
	}
	if len(mnt) != len(df) || len(lsblk) != len(df) {
		t.Errorf("df/mount/lsblk disagree on mount count: df=%d mount=%d lsblk=%d", len(df), len(mnt), len(lsblk))
	}

	// used + available == size on every real-device df line (no fictional free space).
	for _, line := range strings.Split(dfStr(p), "\n") {
		f := strings.Fields(line)
		if len(f) < 6 || !strings.HasPrefix(f[0], "/dev/") {
			continue
		}
		blocks, _ := strconv.Atoi(f[1])
		used, _ := strconv.Atoi(f[2])
		avail, _ := strconv.Atoi(f[3])
		if used+avail != blocks {
			t.Errorf("df line %q: used(%d)+avail(%d) != size(%d)", f[0], used, avail, blocks)
		}
	}

	// No x86 / Xen / Intel / vmlinuz residue anywhere in the disk + boot story.
	story := dfStr(p) + mountStr(p) + lsblkStr(p) + dmesgStr(p)
	for _, bad := range []string{"xvda", "xvdb", "Xen", "xen", "x86", "Intel", "GenuineIntel", "vmlinuz", "amd64"} {
		if strings.Contains(story, bad) {
			t.Errorf("embedded disk/boot story leaks %q:\n%s", bad, story)
		}
	}
	// ...and it is unmistakably an ARM board.
	if !strings.Contains(dmesgStr(p), "arm64") {
		t.Errorf("embedded dmesg does not read as arm64:\n%s", dmesgStr(p))
	}
}

// Two boxes must never present byte-identical disk geometry (doctrine #7): a scanner
// that correlates IPs would otherwise fingerprint the honeypot on df alone. The
// numbers are derived from the persona, so they are stable per instance yet vary
// across instances, while df and lsblk still agree (proven above).
func TestDiskGeometryVariesPerInstance(t *testing.T) {
	for _, profile := range []string{"web", "legacy"} {
		seenDF := map[string]bool{}
		seenLsblk := map[string]bool{}
		for range 16 {
			p := persona.GenerateProfile(profile)
			seenDF[dfStr(p)] = true
			seenLsblk[lsblkStr(p)] = true
		}
		if len(seenDF) < 2 {
			t.Errorf("%s: df is identical across 16 instances — geometry is not per-instance", profile)
		}
		if len(seenLsblk) < 2 {
			t.Errorf("%s: lsblk is identical across 16 instances — geometry is not per-instance", profile)
		}
	}
}

// The geometry must be stable within one instance: df called twice on the same box
// can never disagree, or a recon attacker watching free space sees it teleport.
func TestDiskGeometryIsStableWithinInstance(t *testing.T) {
	p := persona.GenerateProfile("legacy")
	if dfStr(p) != dfStr(p) || lsblkStr(p) != lsblkStr(p) {
		t.Fatal("disk geometry changed between calls on the same persona")
	}
}
