package fakehost

import (
	"embed"
	"strings"
	"time"

	"sweetty/internal/persona"
	"sweetty/internal/vfs"
)

//go:embed all:fakeroot_nas
var nasFS embed.FS

// decoyFS holds the image bytes grafted into the per-instance loot directory.
// They live outside the served fakeroot_nas tree (whose paths are fixed) because
// the loot directory's path is randomized per instance and assembled at load
// time. The bytes are deliberately innocuous images: an attacker who only ls/stat/
// file/head's a bait sees a normal photo, and the gag fires the moment they try to
// actually view or grab one (cat, base64, an ASCII image viewer) - that is what
// renders the colour-ANSI payload from internal/shell/reveal.
//
//go:embed decoys
var decoyFS embed.FS

// baitNames are the alluring filenames planted in the loot directory. They are the
// lure, not a spoiler: each promises exactly what an attacker came to steal.
var baitNames = []string{
	"aws_root_keys.png",
	"prod_db_credentials.png",
	"wallet_seed_phrase.png",
	"vpn_config_admin.png",
	"ssl_private_backup.jpg",
	"customer_export_full.jpg",
	"payroll_2026_q2.jpg",
}

// LoadNAS builds the backup/NAS host an attacker can pivot to from the main host,
// rendered against the (derived) persona so it shares the network and carries its
// own hostname.
//
// The bait images are not at a fixed location: they are grafted into this
// instance's randomized, obscure loot directory (persona.LootPath), which the
// breadcrumb trail - the NAS shell history - leads to. Nothing in the filesystem
// reveals the gag; finding the stash takes real work, and viewing what is in it is
// the payoff. See graftLoot.
func LoadNAS(p *persona.Persona) (*vfs.FS, error) {
	f, err := vfs.Load(nasFS, "fakeroot_nas", renderer(p))
	if err != nil {
		return nil, err
	}
	graftLoot(f, p)
	return f, nil
}

// graftLoot plants the bait images in this instance's per-instance loot directory.
// The directory and files are root-owned and tight-permissioned (0700/0600) to
// match the "moved the private set off the open share" story the NAS history
// tells, and their mtimes are staggered over the days before now so the stash
// looks accreted rather than freshly minted.
func graftLoot(f *vfs.FS, p *persona.Persona) {
	if p.LootPath == "" {
		return
	}
	png, _ := decoyFS.ReadFile("decoys/decoy.png")
	jpg, _ := decoyFS.ReadFile("decoys/decoy.jpg")
	now := time.Now()
	f.Mkdir(p.LootPath, 0o700, "root", "root", now.Add(-6*24*time.Hour))
	for i, name := range baitNames {
		data := png
		if strings.HasSuffix(name, ".jpg") || strings.HasSuffix(name, ".jpeg") {
			data = jpg
		}
		mtime := now.Add(-time.Duration(5*24-i*7) * time.Hour)
		f.Place(p.LootPath+"/"+name, data, 0o600, "root", "root", mtime)
	}
}

// NAS resolves a pivot target (a host name or IP) to the backup/NAS host's
// filesystem and its derived persona, or reports that the target is not the NAS.
// The NAS shares the main host's network and software but carries the backup
// hostname and address, so `ssh <backup>` from the main shell lands on a coherent
// neighbour. It is the single source of the pivot for every protocol that offers a
// shell (telnet and ssh), so the two cannot drift. It returns no shell types, so
// fakehost stays independent of the shell package.
func NAS(p *persona.Persona) (*vfs.FS, *persona.Persona, bool) {
	np := *p
	np.Hostname = p.BackupHost
	np.HostIP = p.BackupIP
	fs, err := LoadNAS(&np)
	if err != nil {
		return nil, nil, false
	}
	return fs, &np, true
}
