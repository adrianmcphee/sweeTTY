package vfs

import (
	"encoding/json"
	"io/fs"
	"strconv"
	"strings"
	"time"
)

// manifest describes filesystem metadata that embedded file content cannot carry
// on its own: ownership, permissions, timestamps, plus synthetic directories,
// symlinks, and stub binaries that make listings look like a real host.
type manifest struct {
	Defaults manifestDefaults        `json:"defaults"`
	Meta     map[string]metaOverride `json:"meta"`
	Dirs     []dirEntry              `json:"dirs"`
	Links    []linkEntry             `json:"links"`
	Binaries []binGroup              `json:"binaries"`
}

type manifestDefaults struct {
	UID      int    `json:"uid"`
	GID      int    `json:"gid"`
	Uname    string `json:"uname"`
	Gname    string `json:"gname"`
	DirMode  string `json:"dirmode"`
	FileMode string `json:"filemode"`
	Mtime    string `json:"mtime"` // absolute (RFC3339 / date) or relative ("-45d")
}

type metaOverride struct {
	Mode  string `json:"mode,omitempty"`
	UID   *int   `json:"uid,omitempty"`
	GID   *int   `json:"gid,omitempty"`
	Uname string `json:"uname,omitempty"`
	Gname string `json:"gname,omitempty"`
	Mtime string `json:"mtime,omitempty"`
}

type dirEntry struct {
	Path  string `json:"path"`
	Mode  string `json:"mode,omitempty"`
	Uname string `json:"uname,omitempty"`
	Gname string `json:"gname,omitempty"`
	UID   *int   `json:"uid,omitempty"`
	GID   *int   `json:"gid,omitempty"`
}

type linkEntry struct {
	Path   string `json:"path"`
	Target string `json:"target"`
}

type binGroup struct {
	Dir   string   `json:"dir"`
	Names []string `json:"names"`
	Mode  string   `json:"mode,omitempty"`
	Size  int64    `json:"size,omitempty"`
}

type loader struct {
	f         *FS
	defDir    fs.FileMode
	defFile   fs.FileMode
	uid, gid  int
	uname     string
	gname     string
	baseMtime time.Time
}

// Transform optionally rewrites a file's content as it is loaded, keyed by its
// absolute path. It is used to render per-instance templates so nothing
// identifying is fixed in the embedded source. A nil Transform is identity.
type Transform func(path string, content []byte) []byte

// Load builds a read-only FS from an embedded tree rooted at root within efs. A
// manifest.json at the tree root supplies metadata; file content comes from the
// embedded files themselves (optionally rewritten by transform), so sizes and
// reads always agree.
func Load(efs fs.FS, root string, transform Transform) (*FS, error) {
	now := time.Now()

	var m manifest
	if data, err := fs.ReadFile(efs, root+"/manifest.json"); err == nil {
		if err := json.Unmarshal(data, &m); err != nil {
			return nil, err
		}
	}

	ld := &loader{
		f:         &FS{},
		defDir:    fs.ModeDir | modeOr(m.Defaults.DirMode, 0o755),
		defFile:   modeOr(m.Defaults.FileMode, 0o644),
		uid:       m.Defaults.UID,
		gid:       m.Defaults.GID,
		uname:     orStr(m.Defaults.Uname, "root"),
		gname:     orStr(m.Defaults.Gname, "root"),
		baseMtime: parseWhen(m.Defaults.Mtime, now),
	}
	ld.f.root = &Node{
		name:     "/",
		mode:     fs.ModeDir | 0o755,
		uname:    ld.uname,
		gname:    ld.gname,
		mtime:    ld.baseMtime,
		children: map[string]*Node{},
	}

	// 1. Embedded files and their directories.
	err := fs.WalkDir(efs, root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == root {
			return nil
		}
		abs := "/" + strings.TrimPrefix(p, root+"/")
		if base := baseName(abs); base == "manifest.json" || base == ".DS_Store" {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			ld.ensureDir(abs)
			return nil
		}
		content, rerr := fs.ReadFile(efs, p)
		if rerr != nil {
			return rerr
		}
		if transform != nil {
			content = transform(abs, content)
		}
		ld.addFile(abs, content)
		return nil
	})
	if err != nil {
		return nil, err
	}

	// 2. Synthetic directories.
	for _, de := range m.Dirs {
		n := ld.ensureDir(cleanAbs(de.Path))
		if pm, ok := parseMode(de.Mode); ok {
			n.mode = fs.ModeDir | pm
		}
		applyOwner(n, de.Uname, de.Gname, de.UID, de.GID)
	}

	// 3. Stub binaries.
	for _, bg := range m.Binaries {
		mode := fs.FileMode(0o755)
		if pm, ok := parseMode(bg.Mode); ok {
			mode = pm
		}
		dir := ld.ensureDir(cleanAbs(bg.Dir))
		for _, name := range bg.Names {
			// Derive a stable per-binary size and mtime from the name. Real binaries
			// span tens of KB to over a MB and were installed at slightly different
			// times; a whole /usr/bin at one identical size and date is an instant tell.
			// An explicit bg.Size still pins the group if a manifest wants a fixed value.
			size := bg.Size
			mtime := ld.baseMtime
			if size == 0 {
				h := binHash(name)
				size = int64(14000 + h%1250000)
				mtime = ld.baseMtime.Add(-time.Duration(h%3000) * time.Hour)
			}
			dir.children[name] = &Node{
				name: name, mode: mode, uid: ld.uid, gid: ld.gid,
				uname: ld.uname, gname: ld.gname, mtime: mtime,
				stub: true, size: size,
			}
		}
	}

	// 4. Symlinks.
	for _, le := range m.Links {
		abs := cleanAbs(le.Path)
		parent := ld.ensureDir(parentDir(abs))
		name := baseName(abs)
		parent.children[name] = &Node{
			name: name, mode: fs.ModeSymlink | 0o777,
			uname: ld.uname, gname: ld.gname, mtime: ld.baseMtime, link: le.Target,
		}
	}

	// 5. Metadata overrides (last, so they win).
	for path, ov := range m.Meta {
		n := ld.f.getNode(cleanAbs(path))
		if n == nil {
			continue
		}
		if pm, ok := parseMode(ov.Mode); ok {
			n.mode = (n.mode & fs.ModeType) | pm
		}
		applyOwner(n, ov.Uname, ov.Gname, ov.UID, ov.GID)
		if ov.Mtime != "" {
			n.mtime = parseWhen(ov.Mtime, now)
		}
	}

	return ld.f, nil
}

func (ld *loader) ensureDir(abs string) *Node {
	if abs == "/" || abs == "." {
		return ld.f.root
	}
	parent := ld.ensureDir(parentDir(abs))
	name := baseName(abs)
	if c, ok := parent.children[name]; ok && c.IsDir() {
		return c
	}
	n := &Node{
		name: name, mode: ld.defDir, uid: ld.uid, gid: ld.gid,
		uname: ld.uname, gname: ld.gname, mtime: ld.baseMtime,
		children: map[string]*Node{},
	}
	parent.children[name] = n
	return n
}

func (ld *loader) addFile(abs string, content []byte) {
	parent := ld.ensureDir(parentDir(abs))
	name := baseName(abs)
	parent.children[name] = &Node{
		name: name, mode: ld.defFile, uid: ld.uid, gid: ld.gid,
		uname: ld.uname, gname: ld.gname, mtime: ld.baseMtime, content: content,
	}
}

// Mkdir creates dir (and any missing ancestors) in the base tree and applies
// mode, ownership, and mtime to the leaf. It is how content whose path is
// randomized per instance is grafted in after Load, since embedded paths are
// fixed at build time. Ancestors that must be created are given conventional
// directory perms inherited from the root.
func (f *FS) Mkdir(abs string, mode fs.FileMode, uname, gname string, mtime time.Time) *Node {
	abs = cleanAbs(abs)
	if abs == "/" {
		return f.root
	}
	parent := f.mkdirAll(parentDir(abs))
	name := baseName(abs)
	n, ok := parent.children[name]
	if !ok || !n.IsDir() {
		n = &Node{name: name, children: map[string]*Node{}}
		parent.children[name] = n
	}
	n.mode = fs.ModeDir | mode
	n.uname, n.gname, n.mtime = uname, gname, mtime
	return n
}

// mkdirAll ensures every directory on the path to abs exists, returning the leaf.
// Created directories inherit the root's ownership and conventional 0755 perms.
func (f *FS) mkdirAll(abs string) *Node {
	abs = cleanAbs(abs)
	if abs == "/" || abs == "." {
		return f.root
	}
	parent := f.mkdirAll(parentDir(abs))
	name := baseName(abs)
	if c, ok := parent.children[name]; ok && c.IsDir() {
		return c
	}
	n := &Node{
		name: name, mode: fs.ModeDir | 0o755,
		uname: f.root.uname, gname: f.root.gname, mtime: f.root.mtime,
		children: map[string]*Node{},
	}
	parent.children[name] = n
	return n
}

// binHash is a small stable FNV-1a hash of a binary name, used to derive a varied
// but repeatable size and mtime so a stub-binary listing looks like a real one.
func binHash(name string) uint32 {
	h := uint32(2166136261)
	for i := 0; i < len(name); i++ {
		h = (h ^ uint32(name[i])) * 16777619
	}
	return h
}

// Place writes a file at abs (creating ancestor directories) with the given
// content, mode, ownership, and mtime, overwriting any existing node. It is the
// file counterpart to Mkdir for grafting per-instance content.
func (f *FS) Place(abs string, content []byte, mode fs.FileMode, uname, gname string, mtime time.Time) {
	abs = cleanAbs(abs)
	if abs == "/" {
		return
	}
	parent := f.mkdirAll(parentDir(abs))
	name := baseName(abs)
	parent.children[name] = &Node{
		name: name, mode: mode, uname: uname, gname: gname,
		mtime: mtime, content: content,
	}
}

func (f *FS) getNode(abs string) *Node {
	if abs == "/" {
		return f.root
	}
	node := f.root
	for _, name := range splitPath(abs) {
		if node == nil || node.children == nil {
			return nil
		}
		node = node.children[name]
	}
	return node
}

func applyOwner(n *Node, uname, gname string, uid, gid *int) {
	if uname != "" {
		n.uname = uname
	}
	if gname != "" {
		n.gname = gname
	}
	if uid != nil {
		n.uid = *uid
	}
	if gid != nil {
		n.gid = *gid
	}
}

// parseMode parses a 3- or 4-digit octal mode string into permission and special
// bits. Returns ok=false for an empty or invalid string.
func parseMode(s string) (fs.FileMode, bool) {
	if s == "" {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return 0, false
	}
	mode := fs.FileMode(v & 0o777)
	if v&0o4000 != 0 {
		mode |= fs.ModeSetuid
	}
	if v&0o2000 != 0 {
		mode |= fs.ModeSetgid
	}
	if v&0o1000 != 0 {
		mode |= fs.ModeSticky
	}
	return mode, true
}

func modeOr(s string, def fs.FileMode) fs.FileMode {
	if pm, ok := parseMode(s); ok {
		return pm
	}
	return def
}

func orStr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// parseWhen accepts an absolute time (RFC3339 or YYYY-MM-DD) or a relative offset
// like "-45d", "-12h", "-30m", "-10s" from now. Anchoring mtimes to now keeps a
// "live" box from showing frozen build-time dates.
func parseWhen(s string, now time.Time) time.Time {
	if s == "" {
		return now
	}
	if strings.HasPrefix(s, "-") && len(s) >= 3 {
		unit := s[len(s)-1]
		if n, err := strconv.Atoi(s[1 : len(s)-1]); err == nil {
			var d time.Duration
			switch unit {
			case 'd':
				d = time.Duration(n) * 24 * time.Hour
			case 'h':
				d = time.Duration(n) * time.Hour
			case 'm':
				d = time.Duration(n) * time.Minute
			case 's':
				d = time.Duration(n) * time.Second
			default:
				return now
			}
			return now.Add(-d)
		}
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t
	}
	return now
}
