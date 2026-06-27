package vfs

import (
	"io/fs"
	pathpkg "path"
	"sort"
	"strings"
	"time"
)

// Overlay budget. The overlay holds attacker-written bytes in RAM for the life of
// the session, so it needs a ceiling: without one, redirect amplification
// (cat seed seed seed > seed) turns a 64KB seed into gigabytes and the OS
// OOM-killer drops the whole process (a Go out-of-memory is a fatal throw that
// recover() cannot catch). The limits are generous enough that an attacker
// exploring a box never notices, and tight enough that no single session can
// exhaust host memory. A full overlay reports a believable ENOSPC.
const (
	maxOverlayBytes     = 8 << 20 // total bytes across all written files in a session
	maxOverlayFileBytes = 2 << 20 // largest single file
	maxOverlayEntries   = 2048    // overlay nodes + tombstones, bounding entry churn
)

// Session is a per-connection writable view over the shared read-only base tree.
// Writes land in an in-memory overlay and deletions in a tombstone set; neither
// touches the host disk, and both vanish when the session is dropped.
type Session struct {
	base    *FS
	overlay map[string]*Node // abs path -> created/modified node
	deleted map[string]bool  // abs path -> tombstone
	cwd     string
	bytes   int // running sum of overlay file content bytes, for the budget
}

// NewSession returns a fresh writable view rooted at cwd.
func (f *FS) NewSession(cwd string) *Session {
	if cwd == "" {
		cwd = "/"
	}
	return &Session{
		base:    f,
		overlay: map[string]*Node{},
		deleted: map[string]bool{},
		cwd:     cleanAbs(cwd),
	}
}

// entries counts everything the session is keeping in memory: overlay nodes plus
// tombstones. Both grow with attacker churn (touch/mkdir/rm loops), so both are
// bounded by maxOverlayEntries.
func (s *Session) entries() int { return len(s.overlay) + len(s.deleted) }

func (s *Session) Cwd() string { return s.cwd }

// Resolve turns a possibly-relative path into a clean absolute path against cwd.
func (s *Session) Resolve(p string) string {
	if p == "" {
		return s.cwd
	}
	if !strings.HasPrefix(p, "/") {
		p = pathpkg.Join(s.cwd, p)
	}
	return cleanAbs(p)
}

// Stat resolves a path, following a final symlink. Lstat does not follow it.
func (s *Session) Stat(p string) (*Node, error)  { return s.lookup(s.Resolve(p), true, 0) }
func (s *Session) Lstat(p string) (*Node, error) { return s.lookup(s.Resolve(p), false, 0) }

// ReadFile returns the bytes of a file, following symlinks.
func (s *Session) ReadFile(p string) ([]byte, error) {
	n, err := s.lookup(s.Resolve(p), true, 0)
	if err != nil {
		return nil, err
	}
	if n.IsDir() {
		return nil, ErrIsDir
	}
	return n.Content(), nil
}

// ReadDir lists a directory, merging base children with overlay additions and
// hiding tombstoned entries, sorted by name.
func (s *Session) ReadDir(p string) ([]*Node, error) {
	abs := s.Resolve(p)
	node, err := s.lookup(abs, true, 0)
	if err != nil {
		return nil, err
	}
	if !node.IsDir() {
		return nil, ErrNotDir
	}
	seen := map[string]*Node{}
	for name, c := range node.children {
		seen[name] = c
	}
	for op, on := range s.overlay {
		if parentDir(op) == abs {
			seen[baseName(op)] = on
		}
	}
	out := make([]*Node, 0, len(seen))
	for name, c := range seen {
		if s.isDeleted(pathpkg.Join(abs, name)) {
			continue
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out, nil
}

// Chdir changes the working directory if the target exists and is a directory.
func (s *Session) Chdir(p string) error {
	abs := s.Resolve(p)
	n, err := s.lookup(abs, true, 0)
	if err != nil {
		return err
	}
	if !n.IsDir() {
		return ErrNotDir
	}
	s.cwd = abs
	return nil
}

// WriteFile creates or replaces a file in the overlay.
func (s *Session) WriteFile(p string, content []byte) error {
	abs := s.Resolve(p)
	if abs == "/" {
		return ErrIsDir
	}
	pn, err := s.lookup(parentDir(abs), true, 0)
	if err != nil {
		return ErrNotExist
	}
	if !pn.IsDir() {
		return ErrNotDir
	}
	if existing, err := s.lookup(abs, false, 0); err == nil && existing.IsDir() {
		return ErrIsDir
	}
	if len(content) > maxOverlayFileBytes {
		return ErrNoSpace
	}
	// Budget the write: a replacement releases the bytes it overwrites; a brand new
	// path also consumes an entry slot. Either way the projected totals must stay
	// within the session ceiling.
	oldLen := 0
	_, isReplacement := s.overlay[abs]
	if prev := s.overlay[abs]; prev != nil && !prev.IsDir() {
		oldLen = len(prev.content)
	}
	if s.bytes-oldLen+len(content) > maxOverlayBytes {
		return ErrNoSpace
	}
	if !isReplacement && s.entries() >= maxOverlayEntries {
		return ErrNoSpace
	}
	delete(s.deleted, abs)
	s.bytes = s.bytes - oldLen + len(content)
	s.overlay[abs] = &Node{
		name:    baseName(abs),
		mode:    0644,
		uname:   "root",
		gname:   "root",
		mtime:   time.Now(),
		content: content,
	}
	return nil
}

// Mkdir creates a directory in the overlay.
func (s *Session) Mkdir(p string) error {
	abs := s.Resolve(p)
	if abs == "/" {
		return ErrExist
	}
	pn, err := s.lookup(parentDir(abs), true, 0)
	if err != nil {
		return ErrNotExist
	}
	if !pn.IsDir() {
		return ErrNotDir
	}
	if _, err := s.lookup(abs, false, 0); err == nil {
		return ErrExist
	}
	if _, tombstoned := s.deleted[abs]; !tombstoned && s.entries() >= maxOverlayEntries {
		return ErrNoSpace
	}
	delete(s.deleted, abs)
	s.overlay[abs] = &Node{
		name:     baseName(abs),
		mode:     fs.ModeDir | 0755,
		uname:    "root",
		gname:    "root",
		mtime:    time.Now(),
		children: map[string]*Node{},
	}
	return nil
}

// Remove tombstones a path (file or directory) for this session.
func (s *Session) Remove(p string) error {
	abs := s.Resolve(p)
	if abs == "/" {
		return ErrPermission
	}
	if _, err := s.lookup(abs, false, 0); err != nil {
		return err
	}
	if prev := s.overlay[abs]; prev != nil && !prev.IsDir() {
		s.bytes -= len(prev.content)
	}
	delete(s.overlay, abs)
	s.deleted[abs] = true
	return nil
}

// Exists reports whether a path resolves to something visible in this session.
func (s *Session) Exists(p string) bool {
	_, err := s.lookup(s.Resolve(p), true, 0)
	return err == nil
}

// ---- resolution ----

const maxLinkDepth = 40

func (s *Session) lookup(abs string, followFinal bool, depth int) (*Node, error) {
	if depth > maxLinkDepth {
		return nil, ErrNotExist
	}
	abs = cleanAbs(abs)
	if s.isDeleted(abs) {
		return nil, ErrNotExist
	}
	if abs == "/" {
		return s.base.root, nil
	}
	parts := splitPath(abs)
	node := s.base.root
	cur := "/"
	for i, name := range parts {
		if node == nil {
			return nil, ErrNotExist
		}
		if !node.IsDir() {
			return nil, ErrNotDir
		}
		child := s.child(cur, node, name)
		if child == nil {
			return nil, ErrNotExist
		}
		isFinal := i == len(parts)-1
		if child.IsLink() && (!isFinal || followFinal) {
			target, err := s.resolveLink(cur, child, depth+1)
			if err != nil {
				return nil, err
			}
			child = target
		}
		node = child
		cur = pathpkg.Join(cur, name)
	}
	return node, nil
}

func (s *Session) child(parentAbs string, parentNode *Node, name string) *Node {
	childAbs := pathpkg.Join(parentAbs, name)
	if s.isDeleted(childAbs) {
		return nil
	}
	if ov, ok := s.overlay[childAbs]; ok {
		return ov
	}
	return childOf(parentNode, name)
}

func (s *Session) resolveLink(parentAbs string, link *Node, depth int) (*Node, error) {
	tgt := link.link
	var abs string
	if strings.HasPrefix(tgt, "/") {
		abs = cleanAbs(tgt)
	} else {
		abs = cleanAbs(pathpkg.Join(parentAbs, tgt))
	}
	return s.lookup(abs, true, depth)
}

func (s *Session) isDeleted(abs string) bool {
	for p := abs; ; p = parentDir(p) {
		if s.deleted[p] {
			return true
		}
		if p == "/" {
			return false
		}
	}
}

// ---- path helpers ----

func cleanAbs(p string) string {
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return pathpkg.Clean(p)
}

func splitPath(abs string) []string {
	abs = strings.Trim(abs, "/")
	if abs == "" {
		return nil
	}
	return strings.Split(abs, "/")
}

func parentDir(abs string) string { return pathpkg.Dir(abs) }
func baseName(abs string) string  { return pathpkg.Base(abs) }
