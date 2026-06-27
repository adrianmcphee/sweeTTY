// Package vfs is a small in-memory virtual filesystem: one read-only node tree
// shared by every connection, plus a per-session copy-on-write overlay so an
// attacker's mutations (touch, mkdir, redirect, fake downloads) are visible for
// the rest of their session and then evaporate. Nothing here ever touches the
// real host filesystem.
package vfs

import (
	"errors"
	"io/fs"
	"time"
)

// Sentinel errors. Callers should match with errors.Is, since lookups may wrap
// them with path context.
var (
	ErrNotExist   = errors.New("no such file or directory")
	ErrPermission = errors.New("permission denied")
	ErrNotDir     = errors.New("not a directory")
	ErrIsDir      = errors.New("is a directory")
	ErrExist      = errors.New("file exists")
	// ErrNoSpace is returned when a session's in-memory overlay hits its byte or
	// entry budget. The overlay holds attacker-written bytes in RAM, so without a
	// ceiling a few redirect lines (cat a a a > a) can amplify a 64KB seed into
	// gigabytes and OOM-kill the whole multi-listener process. Callers surface this
	// as a believable "No space left on device".
	ErrNoSpace = errors.New("no space left on device")
)

// Node is one filesystem entry: a file, directory, or symlink. Fields are
// unexported; the accessors below are what callers (the shell) use to format
// ls/stat output, so listings and reads always agree.
type Node struct {
	name     string
	mode     fs.FileMode // includes type bits (ModeDir, ModeSymlink, ModeSticky)
	uid, gid int
	uname    string
	gname    string
	mtime    time.Time
	content  []byte // file body; nil for dirs and links
	link     string // target, for symlinks
	stub     bool   // synthetic binary; Content yields an ELF header
	size     int64  // declared size; for stubs this exceeds len(content)

	children map[string]*Node
}

func (n *Node) Name() string       { return n.name }
func (n *Node) Mode() fs.FileMode  { return n.mode }
func (n *Node) IsDir() bool        { return n.mode&fs.ModeDir != 0 }
func (n *Node) IsLink() bool       { return n.mode&fs.ModeSymlink != 0 }
func (n *Node) Uid() int           { return n.uid }
func (n *Node) Gid() int           { return n.gid }
func (n *Node) Uname() string      { return n.uname }
func (n *Node) Gname() string      { return n.gname }
func (n *Node) Mtime() time.Time   { return n.mtime }
func (n *Node) LinkTarget() string { return n.link }

// Size reports the entry size used by ls -l. Directories are the conventional
// 4096; stub binaries report their declared size.
func (n *Node) Size() int64 {
	if n.IsDir() {
		return 4096
	}
	if n.stub && n.size > 0 {
		return n.size
	}
	return int64(len(n.content))
}

// LinkCount reports the hard-link count shown by ls -l and stat. A regular file or
// symlink has one link; a directory has two (its own "." and its entry in its
// parent) plus one for every immediate subdirectory's "..". A directory reporting a
// link count of one is impossible on a real filesystem and a clear tell, so this
// derives the real value from the tree.
func (n *Node) LinkCount() int {
	if !n.IsDir() {
		return 1
	}
	links := 2
	for _, c := range n.children {
		if c.IsDir() {
			links++
		}
	}
	return links
}

// Content returns the bytes a reader would see. Stub binaries yield a short but
// valid-looking ELF header so file/head -c4 detect ELF rather than random noise.
func (n *Node) Content() []byte {
	if n.stub {
		return elfStub()
	}
	return n.content
}

// elfStub is a minimal but plausible 64-bit LSB ELF executable header.
func elfStub() []byte {
	b := make([]byte, 64)
	copy(b, []byte{
		0x7f, 'E', 'L', 'F', // magic
		0x02, // EI_CLASS = ELFCLASS64
		0x01, // EI_DATA  = little-endian
		0x01, // EI_VERSION
		0x00, // EI_OSABI = System V
	})
	b[16] = 0x02 // e_type = ET_EXEC
	b[18] = 0x3e // e_machine = x86-64
	b[20] = 0x01 // e_version
	return b
}

// FS is the shared read-only base tree.
type FS struct {
	root *Node
}

// Root returns the root node.
func (f *FS) Root() *Node { return f.root }

// childOf returns the named child of a base directory node, or nil.
func childOf(dir *Node, name string) *Node {
	if dir == nil || dir.children == nil {
		return nil
	}
	return dir.children[name]
}
