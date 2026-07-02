package vfs

import (
	"errors"
	"io/fs"
	"strings"
	"testing"
)

// TestNoPathEscapesFakeRoot locks the behavioural half of the vfs safety story. The
// structural half lives in internal/safety: the vfs cannot import os, os/exec, net,
// net/http, or syscall, so it physically cannot read the host disk, execute, or
// reach the network, which makes a true host escape impossible by construction.
// This test proves the resolution logic on top of that: attacker `..` traversal is
// clamped at the fake root and never leaves a .. in the path, and a path that would
// reach the host's /etc/passwd resolves to the EMBEDDED one, returning embedded
// content, never a host file.
func TestNoPathEscapesFakeRoot(t *testing.T) {
	s := testFS(t).NewSession("/root")

	for _, p := range []string{
		"../../../../etc/passwd",
		"/../../../etc/passwd",
		"/etc/../../../../etc/passwd",
		"../../../../../../../../",
	} {
		got := s.Resolve(p)
		if !strings.HasPrefix(got, "/") || strings.Contains(got, "..") {
			t.Errorf("Resolve(%q) = %q escaped the root or left a .. in the path", p, got)
		}
	}

	// A deep traversal that would reach the host /etc/passwd resolves to the embedded
	// one and returns its content, proving reads come only from the fake tree.
	body, err := s.ReadFile("../../../../../../etc/passwd")
	if err != nil {
		t.Fatalf("read via traversal: %v", err)
	}
	if !strings.Contains(string(body), "root:x:0:0") {
		t.Errorf("traversal read did not return the embedded /etc/passwd: %q", body)
	}

	// A path that resolves to nothing in the tree is simply not-found, never a host peek.
	if _, err := s.ReadFile("/../this-is-not-in-the-embedded-tree"); !errors.Is(err, ErrNotExist) {
		t.Errorf("unknown path should be ErrNotExist, got %v", err)
	}
}

// TestSymlinkCannotEscapeToHost proves a symlink whose target is an absolute path is
// still resolved inside the fake tree: following it reaches an embedded node or
// not-found, and can never open a host file (again, the vfs holds no os handle at
// all). It also confirms a symlink cycle terminates rather than looping forever.
func TestSymlinkCannotEscapeToHost(t *testing.T) {
	s := testFS(t).NewSession("/")

	// /bin/sh -> /usr/bin/bash (from the test manifest): an absolute-target symlink
	// resolves to the embedded bash stub, not anything on the host.
	n, err := s.Stat("/bin/sh")
	if err != nil {
		t.Fatalf("stat /bin/sh: %v", err)
	}
	if n.IsLink() {
		t.Fatal("stat should have followed the symlink into the embedded tree")
	}

	// A self-referential symlink must bottom out at the link-depth bound rather than
	// recursing without limit (a loop would otherwise hang or overflow the stack).
	s.overlay["/tmp/loop"] = &Node{name: "loop", mode: fs.ModeSymlink | 0o777, link: "/tmp/loop"}
	if _, err := s.Stat("/tmp/loop"); err == nil {
		t.Error("a symlink cycle should resolve to an error, not succeed")
	}
}
