package safety

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// guardCase is one package that processes attacker input and the imports it must
// never carry. "net" is banned wherever a package has no business reaching the
// network at all (the shell, the VFS, the embedded fakehost); the protocol packages
// keep "net" available (they live one import away from the wire) but are still
// barred from the capability primitives.
type guardCase struct {
	dir       string
	forbidden []string
}

// attackerReachable is the full set of internal packages that process attacker
// input, directly or one call from it. Every one must appear in guardCases; the
// enumeration test below fails the build if a new one is added without a guard
// entry. proto/* is checked separately and dynamically, so it is not repeated here.
var attackerReachable = []string{
	"shell", "vfs", "fakehost", "server", "proxyproto",
	"event", "record", "util", "persona",
}

// guardCases is the single source of truth for the import guardrail, shared by the
// scan and by the enumeration check that proves no attacker-reachable package slips
// past it.
func guardCases() []guardCase {
	return []guardCase{
		{"shell", []string{"os", "os/exec", "os/signal", "net", "net/http", "syscall"}},
		{"vfs", []string{"os", "os/exec", "net", "net/http", "syscall"}},
		{"fakehost", []string{"os", "os/exec", "net", "net/http", "syscall"}},
		{"proto/telnet", []string{"os", "os/exec", "net/http", "syscall"}},
		{"proto/ssh", []string{"os", "os/exec", "net/http", "syscall"}},
		{"proto/https", []string{"os", "os/exec", "net/http", "syscall"}},
		{"proto/ftp", []string{"os", "os/exec", "net/http", "syscall"}},
		{"proto/http", []string{"os", "os/exec", "net/http", "syscall"}},
		{"proto/adb", []string{"os", "os/exec", "net/http", "syscall"}},
		// server and proxyproto read raw attacker bytes (the accept loop, the PROXY
		// header); they need bare net but nothing that fetches, executes, or touches
		// the host disk.
		{"server", []string{"os", "os/exec", "net/http", "syscall"}},
		{"proxyproto", []string{"os", "os/exec", "net/http", "syscall"}},
		// event and record write attacker-derived strings/bytes to operator-owned
		// files, so they legitimately need os; they must never fetch or execute.
		{"event", []string{"os/exec", "net/http", "syscall"}},
		{"record", []string{"os/exec", "net/http", "syscall"}},
		// persona runs on every login (Accept) and renders into attacker-visible output
		// (uname, banners, /etc files); it needs os only to persist the instance identity
		// at startup, so it gets the same os-but-no-capability treatment as event/record,
		// plus a bare-net ban since it has no business reaching the network.
		{"persona", []string{"os/exec", "net", "net/http", "syscall"}},
		// util parses addresses, so bare net is allowed; the capability primitives are not.
		{"util", []string{"os", "os/exec", "net/http", "syscall"}},
	}
}

// TestHandlersHaveNoCapabilityImports is the structural proof behind the safety
// doctrine. The packages that process attacker input must not import the means to
// breach a boundary: os/exec (execute), net/http (fetch), os (host disk), syscall
// (raw host calls), and for the shell/VFS/fakehost, net (outbound) at all. A
// regression that adds a "verify the URL" http.Get or an os.ReadFile fallback fails
// here, where a behavioral-only test would stay green.
func TestHandlersHaveNoCapabilityImports(t *testing.T) {
	internal := internalDir(t)
	for _, c := range guardCases() {
		dir := filepath.Join(internal, filepath.FromSlash(c.dir))
		imports := scanImports(t, dir)
		for _, banned := range c.forbidden {
			if where := imports[banned]; where != "" {
				t.Errorf("package internal/%s must not import %q (found in %s): it would breach the safety doctrine",
					c.dir, banned, filepath.Base(where))
			}
		}
	}
}

// TestEveryProtoPackageIsGuarded proves the guardrail cannot be outgrown: every
// package under internal/proto (each an attacker-facing handler) must appear in the
// cases above. A new protocol added without a guard entry fails here instead of
// silently shipping unscanned.
func TestEveryProtoPackageIsGuarded(t *testing.T) {
	internal := internalDir(t)
	scanned := map[string]bool{}
	for _, c := range guardCases() {
		scanned[c.dir] = true
	}
	entries, err := os.ReadDir(filepath.Join(internal, "proto"))
	if err != nil {
		t.Fatalf("read internal/proto: %v", err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := "proto/" + e.Name()
		if !scanned[dir] {
			t.Errorf("internal/%s is an attacker-facing protocol but is not in the safety import scan; add it to guardCases", dir)
		}
	}
}

// TestEveryAttackerReachablePackageIsGuarded extends the proto enumeration to the
// rest of the attacker-reachable surface (the shell, the VFS, the server, the
// loggers, persona). The original guard scanned only proto/*, so a non-proto
// package like persona could carry a capability import unscanned; this asserts the
// whole list is covered, so the next omission fails the build rather than silently
// widening the boundary.
func TestEveryAttackerReachablePackageIsGuarded(t *testing.T) {
	scanned := map[string]bool{}
	for _, c := range guardCases() {
		scanned[c.dir] = true
	}
	for _, pkg := range attackerReachable {
		if !scanned[pkg] {
			t.Errorf("internal/%s is attacker-reachable but missing from guardCases; add it to the import guard", pkg)
		}
	}
}

// scanImports returns every import path used by the non-test .go files in dir,
// mapped to the file it appeared in.
func scanImports(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	fset := token.NewFileSet()
	found := false
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		found = true
		path := filepath.Join(dir, name)
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, imp := range f.Imports {
			out[strings.Trim(imp.Path.Value, `"`)] = path
		}
	}
	if !found {
		t.Fatalf("no non-test Go files found in %s", dir)
	}
	return out
}

func internalDir(t *testing.T) string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate the test source file")
	}
	// file is .../internal/safety/imports_test.go -> two dirs up is internal/.
	return filepath.Dir(filepath.Dir(file))
}
