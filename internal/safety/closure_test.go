package safety

import (
	"os/exec"
	"sort"
	"strings"
	"testing"
)

// capabilityImports are the stdlib packages that grant the means to breach a safety
// boundary: execute (os/exec), reach the network (net, net/http), touch the host
// disk (os), or make raw host calls (syscall).
var capabilityImports = map[string]bool{
	"os": true, "os/exec": true, "net": true, "net/http": true, "syscall": true,
}

// approvedCapabilities is the allowlist of internal packages permitted to hold a
// capability import, each with the capabilities it may hold and why. Any internal
// package in the honeypot's dependency closure that imports a capability without an
// entry here fails TestNoUnapprovedCapabilityInClosure. os/exec and syscall are on
// no list, so no internal package may hold them at all.
//
// This is the transitive counterpart to guardCases: guardCases denies specific
// imports to specific handlers by their DIRECT imports; this walks the ENTIRE
// closure of the honeypot binary, so a new helper package that quietly holds os or
// net and is called from a handler cannot route around the direct-imports scan.
var approvedCapabilities = map[string][]string{
	"sweetty/internal/event":        {"os"},                    // append the JSON event log to the operator path
	"sweetty/internal/record":       {"os"},                    // write asciinema casts to the operator path
	"sweetty/internal/persona":      {"os"},                    // persist the instance identity at first run
	"sweetty/internal/config":       {"os"},                    // load and write config at startup
	"sweetty/internal/geo":          {"os"},                    // read the operator GeoIP/ASN CSV
	"sweetty/internal/portal":       {"os", "net", "net/http"}, // loopback dashboard: an HTTP server over the log file
	"sweetty/internal/server":       {"net"},                   // the TCP accept loop
	"sweetty/internal/proxyproto":   {"net"},                   // parse the PROXY header
	"sweetty/internal/util":         {"net"},                   // address parsing
	"sweetty/internal/haproxy":      {"net"},                   // hapwatch reads the local HAProxy admin socket (management plane)
	"sweetty/internal/proto/telnet": {"net"},                   // one hop from the wire
	"sweetty/internal/proto/ssh":    {"net"},
	"sweetty/internal/proto/http":   {"net"},
	"sweetty/internal/proto/https":  {"net"},
	"sweetty/internal/proto/ftp":    {"net"},
}

// TestNoUnapprovedCapabilityInClosure walks the full transitive dependency closure
// of the honeypot binary and asserts that every internal package holding a
// capability import is explicitly approved. A future refactor that factors a fetch
// or exec into a new helper package, or adds a capability to an existing one, fails
// the build here even though its caller's own direct imports still look clean.
func TestNoUnapprovedCapabilityInClosure(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps",
		"-f", "{{.ImportPath}}|{{join .Imports \",\"}}", "sweetty/cmd/sweetty").Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		parts := strings.SplitN(line, "|", 2)
		pkg := parts[0]
		if !strings.HasPrefix(pkg, "sweetty/internal/") {
			continue // the composition root (cmd/sweetty) may wire anything; only handlers are constrained
		}
		seen[pkg] = true
		allowed := map[string]bool{}
		for _, c := range approvedCapabilities[pkg] {
			allowed[c] = true
		}
		if len(parts) < 2 {
			continue
		}
		for _, imp := range strings.Split(parts[1], ",") {
			if capabilityImports[imp] && !allowed[imp] {
				t.Errorf("internal package %s imports the capability %q but is not approved for it.\n"+
					"If a real code path needs it, add it to approvedCapabilities with a justification "+
					"(and confirm attacker input cannot drive it); otherwise remove the import.", pkg, imp)
			}
		}
	}

	// Guard the allowlist against staleness: an approved package that has left the
	// closure (or was never in it) should be pruned so the list stays a true map of
	// where capabilities actually live.
	var stale []string
	for pkg := range approvedCapabilities {
		if !seen[pkg] {
			stale = append(stale, pkg)
		}
	}
	sort.Strings(stale)
	for _, pkg := range stale {
		t.Logf("note: approvedCapabilities lists %s, which is not in the honeypot closure; prune it if it is gone for good", pkg)
	}
}
