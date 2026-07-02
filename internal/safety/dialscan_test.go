package safety

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// outboundCalls are the network primitives that reach OUT: dialing a host or
// resolving one. Inbound (net.Listen) and the config-pinned reverse proxy
// (httputil.ReverseProxy to a validated loopback target) are not here.
var outboundCalls = map[string]map[string]bool{
	"net": {
		"Dial": true, "DialTimeout": true, "DialIP": true, "DialTCP": true, "DialUDP": true,
		"LookupHost": true, "LookupIP": true, "LookupAddr": true, "LookupCNAME": true, "LookupPort": true,
	},
	"http": {"Get": true, "Post": true, "Head": true, "PostForm": true},
}

// TestNoOutboundDialCalls scans the syntax tree of every attacker-reachable package
// for an outbound dial or resolve call. This closes the seam the import allowlist
// cannot: portal legitimately imports net/http (it serves the dashboard) and the
// proto packages import net (they read the wire), so "no outbound fetch" there is
// otherwise enforced only by a runtime canary. A future http.Get(payloadURL) in the
// portal's log analysis, or a net.Dial(attackerHost) in a protocol handler, fails
// the build here instead of shipping as an SSRF relay running same-uid as the sensor.
func TestNoOutboundDialCalls(t *testing.T) {
	internal := internalDir(t)
	// haproxy is deliberately excluded: it is the management-plane hapwatch helper,
	// not an attacker-input handler, and dials the local HAProxy admin unix socket.
	for _, pkg := range []string{
		"shell", "vfs", "fakehost", "server", "proxyproto", "portal", "event", "record", "persona",
		"proto/telnet", "proto/ssh", "proto/http", "proto/https", "proto/ftp",
	} {
		scanForOutboundCalls(t, filepath.Join(internal, filepath.FromSlash(pkg)), pkg)
	}
}

func scanForOutboundCalls(t *testing.T, dir, pkg string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			base, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			if fns := outboundCalls[base.Name]; fns[sel.Sel.Name] {
				pos := fset.Position(call.Pos())
				t.Errorf("internal/%s/%s:%d calls %s.%s, an outbound network primitive.\n"+
					"The honeypot must never dial or resolve an attacker-supplied host (no SSRF). "+
					"If this is legitimate management-plane code, move it out of the attacker-reachable packages.",
					pkg, name, pos.Line, base.Name, sel.Sel.Name)
			}
			return true
		})
	}
}
