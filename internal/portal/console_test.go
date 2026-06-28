package portal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sweetty/internal/config"
	"sweetty/internal/event"
)

// newPortalWithConsoles builds a portal whose config lists the given consoles,
// so the console reverse proxy can be exercised end to end.
func newPortalWithConsoles(t *testing.T, consoles []config.AdminConsole) *Portal {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "sweetty.log")
	if err := os.WriteFile(logPath, nil, 0600); err != nil {
		t.Fatalf("seed log: %v", err)
	}
	lg, err := event.New(logPath)
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	t.Cleanup(func() { lg.Close() })

	cfg := config.Config{
		PortalPort:    0,
		LogFile:       logPath,
		AdminConsoles: consoles,
	}
	return New(cfg, lg)
}

// TestAdminConsoleProxiesToLocalUpstream proves the operator reaches a local
// console through the portal, that the full external path is forwarded by default
// (so an upstream with absolute links keeps them resolving under the mount), and
// that the upstream's response comes back.
func TestAdminConsoleProxiesToLocalUpstream(t *testing.T) {
	var gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("HAPROXY STATS for " + r.URL.RawQuery))
	}))
	defer upstream.Close()

	p := newPortalWithConsoles(t, []config.AdminConsole{
		{Name: "haproxy", Label: "HAProxy", Target: upstream.URL + "/"},
	})
	eng := p.engine()

	// A real net/http request carries a cancellable context; httptest.NewRequest
	// uses context.Background() (Done() == nil), which would push ReverseProxy down
	// its CloseNotifier path. Give it a cancellable context to match production.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/dashboard/console/haproxy/stats?up", nil).WithContext(ctx)
	w := httptest.NewRecorder()
	eng.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("console proxy: status %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "HAPROXY STATS") {
		t.Fatalf("upstream body not returned: %q", w.Body.String())
	}
	if gotPath != "/dashboard/console/haproxy/stats" {
		t.Fatalf("upstream saw path %q, want the full mount path forwarded", gotPath)
	}
}

// TestAdminConsoleStripPrefix proves the opt-in strip_prefix removes the mount
// prefix before forwarding, for an upstream that only serves at its root.
func TestAdminConsoleStripPrefix(t *testing.T) {
	var gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	p := newPortalWithConsoles(t, []config.AdminConsole{
		{Name: "root", Target: upstream.URL + "/", StripPrefix: true},
	})
	eng := p.engine()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/dashboard/console/root/stats", nil).WithContext(ctx)
	w := httptest.NewRecorder()
	eng.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("strip-prefix console: status %d", w.Code)
	}
	if gotPath != "/stats" {
		t.Fatalf("strip-prefix upstream saw %q, want /stats", gotPath)
	}
}

// TestAdminConsoleListHidesTarget proves the dashboard listing exposes the name
// and label but never the upstream address.
func TestAdminConsoleListHidesTarget(t *testing.T) {
	p := newPortalWithConsoles(t, []config.AdminConsole{
		{Name: "haproxy", Label: "HAProxy stats", Target: "http://127.0.0.1:19000/"},
	})
	eng := p.engine()

	req := httptest.NewRequest(http.MethodGet, "/dashboard/consoles", nil)
	w := httptest.NewRecorder()
	eng.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("consoles list: status %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "HAProxy stats") || !strings.Contains(body, "haproxy") {
		t.Fatalf("console name/label missing from listing: %q", body)
	}
	if strings.Contains(body, "19000") {
		t.Fatalf("listing leaked the upstream target: %q", body)
	}
	var parsed struct {
		Consoles []struct{ Name, Label string } `json:"consoles"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if len(parsed.Consoles) != 1 || parsed.Consoles[0].Name != "haproxy" {
		t.Fatalf("unexpected consoles: %+v", parsed.Consoles)
	}
}

// TestAdminConsoleRefusesNonLocalTarget proves a console whose target is not on
// the local host is dropped at build time, so the portal cannot be configured
// into an open proxy onto the network.
func TestAdminConsoleRefusesNonLocalTarget(t *testing.T) {
	p := newPortalWithConsoles(t, []config.AdminConsole{
		{Name: "ext", Target: "http://8.8.8.8:9000/"},
	})
	if _, ok := p.consoles["ext"]; ok {
		t.Fatal("a non-local console target was accepted")
	}
	eng := p.engine()
	req := httptest.NewRequest(http.MethodGet, "/dashboard/console/ext/", nil)
	w := httptest.NewRecorder()
	eng.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("non-local console: status %d, want 404", w.Code)
	}
}

// TestAdminConsoleBareRedirectsToSlash proves a console hit without a trailing
// slash redirects to one, so the upstream's relative links resolve under the
// mount instead of escaping it.
func TestAdminConsoleBareRedirectsToSlash(t *testing.T) {
	p := newPortalWithConsoles(t, []config.AdminConsole{
		{Name: "haproxy", Target: "http://127.0.0.1:19000/"},
	})
	eng := p.engine()
	req := httptest.NewRequest(http.MethodGet, "/dashboard/console/haproxy", nil)
	w := httptest.NewRecorder()
	eng.ServeHTTP(w, req)
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/dashboard/console/haproxy/" {
		t.Fatalf("bare console path: got %d -> %q, want 302 -> /dashboard/console/haproxy/", w.Code, w.Header().Get("Location"))
	}
}
