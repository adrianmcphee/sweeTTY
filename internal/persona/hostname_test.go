package persona

import (
	"strings"
	"testing"
)

// TestServerHostnamesAreVariedAndNonEmpty checks the server namer produces a wide
// spread of shapes and values, so there is no single template to fingerprint.
func TestServerHostnamesAreVariedAndNonEmpty(t *testing.T) {
	const n = 400
	seen := map[string]bool{}
	shapes := map[string]bool{}
	for range n {
		h := makeServerHostname("api")
		if h == "" {
			t.Fatal("empty hostname")
		}
		if strings.ContainsAny(h, " \t/_") {
			t.Fatalf("hostname has invalid chars: %q", h)
		}
		seen[h] = true
		switch {
		case strings.HasPrefix(h, "ip-10-"):
			shapes["ip"] = true
		case !strings.ContainsAny(h, "0123456789-"):
			shapes["codename"] = true // pure-alpha like "atlas"
		case strings.Count(h, "-") >= 2:
			shapes["multi"] = true
		}
	}
	if len(seen) < n/2 {
		t.Fatalf("server hostnames not varied enough: %d distinct of %d", len(seen), n)
	}
	if len(shapes) < 3 {
		t.Fatalf("expected several distinct hostname shapes, saw %v", shapes)
	}
}

// TestApplianceHostnamesLookLikeDevices checks appliances get device-style names
// that carry their role and never a cloud-server ip-in-name shape.
func TestApplianceHostnamesLookLikeDevices(t *testing.T) {
	const role = "cam"
	for range 200 {
		h := makeApplianceHostname(role)
		if h == "" {
			t.Fatal("empty appliance hostname")
		}
		if strings.HasPrefix(h, "ip-10-") {
			t.Fatalf("appliance got a cloud server name: %q", h)
		}
		if !strings.Contains(strings.ToLower(h), role) {
			t.Fatalf("appliance name does not carry its role %q: %q", role, h)
		}
	}
}

// TestProfileRoutesHostnameStyle checks the legacy profile is routed to the
// appliance namer and everything else to the server namer.
func TestProfileRoutesHostnameStyle(t *testing.T) {
	for range 100 {
		if strings.HasPrefix(makeHostnameFromRole("legacy", "dvr"), "ip-10-") {
			t.Fatal("legacy profile should not get an ip-style server name")
		}
	}
	if makeHostnameFromRole("web", "api") == "" {
		t.Fatal("web hostname empty")
	}
}

// TestHostnameBaseSkipsShortStubs checks a two-letter or ip- stub is not used as
// a password base, while a real word still is.
func TestHostnameBaseSkipsShortStubs(t *testing.T) {
	if hostnameBase("ip-10-40-2-13") != "" {
		t.Error("ip- stub should not be a password base")
	}
	if hostnameBase("db-prod-03") != "" {
		t.Error("two-letter db stub should not be a password base")
	}
	if got := hostnameBase("atlas-04"); got != "atlas" {
		t.Errorf("hostnameBase(atlas-04) = %q, want atlas", got)
	}
}
