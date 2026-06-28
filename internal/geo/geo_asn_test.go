package geo

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTemp(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "asn.csv")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadASNAndLocate(t *testing.T) {
	// Mixes the forms the free databases ship: dotted-IPv4 bounds, integer bounds,
	// a quoted org containing a comma, plus rows that must be skipped.
	body := "# header line\n" +
		"1.0.0.0,1.0.0.255,13335,\"CLOUDFLARENET, Inc\"\n" +
		"8.8.8.0,8.8.8.255,15169,GOOGLE\n" +
		"16909060,16909319,9999,EXAMPLE-ISP\n" + // 1.2.3.4 .. 1.2.4.7 as integers
		"only-one-field\n" +
		"2.2.2.0,2.2.2.255,notanumber,BAD\n"

	r := NewResolver()
	n, err := r.LoadASN(writeTemp(t, body))
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 || r.AsnLoaded() != 3 {
		t.Fatalf("loaded %d (AsnLoaded %d), want 3 valid ranges", n, r.AsnLoaded())
	}

	cases := []struct {
		ip  string
		asn uint32
		org string
	}{
		{"1.0.0.50", 13335, "CLOUDFLARENET, Inc"}, // quoted org with comma preserved
		{"8.8.8.8", 15169, "GOOGLE"},
		{"1.2.3.10", 9999, "EXAMPLE-ISP"}, // inside the integer-bound range
		{"9.9.9.9", 0, ""},                // outside every range
	}
	for _, c := range cases {
		loc := r.Locate(c.ip)
		if loc.ASN != c.asn || loc.Org != c.org {
			t.Errorf("Locate(%s) = ASN %d / %q, want %d / %q", c.ip, loc.ASN, loc.Org, c.asn, c.org)
		}
		if c.asn != 0 && loc.Source != "db" {
			t.Errorf("Locate(%s) Source=%q, want db", c.ip, loc.Source)
		}
	}
}

func TestASNNotResolvedWithoutDBOrForSpecialUse(t *testing.T) {
	r := NewResolver() // no database
	if loc := r.Locate("8.8.8.8"); loc.ASN != 0 || loc.Org != "" {
		t.Errorf("no-db Locate set ASN %d / %q", loc.ASN, loc.Org)
	}
	// A database that covers the whole space must still not tag a private address,
	// because special-use scope is decided before any database lookup.
	r.LoadASN(writeTemp(t, "0.0.0.0,255.255.255.255,1,WORLDWIDE\n"))
	if loc := r.Locate("10.0.0.1"); loc.Scope != "private" || loc.ASN != 0 {
		t.Errorf("private addr got scope %q ASN %d, want private / 0", loc.Scope, loc.ASN)
	}
	if loc := r.Locate("8.8.8.8"); loc.ASN != 1 || loc.Org != "WORLDWIDE" {
		t.Errorf("global addr got ASN %d / %q, want 1 / WORLDWIDE", loc.ASN, loc.Org)
	}
}
