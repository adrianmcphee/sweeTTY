package portal

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestOverviewEnrichesISP loads an ASN database and checks that the overview
// tags each source with its AS operator and rolls sources up by ISP.
func TestOverviewEnrichesISP(t *testing.T) {
	p := newTestPortal(t)
	asnPath := filepath.Join(t.TempDir(), "asn.csv")
	if err := os.WriteFile(asnPath, []byte("8.8.8.0,8.8.8.255,15169,GOOGLE\n"), 0600); err != nil {
		t.Fatalf("write asn csv: %v", err)
	}
	if _, err := p.geo.LoadASN(asnPath); err != nil {
		t.Fatalf("load asn: %v", err)
	}

	lines := []string{
		`{"time":"2026-06-27T10:00:01Z","event":"SESSION_START","src_ip":"8.8.8.8","ip":"8.8.8.8:2222","session":"s1","port":22,"protocol":"ssh"}`,
		`{"time":"2026-06-27T10:00:02Z","event":"CREDENTIAL","src_ip":"8.8.8.8","ip":"8.8.8.8:2222","session":"s1","port":22,"protocol":"ssh","username":"root","password":"x"}`,
		`{"time":"2026-06-27T10:01:00Z","event":"SESSION_START","src_ip":"1.2.3.4","ip":"1.2.3.4:3333","session":"s2","port":23,"protocol":"telnet"}`,
	}
	if err := os.WriteFile(p.cfg.LogFile, []byte(strings.Join(lines, "\n")+"\n"), 0600); err != nil {
		t.Fatalf("write log: %v", err)
	}

	eng := p.engine()
	req := httptest.NewRequest(http.MethodGet, "/dashboard/overview", nil)
	w := httptest.NewRecorder()
	eng.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("overview: status %d", w.Code)
	}

	var body struct {
		AsnActive bool `json:"asn_active"`
		ByISP     []struct {
			ASN     uint32 `json:"asn"`
			Org     string `json:"org"`
			Sources int    `json:"sources"`
		} `json:"by_isp"`
		Sources []struct {
			IP  string `json:"ip"`
			ASN uint32 `json:"asn"`
			Org string `json:"org"`
		} `json:"sources"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if !body.AsnActive {
		t.Error("asn_active should be true with an ASN database loaded")
	}

	var found bool
	for _, s := range body.Sources {
		if s.IP == "8.8.8.8" {
			found = true
			if s.ASN != 15169 || s.Org != "GOOGLE" {
				t.Errorf("8.8.8.8 enriched to ASN %d / %q, want 15169 / GOOGLE", s.ASN, s.Org)
			}
		}
	}
	if !found {
		t.Fatal("8.8.8.8 missing from sources")
	}

	var googleSrcs int
	for _, e := range body.ByISP {
		if e.Org == "GOOGLE" {
			googleSrcs = e.Sources
			if e.ASN != 15169 {
				t.Errorf("by_isp GOOGLE ASN %d, want 15169", e.ASN)
			}
		}
	}
	if googleSrcs != 1 {
		t.Errorf("by_isp GOOGLE sources = %d, want 1 (full: %+v)", googleSrcs, body.ByISP)
	}
}
