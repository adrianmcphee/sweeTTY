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
	"time"

	"sweetty/internal/config"
	"sweetty/internal/event"
)

// newTestPortal builds a Portal over a temp log file. The portal binds loopback
// and serves with no application auth, so the handlers answer directly.
func newTestPortal(t *testing.T) *Portal {
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
		PortalPort: 0,
		LogFile:    logPath,
	}
	return New(cfg, lg)
}

func TestEventsFeedStreamsAppendedLines(t *testing.T) {
	if testing.Short() {
		t.Skip("SSE streaming test is timing-bound; skipped under -short")
	}
	p := newTestPortal(t)
	eng := p.engine()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	req := httptest.NewRequest(http.MethodGet, "/dashboard/events", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		eng.ServeHTTP(w, req)
		close(done)
	}()

	// Let the handler open the log and seek to the end before appending, so the
	// new line lands past its start offset and is streamed rather than skipped.
	time.Sleep(150 * time.Millisecond)
	const marker = "203.0.113.77"
	appended := `{"time":"2026-06-27T11:00:00Z","event":"COMMAND","src_ip":"` + marker +
		`","ip":"` + marker + `:4444","session":"streamsess","command":"id"}`
	f, err := os.OpenFile(p.cfg.LogFile, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("open log for append: %v", err)
	}
	if _, err := f.WriteString(appended + "\n"); err != nil {
		t.Fatalf("append line: %v", err)
	}
	f.Close()

	// The feed flushes new lines on a 500ms ticker; give it a few ticks to pick up
	// the appended line before cutting the stream. Reading w.Body only after the
	// handler goroutine has returned keeps the recorder access race-free.
	time.Sleep(1300 * time.Millisecond)
	cancel()
	<-done

	body := w.Body.String()
	if !strings.Contains(body, "event: log") {
		t.Fatalf("stream emitted no log event frame: %q", body)
	}
	if !strings.Contains(body, marker) {
		t.Fatalf("stream did not include the appended line data %q: %q", marker, body)
	}
}

// TestHoneytokensAggregates proves the analytics endpoint counts bait triggers
// per source, attributes a country through the loaded database, classifies a
// special-use source by scope, and surfaces the busiest source first. This is
// the "who tripped the bait, how often, from where" view the bait feeds.
func TestHoneytokensAggregates(t *testing.T) {
	p := newTestPortal(t)
	// Load a tiny country database so a public source resolves to a country.
	// 8.8.8.0 = 134744064, 8.8.8.255 = 134744319.
	geoPath := filepath.Join(t.TempDir(), "geo.csv")
	if err := os.WriteFile(geoPath, []byte("8.8.8.0,8.8.8.255,US\n"), 0600); err != nil {
		t.Fatalf("write geo csv: %v", err)
	}
	if _, err := p.geo.LoadCSV(geoPath); err != nil {
		t.Fatalf("load geo: %v", err)
	}

	lines := []string{
		`{"time":"2026-06-27T10:00:00Z","event":"HONEYTOKEN","src_ip":"8.8.8.8","ip":"8.8.8.8:5555","session":"a","note":"vault","command":"vault"}`,
		`{"time":"2026-06-27T10:00:05Z","event":"HONEYTOKEN","src_ip":"8.8.8.8","ip":"8.8.8.8:5555","session":"a","note":"portrait","command":"chafa wallet_seed_phrase.png"}`,
		`{"time":"2026-06-27T10:00:09Z","event":"HONEYTOKEN","src_ip":"8.8.8.8","ip":"8.8.8.8:6666","session":"b","note":"vault","command":"wallet"}`,
		`{"time":"2026-06-27T10:01:00Z","event":"HONEYTOKEN","src_ip":"10.0.0.9","ip":"10.0.0.9:7777","session":"c","note":"vault","command":"balance"}`,
		`{"time":"2026-06-27T10:02:00Z","event":"COMMAND","src_ip":"8.8.8.8","ip":"8.8.8.8:5555","session":"a","command":"ls"}`,
	}
	if err := os.WriteFile(p.cfg.LogFile, []byte(strings.Join(lines, "\n")+"\n"), 0600); err != nil {
		t.Fatalf("write log: %v", err)
	}

	eng := p.engine()
	req := httptest.NewRequest(http.MethodGet, "/dashboard/honeytokens", nil)
	w := httptest.NewRecorder()
	eng.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("honeytokens: status %d", w.Code)
	}

	var body struct {
		Total      int            `json:"total"`
		UniqueSrcs int            `json:"unique_srcs"`
		GeoActive  bool           `json:"geo_active"`
		ByToken    map[string]int `json:"by_token"`
		Sources    []struct {
			IP       string   `json:"ip"`
			Country  string   `json:"country"`
			Scope    string   `json:"scope"`
			Count    int      `json:"count"`
			Sessions []string `json:"sessions"`
			Tokens   []string `json:"tokens"`
		} `json:"sources"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("bad json: %v", err)
	}

	if body.Total != 4 {
		t.Fatalf("total triggers = %d, want 4 (the COMMAND is excluded)", body.Total)
	}
	if body.UniqueSrcs != 2 {
		t.Fatalf("unique sources = %d, want 2", body.UniqueSrcs)
	}
	if !body.GeoActive {
		t.Fatal("geo_active should be true with a database loaded")
	}
	if body.ByToken["vault"] != 3 || body.ByToken["portrait"] != 1 {
		t.Fatalf("by_token = %v, want vault:3 portrait:1", body.ByToken)
	}
	if len(body.Sources) != 2 {
		t.Fatalf("sources = %d, want 2", len(body.Sources))
	}

	// Busiest first: 8.8.8.8 tripped three tokens, 10.0.0.9 only one.
	top := body.Sources[0]
	if top.IP != "8.8.8.8" || top.Count != 3 {
		t.Fatalf("top source = %s x%d, want 8.8.8.8 x3", top.IP, top.Count)
	}
	if top.Country != "US" {
		t.Fatalf("top source country = %q, want US", top.Country)
	}
	if len(top.Sessions) != 2 {
		t.Fatalf("top source sessions = %v, want 2 distinct", top.Sessions)
	}

	// The private source is classified by scope and carries no country.
	priv := body.Sources[1]
	if priv.IP != "10.0.0.9" || priv.Scope != "private" || priv.Country != "" {
		t.Fatalf("private source = %+v, want 10.0.0.9 scope=private no country", priv)
	}
}

func TestLogQueryFilters(t *testing.T) {
	p := newTestPortal(t)
	lines := []string{
		`{"time":"2026-06-27T10:00:00Z","event":"SESSION_START","src_ip":"1.2.3.4","ip":"1.2.3.4:5555","session":"sess1","port":23}`,
		`{"time":"2026-06-27T10:00:01Z","event":"CREDENTIAL","src_ip":"1.2.3.4","ip":"1.2.3.4:5555","session":"sess1","username":"root","password":"toor"}`,
		`{"time":"2026-06-27T10:00:02Z","event":"COMMAND","src_ip":"5.6.7.8","ip":"5.6.7.8:6666","session":"sess2","command":"uname -a"}`,
		`{"time":"2026-06-27T10:00:03Z","event":"DOWNLOAD_ATTEMPT","src_ip":"5.6.7.8","ip":"5.6.7.8:6666","session":"sess2","url":"http://evil/x.sh"}`,
	}
	if err := os.WriteFile(p.cfg.LogFile, []byte(strings.Join(lines, "\n")+"\n"), 0600); err != nil {
		t.Fatalf("write log: %v", err)
	}
	eng := p.engine()

	get := func(path string) map[string]any {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		eng.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s: status %d", path, w.Code)
		}
		var body map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("GET %s: bad json: %v", path, err)
		}
		return body
	}

	all := get("/dashboard/log?limit=200")
	if c, _ := all["count"].(float64); int(c) != 4 {
		t.Fatalf("unfiltered count = %v, want 4", all["count"])
	}
	// Newest first: the download attempt was last written, so it leads.
	ents := all["entries"].([]any)
	first := ents[0].(map[string]any)
	if first["event"] != "DOWNLOAD_ATTEMPT" {
		t.Fatalf("newest-first leader = %v, want DOWNLOAD_ATTEMPT", first["event"])
	}

	byEvent := get("/dashboard/log?event=COMMAND")
	if c, _ := byEvent["count"].(float64); int(c) != 1 {
		t.Fatalf("event=COMMAND count = %v, want 1", byEvent["count"])
	}

	byIP := get("/dashboard/log?ip=5.6")
	if c, _ := byIP["count"].(float64); int(c) != 2 {
		t.Fatalf("ip=5.6 prefix count = %v, want 2", byIP["count"])
	}

	sess := get("/dashboard/session/sess1")
	if c, _ := sess["count"].(float64); int(c) != 2 {
		t.Fatalf("session sess1 count = %v, want 2", sess["count"])
	}

	ipAll := get("/dashboard/ip/5.6.7.8")
	if c, _ := ipAll["count"].(float64); int(c) != 2 {
		t.Fatalf("ip 5.6.7.8 count = %v, want 2", ipAll["count"])
	}
}

// TestByIPReturnsAssessment proves the per-IP drill-down carries the source
// assessment alongside the raw entries: a source that logs in and changes root's
// password reads as a loader that reached the exploit phase.
func TestByIPReturnsAssessment(t *testing.T) {
	p := newTestPortal(t)
	lines := []string{
		`{"time":"2026-06-27T10:00:00Z","event":"SESSION_START","src_ip":"9.8.7.6","ip":"9.8.7.6:5","session":"s","port":22,"protocol":"ssh"}`,
		`{"time":"2026-06-27T10:00:01Z","event":"CREDENTIAL","src_ip":"9.8.7.6","ip":"9.8.7.6:5","session":"s","username":"root","password":"1qazxc"}`,
		`{"time":"2026-06-27T10:00:02Z","event":"COMMAND","src_ip":"9.8.7.6","ip":"9.8.7.6:5","session":"s","command":"echo \"root:x\"|chpasswd|bash"}`,
	}
	if err := os.WriteFile(p.cfg.LogFile, []byte(strings.Join(lines, "\n")+"\n"), 0600); err != nil {
		t.Fatalf("write log: %v", err)
	}
	eng := p.engine()

	req := httptest.NewRequest(http.MethodGet, "/dashboard/ip/9.8.7.6", nil)
	w := httptest.NewRecorder()
	eng.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	var body struct {
		Profile Assessment `json:"profile"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if body.Profile.Kind != kindLoader {
		t.Fatalf("profile.kind = %q, want %q (reasons: %v)", body.Profile.Kind, kindLoader, body.Profile.Reasons)
	}
	if !containsStr(body.Profile.Phases, phaseExploit) {
		t.Errorf("profile.phases = %v, want to include %q", body.Profile.Phases, phaseExploit)
	}
	if len(body.Profile.Reasons) == 0 {
		t.Error("profile carries no reasons; the verdict should be explained")
	}
}
