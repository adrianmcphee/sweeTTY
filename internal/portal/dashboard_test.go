package portal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// streamFor opens the SSE feed with an optional Last-Event-ID, runs afterConnect
// once the handler is live (so an appended line lands after the handler has
// positioned itself in the file), waits a few of the 500ms flush ticks, then
// returns the accumulated response body. Reading the recorder only after the
// handler goroutine has returned keeps the access race-free.
func streamFor(t *testing.T, p *Portal, lastEventID string, afterConnect func()) string {
	t.Helper()
	if testing.Short() {
		t.Skip("SSE streaming test is timing-bound; skipped under -short")
	}
	eng := p.engine()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/dashboard/events", nil).WithContext(ctx)
	if lastEventID != "" {
		req.Header.Set("Last-Event-ID", lastEventID)
	}
	w := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		eng.ServeHTTP(w, req)
		close(done)
	}()

	// Let the handler open the log and seek/position before any append lands.
	time.Sleep(150 * time.Millisecond)
	if afterConnect != nil {
		afterConnect()
	}
	// The feed flushes new lines on a 500ms ticker; give it a few ticks.
	time.Sleep(1300 * time.Millisecond)
	cancel()
	<-done
	return w.Body.String()
}

// appendLine appends one JSON line to the portal's log file.
func appendLine(t *testing.T, p *Portal, line string) {
	t.Helper()
	f, err := os.OpenFile(p.cfg.LogFile, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("open log for append: %v", err)
	}
	defer f.Close()
	if _, err := f.WriteString(line + "\n"); err != nil {
		t.Fatalf("append line: %v", err)
	}
}

// TestEventsFeedIDIsByteOffset locks the resume contract: each streamed event
// carries an id equal to the byte offset just past it, which is exactly where a
// reconnect resumes from.
func TestEventsFeedIDIsByteOffset(t *testing.T) {
	p := newTestPortal(t) // the seeded log starts empty
	line := `{"time":"2026-06-27T10:00:00Z","event":"COMMAND","src_ip":"9.9.9.9","ip":"9.9.9.9:9","session":"s","command":"id-probe"}`

	body := streamFor(t, p, "", func() { appendLine(t, p, line) })

	want := "id: " + strconv.Itoa(len(line)+1) // +1 for the trailing newline
	if !strings.Contains(body, want) {
		t.Fatalf("emitted id is not the resumable byte offset; want %q in %q", want, body)
	}
}

// TestEventsFeedResumesFromLastEventID proves a reconnecting client backfills the
// events written during the gap: with two lines already on disk and Last-Event-ID
// pointing just past the first, the feed must replay the second and only the
// second.
func TestEventsFeedResumesFromLastEventID(t *testing.T) {
	p := newTestPortal(t)
	line1 := `{"time":"2026-06-27T10:00:00Z","event":"COMMAND","src_ip":"1.1.1.1","ip":"1.1.1.1:1","session":"s1","command":"alpha-cmd"}`
	line2 := `{"time":"2026-06-27T10:00:01Z","event":"COMMAND","src_ip":"2.2.2.2","ip":"2.2.2.2:2","session":"s2","command":"bravo-cmd"}`
	if err := os.WriteFile(p.cfg.LogFile, []byte(line1+"\n"+line2+"\n"), 0600); err != nil {
		t.Fatalf("write log: %v", err)
	}

	resume := strconv.Itoa(len(line1) + 1) // offset of line2's first byte
	body := streamFor(t, p, resume, nil)

	if !strings.Contains(body, "bravo-cmd") {
		t.Fatalf("resume did not backfill the line after Last-Event-ID: %q", body)
	}
	if strings.Contains(body, "alpha-cmd") {
		t.Fatalf("resume replayed a line at/before Last-Event-ID: %q", body)
	}
	if !strings.Contains(body, "id: ") {
		t.Fatalf("resumed stream carried no id: %q", body)
	}
}

// TestEventsFeedFreshConnectSkipsExisting guards that a connection without a
// Last-Event-ID starts at end-of-file: it streams new lines but never replays the
// backlog (which would flood the feed on every page load).
func TestEventsFeedFreshConnectSkipsExisting(t *testing.T) {
	p := newTestPortal(t)
	stale := `{"time":"2026-06-27T09:00:00Z","event":"COMMAND","src_ip":"3.3.3.3","ip":"3.3.3.3:3","session":"s0","command":"stale-cmd"}`
	if err := os.WriteFile(p.cfg.LogFile, []byte(stale+"\n"), 0600); err != nil {
		t.Fatalf("write log: %v", err)
	}
	fresh := `{"time":"2026-06-27T09:00:01Z","event":"COMMAND","src_ip":"4.4.4.4","ip":"4.4.4.4:4","session":"s1","command":"fresh-cmd"}`

	body := streamFor(t, p, "", func() { appendLine(t, p, fresh) })

	if !strings.Contains(body, "fresh-cmd") {
		t.Fatalf("fresh connect did not stream the appended line: %q", body)
	}
	if strings.Contains(body, "stale-cmd") {
		t.Fatalf("fresh connect replayed a pre-existing line; it must seek to end: %q", body)
	}
}

// TestEventsFeedIgnoresUnusableLastEventID exercises the resume guard's fallback:
// an offset past the end of a rotated/truncated log, a negative value, and
// non-numeric garbage must all degrade to an end-of-file start - streaming new
// lines without erroring and without replaying the existing backlog.
func TestEventsFeedIgnoresUnusableLastEventID(t *testing.T) {
	for _, bad := range []string{"999999", "-5", "abc"} {
		t.Run(bad, func(t *testing.T) {
			p := newTestPortal(t)
			stale := `{"time":"2026-06-27T08:00:00Z","event":"COMMAND","src_ip":"7.7.7.7","ip":"7.7.7.7:7","session":"s0","command":"stale-cmd"}`
			if err := os.WriteFile(p.cfg.LogFile, []byte(stale+"\n"), 0600); err != nil {
				t.Fatalf("write log: %v", err)
			}
			fresh := `{"time":"2026-06-27T08:00:01Z","event":"COMMAND","src_ip":"8.8.8.1","ip":"8.8.8.1:8","session":"s1","command":"fresh-cmd"}`

			body := streamFor(t, p, bad, func() { appendLine(t, p, fresh) })

			if !strings.Contains(body, "fresh-cmd") {
				t.Fatalf("Last-Event-ID %q did not fall back to streaming new lines: %q", bad, body)
			}
			if strings.Contains(body, "stale-cmd") {
				t.Fatalf("Last-Event-ID %q replayed the backlog instead of starting at end-of-file: %q", bad, body)
			}
		})
	}
}

// TestRecordingsListsCastIDsOnly checks the replay-list endpoint surfaces exactly
// the safe .cast session ids, sorted, and drops anything else in the directory.
func TestRecordingsListsCastIDsOnly(t *testing.T) {
	p := newTestPortal(t)
	dir := t.TempDir()
	p.cfg.RecordDir = dir
	write := func(name string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("[0.0,\"o\",\"hi\"]\n"), 0600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	write("aaa111.cast") // valid
	write("bbb222.cast") // valid
	write("notes.txt")   // wrong extension -> excluded
	write("bad id.cast") // unsafe id (space) -> excluded
	write(".cast")       // empty id -> excluded

	eng := p.engine()
	req := httptest.NewRequest(http.MethodGet, "/dashboard/recordings", nil)
	w := httptest.NewRecorder()
	eng.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("recordings: status %d", w.Code)
	}

	var body struct {
		Recordings []string `json:"recordings"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if got := strings.Join(body.Recordings, ","); got != "aaa111,bbb222" {
		t.Fatalf("recordings = %q, want \"aaa111,bbb222\" (sorted, safe .cast ids only)", got)
	}
}

// TestServedHTMLReachesNothingOffHost is the management-plane invariant: the
// served page may not reference an external asset, so the console never leaves
// the box. An explicit scheme://host is the obvious giveaway; a protocol-relative
// //host (in an attribute, a CSS url(), or a fetch/EventSource arg) is the subtle
// one. Both are caught here. Same-origin relative URLs ("/dashboard/...") and
// data: URIs carry none of these markers and stay allowed.
func TestServedHTMLReachesNothingOffHost(t *testing.T) {
	offHost := []string{"://", `"//`, "'//", "(//"}
	for _, marker := range offHost {
		if strings.Contains(dashboardHTML, marker) {
			t.Errorf("dashboard page contains an off-host URL marker %q; the console must reference no external assets", marker)
		}
	}
}

func TestPortalSetsBrowserBoundaryHeaders(t *testing.T) {
	p := newTestPortal(t)
	w := httptest.NewRecorder()
	p.engine().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/dashboard", nil))
	for _, name := range []string{"X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy", "Content-Security-Policy"} {
		if w.Header().Get(name) == "" {
			t.Errorf("portal response missing %s", name)
		}
	}
}

// TestDashboardScriptElementIDsResolve catches the classic single-page-app
// regression: the script reaching for an element id that the markup no longer
// declares. Every literal id passed to getElementById or setNum must exist.
func TestDashboardScriptElementIDsResolve(t *testing.T) {
	refs := map[string]bool{}
	for _, re := range []*regexp.Regexp{
		regexp.MustCompile(`getElementById\('([^']+)'\)`),
		regexp.MustCompile(`setNum\('([^']+)'`),
	} {
		for _, m := range re.FindAllStringSubmatch(dashboardHTML, -1) {
			refs[m[1]] = true
		}
	}
	if len(refs) == 0 {
		t.Fatal("matched no element-id references; the extraction regex needs updating")
	}
	for id := range refs {
		if !strings.Contains(dashboardHTML, `id="`+id+`"`) {
			t.Errorf("script references #%s but no element declares id=%q", id, id)
		}
	}
}

// TestDashboardHasSourceFilters checks the Sources view carries the repeat-visitor
// controls: the four filter buttons, the kind-chip and returning-badge rendering,
// and the styles that back them. It guards against a markup-vs-script drift where
// the filter buttons exist but nothing wires or renders them.
func TestDashboardHasSourceFilters(t *testing.T) {
	for _, want := range []string{
		`data-srcfilter="all"`,
		`data-srcfilter="returning"`,
		`data-srcfilter="bots"`,
		`data-srcfilter="human"`,
		"function matchSrcFilter",
		"function kindTag",
		"'bot:loader'",
		".filterbar{",
		".kindtag{",
		".retbadge{",
		`id="src_country"`,
		`id="src_search"`,
		"function populateCountryFilter",
		".fsearch{",
		// Service filter and the exposed-services surface it is driven from.
		`id="src_proto"`,
		`id="src_summary"`,
		"function populateProtoFilter",
		"function filterByProto",
		"function renderSrcSummary",
		"function surfaceRow",
		"Exposed services",
		".srcsum{",
	} {
		if !strings.Contains(dashboardHTML, want) {
			t.Errorf("dashboard page missing the Sources-filter hook %q", want)
		}
	}
}

// TestDashboardHasStatScopeToggle checks the live-feed stat cards carry the
// Today / All-time scope toggle and the code that switches them.
func TestDashboardHasStatScopeToggle(t *testing.T) {
	for _, want := range []string{
		`data-scope="today"`,
		`data-scope="all"`,
		"var statScope=",
		"statScope==='all'",
		".scbtn{",
	} {
		if !strings.Contains(dashboardHTML, want) {
			t.Errorf("dashboard page missing the stat-scope toggle hook %q", want)
		}
	}
}

// TestDashboardRefreshesCardsOnNotableEvent proves a notable feed event (a JT
// reveal or a payload pull) triggers a prompt stat-card refresh, so the counter
// ticks up in step with the confetti rather than lagging on the slow poll timer.
func TestDashboardRefreshesCardsOnNotableEvent(t *testing.T) {
	if !strings.Contains(dashboardHTML, "NOTABLE[e.event])scheduleOverview()") {
		t.Error("a notable feed event does not trigger a prompt stat-card refresh")
	}
}

// TestDashboardFlashesJTOnReveal checks the honeytoken celebration flash is wired:
// the overlay markup, styles, and trigger exist, and flashJT is invoked only from
// prizeMoment (which fires solely on a HONEYTOKEN, a JT reveal), never elsewhere.
func TestDashboardFlashesJTOnReveal(t *testing.T) {
	for _, want := range []string{
		`id="jtflash"`,
		`src="/dashboard/jt-prize.jpg"`,
		"function flashJT",
		"#jtflash.on{",
		"@keyframes jtflash",
		"flashJT();",
	} {
		if !strings.Contains(dashboardHTML, want) {
			t.Errorf("dashboard page missing the JT-flash hook %q", want)
		}
	}
	// The only call site is inside prizeMoment, so it cannot fire on a generic event.
	if strings.Count(dashboardHTML, "flashJT();") != 1 {
		t.Errorf("flashJT() should be called exactly once (from prizeMoment); found %d", strings.Count(dashboardHTML, "flashJT();"))
	}
}

// TestJTPrizeImageServed proves the embedded celebration portrait is served as a
// same-origin JPEG, so the console references nothing off-host.
func TestJTPrizeImageServed(t *testing.T) {
	p := newTestPortal(t)
	eng := p.engine()
	req := httptest.NewRequest(http.MethodGet, "/dashboard/jt-prize.jpg", nil)
	w := httptest.NewRecorder()
	eng.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "image/jpeg") {
		t.Errorf("content-type = %q, want image/jpeg", ct)
	}
	if b := w.Body.Bytes(); len(b) < 1000 || b[0] != 0xFF || b[1] != 0xD8 {
		t.Errorf("served bytes are not a valid embedded JPEG (%d bytes)", len(b))
	}
}

// TestDashboardRendersAssessmentPanel checks the per-IP drawer wires the profile
// into an assessment panel: the builders, the styles, and the threading of the
// byIP response's profile into renderDetail.
func TestDashboardRendersAssessmentPanel(t *testing.T) {
	for _, want := range []string{
		"function buildAssessment",
		"function buildTimeline",
		"function buildPhases",
		"d.profile||null",
		"function renderDetail(ip,list,profile",
		"VERDICTLBL",
		".assess{",
		".tlbar{",
		".ribbon{",
	} {
		if !strings.Contains(dashboardHTML, want) {
			t.Errorf("dashboard page missing the assessment-panel hook %q", want)
		}
	}
}
