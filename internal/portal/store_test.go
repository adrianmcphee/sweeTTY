package portal

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// storeGet drives one dashboard route through the engine and returns the body.
func storeGet(t *testing.T, p *Portal, path string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	w := httptest.NewRecorder()
	p.engine().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("%s: status %d", path, w.Code)
	}
	return w.Body.String()
}

func appendLog(t *testing.T, p *Portal, lines ...string) {
	t.Helper()
	f, err := os.OpenFile(p.cfg.LogFile, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("open log: %v", err)
	}
	defer f.Close()
	if _, err := f.WriteString(strings.Join(lines, "\n") + "\n"); err != nil {
		t.Fatalf("append log: %v", err)
	}
}

// storeFixture is a mixed log exercising every projection: sessions, commands,
// credentials, a honeytoken, a download, and a dropper, across two sources.
var storeFixture = []string{
	`{"time":"2026-06-27T10:00:00Z","epoch_ms":1782554400000,"event":"SESSION_START","src_ip":"8.8.8.8","ip":"8.8.8.8:2222","session":"s1","port":22,"protocol":"ssh"}`,
	`{"time":"2026-06-27T10:00:01Z","epoch_ms":1782554401000,"event":"CREDENTIAL","src_ip":"8.8.8.8","ip":"8.8.8.8:2222","session":"s1","port":22,"protocol":"ssh","username":"root","password":"toor"}`,
	`{"time":"2026-06-27T10:00:02Z","epoch_ms":1782554402000,"event":"COMMAND","src_ip":"8.8.8.8","ip":"8.8.8.8:2222","session":"s1","port":22,"protocol":"ssh","command":"uname -a"}`,
	`{"time":"2026-06-27T10:00:03Z","epoch_ms":1782554403000,"event":"HONEYTOKEN","src_ip":"8.8.8.8","ip":"8.8.8.8:2222","session":"s1","note":"vault","command":"vault"}`,
	`{"time":"2026-06-27T10:01:00Z","epoch_ms":1782554460000,"event":"DOWNLOAD_ATTEMPT","src_ip":"10.0.0.9","ip":"10.0.0.9:3333","session":"s2","port":80,"protocol":"http","url":"http://evil/x.sh"}`,
	`{"time":"2026-06-27T10:01:01Z","epoch_ms":1782554461000,"event":"DROPPER","src_ip":"10.0.0.9","ip":"10.0.0.9:3333","session":"s2","port":80,"protocol":"http","filename":"/tmp/x","sha256":"abc123"}`,
	`{"time":"2026-06-27T10:01:02Z","epoch_ms":1782554462000,"event":"SESSION_END","src_ip":"10.0.0.9","ip":"10.0.0.9:3333","session":"s2","port":80,"protocol":"http"}`,
}

// TestStoreIncrementalFoldMatchesFreshFold proves the store's defining property:
// folding a log in two increments (with reads in between) produces byte-identical
// analytics to a fresh portal reading the finished log in one pass. If the
// incremental path ever drifted from the from-scratch path, every number on the
// dashboard would silently go wrong.
func TestStoreIncrementalFoldMatchesFreshFold(t *testing.T) {
	inc := newTestPortal(t)
	half := len(storeFixture) / 2
	appendLog(t, inc, storeFixture[:half]...)

	// Fold the first half through every projection-backed route.
	routes := []string{"/dashboard/overview", "/dashboard/honeytokens", "/dashboard/payloads", "/dashboard/sessions/active"}
	for _, r := range routes {
		storeGet(t, inc, r)
	}

	// Append the rest and read again: the store folds only the tail.
	appendLog(t, inc, storeFixture[half:]...)

	// A fresh portal over the complete log is the from-scratch reference.
	fresh := newTestPortal(t)
	appendLog(t, fresh, storeFixture...)

	for _, r := range routes {
		got := storeGet(t, inc, r)
		want := storeGet(t, fresh, r)
		if got != want {
			t.Errorf("%s: incremental fold diverged from fresh fold\nincremental: %s\nfresh:       %s", r, got, want)
		}
	}
}

// TestStoreRefoldsAfterRotation proves a log that shrinks (rotation or truncation)
// resets the projections and refolds from the start, rather than serving stale
// figures or misreading the new file from a stale offset.
func TestStoreRefoldsAfterRotation(t *testing.T) {
	p := newTestPortal(t)
	appendLog(t, p, storeFixture...)
	if got := storeGet(t, p, "/dashboard/honeytokens"); !strings.Contains(got, `"total":1`) {
		t.Fatalf("pre-rotation honeytokens: %s", got)
	}

	// Rotate: replace the log with one shorter line, a fresh history.
	if err := os.WriteFile(p.cfg.LogFile, []byte(storeFixture[0]+"\n"), 0600); err != nil {
		t.Fatalf("rotate log: %v", err)
	}
	if got := storeGet(t, p, "/dashboard/honeytokens"); !strings.Contains(got, `"total":0`) {
		t.Fatalf("post-rotation honeytokens still carry the old history: %s", got)
	}
	if got := storeGet(t, p, "/dashboard/overview"); !strings.Contains(got, `"events":1`) {
		t.Fatalf("post-rotation overview not refolded from the new file: %s", got)
	}
}

// TestStoreFoldsPartialLineOnlyOnceComplete proves a line whose newline has not
// landed yet (a write in flight) is not folded early, and is folded exactly once
// after it completes.
func TestStoreFoldsPartialLineOnlyOnceComplete(t *testing.T) {
	p := newTestPortal(t)
	line := storeFixture[3] // the HONEYTOKEN line
	cut := len(line) / 2

	f, err := os.OpenFile(p.cfg.LogFile, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("open log: %v", err)
	}
	if _, err := f.WriteString(line[:cut]); err != nil {
		t.Fatalf("write partial: %v", err)
	}
	if got := storeGet(t, p, "/dashboard/honeytokens"); !strings.Contains(got, `"total":0`) {
		t.Fatalf("a partial line was folded early: %s", got)
	}
	if _, err := f.WriteString(line[cut:] + "\n"); err != nil {
		t.Fatalf("complete line: %v", err)
	}
	f.Close()
	if got := storeGet(t, p, "/dashboard/honeytokens"); !strings.Contains(got, `"total":1`) {
		t.Fatalf("the completed line was not folded exactly once: %s", got)
	}
}

// TestLiveProjectionDropsEndedAndStale proves the live-rail projection holds only
// open sessions: an ended session leaves the map at once, and an orphan (no END,
// long idle) is swept, so the projection cannot accumulate every session id the
// log has ever seen the way the per-request scan transiently did.
func TestLiveProjectionDropsEndedAndStale(t *testing.T) {
	p := newTestPortal(t)
	now := time.Now()
	nowMs := now.UnixMilli()
	stamp := now.UTC().Format(time.RFC3339)

	appendLog(t, p,
		`{"time":"`+stamp+`","epoch_ms":`+itoa64(nowMs)+`,"event":"SESSION_START","src_ip":"8.8.8.8","ip":"8.8.8.8:1","session":"open1","port":22,"protocol":"ssh"}`,
		`{"time":"`+stamp+`","epoch_ms":`+itoa64(nowMs)+`,"event":"SESSION_START","src_ip":"8.8.4.4","ip":"8.8.4.4:2","session":"done1","port":23,"protocol":"telnet"}`,
		`{"time":"`+stamp+`","epoch_ms":`+itoa64(nowMs)+`,"event":"SESSION_END","src_ip":"8.8.4.4","ip":"8.8.4.4:2","session":"done1","port":23,"protocol":"telnet"}`,
	)
	body := storeGet(t, p, "/dashboard/sessions/active")
	if !strings.Contains(body, "open1") || strings.Contains(body, "done1") {
		t.Fatalf("live rail should list open1 only: %s", body)
	}
	p.store.mu.Lock()
	if _, tracked := p.store.live.byID["done1"]; tracked {
		t.Error("an ended session is still held by the projection")
	}
	p.store.mu.Unlock()

	// An orphan far older than the sweep horizon disappears from the projection
	// on the next read, not just from the response.
	staleMs := nowMs - (liveSweepFactor*activeWindow.Milliseconds() + 60_000)
	appendLog(t, p,
		`{"time":"`+stamp+`","epoch_ms":`+itoa64(staleMs)+`,"event":"SESSION_START","src_ip":"9.9.9.9","ip":"9.9.9.9:3","session":"orphan1","port":21,"protocol":"ftp"}`,
	)
	storeGet(t, p, "/dashboard/sessions/active")
	p.store.mu.Lock()
	if _, tracked := p.store.live.byID["orphan1"]; tracked {
		t.Error("a stale orphan session was never swept from the projection")
	}
	p.store.mu.Unlock()
}

// TestLogQueryKeepsNewestUnderLimit proves the feed's bounded scan returns the
// newest matches when the log holds more than the limit, newest first, so the
// ring never silently serves the oldest slice instead.
func TestLogQueryKeepsNewestUnderLimit(t *testing.T) {
	p := newTestPortal(t)
	lines := make([]string, 0, 30)
	for i := 0; i < 30; i++ {
		lines = append(lines, `{"time":"2026-06-27T10:00:`+pad2(i)+`Z","event":"COMMAND","src_ip":"8.8.8.8","ip":"8.8.8.8:1","session":"s1","command":"cmd`+itoa(i)+`"}`)
	}
	appendLog(t, p, lines...)

	body := storeGet(t, p, "/dashboard/log?limit=5")
	if !strings.Contains(body, `"count":5`) {
		t.Fatalf("limit not applied: %s", body)
	}
	if !strings.Contains(body, "cmd29") || strings.Contains(body, "cmd24") {
		t.Fatalf("ring did not keep the newest matches: %s", body)
	}
	// Newest first: cmd29 must appear before cmd28.
	if strings.Index(body, "cmd29") > strings.Index(body, "cmd28") {
		t.Fatalf("feed is not newest-first: %s", body)
	}
}

func itoa64(n int64) string {
	if n < 0 {
		return "-" + itoa64(-n)
	}
	return itoa(int(n))
}

func pad2(n int) string {
	if n < 10 {
		return "0" + itoa(n)
	}
	return itoa(n)
}
