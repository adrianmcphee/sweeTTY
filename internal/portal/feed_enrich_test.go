package portal

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// enrichFixture gives one public source a history that makes every enrichment
// facet observable: a bare scan then a session with a command, so the source is
// geo-resolvable, marked returning (scanned, then came back and got a shell),
// and countable.
var enrichFixture = []string{
	`{"time":"2026-06-27T10:00:00Z","epoch_ms":1782554400000,"event":"PORT_SCAN","src_ip":"8.8.8.8","ip":"8.8.8.8:1111","port":23,"protocol":"telnet"}`,
	`{"time":"2026-06-27T10:00:01Z","epoch_ms":1782554401000,"event":"SESSION_START","src_ip":"8.8.8.8","ip":"8.8.8.8:2222","session":"e1","port":22,"protocol":"ssh"}`,
	`{"time":"2026-06-27T10:00:02Z","epoch_ms":1782554402000,"event":"COMMAND","src_ip":"8.8.8.8","ip":"8.8.8.8:2222","session":"e1","port":22,"protocol":"ssh","command":"uname -a"}`,
}

func loadTestGeo(t *testing.T, p *Portal) {
	t.Helper()
	geoPath := filepath.Join(t.TempDir(), "geo.csv")
	if err := os.WriteFile(geoPath, []byte("8.8.8.0,8.8.8.255,US\n"), 0600); err != nil {
		t.Fatalf("write geo csv: %v", err)
	}
	if _, err := p.geo.LoadCSV(geoPath); err != nil {
		t.Fatalf("load geo: %v", err)
	}
}

// TestFeedBackfillCarriesSourceContext proves the feed's backfill query attaches
// the portal-plane context to each entry: the resolved country and the
// returning-visitor flag, so the dashboard can render where an attacker is from
// and whether it has been here before without a per-row lookup.
func TestFeedBackfillCarriesSourceContext(t *testing.T) {
	p := newTestPortal(t)
	loadTestGeo(t, p)
	appendLog(t, p, enrichFixture...)

	body := storeGet(t, p, "/dashboard/log?limit=10")
	if !strings.Contains(body, `"geo":{`) {
		t.Fatalf("backfill entries carry no geo context: %s", body)
	}
	if !strings.Contains(body, `"country":"US"`) {
		t.Fatalf("backfill entries carry no country: %s", body)
	}
	if !strings.Contains(body, `"returning":true`) {
		t.Fatalf("a scanned-then-shelled source is not marked returning: %s", body)
	}
}

// TestEventsFeedFramesCarrySourceContext proves a line streamed over SSE is
// enriched the same way the backfill is, so a live row and a backfilled row
// render identically.
func TestEventsFeedFramesCarrySourceContext(t *testing.T) {
	if testing.Short() {
		t.Skip("SSE streaming test is timing-bound; skipped under -short")
	}
	p := newTestPortal(t)
	loadTestGeo(t, p)
	appendLog(t, p, enrichFixture...)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/dashboard/events", nil).WithContext(ctx)
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		p.engine().ServeHTTP(w, req)
		close(done)
	}()

	// Let the handler seek to the end, then append: the streamed frame must carry
	// the enrichment reflecting the history already on disk.
	time.Sleep(150 * time.Millisecond)
	appendLog(t, p,
		`{"time":"2026-06-27T11:00:00Z","epoch_ms":1782558000000,"event":"COMMAND","src_ip":"8.8.8.8","ip":"8.8.8.8:2222","session":"e1","port":22,"protocol":"ssh","command":"id"}`)

	time.Sleep(1300 * time.Millisecond)
	cancel()
	<-done

	body := w.Body.String()
	if !strings.Contains(body, "event: log") {
		t.Fatalf("stream emitted no log frame: %q", body)
	}
	if !strings.Contains(body, `"geo":{`) || !strings.Contains(body, `"country":"US"`) {
		t.Fatalf("streamed frame carries no source context: %q", body)
	}
	if !strings.Contains(body, `"returning":true`) {
		t.Fatalf("streamed frame does not mark a returning source: %q", body)
	}
	// The line on disk is untouched: enrichment is display-plane only.
	raw, _ := os.ReadFile(p.cfg.LogFile)
	if strings.Contains(string(raw), `"geo"`) {
		t.Fatal("enrichment leaked into the log file itself")
	}
}
