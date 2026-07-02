package portal

import (
	"context"
	"fmt"
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

// portalWithLog builds a portal whose feed reads a crafted log file directly, so a
// test can seed exact entries (with backdated timestamps) without going through the
// live logger.
func portalWithLog(t *testing.T, lines []string, recDir string) *Portal {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "crafted.log")
	body := ""
	if len(lines) > 0 {
		body = strings.Join(lines, "\n") + "\n"
	}
	if err := os.WriteFile(logPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	lg, err := event.New(filepath.Join(dir, "logger.log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lg.Close() })
	return New(config.Config{LogFile: logPath, RecordDir: recDir}, lg)
}

// TestActiveSessionsShowsOnlyLiveOnes proves the live rail lists a started session
// with no SESSION_END and recent activity, and excludes one that has ended and one
// whose last event is older than the active window.
func TestActiveSessionsShowsOnlyLiveOnes(t *testing.T) {
	now := time.Now().UnixMilli()
	old := now - (activeWindow + time.Minute).Milliseconds()
	ev := func(ms int64, ev, sess string) string {
		return fmt.Sprintf(`{"time":"t","epoch_ms":%d,"event":%q,"session":%q,"src_ip":"1.2.3.4","ip":"1.2.3.4:22","protocol":"ssh","port":22}`, ms, ev, sess)
	}
	lines := []string{
		ev(now-1000, "SESSION_START", "live1"),
		ev(now-500, "COMMAND", "live1"),
		ev(now-2000, "SESSION_START", "ended1"),
		ev(now-1000, "SESSION_END", "ended1"),
		ev(old, "SESSION_START", "stale1"),
	}
	p := portalWithLog(t, lines, "")

	req := httptest.NewRequest(http.MethodGet, "/dashboard/sessions/active", nil)
	w := httptest.NewRecorder()
	p.engine().ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, `"live1"`) {
		t.Errorf("live session missing from active list:\n%s", body)
	}
	if strings.Contains(body, "ended1") {
		t.Errorf("an ended session must not be listed as active:\n%s", body)
	}
	if strings.Contains(body, "stale1") {
		t.Errorf("a stale (old) session must not be listed as active:\n%s", body)
	}
}

// TestWatchStreamsCastFrames proves the watch endpoint tails a session's cast and
// streams its frames over SSE, from the start of the recording, so an operator can
// watch an in-progress session's terminal render live.
func TestWatchStreamsCastFrames(t *testing.T) {
	p, _ := newPortalWithRecordDir(t) // seeds casts/sessABC123.cast with a "login: " frame

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/dashboard/watch/sessABC123", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		p.engine().ServeHTTP(w, req)
		close(done)
	}()
	// Give the tailer a couple of ticks to flush the existing frames, then stop it.
	time.Sleep(600 * time.Millisecond)
	cancel()
	<-done

	body := w.Body.String()
	if !strings.Contains(body, "event: frame") || !strings.Contains(body, "login: ") {
		t.Errorf("watch did not stream the cast frames:\n%s", body)
	}
}

// TestWatchRejectsBadIDAndNoRecordDir proves the watch endpoint is path-injection
// safe and disabled when recording is off.
func TestWatchRejectsBadIDAndNoRecordDir(t *testing.T) {
	p, _ := newPortalWithRecordDir(t)
	if w := dashGet(t, p, "/dashboard/watch/..%2f..%2fetc%2fpasswd"); w.Code != http.StatusNotFound {
		t.Errorf("traversal id should 404, got %d", w.Code)
	}

	noRec := portalWithLog(t, nil, "")
	if w := dashGet(t, noRec, "/dashboard/watch/anything"); w.Code != http.StatusNotFound {
		t.Errorf("watch with no record dir should 404, got %d", w.Code)
	}
}
