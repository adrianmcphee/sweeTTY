package portal

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"sweetty/internal/config"
	"sweetty/internal/event"
)

// newPortalWithRecordDir builds a portal whose config points at a recordings
// directory, and seeds one cast file there.
func newPortalWithRecordDir(t *testing.T) (*Portal, string) {
	t.Helper()
	dir := t.TempDir()
	recDir := filepath.Join(dir, "casts")
	if err := os.MkdirAll(recDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(recDir, "sessABC123.cast"),
		[]byte("{\"version\":2,\"width\":80,\"height\":24}\n[0.1, \"o\", \"login: \"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "sweetty.log")
	os.WriteFile(logPath, nil, 0o600)
	lg, err := event.New(logPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lg.Close() })
	cfg := config.Config{LogFile: logPath, RecordDir: recDir}
	return New(cfg, lg), recDir
}

func dashGet(t *testing.T, p *Portal, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	w := httptest.NewRecorder()
	p.engine().ServeHTTP(w, req)
	return w
}

// TestCastServesRecording proves a recorded session is listed and served back
// for the inline player.
func TestCastServesRecording(t *testing.T) {
	p, _ := newPortalWithRecordDir(t)

	list := dashGet(t, p, "/dashboard/recordings")
	if list.Code != http.StatusOK {
		t.Fatalf("recordings: status %d", list.Code)
	}
	if !contains(list.Body.String(), "sessABC123") {
		t.Fatalf("recording id not listed: %q", list.Body.String())
	}

	cast := dashGet(t, p, "/dashboard/cast/sessABC123")
	if cast.Code != http.StatusOK {
		t.Fatalf("cast: status %d", cast.Code)
	}
	if !contains(cast.Body.String(), "\"version\":2") || !contains(cast.Body.String(), "login: ") {
		t.Fatalf("cast body not served: %q", cast.Body.String())
	}
}

// TestRecordingsTargetedIDs proves ?ids= answers exactly for the asked sessions:
// existing casts are confirmed, missing ones are not, and unsafe ids never touch
// the filesystem. The drawer asks about the sessions it shows instead of listing
// a recording ring that can hold tens of thousands of casts.
func TestRecordingsTargetedIDs(t *testing.T) {
	p, _ := newPortalWithRecordDir(t)
	w := dashGet(t, p, "/dashboard/recordings?ids=sessABC123,nothere,..%2fescape")
	if w.Code != http.StatusOK {
		t.Fatalf("recordings?ids: status %d", w.Code)
	}
	body := w.Body.String()
	if !contains(body, "sessABC123") {
		t.Fatalf("existing cast not confirmed: %q", body)
	}
	if contains(body, "nothere") || contains(body, "escape") {
		t.Fatalf("missing or unsafe id confirmed: %q", body)
	}
}

// TestCastRejectsBadID proves an id that is not a bare session identifier (a path
// traversal attempt, or one with separators) never reaches the filesystem.
func TestCastRejectsBadID(t *testing.T) {
	p, _ := newPortalWithRecordDir(t)
	for _, id := range []string{"..%2f..%2fetc%2fpasswd", "sess.dot", "nope"} {
		w := dashGet(t, p, "/dashboard/cast/"+id)
		if w.Code != http.StatusNotFound {
			t.Fatalf("cast %q: status %d, want 404", id, w.Code)
		}
	}
}

func contains(s, sub string) bool { return len(s) >= len(sub) && indexOf(s, sub) >= 0 }
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
