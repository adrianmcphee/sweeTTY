package portal

import (
	"compress/gzip"
	"io"
	"strings"
	"testing"
)

// TestJTSplashServesGzippedArt proves the boot splash is served pre-gzipped and
// decodes to the colour-ASCII pre fragment the dashboard animates on load.
func TestJTSplashServesGzippedArt(t *testing.T) {
	p := portalWithLog(t, nil, "")
	w := dashGet(t, p, "/dashboard/jt-splash")
	if w.Code != 200 {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if enc := w.Header().Get("Content-Encoding"); enc != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", enc)
	}
	gr, err := gzip.NewReader(w.Body)
	if err != nil {
		t.Fatalf("body is not valid gzip: %v", err)
	}
	body, err := io.ReadAll(gr)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `class="jtart"`) {
		t.Errorf("decoded splash does not contain the jtart fragment")
	}
}
