package portal

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"testing"
)

// TestJTSplashServesGzippedGrid proves the boot splash is served pre-gzipped and
// decodes to a valid palette + row grid the dashboard paints to a canvas on load.
func TestJTSplashServesGzippedGrid(t *testing.T) {
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
	var grid struct {
		W    int      `json:"w"`
		H    int      `json:"h"`
		Pal  []string `json:"pal"`
		Rows [][]int  `json:"rows"`
	}
	if err := json.Unmarshal(body, &grid); err != nil {
		t.Fatalf("decoded splash is not valid JSON: %v", err)
	}
	if grid.W <= 0 || grid.H <= 0 || len(grid.Pal) == 0 || len(grid.Rows) != grid.H {
		t.Errorf("splash grid malformed: w=%d h=%d pal=%d rows=%d", grid.W, grid.H, len(grid.Pal), len(grid.Rows))
	}
}
