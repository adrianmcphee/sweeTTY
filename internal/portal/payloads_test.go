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

// TestPayloadsAggregatesWhoPulledWhat drives a log of payload fetches through the
// payloads endpoint and checks the answer to "who is doing what": only
// DOWNLOAD_ATTEMPT events count, each source row carries its captured URLs and geo
// attribution, the same URL pulled by two sources rolls up once in the IOC list
// with the true hit count, and command/system noise never leaks onto the page.
func TestPayloadsAggregatesWhoPulledWhat(t *testing.T) {
	p := newTestPortal(t)
	geoPath := filepath.Join(t.TempDir(), "geo.csv")
	if err := os.WriteFile(geoPath, []byte("8.8.8.0,8.8.8.255,US\n"), 0600); err != nil {
		t.Fatalf("write geo csv: %v", err)
	}
	if _, err := p.geo.LoadCSV(geoPath); err != nil {
		t.Fatalf("load geo: %v", err)
	}

	lines := []string{
		// 8.8.8.8 (US): two distinct payload URLs in one session.
		`{"time":"2026-06-27T10:00:00Z","event":"DOWNLOAD_ATTEMPT","src_ip":"8.8.8.8","ip":"8.8.8.8:1","session":"s1","port":23,"protocol":"telnet","url":"http://evil/a.sh"}`,
		`{"time":"2026-06-27T10:00:01Z","event":"DOWNLOAD_ATTEMPT","src_ip":"8.8.8.8","ip":"8.8.8.8:1","session":"s1","port":23,"protocol":"telnet","url":"http://evil/b.bin"}`,
		// 10.0.0.9 (private): the same URL twice - counts twice, one distinct URL.
		`{"time":"2026-06-27T10:01:00Z","event":"DOWNLOAD_ATTEMPT","src_ip":"10.0.0.9","ip":"10.0.0.9:2","port":80,"protocol":"http","url":"http://evil/a.sh"}`,
		`{"time":"2026-06-27T10:01:01Z","event":"DOWNLOAD_ATTEMPT","src_ip":"10.0.0.9","ip":"10.0.0.9:2","port":80,"protocol":"http","url":"http://evil/a.sh"}`,
		// Noise that must never appear on the payloads page.
		`{"time":"2026-06-27T10:02:00Z","event":"COMMAND","src_ip":"8.8.8.8","ip":"8.8.8.8:1","session":"s1","command":"uname -a"}`,
		`{"time":"2026-06-27T10:02:01Z","event":"SYSTEM","message":"portal noise"}`,
	}
	if err := os.WriteFile(p.cfg.LogFile, []byte(strings.Join(lines, "\n")+"\n"), 0600); err != nil {
		t.Fatalf("write log: %v", err)
	}

	eng := p.engine()
	req := httptest.NewRequest(http.MethodGet, "/dashboard/payloads", nil)
	w := httptest.NewRecorder()
	eng.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("payloads: status %d", w.Code)
	}

	var body struct {
		Total      int            `json:"total"`
		UniqueSrcs int            `json:"unique_srcs"`
		ByURL      map[string]int `json:"by_url"`
		GeoActive  bool           `json:"geo_active"`
		Sources    []struct {
			IP      string   `json:"ip"`
			Country string   `json:"country"`
			Scope   string   `json:"scope"`
			Count   int      `json:"count"`
			URLs    []string `json:"urls"`
		} `json:"sources"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("bad json: %v", err)
	}

	// Four fetches from two sources; the command and system notice are excluded.
	if body.Total != 4 {
		t.Fatalf("total = %d, want 4 (only DOWNLOAD_ATTEMPT)", body.Total)
	}
	if body.UniqueSrcs != 2 {
		t.Fatalf("unique_srcs = %d, want 2", body.UniqueSrcs)
	}
	// Two distinct URLs; a.sh was pulled three times across both sources.
	if len(body.ByURL) != 2 || body.ByURL["http://evil/a.sh"] != 3 || body.ByURL["http://evil/b.bin"] != 1 {
		t.Fatalf("by_url = %v, want a.sh:3 b.bin:1", body.ByURL)
	}
	if !body.GeoActive {
		t.Fatal("geo_active should be true with a database loaded")
	}

	seen := map[string]bool{}
	for _, s := range body.Sources {
		seen[s.IP] = true
		switch s.IP {
		case "8.8.8.8":
			if s.Country != "US" || s.Count != 2 || len(s.URLs) != 2 {
				t.Errorf("8.8.8.8 = %+v, want US count=2 with 2 distinct urls", s)
			}
		case "10.0.0.9":
			if s.Scope != "private" || s.Count != 2 || len(s.URLs) != 1 {
				t.Errorf("10.0.0.9 = %+v, want private count=2 with 1 distinct url", s)
			}
		default:
			t.Errorf("unexpected source on the payloads page: %s", s.IP)
		}
	}
	if !seen["8.8.8.8"] || !seen["10.0.0.9"] {
		t.Fatalf("missing a source: %+v", body.Sources)
	}
}

// TestPayloadsIncludesInlineDroppers proves a payload assembled in place (a DROPPER
// event) appears on the payloads page alongside over-the-wire fetches, carrying its
// filename and sha256 and counted in dropper_total, so the page is meaningful on a
// sensor whose loaders deliver inline instead of via wget/curl.
func TestPayloadsIncludesInlineDroppers(t *testing.T) {
	p := newTestPortal(t)
	lines := []string{
		`{"time":"2026-06-27T10:00:00Z","event":"DOWNLOAD_ATTEMPT","src_ip":"8.8.8.8","ip":"8.8.8.8:1","session":"s1","url":"http://evil/a.sh"}`,
		`{"time":"2026-06-27T10:01:00Z","event":"DROPPER","src_ip":"9.9.9.9","ip":"9.9.9.9:2","session":"s2","filename":"/tmp/.x","sha256":"abc123","data":"#!/bin/sh"}`,
		`{"time":"2026-06-27T10:02:00Z","event":"COMMAND","src_ip":"9.9.9.9","ip":"9.9.9.9:2","session":"s2","command":"uname -a"}`,
	}
	if err := os.WriteFile(p.cfg.LogFile, []byte(strings.Join(lines, "\n")+"\n"), 0600); err != nil {
		t.Fatalf("write log: %v", err)
	}
	eng := p.engine()
	req := httptest.NewRequest(http.MethodGet, "/dashboard/payloads", nil)
	w := httptest.NewRecorder()
	eng.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	var body struct {
		Total        int `json:"total"`
		DropperTotal int `json:"dropper_total"`
		Sources      []struct {
			IP       string `json:"ip"`
			Droppers []struct {
				Filename string `json:"filename"`
				SHA256   string `json:"sha256"`
			} `json:"droppers"`
		} `json:"sources"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if body.Total != 2 {
		t.Fatalf("total = %d, want 2 (the fetch and the dropper, not the command)", body.Total)
	}
	if body.DropperTotal != 1 {
		t.Fatalf("dropper_total = %d, want 1", body.DropperTotal)
	}
	var found bool
	for _, s := range body.Sources {
		if s.IP == "9.9.9.9" {
			if len(s.Droppers) != 1 || s.Droppers[0].Filename != "/tmp/.x" || s.Droppers[0].SHA256 != "abc123" {
				t.Errorf("9.9.9.9 droppers = %+v, want /tmp/.x abc123", s.Droppers)
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("the dropper source is missing from the page: %+v", body.Sources)
	}
}
