package portal

import (
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const maxRecordings = 2000

// safeID reports whether id is a plain session identifier (the base58 ids the
// server mints), so it can be used as a filename without any path traversal: no
// slashes, dots, or other separators are admitted.
func safeID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

// recordings reports which session ids have a cast recording on disk, so the
// drawer shows a replay control only where one exists. With ?ids=a,b,c it stats
// exactly those ids — the recording ring holds tens of thousands of casts, so
// callers ask about the sessions they are showing rather than listing the world.
// Without ids it falls back to listing the directory, capped: that form is only
// a browse aid and must stay bounded.
func (p *Portal) recordings(w http.ResponseWriter, r *http.Request) {
	ids := []string{}
	if p.cfg.RecordDir != "" {
		if q := r.URL.Query().Get("ids"); q != "" {
			asked := strings.Split(q, ",")
			if len(asked) > maxRecordings {
				asked = asked[:maxRecordings]
			}
			ids = p.recordedOf(asked)
		} else if ents, err := os.ReadDir(p.cfg.RecordDir); err == nil {
			for _, e := range ents {
				if id, ok := strings.CutSuffix(e.Name(), ".cast"); ok && safeID(id) {
					ids = append(ids, id)
					if len(ids) >= maxRecordings {
						break
					}
				}
			}
		}
	}
	sort.Strings(ids)
	writeJSON(w, http.StatusOK, map[string]any{"recordings": ids})
}

// recordedOf returns the subset of ids whose cast exists on disk, statting each
// directly. Invalid ids are simply not recorded; they never touch the filesystem.
func (p *Portal) recordedOf(ids []string) []string {
	out := []string{}
	if p.cfg.RecordDir == "" {
		return out
	}
	for _, id := range ids {
		if !safeID(id) {
			continue
		}
		if _, err := os.Stat(filepath.Join(p.cfg.RecordDir, id+".cast")); err == nil {
			out = append(out, id)
		}
	}
	return out
}

// cast serves one session's asciinema recording for the inline player. The id is
// validated to a bare session identifier before it ever touches the filesystem.
func (p *Portal) cast(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if p.cfg.RecordDir == "" || !safeID(id) {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	data, err := os.ReadFile(filepath.Join(p.cfg.RecordDir, id+".cast"))
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	writeData(w, http.StatusOK, "application/x-asciicast; charset=utf-8", data)
}
