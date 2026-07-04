package shell

import (
	"io/fs"
	"strings"
	"testing"
)

// TestRevealArtIsWellFormed pins the format of the embedded payoff art so a
// regenerated or operator-added rendering that would render as garbage (empty,
// no colour, or unbounded line width) is caught at build time rather than shown
// to an attacker. Every shipped rendering must be non-empty, use 256-colour SGR
// codes, reset colour at each line end so nothing bleeds into the prompt, and
// stay within a width a standard terminal shows without wrapping.
func TestRevealArtIsWellFormed(t *testing.T) {
	entries, err := fs.ReadDir(revealArt, "reveal")
	if err != nil {
		t.Fatalf("read reveal dir: %v", err)
	}
	var count int
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".txt") {
			continue
		}
		count++
		data, err := fs.ReadFile(revealArt, "reveal/"+e.Name())
		if err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		art := string(data)
		if strings.TrimSpace(art) == "" {
			t.Errorf("%s: empty", e.Name())
			continue
		}
		if !strings.Contains(art, "\x1b[38;5;") {
			t.Errorf("%s: no 256-colour SGR codes; art would render as plain glyph noise", e.Name())
		}
		lines := strings.Split(strings.TrimRight(art, "\n"), "\n")
		for i, ln := range lines {
			ln = strings.TrimRight(ln, "\r")
			if ln == "" {
				continue
			}
			if !strings.HasSuffix(ln, "\x1b[0m") {
				t.Errorf("%s line %d: does not reset colour at end; colour bleeds into the next line", e.Name(), i+1)
			}
			// Cell count = number of block glyphs; the source renders at 72 columns.
			if cells := strings.Count(ln, "▀"); cells > 120 {
				t.Errorf("%s line %d: %d cells wide, too wide for a standard terminal", e.Name(), i+1, cells)
			}
		}
	}
	if count == 0 {
		t.Fatal("no reveal art embedded")
	}
}

// TestRandomRevealReturnsArt proves the selector returns one of the embedded
// renderings, so the payoff path never falls through to an empty reveal.
func TestRandomRevealReturnsArt(t *testing.T) {
	got := randomReveal()
	if !strings.Contains(got, "\x1b[38;5;") || !strings.Contains(got, "▀") {
		t.Fatalf("randomReveal returned no half-block colour art: %q", firstRunes(got, 40))
	}
}

func firstRunes(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}
