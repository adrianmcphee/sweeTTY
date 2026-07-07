package persona

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoadOrCreateGeneratesOnFirstRun proves a genuine first run (no file) creates
// and persists a stable identity that a second call reads back unchanged - so a
// restart keeps the same SSH host key, hostname, and secrets.
func TestLoadOrCreateGeneratesOnFirstRun(t *testing.T) {
	path := filepath.Join(t.TempDir(), "persona.json")

	a, err := LoadOrCreate(path)
	if err != nil {
		t.Fatalf("first run: %v", err)
	}
	b, err := LoadOrCreate(path)
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if a.Hostname != b.Hostname || a.SSHKeyFP != b.SSHKeyFP || a.RootPwHash != b.RootPwHash {
		t.Fatal("identity changed across a reload: the persona is not stable")
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("persona file mode = %v (want 0600): the instance secrets must not be world-readable", info.Mode().Perm())
	}
}

// TestLoadOrCreateRegeneratesEmptyFile proves a zero-byte or whitespace-only
// persona file (e.g. an interrupted first write) is treated as a first run and
// regenerated, rather than being rejected by the refuse-to-clobber path and
// bricking startup.
func TestLoadOrCreateRegeneratesEmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "persona.json")
	if err := os.WriteFile(path, []byte("   \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := LoadOrCreate(path)
	if err != nil {
		t.Fatalf("an empty persona file should regenerate, not error: %v", err)
	}
	if p.Hostname == "" {
		t.Fatal("regenerated persona has no hostname")
	}
}

// TestLoadOrCreateRefusesToClobberInvalidFile proves a corrupt persona.json is NOT
// silently regenerated - that would change the host key on restart and break log
// correlation. The operator must intervene instead.
func TestLoadOrCreateRefusesToClobberInvalidFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "persona.json")
	if err := os.WriteFile(path, []byte("{ this is not valid json"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)

	if _, err := LoadOrCreate(path); err == nil {
		t.Fatal("LoadOrCreate silently accepted a corrupt persona file instead of refusing")
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("LoadOrCreate overwrote the existing (corrupt) persona file instead of leaving it for the operator")
	}
}
