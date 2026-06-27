package config

import (
	"path/filepath"
	"testing"
)

func TestWriteDefaultConfigRefusesOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := WriteDefault(path); err != nil {
		t.Fatal(err)
	}
	if err := WriteDefault(path); err == nil {
		t.Fatal("expected error overwriting existing config")
	}
}
