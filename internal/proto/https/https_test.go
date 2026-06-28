package https

import (
	"testing"

	"sweetty/internal/persona"
)

func TestNewNameAndClientFirst(t *testing.T) {
	proto := New(persona.Generate())
	if got := proto.Name(); got != "https" {
		t.Errorf("Name() = %q, want %q", got, "https")
	}
	if !proto.ClientFirst() {
		t.Error("ClientFirst() = false, want true")
	}
}
