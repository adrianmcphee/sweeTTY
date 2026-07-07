package main

import (
	"testing"

	"sweetty/internal/config"
	"sweetty/internal/fakehost"
	"sweetty/internal/persona"
)

// TestBuildProtocolWiresEveryConfiguredProtocol proves the startup wiring handles
// every protocol an instance can be configured with. A missing case returns nil and
// the listener is silently skipped, so a service the operator configured would just
// never come up - caught here instead of in production.
func TestBuildProtocolWiresEveryConfiguredProtocol(t *testing.T) {
	p := persona.GenerateProfile("full")
	base, err := fakehost.Load(p)
	if err != nil {
		t.Fatal(err)
	}

	// The "full" profile exposes every protocol; the DefaultConfig fallback is the
	// other source of listeners. Together they cover every protocol buildProtocol
	// must handle.
	protos := map[string]bool{}
	for _, lc := range config.Generate(persona.GenerateProfile("full")).Listeners {
		protos[lc.Protocol] = true
	}
	for _, lc := range config.DefaultConfig().Listeners {
		protos[lc.Protocol] = true
	}
	if len(protos) < 5 {
		t.Fatalf("expected to cover all protocols, only saw %v", protos)
	}

	for proto := range protos {
		got := buildProtocol(config.Listener{Protocol: proto, Port: 1}, p, base)
		if got == nil {
			t.Errorf("buildProtocol(%q) is nil: a configured service would be silently dropped at startup", proto)
			continue
		}
		if got.Name() != proto {
			t.Errorf("buildProtocol(%q).Name() = %q: the wired protocol disagrees with the config", proto, got.Name())
		}
	}

	// An unknown protocol must be skipped (nil), never panic.
	if got := buildProtocol(config.Listener{Protocol: "gopher", Port: 1}, p, base); got != nil {
		t.Errorf("buildProtocol for an unknown protocol should be nil, got %T", got)
	}
}
