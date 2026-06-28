package config

import (
	"testing"

	"sweetty/internal/persona"
)

func TestGenerateFromPersona(t *testing.T) {
	p := persona.GenerateProfile("full")
	cfg := Generate(p)
	if len(cfg.Listeners) != len(p.Services) {
		t.Fatalf("listeners %d != services %d", len(cfg.Listeners), len(p.Services))
	}
	for i, s := range p.Services {
		if cfg.Listeners[i].Protocol != s.Protocol || cfg.Listeners[i].Port != s.Port {
			t.Errorf("listener %d mismatch: %+v vs %+v", i, cfg.Listeners[i], s)
		}
	}
	if cfg.PortalPort != defaultPortalPort {
		t.Errorf("portal port %d, want fixed %d", cfg.PortalPort, defaultPortalPort)
	}
	for _, lc := range cfg.Listeners {
		if lc.Port == cfg.PortalPort {
			t.Errorf("portal port collides with service port %d", lc.Port)
		}
	}
}

func TestPortalPortIsFixedLoopback(t *testing.T) {
	// The portal binds loopback and is reached only over the SSH tunnel, so its
	// port is a fixed known value, not randomized: stable across instances.
	for range 25 {
		if got := Generate(persona.Generate()).PortalPort; got != defaultPortalPort {
			t.Fatalf("portal port %d, want fixed %d", got, defaultPortalPort)
		}
	}
}
