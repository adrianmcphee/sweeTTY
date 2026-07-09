package portal

import (
	"fmt"
	"testing"

	"sweetty/internal/event"
	"sweetty/internal/geo"
)

func TestPortalProjectionsBoundAttackerCardinality(t *testing.T) {
	p := &Portal{geo: geo.NewResolver()}
	var ov overviewProj
	var ht honeytokenProj
	var pay payloadProj
	for i := 0; i < maxProjectedSources+32; i++ {
		src := fmt.Sprintf("198.51.%d.%d", i/256, i%256)
		base := event.Entry{Time: "2026-07-09T18:00:00Z", EpochMs: 1, SrcIP: src, IP: src, Session: fmt.Sprintf("s-%d", i)}
		o := base
		o.Event = "SESSION_START"
		ov.fold(o, p)
		h := base
		h.Event, h.Note = "HONEYTOKEN", "token-"+src
		ht.fold(h, p)
		d := base
		d.Event, d.URL = "DOWNLOAD_ATTEMPT", "https://example.invalid/"+src
		pay.fold(d, p)
	}
	if len(ov.bySrc) != maxProjectedSources || len(ov.sigBySrc) != maxProjectedSources {
		t.Fatalf("overview retained %d sources/signals, want %d", len(ov.bySrc), maxProjectedSources)
	}
	if len(ht.bySrc) != maxProjectedSources || len(pay.bySrc) != maxProjectedSources {
		t.Fatalf("payload projections retained %d/%d sources, want %d", len(ht.bySrc), len(pay.bySrc), maxProjectedSources)
	}

	var sig sourceSignals
	for i := 0; i < maxUniqueCommands+32; i++ {
		sig.observe(event.Entry{Event: "COMMAND", Command: fmt.Sprintf("unique-%d", i), EpochMs: int64(i + 1)})
	}
	if len(sig.seen) != maxUniqueCommands {
		t.Fatalf("source classifier retained %d commands, want %d", len(sig.seen), maxUniqueCommands)
	}
}

func TestSourceAnalyzerVisitsAreBounded(t *testing.T) {
	var a sourceAnalyzer
	for i := 0; i < maxProjectedDetails+32; i++ {
		a.observe(event.Entry{
			Event:   "SESSION_START",
			Time:    fmt.Sprintf("2026-07-09T18:%02d:00Z", i%60),
			EpochMs: int64(i+1) * (visitGapMs + 1),
		})
	}
	if len(a.visits) != maxProjectedDetails {
		t.Fatalf("source analyzer retained %d visits, want %d", len(a.visits), maxProjectedDetails)
	}
}
