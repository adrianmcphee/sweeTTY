package persona

import (
	"fmt"
	"testing"
	"time"
)

func TestAcceptFromRealCredentialAlwaysWins(t *testing.T) {
	p := Generate()
	if ok, bf := p.AcceptFrom("1.2.3.4", "root", p.RootPassword); !ok || bf {
		t.Errorf("real root password: got (%v,%v), want (true,false)", ok, bf)
	}
	if ok, bf := p.AcceptFrom("1.2.3.4", p.Username, p.UserPassword); !ok || bf {
		t.Errorf("real user password: got (%v,%v), want (true,false)", ok, bf)
	}
}

func TestAcceptFromDisabledRejectsGuesses(t *testing.T) {
	p := Generate() // no SetBruteForce
	for i := range 50 {
		if ok, bf := p.AcceptFrom("1.2.3.4", "root", "guess"); ok || bf {
			t.Fatalf("attempt %d let in with brute-force disabled", i)
		}
	}
}

func TestAcceptFromLetsPersistentGuesserIn(t *testing.T) {
	p := Generate()
	p.SetBruteForce(BruteForceConfig{Enabled: true, AfterTries: 3, After: 0, Probability: 1})

	// The first two attempts are under the try threshold.
	for i := 1; i <= 2; i++ {
		if ok, _ := p.AcceptFrom("9.9.9.9", "root", "hunter2"); ok {
			t.Fatalf("attempt %d cracked too early", i)
		}
	}
	// The third crosses the threshold and is accepted as a brute-force.
	if ok, bf := p.AcceptFrom("9.9.9.9", "root", "hunter2"); !ok || !bf {
		t.Fatalf("third attempt: got (%v,%v), want (true,true)", ok, bf)
	}
	// The cracked credential keeps working for that source (coherent reconnect).
	if ok, _ := p.AcceptFrom("9.9.9.9", "root", "hunter2"); !ok {
		t.Error("remembered credential stopped working on reconnect")
	}
	// A different source starts fresh: its first attempt is not let in.
	if ok, _ := p.AcceptFrom("8.8.8.8", "root", "hunter2"); ok {
		t.Error("brute-force state leaked across sources")
	}
}

func TestAcceptFromGates(t *testing.T) {
	// Probability 0 never accepts, even past the try threshold.
	p := Generate()
	p.SetBruteForce(BruteForceConfig{Enabled: true, AfterTries: 1, After: 0, Probability: 0})
	for i := range 20 {
		if ok, _ := p.AcceptFrom("1.1.1.1", "root", "x"); ok {
			t.Fatalf("probability 0 let attempt %d in", i)
		}
	}

	// A long time gate keeps a fast burst out.
	p2 := Generate()
	p2.SetBruteForce(BruteForceConfig{Enabled: true, AfterTries: 1, After: time.Hour, Probability: 1})
	for i := range 20 {
		if ok, _ := p2.AcceptFrom("2.2.2.2", "root", "x"); ok {
			t.Fatalf("time gate let attempt %d in within the hour", i)
		}
	}

	// An unknown user is never brute-accepted (it is not a real account)...
	p3 := Generate()
	p3.SetBruteForce(BruteForceConfig{Enabled: true, AfterTries: 1, After: 0, Probability: 1})
	for i := range 20 {
		if ok, bf := p3.AcceptFrom("3.3.3.3", "nosuchuser", "x"); ok || bf {
			t.Fatalf("unknown user let in (attempt %d)", i)
		}
	}
	// ...but a real account under the same policy is let in.
	if ok, bf := p3.AcceptFrom("3.3.3.4", "root", "x"); !ok || !bf {
		t.Errorf("real account not let in under the same policy: (%v,%v)", ok, bf)
	}
}

// TestBruteForceSourceTableIsBounded proves the per-source attempt map cannot grow
// without bound. A distributed credential-stuffing sweep across many source IPs
// would otherwise fill the map for the process lifetime and OOM a long-lived
// sensor. Past the cap a brand-new source is refused (never tracked) even when its
// parameters would otherwise crack in immediately.
func TestBruteForceSourceTableIsBounded(t *testing.T) {
	p := Generate()
	p.SetBruteForce(BruteForceConfig{Enabled: true, AfterTries: 1, After: 0, Probability: 1})
	for i := range maxBruteSources {
		ip := fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255)
		p.AcceptFrom(ip, "root", "x")
	}
	if ok, _ := p.AcceptFrom("203.0.113.250", "root", "x"); ok {
		t.Fatal("a new source was let in past the source-table cap; the map is unbounded")
	}
}

func TestBruteForceAcceptedCredentialsAreBounded(t *testing.T) {
	p := Generate()
	p.SetBruteForce(BruteForceConfig{Enabled: true, AfterTries: 1, After: 0, Probability: 1})
	for i := range maxAcceptedCredentials + 20 {
		p.AcceptFrom("192.0.2.9", "root", fmt.Sprintf("guess-%d", i))
	}
	if got := len(p.bf.src["192.0.2.9"].accepted); got != maxAcceptedCredentials {
		t.Fatalf("accepted credential set grew to %d, want cap %d", got, maxAcceptedCredentials)
	}
}
