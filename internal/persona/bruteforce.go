package persona

import (
	mrand "math/rand/v2"
	"sync"
	"time"
)

// BruteForceConfig tunes the optional "let a persistent guesser in" policy. With
// it enabled, a source that keeps trying credentials against a real account is
// eventually let in with the credential it just offered, so a credential-stuffing
// bot believes it cracked the box and goes on to reveal its loader, the whole
// point of the trap. It is deliberately gated and probabilistic so the moment of
// "cracking" is not a clean fingerprint, and the working credential is remembered
// per source so a reconnect with it keeps working (the deception stays coherent).
type BruteForceConfig struct {
	Enabled     bool          // off by default
	AfterTries  int           // minimum attempts from a source before it can crack in
	After       time.Duration // minimum elapsed since the source's first attempt
	Probability float64       // per-eligible-attempt chance to accept the tried credential
}

// bruteForce holds the per-source attempt state behind Persona.AcceptFrom.
type bruteForce struct {
	cfg BruteForceConfig
	mu  sync.Mutex
	src map[string]*srcAuth
}

type srcAuth struct {
	tries    int
	first    time.Time
	accepted map[string]struct{} // credentials that now work for this source
}

// maxBruteSources bounds the per-source attempt table. Without it a distributed
// credential-stuffing sweep across many source IPs grows the map for the process
// lifetime and eventually OOMs a long-lived sensor. At the cap new sources stop
// being tracked (they simply never crack in) rather than growing memory without end.
const maxBruteSources = 50000
const maxAcceptedCredentials = 64

func credKey(user, pass string) string { return user + "\x00" + pass }

// consider records an attempt from srcIP and decides whether to let the source in
// with the credential it just tried. Once a credential is accepted for a source it
// is remembered, so the same pair keeps working on later connections.
func (b *bruteForce) consider(srcIP, user, pass string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	st := b.src[srcIP]
	if st == nil {
		if len(b.src) >= maxBruteSources {
			// Table full: refuse to grow under a distributed sweep. An untracked source
			// is simply never let in, which is the safe default for the trap.
			return false
		}
		st = &srcAuth{accepted: map[string]struct{}{}}
		b.src[srcIP] = st
	}
	key := credKey(user, pass)
	if _, ok := st.accepted[key]; ok {
		return true // already cracked here: stay consistent on reconnect
	}
	st.tries++
	if st.first.IsZero() {
		st.first = time.Now()
	}
	if st.tries >= b.cfg.AfterTries && time.Since(st.first) >= b.cfg.After && mrand.Float64() < b.cfg.Probability {
		if len(st.accepted) < maxAcceptedCredentials {
			st.accepted[key] = struct{}{}
		}
		return true
	}
	return false
}
