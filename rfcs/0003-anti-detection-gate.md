# RFC 0003: An anti-detection gate that runs the skeptic's own probes

Feature tree: [Adversary gate](../FEATURE-TREE.md#adversary-gate).
Doctrine: VISION's measure of the product (survive the first minutes of skeptical
probing by someone who has read the source).

## Problem

The suite guards coherence from the inside: one persona tells one story across
every service (`internal/crosscheck`), a listed file can be read, `/proc` is
synthetic and per-arch, the VFS cannot be escaped. What it does not do is take the
attacker's side and run the tools a fingerprinter reaches for.

This RFC adds a gate that stands a live instance up and runs the probes a skeptic
runs, failing the build on any tell it finds: the algorithm enumeration that would
catch a banner-versus-crypto mismatch (the seam [RFC 0001](./0001-ssh-crypto-profile.md)
closes), the SSH offer's stability and coherence, and the cross-service checks that
catch a box that is almost right. It turns internal invariants into an adversarial
pass, and it is what RFCs 0001 and 0002 earn their place by passing.

## Constraints

- **Hermetic and self-contained.** The gate stands the services up in-process and
  probes them over loopback through `internal/testharness`
  (`New` for banner-first protocols, `NewListener` for the SSH handshake). It makes
  no external network call and shells out to no external tool, so it runs anywhere
  `make check` runs and stays inside the egress-deny posture.
- **Dependency-light.** The "attacker" side of each probe is written against the
  stdlib and the `golang.org/x/crypto/ssh` client already in `go.mod`. No new
  dependency, no `nmap`, no external scanner binary.
- **The gate asserts coherence, not impossibilities.** It checks that the banner
  version, the offered algorithms, and the derived HASSH agree with each other and
  are stable, not that the HASSH equals a genuine OpenSSH server's. That last
  equality is the conceded seam (VISION non-goals); asserting it would be a test
  that can never pass.
- **A tell fails the build.** Each probe is a Go test; a detected contradiction is a
  test failure, so the gate rides the existing `go test` gate and needs no new
  runner.

## Design

### A new adversary package

Add `internal/adversary/` holding the probes as `_test.go` files (the package
compiles the probe helpers; the assertions live in tests). It is not
attacker-reachable (it only runs in CI against the honeypot's own listeners), so it
may import `internal/testharness`, `internal/persona`, `cmd`-level wiring helpers,
and `golang.org/x/crypto/ssh` as a client. It is a test-only consumer, so it does
not enter the `cmd/sweetty` binary closure and does not need a `safety` guard entry.

The probes, each a test:

1. **`TestSSHAlgorithmOfferMatchesBanner`.** Stand the SSH service up
   (`testharness.NewListener(ssh.New(...))`), read the banner version, then perform
   a client-side key exchange with `x/crypto/ssh` and capture the server's offered
   kex, cipher, and MAC lists from the handshake. Assert they equal
   `profileFor(bannerVersion)` from [RFC 0001](./0001-ssh-crypto-profile.md). A
   banner that says one release while the offer says another fails here. Until
   RFC 0001 lands, this probe asserts the offer is at least stable and drawn from
   the known set.
2. **`TestSSHOfferIsStableAcrossHandshakes`.** Two handshakes against the same
   instance return the identical algorithm offer (the HASSH is deterministic per
   instance), so the fingerprint an attacker records once holds.
3. **`TestBannersAgreeAcrossServices`.** Bring up every service the persona exposes
   and assert the persona facts read the same everywhere (kernel, distro, hostname,
   software versions), the adversarial framing of `internal/crosscheck`
   `TestEveryServiceTellsOnePersonaStory`. Drive each over the wire through
   `testharness` rather than reading internal state, so it checks what an attacker
   sees.
4. **`TestListingAndReadNeverDisagree`.** Over a real shell session, `ls -l /etc`
   then `cat` the first-listed file; assert the read succeeds and its byte count
   matches the size the listing reported, for a sample of directories. This is the
   single most common honeypot tell, checked from the wire.
5. **`TestRepeatedListingsAreStable`.** Run `ls` twice in one session and assert
   byte-identical ordering, catching a reshuffling directory.
6. **`TestNoServiceLeaksHostIdentity`.** Assert no probe response contains the real
   host's hostname, kernel, or `/proc` values (compare against the process's real
   `os.Hostname`/`uname` read only in the test, never in the honeypot), catching a
   handler that accidentally reads the real host.

### A make target and CI job

Add a `Makefile` target:

```make
adversary: ## run the anti-detection gate
	go test ./internal/adversary/...
```

and fold it into the gate so `make check` runs it. Add a GitHub Actions workflow
`.github/workflows/adversary.yml` (or a step in the existing CI workflow) that runs
`make adversary` on every push and pull request, so the gate blocks a merge that
introduces a tell.

## Implementation steps

1. Add `internal/adversary/` with `TestListingAndReadNeverDisagree` and
   `TestRepeatedListingsAreStable` (they need no RFC 0001 dependency). Add the
   `make adversary` target. Commit.
2. Add `TestBannersAgreeAcrossServices` and `TestNoServiceLeaksHostIdentity`.
   Commit.
3. Add `TestSSHOfferIsStableAcrossHandshakes`, and
   `TestSSHAlgorithmOfferMatchesBanner` (full form once RFC 0001 lands; a
   stability-only form before). Commit.
4. Wire `make adversary` into `make check` and add the CI workflow. Update
   [FEATURE-TREE.md](../FEATURE-TREE.md) with an adversary-gate section citing the
   probes.

## Tests

The gate is tests. The acceptance is that each probe passes against a freshly
generated instance and fails when a tell is introduced. Add, in
`internal/adversary`, a negative check for at least one probe (for example, feed
`TestListingAndReadNeverDisagree` a deliberately broken FS in a sub-test and assert
the probe reports the tell), so the gate is proven to actually catch a break rather
than passing vacuously.

Must keep passing: everything the gate wraps, in particular `internal/crosscheck`
`TestEveryServiceTellsOnePersonaStory` and `internal/proto/telnet`
`TestFilesystemCoherence`, which the gate complements from the wire rather than
replaces.

## Acceptance criteria

- `make adversary` stands every persona-exposed service up in-process and runs the
  six probes, making no external network call.
- A deliberately introduced tell (a banner/algo mismatch, a listing/read
  disagreement, a leaked host value) fails the gate, proven by a negative sub-test.
- The gate runs in CI on every push and pull request and blocks a merge on failure.

## Out of scope

- Asserting HASSH or JARM equality with a real OpenSSH or a real web server. Those
  are the conceded fingerprints (VISION non-goals); the gate checks internal
  coherence and stability, not equality with a genuine daemon.
- Running external scanners (`nmap`, `ssh-audit`). The gate is hermetic and
  Go-native; an operator may still run those against a deployed instance, but they
  are not part of the build gate.
- Fuzzing or load testing. This gate is about detection tells, not robustness,
  which the resource-limit tests already cover.
