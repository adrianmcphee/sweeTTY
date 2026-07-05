# SweeTTY RFCs

Build-ready specifications for the directions in [ROADMAP.md](../ROADMAP.md). Each
roadmap direction has one RFC here. An RFC is a proposal, not a record of built
work: what is verified lives in [FEATURE-TREE.md](../FEATURE-TREE.md), cited by
test. When an RFC lands, its acceptance tests are what the feature tree records.

Read [VISION.md](../VISION.md) for the product doctrine and [AGENTS.md](../AGENTS.md)
for the working contract before starting any of these. The RFCs assume both.

## Index

| # | Title | Reference | Doctrine | Touches |
|---|---|---|---|---|
| [0003](./0003-anti-detection-gate.md) | An anti-detection gate that runs the skeptic's own probes | [Adversary gate](../FEATURE-TREE.md#adversary-gate) | measure | `internal/adversary`, `internal/testharness`, `internal/crosscheck` |
| [0004](./0004-additional-services.md) | The services attackers try to own next | [Additional services](../FEATURE-TREE.md#http-https-ftp-adb-redis-docker-mysql) | §2, §3 | `internal/proto/*`, `cmd/sweetty`, `internal/safety` |
| [0005](./0005-bait-that-bites-back.md) | Bait that bites back after they leave | [Direction 1](../ROADMAP.md#1-bait-that-bites-back-after-they-leave) | §8 | `internal/fakehost`, `internal/shell`, `internal/config`, `cmd/sweetty` |
| [0006](./0006-campaign-correlation.md) | The log as campaign intelligence | [Direction 2](../ROADMAP.md#2-the-log-as-campaign-intelligence) | §6 | `internal/portal` |
| [0007](./0007-intelligence-export.md) | Intelligence that travels | [Direction 3](../ROADMAP.md#3-intelligence-that-travels) | §4 | `internal/portal` |

## How each RFC is structured

Every RFC below carries the same sections, so a contributor knows where to look:

1. **Problem** states the tell or the gap, tied to its roadmap direction and vision section.
2. **Constraints** lists the hard rules and boundaries the change must not cross.
3. **Design** gives the concrete packages, files, data structures, and algorithm.
4. **Implementation steps** are ordered, each one a small commit that builds and passes.
5. **Tests** name the tests to add and the invariant each proves, plus the existing tests that must keep passing.
6. **Acceptance criteria** is the definition of done.
7. **Out of scope** fences what this RFC does not do.

## Conventions every RFC inherits

These hold for all the work below, so each RFC states only its own specifics.

- **The gate is `make check`** (`go build` + `go vet` + `go test ./...`). It must
  pass at every commit that touches code. Run `make fmt` first; `gofmt` is law.
- **The safety boundary is never weakened.** A package that handles attacker input
  may not import `os`, `os/exec`, `net/http`, or `syscall` (bare `net` is allowed
  only for the packages already one hop from the wire), and may not call an
  outbound dial, resolve, or fetch primitive. The guardrail in
  [`internal/safety`](../internal/safety) enforces this and fails the build when it
  is violated. Adding an attacker-reachable package means adding its entry to the
  three guard tables (`imports_test.go` `guardCases`, `closure_test.go`
  `approvedCapabilities`, `dialscan_test.go`'s scanned list); RFC 0004 spells this
  out step by step.
- **Capture intent through the session log helpers**, never by acting. The methods
  on `*server.Session` (`LogCredential`, `LogCommand`, `LogDownload`, `LogExec`,
  `LogDropper`, `LogHoneytoken`, `LogRaw`) record what an attacker tried; nothing
  fetches, runs, or writes to the host.
- **Tests prove an invariant or a boundary, not a coverage number.** Match the test
  to the change the way [TESTING.md](../TESTING.md) and [CONTRIBUTING.md](../CONTRIBUTING.md)
  describe: a new generator proves it agrees with the others telling the same fact;
  a new vector carries a boundary canary; a new protocol is driven over the real
  wire through [`internal/testharness`](../internal/testharness); a fingerprintable
  surface is pinned byte-exact, cosmetic output only by cross-source invariant.
- **Update [FEATURE-TREE.md](../FEATURE-TREE.md) in the same commit** a feature
  lands, citing the test that verifies it.
- **Doc and comment style** follows AGENTS.md: present-tense first principles,
  no slide-deck filler, no history narrative, no hand-written status, no em dashes.
