# RFC 0005: Bait that bites back after they leave

Roadmap: [Direction 5](../ROADMAP.md#5-bait-that-bites-back-after-they-leave).
Doctrine: VISION §8 (bait that bites back).

## Problem

The honeytoken is the sharpest signal SweeTTY plants: a legitimate user never runs
the vault or digs the loot out of the per-instance loot path, so every touch is an
attacker, and however they try to open one they get the reveal instead of a secret
(`internal/shell/reveal`, `internal/fakehost/decoys`, the `HONEYTOKEN` event). The
signal ends, though, when the session does. What the attacker carries off the box,
SweeTTY stops watching.

This RFC plants bait that keeps signalling after exfiltration: a credentials file or
an API token that is inert on the box and reveals nothing in place, but whose use
elsewhere raises an alert in an audit trail the operator already watches. A key
lifted from the loot path and tried against the operator's own canary account
reports who used it, from where, and when, long after the connection closed. The
honeypot still reaches out to nothing; it plants, and the attacker's own later use
is what fires.

## Constraints

This is the RFC where the boundary matters most. It must hold exactly.

- **The sensor never phones home.** SweeTTY does not fetch, register, or validate a
  canary token. The operator registers the canary with their own provider (a
  canarytoken service, a decoy cloud account with CloudTrail alerting, a honey
  webhook) out of band. SweeTTY only plants the bytes and lets exfil carry them.
  No egress is added to any plane.
- **Operator bytes, not attacker bytes.** The canary content is operator-supplied
  configuration, read once at startup. Reading an operator-provided file at startup
  is allowed the way reading `config.json` is; the hard rule forbids writing
  *attacker* bytes to the host and reading the host `/proc` for fake output, neither
  of which this does. The read happens in `cmd/sweetty` (the composition root, which
  is exempt from the import guardrail) and the bytes are passed into `fakehost`;
  `fakehost` gains no new import.
- **Never commit a canary token.** Canary content is a secret. It lives in the
  gitignored `config.json` or a gitignored file it points to, alongside the persona
  passwords already kept out of the repo.
- **Inert in place, and it does not reveal.** A canary artifact is a new bait class,
  distinct from the reveal decoys. Reading it serves its (canary) bytes verbatim and
  logs a `HONEYTOKEN` plant-read; it must not trigger the JT reveal, because the
  attacker has to believe it is a real secret to carry it off and use it. The
  existing reveal decoys stay exactly as they are for the on-box payoff.

## Design

### Configuration

Add a `canary_artifacts` section to `config.json` and the `Config` struct
(`internal/config/config.go:21`), shaped like the existing `admin_consoles`:

```go
type CanaryArtifact struct {
	Name    string `json:"name"`     // filename planted in the loot, e.g. "aws_credentials"
	File    string `json:"file"`     // operator-local path to the canary bytes, read at startup
	Where   string `json:"where"`    // "loot" (persona.LootPath) or "home" (the user's home)
}
```

`Config.CanaryArtifacts []CanaryArtifact`. An operator generates a canary at their
provider, saves its bytes to `File`, and names where to plant it. An empty section
means the feature is off, so nothing changes for an instance that does not use it.

### Loading operator bytes in the composition root

In `cmd/sweetty/main.go` `run`, after `persona.LoadOrCreate` (`:255`) and before
`fakehost.Load` (`:266`), read each `CanaryArtifact.File` from disk (this is the
exempt composition root, so `os.ReadFile` is fine here) into a
`[]fakehost.Canary{Name, Content, Where}` slice, skipping and logging any that fail
to read. Pass the slice into a new `fakehost.LoadWithCanaries(p, canaries)` (or an
option on `Load`).

### Planting in fakehost

Add to `internal/fakehost` a graft that mirrors `graftLoot`
(`internal/fakehost/fakehost_nas.go:61`): for each canary, `FS.Place` its bytes at
`persona.LootPath + "/" + Name` (for `Where == "loot"`) or under the user's home
(for `Where == "home"`), root- or user-owned to match the location, with an mtime
staggered like the other loot. The canary is a plain-looking credentials file
(`aws_credentials`, `.env`, a kube config), so an attacker reads it and believes it.
`fakehost` receives the bytes as arguments; it imports no new package.

### Serving the canary without the reveal

The reveal today fires for any image under `persona.LootPath`
(`isLootImage`/`revealForLoot`, `internal/shell/interactive.go`). A canary artifact
must instead serve its own bytes. Distinguish the two classes by tracking canary
filenames on the persona or a session field the shell can consult:

- Add the planted canary names to a set the shell can see (for example
  `persona.CanaryNames []string`, set when the canaries are grafted).
- In the shell's loot-read path, check the canary set before the reveal check: if
  the path is a canary, serve the file's real bytes (from the VFS node, as `cat`
  already does for a normal file) and `LogHoneytoken("canary-read:"+name, detail)`,
  and return without invoking `revealForLoot`. Base64/exfil of a canary likewise
  hands over the real canary bytes and logs `LogHoneytoken("canary-grab:"+name, ...)`.
- A non-canary loot image keeps the existing reveal behavior unchanged.

So the on-box experience is: the attacker finds a plausible credentials file, reads
it, copies it off, and every touch is a `HONEYTOKEN` in the log; the payoff is not
the on-box gag but the operator's own alert when the credential is later used.

### The second act (optional, portal plane)

The alert fires on the operator's canary provider, off-box. Optionally, the portal
ingests that provider's alert feed the way it ingests the geo database: an
operator-supplied file or a portal-plane read (never a sensor read), correlating
"canary `Name` planted on this instance was used from `<ip>` at `<time>`" against
the `HONEYTOKEN` plant-read already in the log. This second act is a separate,
optional phase; the core deliverable is the plant plus the inert on-box capture.

## Implementation steps

1. Add `CanaryArtifact` to config and parse it. Add
   `TestCanaryConfigParsesAndDefaultsOff`. Commit.
2. Add the composition-root read in `cmd/sweetty` and
   `fakehost.LoadWithCanaries` planting via `FS.Place`, plus `persona.CanaryNames`.
   Add `TestCanaryArtifactPlantedInLoot`. Commit.
3. Add the shell serve-not-reveal path. Add the serve and boundary tests below.
   Commit.
4. Update [FEATURE-TREE.md](../FEATURE-TREE.md) bait section citing the tests.

## Tests

- **`TestCanaryArtifactPlantedInLoot`** (`fakehost`): a configured canary lands at
  `persona.LootPath/<name>` with its operator bytes and plausible ownership/mtime.
- **`TestCanaryServedVerbatimNotRevealed`** (`internal/proto/telnet`): reading a
  canary file returns its exact bytes, not the JT reveal, and logs a `HONEYTOKEN`
  with a `canary-read:` note. A non-canary loot image still reveals, proving the two
  classes stay distinct.
- **`TestCanaryExfilHandsOverTokenBytes`** (`internal/proto/telnet`): base64 of a
  canary hands over the exact canary bytes (so the attacker's later decode-and-use
  fires the operator's alert) and logs a `canary-grab:` `HONEYTOKEN`.
- **`TestCanaryConfiguredOpensNoOutboundConnection`** (`internal/proto/telnet` or
  `cmd/sweetty`): a boundary canary in the shape of `TestNoOutboundConnectionOrExec`,
  asserting that configuring and planting canaries dials nothing and writes no host
  byte. This is the load-bearing test for §8's "reaches out to nothing".

Must keep passing unchanged: `internal/proto/telnet` `TestBaitImageRevealsTheGag`,
`TestHoneytokenVaultIsTracked`, `TestPivotToJustinTimberlakeHost`; `internal/shell`
`TestRevealArtIsWellFormed`.

## Acceptance criteria

- A canary artifact configured by the operator is planted in the loot (or home) with
  its operator bytes, and every on-box touch logs a `HONEYTOKEN`.
- Reading or exfiltrating a canary serves its real bytes, never the reveal, so the
  attacker carries off a usable-looking secret.
- No plane fetches, registers, or validates the token: the boundary canary proves
  configuring canaries opens no outbound connection and writes no host byte.
- The feature is off by default (empty config), and no canary token is committed.

## Out of scope

- Registering or minting the canary. That is the operator's job with their own
  provider; SweeTTY only plants operator-supplied bytes.
- Any sensor-side alerting or callback. The alert fires off-box on the operator's
  provider.
- The portal-plane alert-feed correlation (the "second act"), which is an optional
  later phase, not required for this RFC.
