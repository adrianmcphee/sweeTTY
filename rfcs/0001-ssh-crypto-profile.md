# RFC 0001: A version-coherent SSH cryptographic profile

Doctrine: VISION §1 (coherence) and §7 (unpredictable from the source).

## Problem

The interactive SSH service completes a real handshake, so its key-exchange,
cipher, and MAC lists are those of the Go `x/crypto` stack, not the OpenSSH release
the banner claims. Two seams remain today, both visible to a single
`ssh2-enum-algos` scan:

1. **Banner versus crypto.** The banner version is drawn per instance from the
   persona (`persona.OpenSSHVer`, set from `opensshPool` at
   `internal/persona/persona.go:151`), but the algorithm lists are three fixed
   literal slices assigned inline in `Handle`
   (`internal/proto/ssh/ssh.go:152` KeyExchanges, `:157` Ciphers, `:162` MACs).
   A persona that advertises one OpenSSH release while offering a fixed algorithm
   set that no version pins to it is a contradiction.
2. **Shared source-derived fingerprint.** Because the lists are constants in the
   public source, every instance presents the identical algorithm fingerprint.
   That is exactly the shared, source-derived signature §7 exists to remove.

This RFC derives the three lists and their order from the OpenSSH version the
persona advertises, from a small table of what each release actually offers, so the
algorithm set matches the banner and varies across instances the way the banner
already does.

The residual gap this RFC does **not** close: `x/crypto` implements only a subset
of the algorithms a real OpenSSH offers, so the HASSH still will not equal a
genuine OpenSSH server's. That is the conceded price named in the VISION non-goals,
and it stays documented. This RFC removes the banner-versus-algo contradiction and
the shared constant, not the underlying `x/crypto` HASSH.

## Constraints

- **Only offer what `x/crypto` can negotiate as a server.** Every algorithm name
  placed in a profile must be one the linked `golang.org/x/crypto/ssh` version
  actually supports server-side. Offering a name it cannot negotiate breaks real
  clients and is itself a tell. An algorithm a real OpenSSH release offered but
  `x/crypto` lacks is dropped from the profile and noted, the documented price.
- **No new dependency.** `x/crypto` is the one non-stdlib dependency; this RFC adds
  no other. The version tables are hand-authored data in the `ssh` package.
- **The persona picks the version in one place.** The crypto lists derive from
  `persona.OpenSSHVer`; they are not a second independent knob that could drift
  from the banner.
- **The pure banner-and-tarpit stays available.** `ssh.NewTarpit`
  (`internal/proto/ssh/ssh.go:376`) presents a banner and no handshake, so it has
  no algorithm fingerprint at all; it is unchanged except that its banner already
  reads `persona.OpenSSHVer`.

## Design

### A version-to-profile table

Add `internal/proto/ssh/cryptoprofile.go`:

```go
// cryptoProfile is the algorithm offer a given OpenSSH release presents, reduced
// to the names x/crypto can negotiate as a server and kept in that release's
// preference order. The residual (names the real release offered that x/crypto
// does not implement) is dropped; see the package doc for the accepted cost.
type cryptoProfile struct {
	kex     []string
	ciphers []string
	macs    []string
}

// profiles maps a normalized "major.minor" OpenSSH version to its offer. Keys are
// the versions the persona pool can draw (see internal/persona opensshPool). An
// unknown or unparseable version falls back to newest.
var profiles = map[string]cryptoProfile{
	"8.2": { ... },
	"8.9": { ... },
	"9.0": { ... },
	"9.6": { ... },
}

// profileFor parses the OpenSSH version out of a banner-version string such as
// "OpenSSH_8.9p1 Ubuntu-3ubuntu0.7" and returns the matching profile, falling back
// to the newest profile when the version is absent or unmapped.
func profileFor(openSSHVer string) cryptoProfile
```

`profileFor` extracts the numeric version: strip a leading `OpenSSH_`, read up to
the first non-`[0-9.]` byte, then reduce to `major.minor`. Match against
`profiles`; on miss, return the entry for the newest key.

The concrete algorithm lists per version come from that release's documented
defaults (its `ssh -Q kex|cipher|mac` output and `sshd_config` defaults),
intersected with what `x/crypto` supports. As a starting point, the union
`x/crypto` supports server-side is approximately: kex `curve25519-sha256`,
`curve25519-sha256@libssh.org`, `ecdh-sha2-nistp256/384/521`,
`diffie-hellman-group14-sha256`, `diffie-hellman-group16-sha512`; ciphers
`chacha20-poly1305@openssh.com`, `aes128-gcm@openssh.com`, `aes256-gcm@openssh.com`,
`aes128-ctr`, `aes192-ctr`, `aes256-ctr`; MACs `hmac-sha2-256-etm@openssh.com`,
`hmac-sha2-512-etm@openssh.com`, `hmac-sha2-256`, `hmac-sha2-512`. The
implementer confirms the exact supported set against the linked `x/crypto` version
(a test asserts every offered name negotiates, so a wrong entry fails the build,
see Tests) and then trims each per-version profile to the subset that release
actually shipped, in that release's order. Newer releases drop the older
nistp/group14 tail and lead with curve25519; older ones keep more of it. The point
is that the profiles differ from each other, so the version chosen changes the
fingerprint.

### Wiring the handshake to the persona

In `internal/proto/ssh/ssh.go` `Handle`, replace the three fixed slice literals
(`:152`, `:157`, `:162`) with the profile derived from the persona:

```go
prof := profileFor(pr.p.OpenSSHVer)
cfg.KeyExchanges = prof.kex
cfg.Ciphers = prof.ciphers
cfg.MACs = prof.macs
```

`cfg.ServerVersion` (`ssh.go:122`, already `"SSH-2.0-" + pr.p.OpenSSHVer`) and the
crypto lists now derive from the same field, so they cannot disagree.

### Widening the version pool

`opensshPool` (`internal/persona/persona.go:151`) currently holds four
`OpenSSH_8.9p1 Ubuntu-...` strings that all map to one profile, so nothing varies.
Widen it to span releases whose profiles differ, keeping every entry a realistic
Ubuntu or Debian build string, for example an `8.2p1` (Ubuntu 20.04), the existing
`8.9p1` (Ubuntu 22.04), a `9.0p1`, and a `9.6p1` (Ubuntu 24.04). Each must have a
matching key in `profiles`. This is the change that makes the algorithm fingerprint
vary across instances.

## Implementation steps

1. Add `cryptoprofile.go` with `cryptoProfile`, `profiles`, and `profileFor`,
   populated for the versions currently in `opensshPool` (all 8.9), plus the
   fallback. Add `TestProfileForParsesVersion` and
   `TestOfferedAlgorithmsAreImplemented` (below). Commit; `make check` passes with
   behavior unchanged (8.9 profile equals today's fixed lists).
2. Swap the three fixed slices in `Handle` for `profileFor(pr.p.OpenSSHVer)`.
   Commit; existing SSH tests still pass because 8.9 maps to the same lists.
3. Add the differing profiles (`8.2`, `9.0`, `9.6`) and widen `opensshPool` to
   match. Add `TestCryptoProfileVariesAcrossVersions`. Commit.
4. Update the package doc comment in `ssh.go` (currently around `:146`) to state
   that the lists derive from the persona version, and update
   [FEATURE-TREE.md](../FEATURE-TREE.md) SSH section to cite the new tests.

## Tests

Add to `internal/proto/ssh` (package `ssh` for the table tests, package `ssh_test`
driving the harness where a real handshake is needed):

- **`TestOfferedAlgorithmsAreImplemented`**: for every profile in `profiles`, stand
  the server up (via `internal/testharness` `NewListener`) and complete a handshake
  from an `x/crypto` client constrained to that profile's algorithms; assert the
  handshake succeeds for each kex, cipher, and MAC the profile offers. This is the
  guard that no profile lists a name `x/crypto` cannot negotiate.
- **`TestCryptoProfileMatchesBannerVersion`**: for each version in `opensshPool`,
  build a persona with that `OpenSSHVer`, run `Handle`, and assert the negotiated
  lists equal `profileFor(OpenSSHVer)`, so the banner and the offer agree.
- **`TestCryptoProfileVariesAcrossVersions`**: assert at least two versions in the
  pool produce different `(kex, ciphers, macs)` tuples, so the fingerprint is not a
  shared constant.
- **`TestProfileForParsesVersion`**: table test over banner strings
  (`"OpenSSH_8.9p1 Ubuntu-3ubuntu0.7"`, `"OpenSSH_9.6p1"`, `"garbage"`, `""`)
  asserting the parsed key and the newest-fallback behavior.

Must keep passing unchanged: `internal/proto/ssh` `TestSSHBannerFromPersonaAndClientCapture`,
`TestSSHKexCaptured`, `TestInteractiveShellSession`; `internal/crosscheck`
`TestEveryServiceTellsOnePersonaStory`.

## Acceptance criteria

- The negotiated kex, cipher, and MAC lists are a pure function of
  `persona.OpenSSHVer`, verified by `TestCryptoProfileMatchesBannerVersion`.
- Two instances drawing different pool versions present different algorithm
  fingerprints, verified by `TestCryptoProfileVariesAcrossVersions`.
- Every offered algorithm negotiates a real handshake, verified by
  `TestOfferedAlgorithmsAreImplemented`.
- `make check` is green; the feature tree cites the new tests.

## Out of scope

- Making the HASSH equal a genuine OpenSSH server's. `x/crypto` cannot offer the
  full algorithm set, so this stays the conceded seam in VISION's non-goals.
- Host-key algorithm variation (ed25519 versus rsa offers). The host key is already
  a persisted per-instance ed25519 seed; changing the offered host-key algorithms
  is a separate, smaller follow-up and not required here.
- Any change to `ssh.NewTarpit`, which presents no handshake and so has no
  algorithm fingerprint to make coherent.
