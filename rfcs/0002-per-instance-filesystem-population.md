# RFC 0002: Per-instance filesystem population

Doctrine: VISION §7 (unpredictable from the source).

## Problem

The virtual filesystem is coherent: one tree backs every file command
(`internal/vfs`, `internal/fakehost`), and the persona renders identity into it, so
values differ per instance. The **shape** does not. The set of files, the
directories that exist, and the bodies that carry no identity are a constant a
reader of the source knows in full. A machine with a conspicuously thin `/etc`, a
bare `/var/log`, and a home directory with nothing lived-in in it is a tell to the
skeptical human §1 is written for.

This RFC generates the tree's population and its non-identity content per instance:
a plausible installed-package footprint, log files with a believable history, home
directories with the clutter a used account accumulates, and timestamps that agree
with the boot time the persona already fixes. Generation is deterministic from a
per-instance seed persisted in `persona.json`, so it is fixed on first run, never
regenerated, and identical across restarts, with no generator and no external call
at runtime.

## Constraints

- **No host disk, no network, no exec.** `internal/fakehost` and `internal/vfs` are
  on the guarded attacker-reachable list (`internal/safety`), so the generator may
  import only stdlib (`bytes`, `fmt`, `sort`, `time`, `math/rand/v2`) plus `vfs`
  and `persona`. No `os`, no `net`, no `os/exec`.
- **Generate once, never regenerate.** The population derives from a seed stored in
  `persona.json`. `persona.LoadOrCreate` (`internal/persona/persona.go:560`) already
  generates on first run and refuses to clobber, so persisting the seed there gives
  the roadmap's "generate-on-first-run, never regenerated once written" for free
  with no second artifact. Deterministic expansion from the seed means the tree is
  byte-identical across restarts.
- **Coherence is preserved.** Everything generated must agree with the rest of the
  box: home directories are owned by the persona user with the persona UID;
  installed-package stubs agree with what `dpkg`, `which`, and `ls` report; log and
  file mtimes fall between `persona.BootEpoch` and now; no generated body carries a
  residual `{{...}}` placeholder.
- **The base tree stays the shared read-only source of truth.** Generated content
  is grafted into the base `*vfs.FS` after `vfs.Load` with the existing
  `FS.Place` and `FS.Mkdir` (`internal/vfs/load.go:291`, `:240`), exactly the way
  `graftLoot` (`internal/fakehost/fakehost_nas.go:61`) already grafts the loot
  directory. Per-session mutations still go to the copy-on-write overlay, untouched.

## Design

### A persisted per-instance seed

Add one field to the `Persona` struct (`internal/persona/persona.go:36`):

```go
FSSeed string `json:"fs_seed"` // per-instance seed for filesystem population, base64
```

Set it in `GenerateProfile` alongside the other per-instance secrets (near
`SSHHostKeySeed`, `persona.go:369`): `FSSeed = base64(randBytes(16))`. It persists
in `persona.json` with everything else, so it is fixed on first run and never
clobbered. This mirrors `SSHHostKeySeed`, which is already a persisted seed that
deterministically expands to a stable artifact (the host key).

### A deterministic population step

Add `internal/fakehost/populate.go`:

```go
// populate grafts this instance's generated filesystem population onto the base
// tree: an installed-package footprint, log history, and home-directory clutter,
// all derived deterministically from persona.FSSeed so the tree is stable across
// restarts and varies between instances. mtimes are anchored between the persona's
// boot time and now, so the box reads as lived-in rather than freshly built.
func populate(f *vfs.FS, p *persona.Persona)
```

Seed a `math/rand/v2` generator from `FSSeed` (decode the base64 to a `[32]byte`
and use `rand.NewChaCha8`, which takes a seed and is deterministic). Drive every
random choice below from that one generator, so the whole population is a pure
function of the seed. Anchor timestamps to `time.Unix(p.BootEpoch, 0)`
(`persona.BootEpoch`, `persona.go:91`) as the lower bound and `time.Now()` as the
upper bound.

Call it from `Load` (`internal/fakehost/fakehost.go:23`) after `vfs.Load` returns,
the same place `LoadNAS` calls `graftLoot`:

```go
func Load(p *persona.Persona) (*vfs.FS, error) {
	f, err := vfs.Load(fakerootFS, root, renderer(p))
	if err != nil {
		return nil, err
	}
	populate(f, p)
	return f, nil
}
```

The three population dimensions, each a small helper in `populate.go`:

1. **Installed-package footprint.** Pick a plausible package set for the persona
   profile (a web box has nginx/php/certbot; an infra box has docker/prometheus).
   For each package, `Place` its binary stubs under `/usr/bin` and `/usr/sbin` and
   its files under `/usr/lib` and `/etc` using the same stub mechanism the manifest
   binaries use (a synthetic size and mtime derived from the name, see
   `internal/vfs/load.go:160`). Append a matching entry to `/var/lib/dpkg/status`
   so `dpkg -l` and `which` (which read the VFS) stay consistent with what is on
   disk. Use `FS.Place` to overwrite `/var/lib/dpkg/status` with the base content
   plus the generated entries.
2. **Log history.** Under `/var/log`, place rotated logs (`syslog`, `syslog.1`,
   `auth.log`, `auth.log.1`, `dpkg.log`, `nginx/access.log` where the profile runs
   nginx) with a handful of plausible lines and a rotation ladder of mtimes
   stepping back from now toward `BootEpoch`. Bodies carry no identity beyond the
   hostname and user the persona already exposes, rendered directly (not through
   the template engine, since these are generated in Go).
3. **Home-directory clutter.** In the persona user's home (`/home/<user>`, owned by
   `persona.Username` with `persona.UserUID`) and `/root`, place the accretion a
   used account carries: `.bash_history` with a short believable command trail,
   `.cache/` and `.local/` directory trees, `.ssh/known_hosts`, an occasional
   project directory. Ownership must match `/etc/passwd`: home files are the
   persona user, root's are root.

Vary the counts, filenames, and line contents from the seed so two instances differ
while one instance is stable.

## Implementation steps

1. Add `FSSeed` to `Persona` and set it in `GenerateProfile`. Add
   `TestFSSeedIsPopulatedAndVaries` in `internal/persona`. Commit;
   `make check` passes (nothing reads the seed yet).
2. Add `populate.go` with the seed-driven generator and the three helpers, and call
   `populate` from `fakehost.Load`. Add the tests below. Commit.
3. Update [FEATURE-TREE.md](../FEATURE-TREE.md) VFS section to cite the new tests.

Keep the commits small: land the package footprint first with its coherence test,
then the log history, then the home clutter, so each dimension is reviewable on its
own.

## Tests

Add to `internal/fakehost` and `internal/shell` (coherence lives with the shell
that reads the tree):

- **`TestPopulationVariesPerInstance`** (`fakehost`): two personas with different
  `FSSeed` produce trees that differ in their populated paths.
- **`TestPopulationIsStableWithinInstance`** (`fakehost`): loading twice from the
  same persona produces byte-identical populated trees (same files, sizes, mtimes,
  ownership). This is the "never regenerated" guarantee.
- **`TestInstalledPackagesAgreeWithDpkgAndWhich`** (`shell`): every generated
  `/usr/bin` stub the population adds is listed by `dpkg -l` output and resolved by
  `which`, in the shape of `TestListenersMatchPersonaServices`. A package on disk
  that `dpkg` does not know, or vice versa, is a coherence break and fails.
- **`TestPopulatedMtimesFollowBootEpoch`** (`fakehost`): every generated file's
  mtime is between `BootEpoch` and now, so nothing predates the boot the persona
  fixes.
- **`TestHomeClutterOwnedByUser`** (`fakehost`): files under `/home/<user>` are
  owned by `persona.Username`/`persona.UserUID` and files under `/root` by root, in
  the shape of `TestOwnershipMatchesPasswdAndGroup`.

Must keep passing unchanged: `internal/fakehost` `TestNoResidualPlaceholders`,
`TestTwoInstancesDiffer`, `TestOwnershipMatchesPasswdAndGroup`,
`TestCoherentOwnershipAndModes`, `TestProcIdentityRendersPerArch`; `internal/vfs`
`TestContentAndSizeAgree`, `TestReadDirSortedAndDeterministic`; `internal/proto/telnet`
`TestFilesystemCoherence`.

## Acceptance criteria

- `FSSeed` is generated on first run, persisted in `persona.json`, and never
  regenerated once written (it rides `LoadOrCreate`'s existing never-clobber path).
- The populated tree is a pure function of the persona: identical across restarts,
  different across instances, verified by the stability and variance tests.
- Every generated file is coherent with the box: mtimes within the boot window,
  home ownership matching `/etc/passwd`, packages agreeing with `dpkg`/`which`, no
  residual placeholders.
- `make check` is green with no new capability import in `fakehost` (the safety
  guardrail stays satisfied).

## Out of scope

- Real package contents. Binaries stay stubs that report as ELF (`internal/vfs`
  `TestStubBinaryELF`); this RFC adds more of them, not real executables.
- Per-session accretion. The population is instance-level and read-only; an
  attacker's own writes still land only in the copy-on-write overlay.
- Changing the embedded skeleton. The generated population layers over the existing
  `internal/fakehost/fakeroot` tree; the shipped skeleton files are unchanged.
