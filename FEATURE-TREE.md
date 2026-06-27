# SweeTTY Feature Tree

Coverage index of implemented behaviour. Each entry states an invariant and cites
the test that verifies it; an entry whose cited test is absent is a defect in this
file. Design rationale lives in the companion docs ([VISION.md](./VISION.md),
[ARCHITECTURE.md](./ARCHITECTURE.md), [TESTING.md](./TESTING.md),
[AGENTS.md](./AGENTS.md)); this file records only what is verified. Citations read
`package: TestName`.

## Verify

- `go build ./...` compiles every package and the embedded fakeroots.
- `go test ./...` is the full gate; every cited entry is one of these tests.
- `go vet ./...` and `gofmt -l .` report nothing.
- Boundary subsets:
  - `go test ./internal/safety/` (import guardrail).
  - `go test ./internal/proto/telnet/ -run 'TestNoOutboundConnectionOrExec|TestShellWritesNoHostByte|TestOverlayEvaporatesAcrossSessions'` (egress, host-disk, overlay lifetime).
  - `go test ./internal/crosscheck/` (one persona across services).

## Per-instance identity (VISION §7)

- **Every identity field is populated on first run**: hostname, domain, internal range, neighbours, kernel, software versions, secrets, boot time. _internal/persona: TestGenerateIsComplete_
- **Every identifying field varies between instances**; profiles and software versions are drawn from pools and vary across runs. _internal/persona: TestTwoPersonasDiffer, TestEveryIdentityFieldVaries, TestProfileVarietyAcrossRuns, TestSoftwareVersionsVaryAndAreInPool_
- **Profiles select a service set**: web, edge, infra, legacy, ftp; `full` exposes every protocol; an unknown name falls back to random. _internal/persona: TestGenerateProfileFullHasEveryProtocol, TestGenerateProfileNamed, TestUnknownProfileFallsBackToRandom_
- **The legacy profile is aarch64 end to end**; server profiles are x86_64; only arch differs by profile. _internal/persona: TestLegacyProfileIsEmbeddedARM, TestServerProfilesStayX86, TestOSImageOnlyArchDiffersByProfile_
- **Only the per-instance password authenticates**; passwords differ between instances. _internal/persona: TestAcceptOnlyPerInstancePasswords, TestPasswordsVaryPerInstance_
- **The SSH host key is stable across restarts** from a persisted seed. _internal/persona: TestSSHHostKeyStableAndValid_
- **Persona persistence is generate-on-first-run, regenerate-if-empty, never-clobber-if-corrupt**. _internal/persona: TestLoadOrCreateGeneratesOnFirstRun, TestLoadOrCreateRegeneratesEmptyFile, TestLoadOrCreateRefusesToClobberInvalidFile_

## Virtual filesystem coherence (VISION §1)

- **One tree backs every file command**: content equals reported size, metadata overrides apply, symlinks resolve, directory order is sorted and stable, missing paths error. _internal/vfs: TestContentAndSizeAgree, TestMetadataOverrides, TestSymlinkResolution, TestReadDirSortedAndDeterministic, TestMissingPaths_
- **Stub binaries report as ELF** to `file`. _internal/vfs: TestStubBinaryELF_
- **The per-session overlay is copy-on-write**; writes and deletions are session-local; cwd tracks. _internal/vfs: TestCopyOnWriteOverlay, TestCwdAndChdir_
- **The embedded tree renders the instance identity**: no residual placeholders, two instances differ, ownership matches `/etc/passwd` and `/etc/group`, modes consistent. _internal/fakehost: TestLoadRendersInstanceIdentity, TestNoResidualPlaceholders, TestTwoInstancesDiffer, TestOwnershipMatchesPasswdAndGroup, TestCoherentOwnershipAndModes_
- **`/proc` identity is synthetic and per-arch**, not the host's. _internal/fakehost: TestProcIdentityRendersPerArch_

## Configuration and secrets

- **Config is generated from the persona with a per-instance portal port**. _internal/config: TestGenerateFromPersona, TestPortalPortVaries_
- **Writing the default config refuses to overwrite an existing file**. _internal/config: TestWriteDefaultConfigRefusesOverwrite_
