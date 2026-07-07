# Contributing to SweeTTY

SweeTTY takes contributions by fork and pull request. Read [VISION.md](./VISION.md)
for what the product is and [AGENTS.md](./AGENTS.md) for the working contract
before you start; everything below is the short version of how a change gets in.

## What to work on

Pick up either a bug or a direction already on the [roadmap](./ROADMAP.md). A bug
fix is always welcome. A new capability should be one the roadmap already names, so
the surface stays coherent and inside the boundaries [VISION.md](./VISION.md) draws.
If you want something the roadmap does not cover, open an issue to discuss it first
rather than a pull request.

## Workflow

1. Fork the repository to your own account.
2. Branch from `main` for your change.
3. Do the work. Keep commits atomic, with imperative, scoped messages
   (`feat(ssh): ...`, `fix(portal): ...`, `docs: ...`).
4. Run the gate before you push:

   ```bash
   make hooks   # once per clone: installs the commit-msg hook
   make check   # gofmt-check + em-dash-check + go vet + go build + adversary + go test ./...
   ```

5. Open a pull request against `main`, and say what changed and why.

## Tests

Every change carries tests in the same shape as the suite it joins: they prove an
invariant or a boundary, not a line-coverage number. [TESTING.md](./TESTING.md) is
the full philosophy; the short version is that a test should fail when the box
would contradict itself or breach the boundary, and be named for what it proves.
Match the kind of test to the kind of change:

- **A new generator or file command** proves it agrees with the others that
  describe the same fact. A new disk field asserts that `df`, `lsblk`, `fstab`, and
  the VFS still tell one story, the way `TestDiskStoryIsCoherent` does; a new file
  command asserts that a listing and a read cannot disagree, the way
  `TestFilesystemCoherence` does.
- **A new download, exec, or write vector** carries a boundary canary: point it at
  a listener that flags any connect and assert nothing dials or runs, the way
  `TestNoOutboundConnectionOrExec` does, and assert the write lands only in the
  per-session overlay, the way `TestShellWritesNoHostByte` does.
- **A new protocol or handler** is driven over the real wire through
  [`internal/testharness`](./internal/testharness), asserting both the bytes the
  attacker sees and the JSON the session logs, the way the telnet vertical slice
  does in `internal/proto/telnet/slice_test.go`.
- **A fingerprintable surface** (a banner, a header, a negotiation) is pinned
  byte-exact, but only there; cosmetic output is asserted by cross-source
  invariant, never by exact wording.

Then cite the test in [FEATURE-TREE.md](./FEATURE-TREE.md) in the same commit, so
what the change guarantees is recorded next to the proof of it.

## Before you open it

- `make check` passes, and any behaviour you added or changed is covered by a test.
- If the change lands or removes a feature, [FEATURE-TREE.md](./FEATURE-TREE.md) is
  updated in the same commit, citing the test that verifies it.
- The hard rules in [AGENTS.md](./AGENTS.md) hold: the safety boundary is never
  weakened, no captured data or secrets are committed, and there is no AI
  attribution in commit messages.

Small, focused pull requests review fastest.
