# Agent Instructions: SweeTTY

Read [`VISION.md`](./VISION.md) and [`README.md`](./README.md) first. VISION.md is
the canonical product doctrine; README.md is how it builds, runs, and is operated.
Everything below is the working contract for changing this codebase.

---

## 🚨 Hard rules (do not violate)

1. **No AI attribution in git commits.** No `Co-Authored-By`, no "Generated with",
   no 🤖, nothing. Commits represent human authorship. This is non-negotiable and
   applies to every commit in this repo.
2. **The honeypot never grants capability.** It records what an attacker *tries*
   and refuses to do any of it. Three boundaries are load-bearing and non-negotiable:
   - **Never fetch a URL an attacker supplies.** Downloads are faked. No
     `http.Get` of attacker-controlled hosts. (No SSRF primitive.)
   - **Never write attacker bytes to the real host.** Files an attacker "creates"
     live only in a per-session, in-memory overlay that evaporates on disconnect.
   - **Never read the real host `/proc` or `/sys`** for fake output. All
     system-tool output is synthetic. (Reading real `/proc` leaks the honeypot's
     true hardware and identity.)
3. **Original work only.** This is a from-scratch Go honeypot. Do not copy
   honeypot code from other projects, and do not name or reference other
   honeypot projects anywhere in committed files.
4. **Never commit captured data or secrets.** `*.log` (attacker transcripts),
   `*.cast` (replays), `config.json` (per-instance layout), `persona.json`
   (per-instance identity and passwords), and the local design spec are
   git-ignored. Keep it that way.

---

## What this is

A single Go binary that listens on many ports, presents a convincing fake Linux
service on each (telnet shell, SSH, HTTP, HTTPS, FTP), logs every interaction as
structured JSON, and serves a live dashboard bound to loopback and reached over
an SSH tunnel. It is a honeypot deployed where every connection is
already hostile.

## Architecture conventions

- **Stdlib-first, dependency-light.** Reach for the standard library before
  anything else, and justify any new dependency in the PR. The only non-stdlib
  dependency is `golang.org/x/crypto` (SSH server handshake); `go.mod` is the
  source of truth. The portal, the telnet/IAC layer, and every protocol are
  hand-rolled against net/http and net, not pulled from a framework, so the
  honeypot owns the exact bytes on the wire and the binary stays auditable.
- **One virtual filesystem is the single source of truth.** The `internal/vfs`
  package and the embedded `internal/fakehost/fakeroot/` tree back every file command. `ls`, `cat`, `cd`, `pwd`,
  `find`, `stat`, `head`, and `tail` all resolve against the same tree, so they can
  never disagree. If you add a file command, route it through `vfs`. Per-session
  mutations (`touch`, `mkdir`, redirects, faked downloads) go to an in-memory
  copy-on-write overlay, never to disk.
- **One persona, total coherence.** A single persona definition (distribution,
  kernel release/version, hostname, primary user, OpenSSH version) drives
  `uname`, the SSH/telnet banners, `/etc/os-release`, `/etc/hostname`, `/etc/hosts`,
  `/etc/passwd`, and the shell prompt. They must never diverge; a mismatch between
  the SSH banner and `uname` is a classic honeypot tell. Change the persona in one
  place.
- **Generated output must look live.** `ps`, `top`, `free`, `df`, `netstat`,
  `ifconfig`/`ip` are synthetic templates whose volatile fields (uptime, RX/TX
  counters, timestamps) derive from session start time, so repeated calls differ.
  Identical byte counts on every call is a tell.
- **Typed, sanitised, correlated logging.** Events are a typed struct, one JSON
  object per line, each carrying a stable per-session id. Sanitise non-printable
  and invalid-UTF8 bytes out of usernames/passwords/commands before marshalling,
  since a raw newline in a captured field is a log-injection vector that forges
  fake events.
- **Degrade to a believable failure, never a dropped session.** Guard command
  handlers with `recover()` that prints `Segmentation fault (core dumped)`; keep
  `SESSION_END` in a session-level defer that survives panics.

## Code style

- `gofmt` is law (tabs, not spaces). Run `make fmt` before committing.
- Small, focused files; one package per protocol under `internal/proto/`.
- Use sentinel errors with `errors.Is`, not `err == ErrFoo` (the VFS returns
  wrapped `*PathError`-style errors).
- Time matters more than money here, so be deliberate about every `time.Sleep`.

---

## Verification

The gate before any commit:

```bash
make check        # go build + go vet + go test ./...
```

Run the binary and smoke-test a listener locally (high ports need no privilege):

```bash
make build
./sweetty init            # generates this instance's config.json and persona.json
./sweetty                 # or run on high ports for local testing
# in another shell:
nc localhost 2323         # telnet persona; type a login and some commands
```

The portal binds loopback and serves plain HTTP with no login, so locally just
open `http://localhost:<portal_port>`. It carries no application auth; on a remote
host you reach it over an SSH port-forward.

For low ports (<1024) without root: `sudo setcap 'cap_net_bind_service=+ep' ./sweetty`.

When you touch the shell or the VFS, prove coherence by hand: `ls -l /etc` then
`cat /etc/<first-file>` must agree; `cd /tmp && pwd` must follow; running `ls`
twice must produce identical ordering.

If you cannot run a check, say so and say what you did run.

---

## Commit discipline

- **Atomic commits.** One logical change per commit. Build/vet/test should pass at
  each commit where code changed.
- **Imperative, scoped messages**, e.g. `feat(telnet): stateful shell over the
  virtual filesystem`. No AI attribution (see hard rules), enforced by the
  `commit-msg` hook in `.githooks/`; run `make hooks` once per clone to install it.
- **Push as you go.** `git push` after each commit; `main` tracks `origin`.
- **Keep the feature tree current.** When a change lands or removes a feature, update
  [FEATURE-TREE.md](./FEATURE-TREE.md) in the same commit and cite the test that
  verifies it. Its status is carried only by those citations, never hand-written prose.
- Only the `sweetty/` directory is a git repo. Do not initialise or commit from a
  parent directory.

---

## Docs and comments

State present-tense first principles: what the thing is and does, and why. Nothing else.

- No "reframe", "north star", "gold standard", "capstone", or other slide-deck
  filler. Say the thing plainly.
- No history narrative ("we then", "was put through review", "reverted, not
  abandoned", "go-live readiness"). A doc is not a changelog or a project diary.
- No status prose ("covered today", "shipped", "still open", "Now/Next/Later").
  The status of record is the gate, the tests, and git history. Hand-written
  status is just cruft that goes stale.
- No meta-commentary about the document itself ("this document is how we...").
- State current limitations as plain facts, not backlog tiers.
- No em dashes (hard rule), anywhere, including docs and comments.
