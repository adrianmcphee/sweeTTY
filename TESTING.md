# SweeTTY: Testing Strategy

Read [`VISION.md`](./VISION.md) first. The doctrine there is what the suite exists to prove.

## Invariants over line coverage

Line coverage is the wrong target for a deception product. The shell package runs at low line coverage yet is the most exercised code in the repo, and a recon attacker busts the box on `df -h; cat /etc/fstab` or `ps; uptime` against generators whose every line is trivially runnable. What matters is whether the box ever contradicts itself or breaches a boundary; which lines executed is beside the point.

The suite tests four things:

1. **Doctrine proofs** fail when a VISION principle is violated. The structural import guardrail in [`internal/safety`](./internal/safety/imports_test.go) is the model: the packages that handle attacker input cannot even import the means to fetch, execute, or touch the host disk.
2. **Coherence invariants** assert that every pair of generators describing the same fact agrees: df against the VFS against fstab, ps against uptime, systemctl against ps, netstat against the exposed services, a file's numeric against its symbolic owner. They run in milliseconds with no network.
3. **Boundary canaries** prove the hard boundaries hold: no outbound connection, no host byte written, `/proc` reads come from the persona, the overlay evaporates per session.
4. **Golden transcripts** pin byte-exact output only for the handful of wrong-but-plausible fingerprintable surfaces, never for cosmetic prose.

Line coverage is a ratchet on pure functions (parsers, formatters) only, never a global gate.

## Two adversaries

A honeypot is judged by two adversaries that fail it differently:

- **The skeptical human** probes for logical contradictions: a listing that names a file the box cannot read, a kernel that disagrees with the banner, a mount with no directory. This is the coherence axis (doctrine #1), and it is the priority.
- **The automated scanner** fingerprints machine-observable bytes: exact banners, protocol negotiation, TLS/JARM, header order, timing, known tells. This is the fidelity axis. A scan platform correlates all of one IP's banners, so cross-service agreement carries weight here.

## One vertical slice, proven end to end

One complete path proven coherent end to end is worth more than five shallow protocols:

> telnet login, shell prompt, VFS-backed `pwd`/`cd`/`ls`/`cat`/`touch`/`mkdir`/`rm`, fake `wget`/`curl` (intent logged, zero egress, zero host bytes), persona-rendered `/etc/*`

It is proven in [`internal/shell/coherence_test.go`](./internal/shell/coherence_test.go) (fast white-box invariants over the generators) and [`internal/proto/telnet/slice_test.go`](./internal/proto/telnet/slice_test.go) (one scripted attacker session over the real protocol, asserting coherence at every hop plus per-session overlay isolation and the no-host-byte canary).

The harness ([`internal/testharness`](./internal/testharness)) drives a protocol over an in-memory pipe with `server.FastMode` and inspects both the wire bytes and the JSON log. Tests run serially: `server.FastMode` and `scanGrace` are mutable package globals, so do not add `t.Parallel` until they are per-server config.

## What the suite proves

- **Safety (doctrine #2):** the structural import guardrail, plus behavioural no-outbound and no-host-byte canaries. A new `internal/proto` handler fails the build if it is not in the import scan.
- **Coherence (doctrine #1):** one disk story (df, mount, lsblk, fstab, and the VFS agree); `ps` START derives from the boot epoch; `systemctl` and `ps` share one process table; `netstat` and `ss` render from `persona.Services`; every node's numeric uid/gid matches its owner via `/etc/passwd` and `/etc/group`; uname, os-release, meminfo, and cpuinfo agree.
- **Logging (doctrine #4):** per-session id correlation; sanitised input; concurrent writes stay whole and unforgeable under `-race`; a handler panic still yields a correlated PANIC and SESSION_END carrying the pre-crash command count.
- **Management plane (doctrine #6):** the portal binds loopback and serves the dashboard over plain HTTP with no application auth (reached only over an SSH port-forward), every data route answers directly with no cookie or login redirect, the served HTML reaches nothing off-host, and the console reverse proxy refuses any non-local target.
- **Unpredictability (doctrine #7):** two personas differ; identity is randomized.
- **Bait (doctrine #8):** the NAS pivot, baited filenames, honeytoken events.

## What the suite refuses to break

The box survives a hostile connection. These are guarantees the tests enforce:

- **No crash from input.** Exec-recursion depth is bounded, so a self-referential payload cannot overflow the goroutine stack, and the depth-limit message is the generic segfault line, not a fingerprint.
- **No resource exhaustion.** A process-wide connection cap backstops the per-IP cap (a botnet across many IPs defeats per-IP alone); `ReadLine` and the HTTP header loop are length-bounded; the tarpits are interruptible, freeing the goroutine and fd the instant the client disconnects.
- **No silent outage.** The accept loop backs off and keeps accepting on a transient error such as EMFILE; connection setup has its own panic recovery; the process exits cleanly on SIGTERM and non-zero when no listener starts; a shed connection logs a rate-limited notice rather than vanishing.
- **Identity and log integrity.** A corrupt `persona.json` is refused rather than regenerated, which would change the SSH host key and break log correlation; the log is `0600` and reports dropped writes.

## Known gaps

- HTTP response framing (header order, chunked versus Content-Length, the `Connection` handling) is shared across stacks rather than emitted per stack, so a scanner that correlates nginx, Apache, and Tomcat framing sees one emitter behind all three. A per-stack response emitter closes this; the additive header, body, and status pins approximate it meanwhile.
- The appliance personas claim non-x86_64 hardware over an x86_64 Ubuntu base. Scope the architecture per profile, or keep the appliance personas out of production.
- `portal_port` falls back to a fixed `8443` when a config omits it; `init` always randomizes it, so only a hand-edited config is predictable.

## What we do not test, and why

- Wall-clock latency on tarpits is flaky. Assert the delay constants and their order instead.
- Cosmetic generator prose (lscpu, dmesg, the fake apt flow) churns with no detection value. Assert cross-source invariants rather than exact wording.
- Terminating real TLS to get a non-empty JARM would expose Go's own stack. The all-zero JARM is the accepted trade, and 443 is never opened next to a live webserver.
- Spoofing the TCP/IP stack (p0f) is the deploy host's kernel, a deployment concern, not a unit test.
