# RFC 0004: The services attackers try to own next

Feature tree: [Additional services](../FEATURE-TREE.md#http-https-ftp-adb-redis-docker-mysql).
Doctrine: VISION §2 (capture intent, never grant capability) and §3 (one
self-contained binary).

## Problem

SweeTTY answers on telnet, SSH, HTTP, HTTPS, and FTP, each a real service on the
port a real host answers on. The safety boundary that contains them is structural,
not per-protocol (`internal/safety`), and a new service is a package implementing
one interface (`server.Protocol`) wired in one place (`cmd/sweetty`). That is the
cheap part; the point is which surface.

This RFC adds the services a loader reaches for once the easy shells are exhausted,
and that a shell-only sensor never sees: the Android Debug Bridge on 5555 that IoT
botnets sweep for, an unauthenticated Redis, a Docker Engine API, and a database
port. Each lands inside the same boundary as the shell: intent captured, nothing
fetched, nothing run, nothing written to the host.

Each service below is an independent pickup. The shared recipe is the same for all;
read it once, then implement one service.

## The shared recipe

Every new service `internal/proto/<x>/<x>.go` follows the FTP package
(`internal/proto/ftp/ftp.go`) as its template. To land one:

1. **Implement `server.Protocol`** (`internal/server/protocol.go:9`):
   - `Name() string` returns the config string (for example `"redis"`). This is the
     join key: `cmd/sweetty`'s wiring test asserts `constructor(...).Name() == name`.
   - `ClientFirst() bool` reports whether the client speaks first. Redis, Docker,
     and ADB are client-first (`true`); MySQL sends a server greeting first
     (`false`). It drives bare-connect port-scan detection.
   - `Handle(s *server.Session)` owns the connection. Read with `s.ReadLine`,
     `s.ReadN`, or a protocol-specific reader; write with `s.Write`/`s.WriteBytes`;
     capture with the log helpers below. Set `s.Persona = pr.persona` first.
2. **Constructor** `New(p *persona.Persona) server.Protocol` (add `base *vfs.FS`
   only if the service hands the attacker an interactive shell, as ADB does).
3. **Capture intent, never act.** Use the `*server.Session` helpers:
   `LogCredential(user, pass)`, `LogCommand(cmd)`, `LogDownload(cmd, url, host, filename)`
   (emits `DOWNLOAD_ATTEMPT`, the IOC feed), `LogExec(detail, sha)`,
   `LogDropper(filename, command, content)`, `LogRaw(name, data)` for a
   protocol-specific event. Nothing dials, fetches, or writes to the host.
4. **Wire it in `cmd/sweetty/main.go`** `buildProtocol` (`:204`): add a
   `case "<x>": return x.New(p)` and the import. The wiring test
   `TestBuildProtocolWiresEveryConfiguredProtocol` (`cmd/sweetty/main_test.go:15`)
   then requires the constructor to be non-nil and its `Name()` to equal `"<x>"`.
5. **Extend config.** Add `"<x>"` to the `Listener.Protocol` enum comment
   (`internal/config/config.go:79`). To have a profile expose the service, add a
   `ServiceSpec{Protocol, Port, Style}` to the relevant profile's service set in
   `internal/persona` so `config.Generate` emits the listener.
6. **Satisfy the safety guardrail** (three tables, all in `internal/safety`):
   - `imports_test.go` `guardCases`: add `{"proto/<x>", []string{"os", "os/exec", "net/http", "syscall"}}`. Without this, `TestEveryProtoPackageIsGuarded` fails.
   - `closure_test.go` `approvedCapabilities`: if the package imports bare `net`,
     add `"sweetty/internal/proto/<x>": {"net"}`. If it imports no capability, add
     nothing.
   - `dialscan_test.go`: add `"proto/<x>"` to the scanned list in
     `TestNoOutboundDialCalls`.
   The package must not import `os`, `os/exec`, `net/http`, or `syscall`, and must
   call no outbound dial, resolve, or fetch primitive.
7. **Add a harness test** (`internal/proto/<x>/<x>_harness_test.go`): drive the
   service over the wire with `testharness.New` (banner-first or turn-based) or
   `NewListener` (simultaneous-write handshakes), asserting both the bytes the
   client sees and the events the session logs (`h.FindEvent`, `h.WaitEvent`).
8. **Add a persona version field** if the service advertises software (for example
   `RedisVer`), drawn from a pool in `GenerateProfile`, so the banner varies per
   instance the way the others do.
9. **Cite the test in [FEATURE-TREE.md](../FEATURE-TREE.md)** in the same commit.

## The services

Each is independently pickable. Ports are the conventional ones a real host of that
kind answers on.

### 4a. Android Debug Bridge (ADB), TCP 5555

The IoT surface Mirai-class loaders sweep for. ADB is client-first: the client
sends a `CNXN` message. Implement enough of the ADB transport to accept the
connection and capture the `shell:` service payloads.

- Answer the `CNXN` handshake with a plausible device banner
  (`device::ro.product.name=...;ro.product.model=...`), varied from the persona.
- When the client opens a `shell:<command>` stream, extract the command and route
  it through the same inert shell telnet and SSH use
  (`shell.RunOnce(s, base, p, user, style, pivot, cmd)`), so recon and the payload
  pull are captured. Constructor takes `base *vfs.FS`.
- `sync:` (file push) streams log the pushed filename and size as a `DROPPER`; no
  bytes touch the host.
- Persona: reuse the appliance/legacy profile's device naming.

### 4b. Redis, TCP 6379

Unauthenticated Redis is a classic write-primitive RCE (`CONFIG SET dir` +
`dbfilename` + `SET` an SSH key or cron line + `SAVE`). Speak the RESP protocol far
enough to draw the whole chain into the log.

- Parse RESP arrays; answer `PING` with `+PONG`, `INFO` with a plausible
  `redis_version:<persona.RedisVer>` block, `CONFIG GET` with believable values,
  `SELECT`/`AUTH` acceptingly.
- `CONFIG SET`, `SET`, and `SAVE` report success. Capture the `SET` value (usually
  an SSH public key or a cron line) as the payload: `LogDropper` with the value as
  content and the target path (from `CONFIG SET dir`/`dbfilename`) as filename.
  Nothing is written to the host; the "save" is faked.
- If a `SET` value is a URL-bearing loader, `LogDownload` the URL.

### 4c. Docker Engine API, TCP 2375

An unauthenticated Docker daemon is a container-escape-to-host RCE. It speaks HTTP,
so it can reuse the request parsing shape of `internal/proto/http`.

- Answer `GET /version`, `GET /info`, `GET /containers/json`, `GET /images/json`
  with plausible JSON derived from the persona (Docker version, kernel, arch).
- `POST /images/create?fromImage=<ref>` is the malicious image pull: capture
  `<ref>` as a `DOWNLOAD_ATTEMPT` (the image reference is the IOC). Report a
  streaming pull that "succeeds".
- `POST /containers/create` with a bind mount of `/` or a privileged flag is the
  escape attempt: `LogRaw("DOCKER_CREATE", <sanitized body>)` and report success
  with a fake container id. Nothing runs.

### 4d. MySQL, TCP 3306

A database port that carries its own credential-spray and, post-auth, query capture.
MySQL is server-first: send the initial handshake packet, then read the login.

- Emit a valid initial handshake packet (protocol 10) advertising
  `<persona.MySQLVer>` and a random salt.
- Read the client auth packet, `LogCredential(user, "<auth-response, hex>")` (the
  scrambled password is still a captured artifact), and reject with a realistic
  `ERROR 1045 (28000) Access denied`. Optionally accept after persistent tries the
  way the brute-force policy does elsewhere, then capture queries as `LogCommand`.
- Keep it a banner-and-credential capture first; query capture is a follow-up.

A fifth candidate, an SMB or NFS file-sharing port, carries the same class of
kill chain but a heavier binary protocol; leave it as a later pickup once the four
above are in.

## Implementation steps (per service)

1. Create `internal/proto/<x>/<x>.go` with the constructor, `Name`, `ClientFirst`,
   `Handle`, and a persona-derived banner. Add the persona version field and pool.
2. Add the three `internal/safety` guard entries. Run `go test ./internal/safety/`;
   it must pass.
3. Wire the `buildProtocol` case and import; add the profile's `ServiceSpec`.
4. Add `<x>_harness_test.go` driving the service over the wire and asserting the
   captured events. Add a boundary canary asserting nothing dials or writes (the
   shape of `TestNoOutboundConnectionOrExec`).
5. Cite the tests in [FEATURE-TREE.md](../FEATURE-TREE.md).

## Tests (per service)

- **`Test<X>BannerMatchesPersona`**: the advertised version/device string equals the
  persona field, pinned byte-exact for the fingerprintable greeting.
- **`Test<X>CapturesTheKillChain`**: drive the service's characteristic attack (the
  Redis `CONFIG SET`+`SET`+`SAVE`, the Docker image pull, the ADB `shell:` payload,
  the MySQL login) and assert the expected event lands with the expected fields
  (`DOWNLOAD_ATTEMPT` URL/ref, `DROPPER` content/sha, `CREDENTIAL` user/pass).
- **`Test<X>WritesNoHostByteAndDialsNothing`**: a boundary canary in the shape of
  `internal/proto/telnet` `TestNoOutboundConnectionOrExec` and
  `TestShellWritesNoHostByte`.
- The safety subset (`go test ./internal/safety/`) passes with the new guard
  entries, and `TestEveryProtoPackageIsGuarded` no longer flags the package.

Must keep passing: `cmd/sweetty` `TestBuildProtocolWiresEveryConfiguredProtocol`
(now covering the new name), and the whole `internal/safety` suite.

## Acceptance criteria

- The service answers on its conventional port with a persona-derived banner, and
  the wiring test recognizes it.
- Its characteristic kill chain is drawn into the log as the right event with the
  right IOC fields, verified over the wire.
- The safety guardrail passes with the package's three guard entries; a boundary
  canary proves nothing dials, fetches, or writes to the host.
- `make check` is green and the feature tree cites the tests.

## Out of scope

- Full protocol fidelity. Each service answers the handful of commands an attacker
  actually sends before the kill chain, not the whole protocol surface.
- Detonating or emulating what is captured. A pulled image reference, a Redis
  payload, and an ADB dropper are logged as indicators, never fetched or run
  (VISION non-goal).
- The heavier binary file-sharing protocols (SMB, NFS), noted as later pickups.
