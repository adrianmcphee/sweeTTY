# SweeTTY

A multi-protocol honeypot in a single Go binary. SweeTTY listens on many ports at once, presents a convincing fake service on each, and records every interaction as structured JSON. A built-in web portal gives you a live dashboard over the activity, bound to loopback and reached over an SSH tunnel so it leaves no management footprint on the network.

The design goal is simple: **every attacker interaction is logged, automated scanners are frustrated, and human operators are kept engaged long enough to reveal their tooling, payloads, and command-and-control infrastructure.**

SweeTTY is built from scratch in Go and kept deliberately dependency-light. The protocol emulations, the fake shell (including the telnet/IAC layer), the virtual filesystem, and the management portal are implemented directly against the standard library, so the honeypot owns the exact bytes on the wire and the binary stays small and auditable. The only non-stdlib dependency is `golang.org/x/crypto` for the SSH server handshake. The authoritative dependency list is [`go.mod`](./go.mod).

> ### 🚀 Want to deploy this?
> This repo is the **product**. To stand up a real, hardened sensor (HAProxy edge, blue/green releases, firewall, network isolation, randomized management port, and step-by-step setup written for both humans and AI agents), use the companion repo:
>
> **➡️ [`sweetty-instance-template`](https://github.com/adrianmcphee/sweetty-instance-template)**

---

## What it does

- **Listens on many ports**, each running an independent fake service (telnet, SSH, HTTP, HTTPS, FTP, ADB, MySQL, Redis, Docker).
- **Presents a real interactive shell** over SSH and telnet, backed by a coherent **virtual filesystem**: `cd` changes directory, the prompt follows, and `ls`, `cat`, `find`, `stat`, `head`, and `tail` all read from one consistent tree. You cannot trip it up by reading a file you just listed.
- **Lets attackers believe they're winning, inside a sealed boundary.** Downloads complete and the file lands, package installs finish, cron jobs and dropped SSH keys persist, and `scp`/`rsync` report a successful exfil, yet nothing is fetched from the network, nothing they send runs, and nothing touches the host disk. Compiles still grind and fail, and tarpit ports hold scanner threads open doing nothing.
- **Captures credentials, commands, payloads, and download URLs** across every protocol.
- **Detects port scans**: anything that connects and sends nothing is logged and dropped.
- **Logs everything as line-delimited JSON**, one event per line, ready for `jq`, ingestion, or the built-in portal.
- **Serves a live dashboard** with a streaming event feed and per-IP drill-down, bound to loopback and reached over an SSH tunnel.

## Threat-intel value

SweeTTY is an observation instrument. Run it on an isolated host or network segment with no real services behind it, so that **any** connection is by definition unsolicited and worth recording. What it gives you:

- The exact credentials, command sequences, and tooling attackers try against Linux-looking targets.
- The URLs and hosts attackers pull second-stage payloads from (logged before any "download" appears to succeed).
- A sense of which automated campaigns are sweeping your address space, and which interactions are a human at a keyboard.

---

## Quick start

```bash
# Build
go build -o sweetty ./cmd/sweetty

# Generate this instance's config.json
./sweetty init

# Allow binding to ports below 1024 without running as root
sudo setcap 'cap_net_bind_service=+ep' ./sweetty

# Run
./sweetty
```

Then watch the log:

```bash
tail -f sweetty.log | jq '{t: .time[11:19], e: .event, ip: .ip, d: (.command // .username // .request // "")}'
```

…or open the portal. It binds loopback on a fixed port (`8888`) and serves plain HTTP with no login, so locally you just open `http://localhost:8888`. On a remote host it is never exposed; reach it by forwarding that loopback port over the management SSH:

```bash
ssh -L 8888:127.0.0.1:8888 you@host -p <ssh_port>
# then open http://localhost:8888
```

---

## CLI

```
sweetty                 Load config, start all listeners and the portal
sweetty init            Write a per-instance config.json (randomized service profile; portal on a fixed loopback port; fails if one exists)
sweetty version         Print the version, commit, and build date
```

A `-config <path>` flag selects an alternate config file (default `config.json`); `-profile <name>` picks the service profile for `init` (`web`, `edge`, `infra`, `legacy`, `ftp`, `full`, or `random`).

---

## Configuration

`sweetty init` generates a `config.json` for this instance. The **service profile** is randomized per instance, so that no two sweetties look alike and nothing here is predictable from the public source: which fake services run, and which persona and software version each one presents. The honeypot services themselves still answer on the standard ports attackers expect (a fake telnet on 23, a fake web server on 80, and so on), because that is what a real host of that kind does. What varies is which of them are present and how each one looks. The **management portal** is not part of that deception surface: it binds loopback on a fixed port (`8888`) and is reached only over the SSH tunnel, so it has no reason to move around and is not randomized.

An example of a generated config (yours will differ):

```json
{
  "portal_port": 8888,
  "portal_bind": "127.0.0.1",
  "log_file": "sweetty.log",
  "listeners": [
    { "port": 22,  "protocol": "ssh" },
    { "port": 80,  "protocol": "http" },
    { "port": 443, "protocol": "https" }
  ]
}
```

A listener that fails to bind (port already in use, missing capability) is logged and skipped; the rest still start. You can edit `config.json` freely to pin a specific layout.

A few optional fields control the management plane and the network edge:

- `portal_bind` (default `127.0.0.1`): the host the portal binds. Loopback by default, so it is reachable only by tunnelling the management SSH to it. The portal serves plain HTTP with no application auth, so set `0.0.0.0` to expose it directly only behind a trusted boundary (rarely wanted).
- `proxy_protocol` (default `false`): parse an HAProxy PROXY header at the front of each connection and log the attacker's real source IP. Enable it only when the honeypot ports sit behind an HAProxy edge configured with `send-proxy`; the two are a matched pair (see the instance template).
- `record_dir` (default empty, disabled): a directory to write per-session [asciinema](https://asciinema.org) cast recordings to, one `<session-id>.cast` per connection, capturing exactly the bytes the attacker saw. The portal can replay them inline.
- `persona_file` (default empty: `persona.json` beside the config): where the generated per-instance identity is persisted. The honeypot writes it on first run (atomically), so when the config directory is operator-owned and read-only (the hardened deployment), point this at a directory the honeypot user owns and can write.
- `geoip_file` (default empty, disabled): an operator-supplied IPv4-to-country CSV (`start,end,CC` or `cidr,CC`), read only by the portal, so the dashboard tags each source with a country. The honeypot host has no egress, so this is a static offline database; the operator refreshes it out of band.
- `asn_file` (default empty, disabled): an operator-supplied IPv4-to-ASN CSV (`start,end,asn,org`), read only by the portal, so the dashboard shows each source's ISP / hosting provider and a "top ISPs" rollup. Offline like `geoip_file`.
- `bruteforce` (default off): the "let a persistent guesser in" policy. The per-instance password always works; with this on, a source that keeps trying against a real account (`root` or the primary user) is eventually let in with the credential it offered, so a credential-stuffing bot believes it cracked the box and reveals its loader. It is gated (`after_tries`, `after_seconds`) and `probability`-based so the moment of cracking is not a fixed fingerprint, and the working credential is remembered per source so a reconnect stays coherent. Accepted brute-force logins are logged as `accepted (brute-forced)`. Example: `"bruteforce": {"enabled": true, "after_tries": 8, "after_seconds": 120, "probability": 0.25}`.

### What each service presents

Each instance exposes a realistic subset of the services below, and each one chooses a plausible persona and software version at generation time. The specific versions, the exact set of services, and the host identity behind all of them are part of the instance identity and are never fixed in this repository.

- **telnet**: by default a full interactive Ubuntu login shell over telnet (the same shell and virtual filesystem as SSH, worn end to end even by the ARM appliance persona). A router/edge persona instead answers with a minimal Cisco IOS-style CLI (`show version`, `enable`, and the like) that still captures the credentials and commands tried against it, but is deliberately not a unix shell and is not backed by the virtual filesystem.
- **http / https**: a web service presenting as one of several common stacks (for example a WordPress, Tomcat, or static-nginx site) with a plausible version, plus a TLS probe logger on the secured port. The TLS port never completes a handshake: it captures and logs the ClientHello and holds the socket open. A fingerprinter therefore sees an all-zero JARM (and `nmap` reports `tcpwrapped`), an accepted trade: terminating real TLS would expose the Go runtime's own JARM, which would not match the advertised nginx/Apache anyway.
- **ssh**: a full interactive Linux shell over a real SSH handshake, backed by the same shell and virtual filesystem the telnet service exposes: the same coherent tree, reached over a different protocol. It presents the persona's OpenSSH banner, accepts the per-instance random password for `root` (or the primary user), records every credential tried with its accept/reject verdict, and drops the attacker into the coherent shell, executing nothing they send (downloads fetch nothing, mutations live only in the per-session overlay). The working password is generated per instance and stored only in the gitignored persona file, so it is never a constant in this source; `sweetty init` prints it. Completing the handshake is a deliberate trade: it exposes this Go SSH stack's algorithm fingerprint (its HASSH), which a determined fingerprinter can distinguish from a real OpenSSH server even though the banner matches, in exchange for full session capture (credentials, commands, payloads, and the behaviour of a bot that believes it is in). A pure banner-and-tarpit with zero crypto fingerprint, which completes no handshake and establishes no session, is still available by setting that listener's persona to `tarpit`.
- **ftp**: an FTP banner and credential trap.

Reading this source reveals the method, while a deployed instance's identity stays randomized and unknown.

---

## Virtual filesystem

The interactive shell is backed by a real virtual filesystem, not a lookup table of canned outputs. One tree serves the telnet and SSH shells identically (the shell is the same code behind both ports), so what an attacker sees never depends on how they got in. The fake root is authored as ordinary files under `fakeroot/` and embedded into the binary at build time, so the deployed binary is fully self-contained, with nothing on disk for an attacker to notice or tamper with.

- File **contents** are the embedded files. Their **sizes** in `ls -l` are derived from those contents, so listings and reads never contradict each other.
- File **ownership, permissions, and timestamps** come from sensible defaults plus a small per-path overlay, so `/etc/shadow` is `root:shadow 0640`, `/root` is `0700`, `/root/.ssh/id_rsa` is `0600`, and web files are owned by `www-data`.
- Each session gets a **copy-on-write overlay**: `touch`, `echo > file`, `mkdir`, and `rm` take effect for the rest of that session and are visible to later `ls`/`cat`, then vanish when the session ends.

Dynamic, non-file outputs (`ps`, `top`, `free`, `df`, `netstat`, `ifconfig`, `uptime`) are generated to look live and internally consistent.

---

## Logging and events

Every event is one JSON object on its own line in `log_file`. A compact human summary is also printed to stdout. Event types include:

| Event | Meaning |
|-------|---------|
| `SESSION_START` / `SESSION_END` | Connection opened / closed, with duration and command count |
| `PORT_SCAN` | Connected but sent no data within the grace window |
| `FLOOD_BLOCKED` | The optional HAProxy edge rate-limited a source's connection flood (logged by the `hapwatch` helper from HAProxy's stick-table) |
| `CREDENTIAL` | Username / password captured |
| `COMMAND` | A shell command was run |
| `DOWNLOAD_ATTEMPT` | `wget`/`curl`/interpreter pull of a remote payload |
| `EXEC_ATTEMPT` | Piped-to-shell or remote-code execution attempt |
| `HTTP_REQUEST` / `HTTP_POST` | HTTP request line, headers, and body |
| `HONEYTOKEN` | A planted bait was triggered (the fake vault, or an image viewer on a bait file) |

Filter and follow with `jq`, or use the portal's per-IP drill-down to read a single attacker's full transcript.

### Bait and honeytokens

From the shell (over telnet or SSH alike) an attacker can `ssh` to an internal host named in `.bash_history` and `backup.sh` and land on a second fake machine. Its shell history is a breadcrumb trail: it shows the private set being moved off the open share into an obscure, per-instance-random loot directory (`persona.LootPath`), which is where the bait files actually live. The filenames are compelling and exfiltration-worthy, and nothing in the filesystem reveals the joke first: `ls`, `stat`, `file`, and `head` all show a normal image. The gag fires only when an attacker tries to *use* one. However they grab a bait file (`cat`, `base64`, the terminal image viewers `jp2a` / `catimg` / `chafa`, or the fake `vault` / `wallet` command), they get a colour-ANSI reveal rather than a real secret, and every such access is logged as a `HONEYTOKEN` event with the source IP and session, since a legitimate user never does this.

Both halves are operator-replaceable. The reveal art is the payoff: drop any number of your own `.txt` renderings into `internal/shell/reveal/` and rebuild, and one is chosen at random per view. The bait images are the lure: the placeholder decoys in `internal/fakehost/decoys/` (`decoy.png`, `decoy.jpg`) are what `ls`/`file` see, so replace them with whatever innocuous photo you want a bait to appear to be.

---

## Management portal

The portal binds **loopback** on a fixed port (`portal_port`, default `8888`), serves plain HTTP, and is never exposed to the network. It carries no application auth of its own: you reach it by forwarding the box's real management SSH to it, so SSH key authentication is the single front door. The management SSH does not advertise as the admin door either: the instance template puts it on a randomized, http-like port (8088 and friends) that blends in among web services and differs per instance, so a scan finds the honeypot's ports and what looks like one more web service, never an obvious way in.

Through the tunnel you get:

- A **live feed** of events streamed over Server-Sent Events, colour-coded by type, with stat cards for sessions, unique sources, download attempts, and bait tripped.
- A **Sources** view ranking every host that has touched the honeypot, tagging each with an assessed kind (loader, brute-force, scanner, or a tentative human) and a returning-visitor badge, filterable to returning visitors, bots, humans, or the service they hit, and a **Honeytokens** view breaking the planted-bait triggers down by source and country.
- An **Exposed services** panel showing the sensor's own attack surface: every open service with its public port, protocol, persona, live hit and scan counts, and whether it is actually serving, so you see what is exposed even before anything probes it. Click a service (or pick it from the service dropdown) to narrow the Sources list to just that protocol, with a summary line giving the human, bot, and scanner split, so a question like "the telnet attackers, which were human and which were bots" reads off directly.
- **Per-IP drill-down**: click any event or source to see that IP's assessment first (the bot/human verdict with the evidence behind it, a phase ribbon from recon to exploit, and a timeline of its visits), then its sessions, credentials tried, commands run, download attempts, and full chronological transcript.
- **Session replay**: where `record_dir` is set, recorded sessions get a replay link that plays the captured terminal back inline.
- **Operator consoles**: any local admin console named in `admin_consoles` (such as the HAProxy stats page) is reverse-proxied into the sidebar and reached over the same SSH tunnel.

The source assessment is computed in the portal plane from the same event log, never by reaching out. The verdict is deliberately conservative: a source stays unknown unless the evidence is clear, a bot is named by what only a bot does (loader and persistence commands, a honeypot-probe credential, a BusyBox presence probe, or a machine-fast command burst), and a human is only ever a tentative hypothesis. Every verdict carries the reasons behind it, so it is auditable rather than a black box.

### Operator consoles

The portal can reverse-proxy local operator consoles, so you reach them over the same SSH tunnel as the portal instead of a second exposed port. Each console is declared in config under `admin_consoles`:

```json
"admin_consoles": [
  { "name": "haproxy", "label": "HAProxy", "target": "http://127.0.0.1:19000/" }
]
```

A link per console appears in the topbar, opening it at `/dashboard/console/<name>/`. Targets are fixed in config and **restricted to the local host** (loopback or a private address), so a misconfiguration cannot turn the portal into an open proxy. By default the full request path is forwarded, so a console that emits absolute links (the HAProxy stats page) works when it is set to serve under the mount path; set `"strip_prefix": true` for an upstream that only answers at its root. The instance template uses this to put the HAProxy stats console behind the portal, reached over the same SSH tunnel.

---

## Releases

The release is **manual**: trigger the workflow from the Actions tab (`workflow_dispatch`) or with `gh workflow run release.yml`. With no version input it bumps the patch from the last tag; pass an explicit `version` (a `vX.Y.Z` tag) to cut a specific major/minor. The run builds version-stamped, statically linked binaries for `linux/amd64`, `linux/arm64`, `darwin/amd64`, and `darwin/arm64`, writes a `checksums.txt`, creates the `vX.Y.Z` tag and GitHub Release, and signs a build-provenance attestation for each archive (verify one with `gh attestation verify <file> --repo adrianmcphee/sweetty`). Nothing is built or published on an ordinary push to `main`. Build the same archives locally with `make release-local`. The instance template pulls a pinned tag's `linux` archive, verifies it against `checksums.txt`, and rolls it into place.

### Getting the binaries

The same archives are also published as a single OCI artifact to the GitHub Container Registry at `ghcr.io/adrianmcphee/sweetty`, tagged with the version and `latest`. This is **an OCI artifact, not a Docker image**: it is a content-addressed bundle of the platform tarballs, not a runnable container. The GitHub package page shows a `docker pull` command because GitHub renders that for every package, but `docker pull` will not give you anything you can run. Pull it with [ORAS](https://oras.land) instead:

```bash
# Pull the cross-platform archives (all four targets + checksums.txt) for a tag
oras pull ghcr.io/adrianmcphee/sweetty:vX.Y.Z
tar -xzf sweetty_X.Y.Z_linux_amd64.tar.gz
```

Or just download the `.tar.gz` for your platform straight from the [GitHub Release](https://github.com/adrianmcphee/sweetty/releases). Either way, verify it against `checksums.txt`. The instance template automates this: it pulls a pinned tag's `linux` archive, checks the SHA256, and rolls it into place.

---

## Deployment

Production host provisioning and hardening (a dedicated user, firewall, network
isolation, intrusion detection, append-only off-host logging, and blue/green
rollout of a released binary) are owned by the separate
[`sweetty-instance-template`](https://github.com/adrianmcphee/sweetty-instance-template)
repository, deliberately kept out of this one so the product and its deployment
evolve independently. What follows is the minimal manual path for running a
single instance.

Run as a dedicated unprivileged user after granting the low-port capability:

```bash
useradd -r -s /bin/false sweetty
install -o sweetty -g sweetty -m 0755 sweetty /opt/sweetty/sweetty
sudo setcap 'cap_net_bind_service=+ep' /opt/sweetty/sweetty
```

`/etc/systemd/system/sweetty.service`:

```ini
[Unit]
Description=SweeTTY honeypot
After=network.target

[Service]
Type=simple
User=sweetty
WorkingDirectory=/opt/sweetty
ExecStart=/opt/sweetty/sweetty -config /opt/sweetty/config.json
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Lock down the host so management ports are reachable only from you, and the honeypot ports are open to the world:

```bash
ufw default deny incoming
ufw default allow outgoing
ufw allow from YOUR_IP to any port 9999   # your real SSH (the portal is reached by tunnelling through it, so it needs no rule of its own)
jq -r '.listeners[].port' /opt/sweetty/config.json | while read -r port; do
  ufw allow "${port}/tcp"                  # generated profile's honeypot surface
done
ufw enable
```

Make the log append-only so a shell that escapes containment still cannot rewrite history:

```bash
sudo chattr +a /opt/sweetty/sweetty.log
```

### Binding low ports without root

Preferred (file capability):

```bash
sudo setcap 'cap_net_bind_service=+ep' ./sweetty
```

Alternative (redirect with iptables and run unprivileged on a high port):

```bash
sudo iptables -t nat -A PREROUTING -p tcp --dport 23 -j REDIRECT --to-port 2323
```

---

## A word of caution

A honeypot is an attractant. Run SweeTTY on a host you are prepared to lose, isolated from anything real, with outbound traffic constrained. Everything an attacker types is fake; nothing they "download" executes; but the box still ends up on the radar of the people you are studying. Treat it accordingly, and make sure you are authorised to operate it on the network where you deploy it.

---

## Documentation

- [VISION.md](./VISION.md): why it exists and the design doctrine.
- [ARCHITECTURE.md](./ARCHITECTURE.md): how the pieces fit and where the safety boundary sits.
- [FEATURE-TREE.md](./FEATURE-TREE.md): the coverage index of what is built, each entry citing the test that verifies it.
- [ROADMAP.md](./ROADMAP.md): where the capability set is going and why, each direction named against the doctrine it serves.
- [rfcs/](./rfcs/README.md): build-ready specifications for each roadmap direction, scoped to be picked up on their own.
- [TESTING.md](./TESTING.md): how the honeypot is judged and what the suite covers.
- [AGENTS.md](./AGENTS.md): contributor rules and conventions.
- [CONTRIBUTING.md](./CONTRIBUTING.md): how to fork, run the gate, and open a pull request.

## Project layout

```
sweetty/
├── cmd/sweetty/         Entry point: CLI subcommands, startup, listener wiring
└── internal/
    ├── util/            Small shared helpers
    ├── event/           Thread-safe JSON event logger and schema
    ├── auth/            Portal token generation, hashing, validation
    ├── config/          Config load/write and per-instance generation
    ├── persona/         The randomized per-instance host identity
    ├── vfs/             The virtual filesystem engine and per-session overlay
    ├── fakehost/        Embeds and renders the fake host content
    │   └── fakeroot/    The embedded fake filesystem templates
    ├── server/          TCP listeners, sessions, IO helpers, the Protocol interface
    ├── shell/           The fake interactive shell: parsing, dispatch, fake editor
    ├── proto/           One package per service (telnet, ssh, http, https, ftp)
    └── portal/          The net/http management portal (dashboard, SSE, log API)
```

## Adding a protocol

1. Create `internal/proto/<name>/` with a type implementing the `server.Protocol` interface (`Name()`, `ClientFirst()`, `Handle(*server.Session)`).
2. Add a case for it to `buildProtocol()` in `cmd/sweetty/main.go`.
3. Add a listener entry to `config.json`.
