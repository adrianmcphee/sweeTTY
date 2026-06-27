# SweeTTY

A multi-protocol honeypot in a single Go binary. SweeTTY listens on many ports at
once, presents a convincing fake service on each, and records every interaction
as structured JSON.

The design goal is simple: every attacker interaction is logged, automated
scanners are frustrated, and human operators are kept engaged long enough to
reveal their tooling, payloads, and command-and-control infrastructure.

SweeTTY is built from scratch in Go and kept deliberately dependency-light. The
protocol emulations, the fake shell (including the telnet/IAC layer), and the
virtual filesystem are implemented directly against the standard library, so the
honeypot owns the exact bytes on the wire.

## What it does

- **Presents a real interactive shell** over telnet, backed by a coherent
  **virtual filesystem**: `cd` changes directory, the prompt follows, and `ls`,
  `cat`, `find`, `stat`, `head`, and `tail` all read from one consistent tree.
- **Lets attackers believe they are winning, inside a sealed boundary.** Nothing
  they send runs, nothing is fetched from the network, and nothing touches the
  host disk.
- **Captures credentials, commands, and payloads.**
- **Logs everything as line-delimited JSON**, one event per line.

## Quick start

```bash
go build -o sweetty ./cmd/sweetty
./sweetty init
./sweetty
```
