# SweeTTY Roadmap

Directions that make the deception sharper, the capture wider, and the log more
useful, without crossing the line [VISION.md](./VISION.md) draws: nothing is
fetched from the network, nothing an attacker sends is executed, nothing touches
the host disk, and everything still ships in one self-contained binary. Each
direction below names the doctrine it serves and the capability it already stands
on.

[FEATURE-TREE.md](./FEATURE-TREE.md) records what is built and verified, each
entry citing its test. The remaining directions here are where the capability set
is going and why. The order runs from wider capture to the intelligence the log
can yield. Each direction links to a build-ready spec in
[rfcs/](./rfcs/README.md), scoped to be picked up on its own.

## Directions

### 1. The services attackers try to own next

_Spec: [RFC 0004](./rfcs/0004-additional-services.md)._

SweeTTY already answers on more than the shell: telnet, SSH, HTTP, HTTPS, and FTP,
each a real service on the port a real host of that kind answers on. The safety
boundary that contains them is structural, not per-protocol (`internal/safety`),
and a new service is a package implementing one interface (`server.Protocol`)
wired in one place (`cmd/sweetty`). That is the cheap part of adding surface; the
point is which surface.

The direction is the services a loader reaches for once the easy shells are
exhausted, and that a shell-only sensor never sees: an unauthenticated Redis, a
Docker Engine API, and the database and file-sharing ports that carry their own
command-injection kill chains. Each one draws a chain that today lands on a closed
port and reveals nothing, and each one lands inside the same boundary as the
shell: intent captured, nothing fetched, nothing run, nothing written to the host.
It is §2 and §3 applied to a wider door, and it costs the doctrine nothing,
because the boundary already holds every handler by construction.

### 2. Bait that bites back after they leave

_Spec: [RFC 0005](./rfcs/0005-bait-that-bites-back.md)._

The honeytoken is the sharpest signal SweeTTY plants: a legitimate user never runs
the vault or digs the loot out of the per-instance loot path, so every touch is an
attacker by construction, and however they try to open one they get the reveal
instead of a secret (`internal/shell/reveal`, `internal/fakehost/decoys`, the
`HONEYTOKEN` event). The signal ends, though, when the session does. What the
attacker carries off the box, SweeTTY stops watching.

The direction is bait that keeps signalling after exfiltration: a credentials file
or an API token that is inert on the box and reveals nothing in place, but whose
use elsewhere raises an alert in an audit trail the operator already watches, so a
key lifted from the loot path and tried against the operator's own canary account
reports who used it, from where, and when, long after the connection closed. The
honeypot still reaches out to nothing; it plants, and the attacker's own later use
is what fires. It extends §8 from the moment of the grab to the moment of the use,
and it keeps the reveal culture the box already has, since the operator still gets
the payoff, now with a second act.

### 3. The log as campaign intelligence

_Spec: [RFC 0006](./rfcs/0006-campaign-correlation.md)._

The portal already reads each source for what it is: it folds the log into
incremental projections (`internal/portal`), segments a source's visits across an
idle gap, and returns a conservative verdict, loader or brute-force or scanner or a
tentative human, with the evidence behind it. It reads each source alone. The
hundred sources running the same loader against the box in the same week are a
hundred separate drill-downs, not one thing seen clearly.

The direction is correlation across sources: cluster them by what they share, the
same payload URL, the same reconstructed dropper (its sha256 is already captured),
the same credential list, the same command sequence, into campaigns the portal
names and counts, so the operator sees one botnet with four hundred addresses and
one loader rather than four hundred rows. It builds on the analyzer and the payload
rollup that already exist, the per-source assessment and the `DOWNLOAD_ATTEMPT` and
`DROPPER` aggregation, and on the same incremental projection the dashboard already
reads. It is §6, the loud dashboard, taken from what one source did to what one
campaign is doing.

### 4. Intelligence that travels

_Spec: [RFC 0007](./rfcs/0007-intelligence-export.md)._

Every event is already one self-describing JSON object with a stable session
identity, sanitised so an attacker cannot forge a line (`internal/event`). It is
honest and it is structured, which is most of what an intelligence feed needs; what
it is not yet is portable, phrased in a vocabulary another system already parses.
The highest-value captures, the command-and-control URLs an attacker pulls a second
stage from, the dropper hashes, and the credentials, sit in a schema that is
SweeTTY's own.

The direction is to emit those captures in the shapes an intelligence pipeline
already ingests, from the management plane and never from the sensor: a standard
event schema for a SIEM, and indicator bundles for a threat-sharing exchange,
generated by the portal that already enriches each source with geography and
operator (`internal/geo`, `internal/portal`). The honeypot host still ships one
thing off-box, its log, with no egress of its own; the translation into portable
intelligence happens where the operator already stands, behind the tunnel. It is
§4, honest structured logging, carried the last step to intelligence someone else
can act on without first learning SweeTTY's private dialect.

## The line these hold

None of this moves the line. The measure in [VISION.md](./VISION.md) still holds
for every direction here: the deception survives the skeptic, the whole chain lands
in the log, the operator can replay and now correlate exactly what happened, and at
no point did the box fetch a byte from the network, touch the host disk, or run a
single thing an attacker asked it to.
