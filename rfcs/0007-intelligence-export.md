# RFC 0007: Intelligence that travels

Roadmap: [Direction 7](../ROADMAP.md#7-intelligence-that-travels).
Doctrine: VISION §4 (honest, structured, tamper-evident logging).

## Problem

Every event is one self-describing JSON object with a stable session identity,
sanitised so an attacker cannot forge a line (`internal/event`). It is honest and
structured, which is most of what an intelligence feed needs; what it is not yet is
portable, phrased in a vocabulary another system already parses. The highest-value
captures, the command-and-control URLs an attacker pulls a second stage from, the
dropper hashes, and the credentials, sit in a schema that is SweeTTY's own.

This RFC emits those captures in the shapes an intelligence pipeline already
ingests, from the management plane and never from the sensor: a standard event
schema for a SIEM, and an indicator bundle for a threat-sharing exchange, generated
by the portal that already enriches each source with geography and operator
(`internal/geo`, `internal/portal`).

## Constraints

- **Portal plane only; the sensor emits nothing new.** The honeypot host still ships
  one thing off-box, its log, with no egress of its own. The translation into
  portable intelligence happens in `internal/portal`, behind the tunnel, where the
  operator already stands. No change to any `internal/proto/*` handler or to
  `internal/event`.
- **Pull, not push.** The export is an operator request over the loopback tunnel,
  served like every other dashboard route. The portal does not connect out to a
  SIEM or a TAXII server; the operator downloads the artifact and forwards it with
  their own tooling. This keeps the portal's "nothing off-host" posture
  (`PORTAL.md`) intact.
- **Reuse the existing enrichment and projections.** Geography and operator come
  from the portal-plane `geo.Resolver` (`internal/geo/geo.go:88` `Locate`), the same
  one the overview and payload projections use. The indicators come from the payload
  projection (`internal/portal/store.go:358` `payloadProj`), so the export is a
  formatting layer, not a second scan.
- **Deterministic, stable identifiers.** A re-export of the same captures produces
  the same STIX object ids, so a downstream platform dedupes rather than
  duplicating. Derive ids from the indicator value with a fixed namespace (a UUIDv5
  computed from the value), not a random UUID.

## Design

Add `internal/portal/export.go` with two handlers and their formatters. Both read
the store snapshot under the store lock, the way `payloads`
(`internal/portal/payloads.go:41`) does, and enrich with `p.geo`.

### 1. SIEM event stream (ECS-mapped NDJSON)

Route `GET /dashboard/export/ndjson`: stream the log as newline-delimited JSON,
each line an event mapped to Elastic Common Schema field names and enriched with
geo/operator, so an operator points Filebeat or Logstash at the download and the
fields land in the shapes their dashboards expect. The mapping, `entryToECS(e, loc)`:

- `@timestamp` from `e.Time`; `event.action` from `e.Event` lowercased;
  `event.kind` `"event"`.
- `source.ip` from `srcOf(e)`; `source.geo.country_iso_code` from `loc.Country`;
  `source.as.number` from `loc.ASN`; `source.as.organization.name` from `loc.Org`.
- `destination.port` from `e.Port`; `network.protocol` from `e.Protocol`.
- `url.full` from `e.URL`; `file.hash.sha256` from `e.SHA256`;
  `file.name` from `e.Filename`; `user.name` from `e.Username`;
  `user_agent.original` from `e.UserAgent`; `http.request.method` from `e.Method`.
- `honeypot.session` from `e.Session` and `honeypot.sensor` from `e.Sensor` under a
  custom namespace, so the honeypot-specific fields travel without colliding with
  ECS.

Stream it: the handler tails the log file line by line (a bounded streaming scan,
the drill-down access pattern in `PORTAL.md`), maps each parsed entry, and writes
one ECS JSON object per line. A line that fails to parse is skipped, the same
tolerance the projections have. Support an optional `?since=<rfc3339>` filter so an
operator can pull an incremental slice.

### 2. Threat-sharing indicator bundle (STIX 2.1)

Route `GET /dashboard/export/stix`: return a STIX 2.1 bundle of the high-value
IOCs from the payload projection, the feed a threat-sharing exchange (or MISP via
its STIX import) ingests. Build it from `p.store.pay`:

- For each distinct C2 URL (`payloadProj.byURL`): a STIX `indicator` with
  `pattern: "[url:value = '<url>']"`, `pattern_type: "stix"`, and `valid_from` the
  first-seen time.
- For each distinct dropper sha (`payloadProj.bySha`): an `indicator` with
  `pattern: "[file:hashes.'SHA-256' = '<sha>']"`.
- Optionally, per-source `infrastructure` or `observed-data` objects tying the
  indicators to the observing sensor, gated behind a query flag to keep the default
  bundle lean.

Each object's `id` is `indicator--<uuidv5(namespace, patternValue)>`, so the same
URL or hash always yields the same id. Compute UUIDv5 with `crypto/sha1` over a
fixed namespace UUID plus the value (stdlib, no dependency). The bundle `id` is
`bundle--<uuidv5(namespace, sorted-member-ids)>`, stable for a stable member set.
Set `created`/`modified` from the capture times already in the projection, not from
wall-clock at export, so re-exports are byte-stable.

Register both routes in `portal.go` `engine` (near `:145`):

```go
mux.HandleFunc("GET /dashboard/export/ndjson", p.exportNDJSON)
mux.HandleFunc("GET /dashboard/export/stix", p.exportSTIX)
```

Add download affordances (two links) to the dashboard in `html.go`; the routes are
the substance.

## Implementation steps

1. Add `export.go` with `entryToECS` and `exportNDJSON`, streaming the log with the
   bounded-scan pattern and the `?since` filter. Add the ECS tests. Commit.
2. Add the STIX builder and `exportSTIX` over the payload projection, with
   deterministic UUIDv5 ids. Add the STIX tests. Commit.
3. Register both routes and add the download links in `html.go`. Commit.
4. Update [FEATURE-TREE.md](../FEATURE-TREE.md) portal section citing the tests.

## Tests

Add to `internal/portal` (`payloads_test.go`/`overview_test.go` shape):

- **`TestExportNDJSONIsValidECS`**: every emitted line parses as JSON and carries
  the required ECS fields for its event type (a `DOWNLOAD_ATTEMPT` has `url.full`, a
  `DROPPER` has `file.hash.sha256`, a `CREDENTIAL` has `user.name`), with geo fields
  present when the resolver has a database loaded.
- **`TestExportNDJSONSinceFilters`**: `?since` returns only events at or after the
  cutoff.
- **`TestExportSTIXBundleValidates`**: the response is a `bundle` with `type` and
  `id` set and `indicator` objects whose `pattern`/`pattern_type` are well formed.
- **`TestExportStixIdsAreDeterministic`**: two exports of the same captures produce
  identical object and bundle ids (the dedupe contract).
- **`TestExportStixIncludesC2AndDroppers`**: a `DOWNLOAD_ATTEMPT` URL and a
  `DROPPER` sha each appear as the expected indicator pattern.
- **`TestExportEnrichesWithGeo`**: with a country/ASN database loaded, the ECS lines
  carry `source.geo.country_iso_code` and `source.as.number`.
- **`TestExportEmitsNothingFromSensor`**: a boundary-shaped assertion that the
  export handlers add no event to the log and open no outbound connection (they are
  read-only formatters over the store and log).

Must keep passing unchanged: `internal/portal` `TestPayloadsAggregatesWhoPulledWhat`,
`TestOverviewEnrichesISP`, `TestServedHTMLReachesNothingOffHost`.

## Acceptance criteria

- `/dashboard/export/ndjson` streams every event as ECS-mapped JSON enriched with
  geo/operator, filterable by `?since`, verified valid line by line.
- `/dashboard/export/stix` returns a valid STIX 2.1 bundle of the C2 URLs and
  dropper hashes with deterministic, re-export-stable ids.
- Both are portal-plane, pull-only, read-only: no sensor change, no new log event,
  no outbound connection, verified by the boundary test.
- `make check` is green and the feature tree cites the tests.

## Out of scope

- Pushing to a TAXII server or a SIEM endpoint. The export is pull-only; the
  operator forwards the artifact with their own tooling, so the portal adds no
  egress.
- A second event schema beyond ECS, or a MISP-native JSON format. STIX 2.1 imports
  into MISP; a dedicated MISP format is a later pickup if an operator needs it.
- Real-time streaming into a SIEM. This is batch/pull; the live SSE feed
  (`/dashboard/events`) remains the real-time surface for the operator's own console.
