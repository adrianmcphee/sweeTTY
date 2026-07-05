# RFC 0006: The log as campaign intelligence

Roadmap: [Direction 2](../ROADMAP.md#2-the-log-as-campaign-intelligence).
Doctrine: VISION §6 (a quiet binary and a loud dashboard).

## Problem

The portal reads each source for what it is: it folds the log into incremental
projections (`internal/portal`), segments a source's visits, and returns a
conservative verdict with the evidence behind it (`internal/portal/analyze.go`). It
reads each source alone. The hundred sources running the same loader against the box
in the same week are a hundred separate drill-downs, not one thing seen clearly.

This RFC clusters sources by what they share, the same payload URL, the same
reconstructed dropper (its sha256 is already captured), the same credential list,
the same command sequence, into campaigns the portal names and counts, so the
operator sees one botnet with four hundred addresses and one loader rather than four
hundred rows.

## Constraints

- **A pure read side over the log.** The portal stores nothing of its own; a
  campaign is a fold over the same append-only log every other view reads. The
  clustering lives in a new projection folded once per line, alongside `ov`, `ht`,
  `pay`, and `live` in `store` (`internal/portal/store.go:27`). No database, no
  write path.
- **Incremental equivalence is the contract.** Folding the log incrementally with
  reads in between must produce the identical campaign set a fresh process folding
  the finished log in one pass produces. This is the property
  `TestStoreIncrementalFoldMatchesFreshFold` pins for the existing projections, and
  the campaign projection must satisfy it too. That rules out any clustering that
  depends on seeing all events before it can start; it must be an online, merge-only
  algorithm.
- **Bounded memory.** Like the overview's `overviewSourceCap`, the campaign
  projection caps what it retains: indicators per source, sources per campaign, and
  campaigns returned. A cap that drops data is stated in the response, never silent.
- **Exact shared indicators, not fuzzy similarity.** Clustering is by exact shared
  value (same URL, same sha256, same credential pair, same normalized command
  sequence), so it is deterministic and cheap. Edit-distance or ML similarity is out
  of scope.

## Design

### An online union-find over shared indicators

A campaign is a connected component of sources linked by a shared indicator. Union
sources when they first share an indicator; the components are the campaigns. Union
by index into the source list keeps merges O(alpha) and order-independent, so
incremental and from-scratch folds converge to the same components.

Add `internal/portal/campaigns.go`:

```go
// campaignProj clusters sources into campaigns by shared indicators, folded online
// so the set of campaigns is identical whether the log is folded incrementally or
// in one pass. Sources are linked by union-find the moment they share an indicator.
type campaignProj struct {
	idOf    map[string]int      // source ip -> dense index
	srcs    []string            // index -> source ip
	parent  []int               // union-find over source indices
	byInd   map[string][]int    // indicator key -> source indices that carry it
	indsOf  map[int]map[string]bool // source index -> its indicator keys (capped)
	firstMs map[int]int64
	lastMs  map[int]int64
}
```

`fold(e event.Entry, p *Portal)` extracts the indicators an event carries and links:

- `DOWNLOAD_ATTEMPT`: `url:<payloadURL(e)>` (reuse `payloadURL`,
  `internal/portal/payloads.go:86`).
- `DROPPER`: `sha:<e.SHA256>` (falling back to `file:<e.Filename>`).
- `CREDENTIAL`: `cred:<user>\x00<pass>`.
- `COMMAND`: accumulate per source; at `SESSION_END`, hash the session's ordered
  command list into `cmdseq:<fnv64 of the joined commands>` and link on that, so two
  sources running the identical command sequence cluster even with no shared URL.

For each indicator key on an event, look up `byInd[key]`; union the current source
with the first source already carrying it, then append. Track first/last ms per
source for the campaign window. Cap `indsOf[src]` at a fixed size (for example 64)
so a noisy source cannot grow unbounded, and count the drop.

Wire it into `store`:

- Add `camp campaignProj` to the `store` struct (`store.go:27`).
- Add `st.camp.fold(e, p)` in `store.fold` (`store.go:86`).
- Add `st.camp = campaignProj{}` in `store.reset` (`store.go:101`).

### The handler and route

Add `p.campaigns(w, r)` in `campaigns.go`, following `payloads`
(`internal/portal/payloads.go:41`): lock the store, `syncStoreLocked`, read the
snapshot. Walk union-find roots to build components; for each campaign of size >= 2
(a single source is not yet a campaign), assemble:

```go
type campaign struct {
	ID        string   `json:"id"`         // stable: the dominant indicator's hash
	Size      int      `json:"size"`       // member sources
	Sources   []string `json:"sources"`    // capped, most-recent first
	SharedURLs []string `json:"shared_urls,omitempty"`
	SharedShas []string `json:"shared_shas,omitempty"`
	SharedCreds int     `json:"shared_creds,omitempty"`
	Kind      string   `json:"kind"`       // dominant verdict from analyze
	Countries []string `json:"countries,omitempty"`
	FirstSeen string   `json:"first_seen"`
	LastSeen  string   `json:"last_seen"`
}
```

Name the campaign by its dominant shared indicator (the most common dropper sha or
C2 host across members), so the id is stable across exports. Derive `Kind` by
reusing the overview's per-source signals: the campaign's kind is the majority kind
of its members (the overview already holds `sigBySrc`; the campaign handler can read
the same verdicts). Attach the member countries via `p.geo.Locate` on each source,
the way the overview and payload projections already enrich
(`internal/portal/store.go:221`).

Register the route in `portal.go` `engine` (near `:145`):

```go
mux.HandleFunc("GET /dashboard/campaigns", p.campaigns)
```

Sort campaigns by size then recency; cap the returned list and say so when capped.

A dashboard tab is a thin addition to `internal/portal/html.go` (a Campaigns view
that fetches `/dashboard/campaigns` and renders member count, shared indicators, and
the country spread). The data route is the substance; the tab can follow.

## Implementation steps

1. Add `campaignProj` with `fold` and the union-find, wired into `store`'s struct,
   `fold`, and `reset`. Add the equivalence and clustering tests below. Commit.
2. Add the `campaigns` handler and route, building components and enriching with
   geo. Add the handler tests. Commit.
3. Add the Campaigns dashboard tab in `html.go`. Commit.
4. Update [FEATURE-TREE.md](../FEATURE-TREE.md) portal section citing the tests.

## Tests

Add to `internal/portal` (`store_test.go` shape for the fold, `payloads_test.go`
shape for the handler):

- **`TestCampaignsClusterBySharedDropper`**: two sources emitting the same
  `DROPPER` sha256 land in one campaign; a third with a different sha does not.
- **`TestCampaignsClusterBySharedC2URL`**: two sources with the same
  `DOWNLOAD_ATTEMPT` URL cluster.
- **`TestCampaignsClusterByCommandSequence`**: two sources running the identical
  ordered command list cluster on the `cmdseq` indicator with no shared URL.
- **`TestCampaignIncrementalFoldMatchesFreshFold`**: the campaign set from an
  incremental fold with reads in between is identical to a from-scratch fold, the
  equivalence contract in the shape of `TestStoreIncrementalFoldMatchesFreshFold`.
- **`TestCampaignProjRefoldsAfterRotation`**: a shrunk log resets and refolds the
  campaign projection, in the shape of `TestStoreRefoldsAfterRotation`.
- **`TestCampaignKindIsMemberMajority`**: a campaign of loader sources is tagged
  `bot:loader`.

Must keep passing unchanged: all existing `internal/portal/store_test.go` tests,
`TestOverviewMarksReturningAndKind`, `TestPayloadsAggregatesWhoPulledWhat`.

## Acceptance criteria

- Sources sharing a dropper sha, a C2 URL, a credential pair, or an exact command
  sequence are clustered into one campaign, verified by the four clustering tests.
- The campaign projection satisfies the incremental-equals-fresh equivalence
  contract and refolds on rotation.
- `/dashboard/campaigns` returns campaigns with size, shared indicators, dominant
  verdict, and country spread, capped with the cap stated when hit.
- `make check` is green and the feature tree cites the tests.

## Out of scope

- Fuzzy or approximate clustering (edit distance, embeddings). Only exact shared
  indicators, so the fold stays deterministic and cheap.
- Cross-instance correlation (one campaign seen across several sensors). This RFC
  correlates within one instance's log; multi-sensor aggregation is a portable-intel
  concern that [RFC 0007](./0007-intelligence-export.md) enables at the export layer.
- Naming campaigns with human-friendly labels or threat-actor attribution. The id is
  the dominant indicator's hash, stable but not editorial.
