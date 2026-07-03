package portal

import (
	"net/http"
	"sort"
	"strconv"
	"time"
)

// overviewSourceCap bounds the per-source rollup in the overview response. A busy
// sensor accumulates a long tail of one-off scanners; the busiest few hundred are
// what an operator reads, and the headline source count still reflects the total.
const overviewSourceCap = 300

// overviewSource is one attacker IP's footprint across the whole log: where it
// resolved to, how busy it was, which listener ports and protocols it touched,
// whether it ever just bare-scanned, and the client strings it presented. Country
// and scope come from the portal-plane resolver, never the honeypot process.
type overviewSource struct {
	IP         string   `json:"ip"`
	Country    string   `json:"country,omitempty"`
	ASN        uint32   `json:"asn,omitempty"`
	Org        string   `json:"org,omitempty"`
	Scope      string   `json:"scope"`
	Events     int      `json:"events"`
	Sessions   int      `json:"sessions"`
	FirstSeen  string   `json:"first_seen"`
	LastSeen   string   `json:"last_seen"`
	Protocols  []string `json:"protocols,omitempty"`
	Ports      []int    `json:"ports,omitempty"`
	Scanned    bool     `json:"scanned"`
	Kind       string   `json:"kind,omitempty"`
	Confidence int      `json:"confidence,omitempty"`
	Visits     int      `json:"visits,omitempty"`
	Returning  bool     `json:"returning,omitempty"`
}

// portStat is one listener port's exposure: how many events landed on it and how
// many of those were bare port scans (a connect that sent nothing).
type portStat struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol,omitempty"`
	Hits     int    `json:"hits"`
	Scans    int    `json:"scans"`
}

// countryStat rolls sources up by country (or by scope label when an address is
// not a globally routable one with a known country).
type countryStat struct {
	Country string `json:"country"`
	Sources int    `json:"sources"`
	Events  int    `json:"events"`
}

// ispStat rolls sources up by their autonomous-system operator (the ISP or
// hosting provider), so an operator sees which networks are hammering the box.
type ispStat struct {
	ASN     uint32 `json:"asn,omitempty"`
	Org     string `json:"org"`
	Sources int    `json:"sources"`
	Events  int    `json:"events"`
}

// agentStat is one client/user-agent string and how widely it was seen.
type agentStat struct {
	Agent   string `json:"agent"`
	Count   int    `json:"count"`
	Sources int    `json:"sources"`
}

// overview serves the recon analytics the dashboard needs in a single read:
// headline counts (port scans and the other attempt types), a per-listener-port
// breakdown, a per-country breakdown, the top client user-agent strings, and a
// per-source rollup enriched with country and scope. Management-plane events
// (the portal's own system notices) are excluded so the figures describe
// attacker activity only. The figures come from the incremental projection
// (store.go), so a request folds only the log's unread tail, never the whole
// file.
func (p *Portal) overview(w http.ResponseWriter, _ *http.Request) {
	p.store.mu.Lock()
	defer p.store.mu.Unlock()
	p.syncStoreLocked()
	o := &p.store.ov
	o.init()

	// Tag each source with the analyzer's verdict, its visit count, and whether it
	// is a returning visitor. The reasons are dropped here (the per-IP drawer carries
	// them); the list needs only the headline kind.
	for _, src := range o.order {
		row := o.bySrc[src]
		row.Visits = o.visitCnt[src]
		if sig := o.sigBySrc[src]; sig != nil {
			kind, conf, _ := verdict(*sig)
			row.Kind = kind
			row.Confidence = conf
			row.Returning = o.visitCnt[src] >= 2 || (row.Scanned && (sig.commands > 0 || sig.sessions > 0))
		}
	}

	// Whole-UTC-day counters for the live-feed stat cards, so they reflect the full
	// log for today rather than the capped in-page event buffer the browser holds.
	tSessions, tScans, tDownloads, tBait, tSrcs := o.today(time.Now().UTC().Format("2006-01-02"))

	writeJSON(w, http.StatusOK, map[string]any{
		"totals": map[string]any{
			"events":        o.events,
			"sources":       len(o.order),
			"sessions":      o.sessions,
			"port_scans":    o.scans,
			"credentials":   o.creds,
			"http_requests": o.https,
			"downloads":     o.downloads,
			"exec":          o.execs,
			"bait":          o.bait,
			"user_agents":   len(o.uaStats),
		},
		"today": map[string]any{
			"sessions":   tSessions,
			"sources":    tSrcs,
			"downloads":  tDownloads,
			"bait":       tBait,
			"port_scans": tScans,
		},
		"by_port":     sortedPorts(o.portStats),
		"by_country":  countryRollup(o.order, o.bySrc),
		"by_isp":      ispRollup(o.order, o.bySrc),
		"user_agents": topAgents(o.uaStats),
		"sources":     topSources(o.order, o.bySrc),
		"geo_active":  p.geo.Loaded() > 0,
		"asn_active":  p.geo.AsnLoaded() > 0,
		"version":     p.version,
	})
}

// topSources returns the per-source rollup, busiest first (ties broken by most
// recent activity), capped to overviewSourceCap.
func topSources(order []string, bySrc map[string]*overviewSource) []overviewSource {
	out := make([]overviewSource, 0, len(order))
	for _, src := range order {
		out = append(out, *bySrc[src])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Events != out[j].Events {
			return out[i].Events > out[j].Events
		}
		return out[i].LastSeen > out[j].LastSeen
	})
	if len(out) > overviewSourceCap {
		out = out[:overviewSourceCap]
	}
	return out
}

// sortedPorts returns the per-port breakdown, most-hit first.
func sortedPorts(m map[int]*portStat) []portStat {
	out := make([]portStat, 0, len(m))
	for _, ps := range m {
		out = append(out, *ps)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Hits != out[j].Hits {
			return out[i].Hits > out[j].Hits
		}
		return out[i].Port < out[j].Port
	})
	return out
}

// countryRollup aggregates sources by country, falling back to the scope label
// (private, loopback, global, …) for addresses with no resolved country, so every
// source is accounted for. Most sources first.
func countryRollup(order []string, bySrc map[string]*overviewSource) []countryStat {
	agg := map[string]*countryStat{}
	keys := []string{}
	for _, src := range order {
		row := bySrc[src]
		key := row.Country
		if key == "" {
			key = row.Scope
		}
		if key == "" {
			key = "unknown"
		}
		cs := agg[key]
		if cs == nil {
			cs = &countryStat{Country: key}
			agg[key] = cs
			keys = append(keys, key)
		}
		cs.Sources++
		cs.Events += row.Events
	}
	out := make([]countryStat, 0, len(keys))
	for _, k := range keys {
		out = append(out, *agg[k])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Sources != out[j].Sources {
			return out[i].Sources > out[j].Sources
		}
		return out[i].Events > out[j].Events
	})
	return out
}

// ispRollup aggregates sources by their AS operator (ISP / hosting provider),
// falling back to "AS<number>" when the operator name is unknown and to the scope
// label when there is no ASN at all, so every source is accounted for. Most
// sources first.
func ispRollup(order []string, bySrc map[string]*overviewSource) []ispStat {
	agg := map[string]*ispStat{}
	keys := []string{}
	for _, src := range order {
		row := bySrc[src]
		key := row.Org
		if key == "" && row.ASN != 0 {
			key = "AS" + strconv.FormatUint(uint64(row.ASN), 10)
		}
		if key == "" {
			key = row.Scope
		}
		if key == "" {
			key = "unknown"
		}
		is := agg[key]
		if is == nil {
			is = &ispStat{ASN: row.ASN, Org: key}
			agg[key] = is
			keys = append(keys, key)
		}
		is.Sources++
		is.Events += row.Events
	}
	out := make([]ispStat, 0, len(keys))
	for _, k := range keys {
		out = append(out, *agg[k])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Sources != out[j].Sources {
			return out[i].Sources > out[j].Sources
		}
		return out[i].Events > out[j].Events
	})
	return out
}

// topAgents returns the most-seen client user-agent strings, capped to a sane
// number so one noisy fuzzer cannot bloat the response.
func topAgents(m map[string]*agentStat) []agentStat {
	out := make([]agentStat, 0, len(m))
	for _, ua := range m {
		out = append(out, *ua)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Agent < out[j].Agent
	})
	const cap = 50
	if len(out) > cap {
		out = out[:cap]
	}
	return out
}
