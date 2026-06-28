package portal

import (
	"net/http"
	"sort"
	"strconv"

	"github.com/gin-gonic/gin"
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
	IP        string   `json:"ip"`
	Country   string   `json:"country,omitempty"`
	ASN       uint32   `json:"asn,omitempty"`
	Org       string   `json:"org,omitempty"`
	Scope     string   `json:"scope"`
	Events    int      `json:"events"`
	Sessions  int      `json:"sessions"`
	FirstSeen string   `json:"first_seen"`
	LastSeen  string   `json:"last_seen"`
	Protocols []string `json:"protocols,omitempty"`
	Ports     []int    `json:"ports,omitempty"`
	Scanned   bool     `json:"scanned"`
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

// overview aggregates the whole event log into the recon analytics the dashboard
// needs in a single read: headline counts (port scans and the other attempt
// types), a per-listener-port breakdown, a per-country breakdown, the top client
// user-agent strings, and a per-source rollup enriched with country and scope.
// Management-plane events (the portal's own system notices) are excluded so the
// figures describe attacker activity only.
func (p *Portal) overview(c *gin.Context) {
	entries, err := p.readEntries(nil)
	if err != nil {
		c.JSON(http.StatusOK, emptyOverview(p))
		return
	}

	bySrc := map[string]*overviewSource{}
	order := []string{}
	sessSeen := map[string]map[string]bool{}
	protoSeen := map[string]map[string]bool{}
	portSeen := map[string]map[int]bool{}

	portStats := map[int]*portStat{}
	uaStats := map[string]*agentStat{}
	uaSrcSeen := map[string]map[string]bool{}

	var events, sessions, scans, creds, https, downloads, execs, bait int

	for _, e := range entries {
		switch e.Event {
		case "", "SYSTEM":
			continue
		}
		src := srcOf(e)
		if src == "" {
			continue
		}

		events++
		switch e.Event {
		case "PORT_SCAN":
			scans++
		case "SESSION_START":
			sessions++
		case "CREDENTIAL":
			creds++
		case "HTTP_REQUEST", "HTTP_POST":
			https++
		case "DOWNLOAD_ATTEMPT":
			downloads++
		case "EXEC_ATTEMPT":
			execs++
		case "HONEYTOKEN":
			bait++
		}

		row := bySrc[src]
		if row == nil {
			loc := p.geo.Locate(src)
			row = &overviewSource{IP: src, Country: loc.Country, ASN: loc.ASN, Org: loc.Org, Scope: loc.Scope, FirstSeen: e.Time}
			bySrc[src] = row
			order = append(order, src)
			sessSeen[src] = map[string]bool{}
			protoSeen[src] = map[string]bool{}
			portSeen[src] = map[int]bool{}
		}
		row.Events++
		row.LastSeen = e.Time // entries are chronological, so the last write wins
		if e.Session != "" && !sessSeen[src][e.Session] {
			sessSeen[src][e.Session] = true
			row.Sessions++
		}
		if e.Protocol != "" && !protoSeen[src][e.Protocol] {
			protoSeen[src][e.Protocol] = true
			row.Protocols = append(row.Protocols, e.Protocol)
		}
		if e.Port > 0 && !portSeen[src][e.Port] {
			portSeen[src][e.Port] = true
			row.Ports = append(row.Ports, e.Port)
		}
		if e.Event == "PORT_SCAN" {
			row.Scanned = true
		}

		if e.Port > 0 {
			ps := portStats[e.Port]
			if ps == nil {
				ps = &portStat{Port: e.Port, Protocol: e.Protocol}
				portStats[e.Port] = ps
			}
			if ps.Protocol == "" {
				ps.Protocol = e.Protocol
			}
			ps.Hits++
			if e.Event == "PORT_SCAN" {
				ps.Scans++
			}
		}

		if e.UserAgent != "" {
			ua := uaStats[e.UserAgent]
			if ua == nil {
				ua = &agentStat{Agent: e.UserAgent}
				uaStats[e.UserAgent] = ua
				uaSrcSeen[e.UserAgent] = map[string]bool{}
			}
			ua.Count++
			if !uaSrcSeen[e.UserAgent][src] {
				uaSrcSeen[e.UserAgent][src] = true
				ua.Sources++
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"totals": gin.H{
			"events":        events,
			"sources":       len(order),
			"sessions":      sessions,
			"port_scans":    scans,
			"credentials":   creds,
			"http_requests": https,
			"downloads":     downloads,
			"exec":          execs,
			"bait":          bait,
			"user_agents":   len(uaStats),
		},
		"by_port":     sortedPorts(portStats),
		"by_country":  countryRollup(order, bySrc),
		"by_isp":      ispRollup(order, bySrc),
		"user_agents": topAgents(uaStats),
		"sources":     topSources(order, bySrc),
		"geo_active":  p.geo.Loaded() > 0,
		"asn_active":  p.geo.AsnLoaded() > 0,
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

// emptyOverview is the zero-valued response shape, returned when the log cannot be
// read so the dashboard renders empty panels instead of erroring.
func emptyOverview(p *Portal) gin.H {
	return gin.H{
		"totals": gin.H{
			"events": 0, "sources": 0, "sessions": 0, "port_scans": 0,
			"credentials": 0, "http_requests": 0, "downloads": 0, "exec": 0, "bait": 0, "user_agents": 0,
		},
		"by_port":     []portStat{},
		"by_country":  []countryStat{},
		"by_isp":      []ispStat{},
		"user_agents": []agentStat{},
		"sources":     []overviewSource{},
		"geo_active":  p.geo.Loaded() > 0,
		"asn_active":  p.geo.AsnLoaded() > 0,
	}
}
