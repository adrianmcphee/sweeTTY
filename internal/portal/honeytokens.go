package portal

import (
	"net/http"
	"sort"
)

// honeytokenSource is one attacker's interaction with the planted baits: who
// they are, where they resolved to, how many times they tripped a token, and
// over what window. Country and scope come from the portal-plane resolver, never
// from the honeypot process.
type honeytokenSource struct {
	IP        string   `json:"ip"`
	Country   string   `json:"country,omitempty"`
	Scope     string   `json:"scope"`
	Count     int      `json:"count"`
	FirstSeen string   `json:"first_seen"`
	LastSeen  string   `json:"last_seen"`
	Sessions  []string `json:"sessions"`
	Tokens    []string `json:"tokens"`
}

// honeytokens serves every HONEYTOKEN event as per-source rows plus headline
// totals, so an operator can see at a glance how often a bait (the fake vault,
// or an image viewer pointed at a bait file) was triggered and from where. This
// is the analytics view the bait exists to feed. The rows come from the
// incremental projection (store.go), folded once per log line rather than per
// request.
func (p *Portal) honeytokens(w http.ResponseWriter, _ *http.Request) {
	p.store.mu.Lock()
	defer p.store.mu.Unlock()
	p.syncStoreLocked()
	h := &p.store.ht

	sources := make([]honeytokenSource, 0, len(h.order))
	for _, src := range h.order {
		sources = append(sources, *h.bySrc[src])
	}
	// Busiest sources first, breaking ties by most recent activity so a fresh hit
	// surfaces over an equally-busy stale one.
	sort.SliceStable(sources, func(i, j int) bool {
		if sources[i].Count != sources[j].Count {
			return sources[i].Count > sources[j].Count
		}
		return sources[i].LastSeen > sources[j].LastSeen
	})

	byToken := h.byToken
	if byToken == nil {
		byToken = map[string]int{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sources":     sources,
		"total":       h.total,
		"unique_srcs": len(h.order),
		"by_token":    byToken,
		"geo_active":  p.geo.Loaded() > 0,
	})
}
