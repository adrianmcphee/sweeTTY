package portal

import (
	"net/http"
	"sort"

	"github.com/gin-gonic/gin"

	"sweetty/internal/event"
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

// honeytokens aggregates every HONEYTOKEN event into per-source rows plus
// headline totals, so an operator can see at a glance how often a bait (the fake
// vault, or an image viewer pointed at a bait file) was triggered and from
// where. This is the analytics view the bait exists to feed.
func (p *Portal) honeytokens(c *gin.Context) {
	entries, err := p.readEntries(func(e event.Entry) bool {
		return e.Event == "HONEYTOKEN"
	})
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"sources": []honeytokenSource{}, "total": 0, "by_token": gin.H{}})
		return
	}

	bySrc := map[string]*honeytokenSource{}
	sessionSeen := map[string]map[string]bool{}
	tokenSeen := map[string]map[string]bool{}
	byToken := map[string]int{}
	order := []string{}

	for _, e := range entries {
		src := srcOf(e)
		row := bySrc[src]
		if row == nil {
			loc := p.geo.Locate(src)
			row = &honeytokenSource{
				IP:        src,
				Country:   loc.Country,
				Scope:     loc.Scope,
				FirstSeen: e.Time,
			}
			bySrc[src] = row
			sessionSeen[src] = map[string]bool{}
			tokenSeen[src] = map[string]bool{}
			order = append(order, src)
		}
		row.Count++
		row.LastSeen = e.Time // entries are chronological, so the last write wins
		if e.Session != "" && !sessionSeen[src][e.Session] {
			sessionSeen[src][e.Session] = true
			row.Sessions = append(row.Sessions, e.Session)
		}
		if e.Note != "" && !tokenSeen[src][e.Note] {
			tokenSeen[src][e.Note] = true
			row.Tokens = append(row.Tokens, e.Note)
		}
		token := e.Note
		if token == "" {
			token = "unknown"
		}
		byToken[token]++
	}

	sources := make([]honeytokenSource, 0, len(order))
	for _, src := range order {
		sources = append(sources, *bySrc[src])
	}
	// Busiest sources first, breaking ties by most recent activity so a fresh hit
	// surfaces over an equally-busy stale one.
	sort.SliceStable(sources, func(i, j int) bool {
		if sources[i].Count != sources[j].Count {
			return sources[i].Count > sources[j].Count
		}
		return sources[i].LastSeen > sources[j].LastSeen
	})

	c.JSON(http.StatusOK, gin.H{
		"sources":     sources,
		"total":       len(entries),
		"unique_srcs": len(order),
		"by_token":    byToken,
		"geo_active":  p.geo.Loaded() > 0,
	})
}
