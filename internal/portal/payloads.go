package portal

import (
	"net/http"
	"sort"

	"sweetty/internal/event"
)

// payloadSource is one attacker's payload-fetch activity: who they are, where
// they resolved to, how many fetches they tried, over what window, and the URLs
// they reached for. Country, scope, and operator come from the portal-plane
// resolver, never from the honeypot process.
type payloadSource struct {
	IP        string       `json:"ip"`
	Country   string       `json:"country,omitempty"`
	ASN       uint32       `json:"asn,omitempty"`
	Org       string       `json:"org,omitempty"`
	Scope     string       `json:"scope"`
	Count     int          `json:"count"`
	FirstSeen string       `json:"first_seen"`
	LastSeen  string       `json:"last_seen"`
	Sessions  []string     `json:"sessions"`
	URLs      []string     `json:"urls"`
	Droppers  []droppedRef `json:"droppers,omitempty"`
}

// droppedRef is one file an attacker assembled in place and ran: the honeypot's
// payload indicator when nothing was fetched over the wire. The sha256 is the
// stable identifier; the filename is where they built it.
type droppedRef struct {
	Filename string `json:"filename"`
	SHA256   string `json:"sha256"`
}

// payloads aggregates every DOWNLOAD_ATTEMPT - an attacker's faked wget/curl/tftp
// of a second-stage payload - into per-source rows plus a distinct-URL roll-up and
// headline totals. The captured URLs are the honeypot's highest-value indicator of
// compromise (the malware staging host and, often, the C2), so this is the page an
// operator reads to see who is fetching what, and hands to a threat-intel platform.
func (p *Portal) payloads(w http.ResponseWriter, _ *http.Request) {
	// Both an over-the-wire fetch (DOWNLOAD_ATTEMPT) and an in-place dropper
	// (DROPPER) are payload deliveries; this page rolls up who delivered what by
	// either route, since the loaders on a given sensor may favour one or the other.
	// The rows come from the incremental projection (store.go), folded once per log
	// line rather than per request.
	p.store.mu.Lock()
	defer p.store.mu.Unlock()
	p.syncStoreLocked()
	pa := &p.store.pay

	sources := make([]payloadSource, 0, len(pa.order))
	for _, src := range pa.order {
		sources = append(sources, *pa.bySrc[src])
	}
	// Busiest sources first, breaking ties by most recent activity so a fresh pull
	// surfaces over an equally-busy stale one.
	sort.SliceStable(sources, func(i, j int) bool {
		if sources[i].Count != sources[j].Count {
			return sources[i].Count > sources[j].Count
		}
		return sources[i].LastSeen > sources[j].LastSeen
	})

	byURL, bySha := pa.byURL, pa.bySha
	if byURL == nil {
		byURL = map[string]int{}
	}
	if bySha == nil {
		bySha = map[string]int{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sources":       sources,
		"total":         pa.total,
		"unique_srcs":   len(pa.order),
		"by_url":        byURL,
		"by_sha":        bySha,
		"dropper_total": pa.dropperTotal,
		"geo_active":    p.geo.Loaded() > 0,
	})
}

// payloadURL is the URL an attacker tried to fetch, preferring the structured URL
// field and falling back to the raw command line (some fetchers are logged with
// only the command). An empty result is labelled so it still rolls up.
func payloadURL(e event.Entry) string {
	switch {
	case e.URL != "":
		return e.URL
	case e.Command != "":
		return e.Command
	default:
		return "unknown"
	}
}
