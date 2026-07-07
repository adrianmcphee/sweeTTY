package portal

import "sort"

// surfaceService is one configured listener as the console presents it: the port
// the world reaches (public), the port the process binds, its protocol and
// persona, whether it is actually serving, and how much traffic it has drawn. It
// describes the sensor's own attack surface, independent of whether anyone has
// touched a given port yet, which the traffic-driven by-port rollup cannot show.
type surfaceService struct {
	PublicPort int    `json:"public_port"`
	Port       int    `json:"port"`
	Protocol   string `json:"protocol"`
	Persona    string `json:"persona,omitempty"`
	Listening  bool   `json:"listening"`
	Hits       int    `json:"hits"`
	Scans      int    `json:"scans"`
}

// surfaceServices lists every configured listener for the console's exposed-services
// view. PublicPort falls back to the bound port when the config carries no explicit
// public port (the direct topology, or a hand-written config). Listening comes from
// the active set main records after startup; a configured port missing from it is an
// open edge port with a dead backend, shown so the operator can catch it. Hits and
// scans are folded in from the by-port projection when present. Ordered by the
// public port so the list reads like a port scan of the box.
func (p *Portal) surfaceServices(portStats map[int]*portStat) []surfaceService {
	out := make([]surfaceService, 0, len(p.cfg.Listeners))
	for _, lc := range p.cfg.Listeners {
		pub := lc.PublicPort
		if pub == 0 {
			pub = lc.Port
		}
		listening := true
		if p.active != nil {
			listening = p.active[lc.Port]
		}
		s := surfaceService{
			PublicPort: pub,
			Port:       lc.Port,
			Protocol:   lc.Protocol,
			Persona:    lc.Persona,
			Listening:  listening,
		}
		if ps := portStats[lc.Port]; ps != nil {
			s.Hits = ps.Hits
			s.Scans = ps.Scans
		}
		out = append(out, s)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].PublicPort < out[j].PublicPort })
	return out
}
