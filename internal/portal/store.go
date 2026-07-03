package portal

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"sync"

	"sweetty/internal/event"
)

// store is the portal's incremental read model over the event log. Every
// dashboard-polled endpoint used to re-read and re-parse the whole log per
// request; on a busy sensor that is hundreds of megabytes of transient
// allocation for every poll of every panel, enough to take the process past the
// box's memory and get it killed just by opening the console. The store folds
// each log line into the projections exactly once: sync reads only the bytes
// appended since the last call (the same byte-offset tailing the SSE feed uses)
// and hands each complete line to every projection. A request then reads a
// snapshot instead of the file.
//
// The log file remains the single source of truth: nothing here is persisted,
// and a restart rebuilds the projections with one streaming pass on the first
// request. A log that shrinks (rotation) resets the store and refolds from the
// start.
type store struct {
	mu     sync.Mutex
	offset int64 // bytes of the log already folded

	ov   overviewProj
	ht   honeytokenProj
	pay  payloadProj
	live liveProj
}

// syncStore folds any log bytes appended since the last call into the
// projections, then leaves the store locked state consistent. Callers must hold
// no lock; the handlers call this at the top and then read under the same lock
// via the with* helpers.
func (p *Portal) syncStore() {
	p.store.mu.Lock()
	defer p.store.mu.Unlock()
	p.syncStoreLocked()
}

func (p *Portal) syncStoreLocked() {
	f, err := os.Open(p.cfg.LogFile)
	if err != nil {
		return // no log yet: projections stay empty, exactly like an empty read
	}
	defer f.Close()

	size, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return
	}
	st := &p.store
	if size < st.offset {
		// The file shrank: it was rotated or truncated. Refold from the start.
		st.reset()
	}
	if size == st.offset {
		return
	}
	if _, err := f.Seek(st.offset, io.SeekStart); err != nil {
		return
	}

	reader := bufio.NewReaderSize(f, 256*1024)
	for {
		chunk, rerr := reader.ReadBytes('\n')
		if rerr != nil {
			// EOF with no newline: a line is mid-write. Leave the offset before it
			// so the next sync re-reads the line once its newline has landed.
			break
		}
		st.offset += int64(len(chunk))
		st.fold(chunk[:len(chunk)-1], p)
	}
}

// fold parses one complete log line and hands it to every projection. Lines
// that are not valid JSON are skipped, the same tolerance readEntries has for a
// truncated write.
func (st *store) fold(line []byte, p *Portal) {
	if len(line) == 0 {
		return
	}
	var e event.Entry
	if err := json.Unmarshal(line, &e); err != nil {
		return
	}
	st.ov.fold(e, p)
	st.ht.fold(e, p)
	st.pay.fold(e, p)
	st.live.fold(e)
}

// reset drops every projection so the next sync refolds the whole file.
func (st *store) reset() {
	st.offset = 0
	st.ov = overviewProj{}
	st.ht = honeytokenProj{}
	st.pay = payloadProj{}
	st.live = liveProj{}
}

// ---- overview projection ---------------------------------------------------

// dayAgg carries the whole-UTC-day counters behind the live-feed stat cards,
// bucketed by day so "today" is answerable at read time without refolding.
type dayAgg struct {
	sessions, scans, downloads, bait int
	srcs                             map[string]bool
}

// overviewProj is the overview handler's whole accumulator set, kept across
// requests and folded one entry at a time. The per-source dedup maps grow with
// the log the same way one request's transient maps always did; holding one
// copy steadily replaces allocating a fresh copy per request.
type overviewProj struct {
	bySrc     map[string]*overviewSource
	order     []string
	sessSeen  map[string]map[string]bool
	protoSeen map[string]map[string]bool
	portSeen  map[string]map[int]bool
	sigBySrc  map[string]*sourceSignals
	visitLast map[string]int64
	visitCnt  map[string]int

	portStats map[int]*portStat
	uaStats   map[string]*agentStat
	uaSrcSeen map[string]map[string]bool

	events, sessions, scans, creds, https, downloads, execs, bait int

	days map[string]*dayAgg
}

func (o *overviewProj) init() {
	if o.bySrc != nil {
		return
	}
	o.bySrc = map[string]*overviewSource{}
	o.sessSeen = map[string]map[string]bool{}
	o.protoSeen = map[string]map[string]bool{}
	o.portSeen = map[string]map[int]bool{}
	o.sigBySrc = map[string]*sourceSignals{}
	o.visitLast = map[string]int64{}
	o.visitCnt = map[string]int{}
	o.portStats = map[int]*portStat{}
	o.uaStats = map[string]*agentStat{}
	o.uaSrcSeen = map[string]map[string]bool{}
	o.days = map[string]*dayAgg{}
}

func (o *overviewProj) fold(e event.Entry, p *Portal) {
	switch e.Event {
	case "", "SYSTEM":
		return
	}
	src := srcOf(e)
	if src == "" {
		return
	}
	o.init()

	o.events++
	switch e.Event {
	case "PORT_SCAN":
		o.scans++
	case "SESSION_START":
		o.sessions++
	case "CREDENTIAL":
		o.creds++
	case "HTTP_REQUEST", "HTTP_POST":
		o.https++
	case "DOWNLOAD_ATTEMPT":
		o.downloads++
	case "EXEC_ATTEMPT":
		o.execs++
	case "HONEYTOKEN":
		o.bait++
	}

	if len(e.Time) >= 10 {
		day := e.Time[:10]
		d := o.days[day]
		if d == nil {
			d = &dayAgg{srcs: map[string]bool{}}
			o.days[day] = d
			// Only today's bucket is ever read; drop all but the two newest days
			// (two, not one, so a fold spanning midnight cannot evict the day a
			// concurrent read is about to ask for).
			if len(o.days) > 2 {
				oldest := day
				for k := range o.days {
					if k < oldest {
						oldest = k
					}
				}
				delete(o.days, oldest)
			}
		}
		d.srcs[src] = true
		switch e.Event {
		case "SESSION_START":
			d.sessions++
		case "PORT_SCAN":
			d.scans++
		case "DOWNLOAD_ATTEMPT":
			d.downloads++
		case "HONEYTOKEN":
			d.bait++
		}
	}

	row := o.bySrc[src]
	if row == nil {
		loc := p.geo.Locate(src)
		row = &overviewSource{IP: src, Country: loc.Country, ASN: loc.ASN, Org: loc.Org, Scope: loc.Scope, FirstSeen: e.Time}
		o.bySrc[src] = row
		o.order = append(o.order, src)
		o.sessSeen[src] = map[string]bool{}
		o.protoSeen[src] = map[string]bool{}
		o.portSeen[src] = map[int]bool{}
	}

	// Fold the event into this source's signals and visit counter, the same way
	// analyzeSource does for the drawer, so the list tag matches the drawer verdict.
	sig := o.sigBySrc[src]
	first := sig == nil
	if first {
		sig = &sourceSignals{}
		o.sigBySrc[src] = sig
		o.visitCnt[src] = 1
	}
	ms := entryMs(e)
	if !first && ms != 0 {
		if vl := o.visitLast[src]; vl != 0 && ms-vl > visitGapMs {
			o.visitCnt[src]++
		}
	}
	if ms != 0 {
		o.visitLast[src] = ms
	}
	sig.observe(e)

	row.Events++
	row.LastSeen = e.Time // entries are chronological, so the last write wins
	if e.Session != "" && !o.sessSeen[src][e.Session] {
		o.sessSeen[src][e.Session] = true
		row.Sessions++
	}
	if e.Protocol != "" && !o.protoSeen[src][e.Protocol] {
		o.protoSeen[src][e.Protocol] = true
		row.Protocols = append(row.Protocols, e.Protocol)
	}
	if e.Port > 0 && !o.portSeen[src][e.Port] {
		o.portSeen[src][e.Port] = true
		row.Ports = append(row.Ports, e.Port)
	}
	if e.Event == "PORT_SCAN" {
		row.Scanned = true
	}

	if e.Port > 0 {
		ps := o.portStats[e.Port]
		if ps == nil {
			ps = &portStat{Port: e.Port, Protocol: e.Protocol}
			o.portStats[e.Port] = ps
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
		ua := o.uaStats[e.UserAgent]
		if ua == nil {
			ua = &agentStat{Agent: e.UserAgent}
			o.uaStats[e.UserAgent] = ua
			o.uaSrcSeen[e.UserAgent] = map[string]bool{}
		}
		ua.Count++
		if !o.uaSrcSeen[e.UserAgent][src] {
			o.uaSrcSeen[e.UserAgent][src] = true
			ua.Sources++
		}
	}
}

// today returns the stat-card counters for the given UTC day.
func (o *overviewProj) today(day string) (sessions, scans, downloads, bait, srcs int) {
	d := o.days[day]
	if d == nil {
		return 0, 0, 0, 0, 0
	}
	return d.sessions, d.scans, d.downloads, d.bait, len(d.srcs)
}

// ---- honeytoken projection ---------------------------------------------------

type honeytokenProj struct {
	bySrc       map[string]*honeytokenSource
	order       []string
	sessionSeen map[string]map[string]bool
	tokenSeen   map[string]map[string]bool
	byToken     map[string]int
	total       int
}

func (h *honeytokenProj) fold(e event.Entry, p *Portal) {
	if e.Event != "HONEYTOKEN" {
		return
	}
	if h.bySrc == nil {
		h.bySrc = map[string]*honeytokenSource{}
		h.sessionSeen = map[string]map[string]bool{}
		h.tokenSeen = map[string]map[string]bool{}
		h.byToken = map[string]int{}
	}
	h.total++
	src := srcOf(e)
	row := h.bySrc[src]
	if row == nil {
		loc := p.geo.Locate(src)
		row = &honeytokenSource{IP: src, Country: loc.Country, Scope: loc.Scope, FirstSeen: e.Time}
		h.bySrc[src] = row
		h.sessionSeen[src] = map[string]bool{}
		h.tokenSeen[src] = map[string]bool{}
		h.order = append(h.order, src)
	}
	row.Count++
	row.LastSeen = e.Time
	if e.Session != "" && !h.sessionSeen[src][e.Session] {
		h.sessionSeen[src][e.Session] = true
		row.Sessions = append(row.Sessions, e.Session)
	}
	if e.Note != "" && !h.tokenSeen[src][e.Note] {
		h.tokenSeen[src][e.Note] = true
		row.Tokens = append(row.Tokens, e.Note)
	}
	token := e.Note
	if token == "" {
		token = "unknown"
	}
	h.byToken[token]++
}

// ---- payload projection ------------------------------------------------------

type payloadProj struct {
	bySrc        map[string]*payloadSource
	order        []string
	sessionSeen  map[string]map[string]bool
	urlSeen      map[string]map[string]bool
	dropSeen     map[string]map[string]bool
	byURL        map[string]int
	bySha        map[string]int
	total        int
	dropperTotal int
}

func (pa *payloadProj) fold(e event.Entry, p *Portal) {
	if e.Event != "DOWNLOAD_ATTEMPT" && e.Event != "DROPPER" {
		return
	}
	if pa.bySrc == nil {
		pa.bySrc = map[string]*payloadSource{}
		pa.sessionSeen = map[string]map[string]bool{}
		pa.urlSeen = map[string]map[string]bool{}
		pa.dropSeen = map[string]map[string]bool{}
		pa.byURL = map[string]int{}
		pa.bySha = map[string]int{}
	}
	pa.total++
	src := srcOf(e)
	row := pa.bySrc[src]
	if row == nil {
		loc := p.geo.Locate(src)
		row = &payloadSource{IP: src, Country: loc.Country, ASN: loc.ASN, Org: loc.Org, Scope: loc.Scope, FirstSeen: e.Time}
		pa.bySrc[src] = row
		pa.sessionSeen[src] = map[string]bool{}
		pa.urlSeen[src] = map[string]bool{}
		pa.dropSeen[src] = map[string]bool{}
		pa.order = append(pa.order, src)
	}
	row.Count++
	row.LastSeen = e.Time
	if e.Session != "" && !pa.sessionSeen[src][e.Session] {
		pa.sessionSeen[src][e.Session] = true
		row.Sessions = append(row.Sessions, e.Session)
	}
	if e.Event == "DROPPER" {
		pa.dropperTotal++
		key := e.SHA256
		if key == "" {
			key = e.Filename
		}
		pa.bySha[key]++
		if !pa.dropSeen[src][key] {
			pa.dropSeen[src][key] = true
			row.Droppers = append(row.Droppers, droppedRef{Filename: e.Filename, SHA256: e.SHA256})
		}
		return
	}
	url := payloadURL(e)
	if !pa.urlSeen[src][url] {
		pa.urlSeen[src][url] = true
		row.URLs = append(row.URLs, url)
	}
	pa.byURL[url]++
}

// ---- live-session projection ---------------------------------------------------

// liveAgg is one open connection's rolling state for the live rail.
type liveAgg struct {
	ip, proto       string
	firstMs, lastMs int64
	cmds            int
	started         bool
}

// liveProj tracks connections that have started and not ended. Ended sessions
// are dropped at once and stale ones are swept, so unlike the full-scan
// aggregation this never holds every session id the log has ever seen.
type liveProj struct {
	byID  map[string]*liveAgg
	order []string
}

// liveSweepFactor sets how stale an open session may grow before the projection
// forgets it, as a multiple of the rail's activeWindow. Anything past the window
// is invisible to the rail either way; sweeping at double the window keeps the
// map from accumulating orphans (sessions whose END was lost to a hard restart)
// while never evicting a session the rail could still show.
const liveSweepFactor = 2

func (l *liveProj) fold(e event.Entry) {
	if e.Session == "" {
		return
	}
	if l.byID == nil {
		l.byID = map[string]*liveAgg{}
	}
	a := l.byID[e.Session]
	if a == nil {
		if e.Event == "SESSION_END" {
			return // end of a session we never tracked (or already swept)
		}
		a = &liveAgg{firstMs: e.EpochMs, lastMs: e.EpochMs}
		l.byID[e.Session] = a
		l.order = append(l.order, e.Session)
	}
	if e.Event == "SESSION_END" {
		delete(l.byID, e.Session)
		return
	}
	if e.EpochMs < a.firstMs {
		a.firstMs = e.EpochMs
	}
	if e.EpochMs > a.lastMs {
		a.lastMs = e.EpochMs
	}
	if a.ip == "" {
		a.ip = srcOf(e)
	}
	if a.proto == "" {
		a.proto = e.Protocol
	}
	switch e.Event {
	case "SESSION_START":
		a.started = true
	case "COMMAND":
		a.cmds++
	}
}

// sweep drops sessions idle past the cutoff and compacts the order list to the
// ids still tracked. Called under the store lock by the live-rail handler.
func (l *liveProj) sweep(cutoffMs int64) {
	if l.byID == nil {
		return
	}
	kept := l.order[:0]
	for _, id := range l.order {
		a := l.byID[id]
		if a == nil {
			continue // ended and deleted
		}
		if a.lastMs < cutoffMs {
			delete(l.byID, id)
			continue
		}
		kept = append(kept, id)
	}
	l.order = kept
}
