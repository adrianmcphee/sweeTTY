// Package portal serves the management portal: a dark single-page dashboard over
// the honeypot's structured event log. It reads the same JSON log the listeners
// write, so it adds no new storage and stays a pure read side over the event
// stream. The portal binds loopback and serves plain HTTP with no application
// auth; it is reached over an SSH port-forward tunnel, so SSH key auth is the
// only front door and every dashboard route is served openly.
package portal

import (
	"embed"
	"encoding/json"
	"io"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"time"

	"sweetty/internal/config"
	"sweetty/internal/event"
	"sweetty/internal/geo"
)

// jtPrizeJPG is the celebratory portrait flashed in the console when a honeytoken
// is tripped (a JT reveal). It is embedded and served same-origin, so the console
// still references nothing off-host.
//
//go:embed jt-prize.jpg
var jtPrizeJPG []byte

// jtSplashFS holds the colour-ASCII JT boot splashes as compact palette + row
// run-length JSON (the libcaca portrait reduced to its colour grid), each stored
// gzipped and served with Content-Encoding: gzip so a portrait costs the binary and
// the wire under 20 KB and the browser paints it to a canvas. Drop another
// jt-splash-*.json.gz in beside these and it joins the rotation on the next build,
// one chosen at random per load.
//
//go:embed jt-splash-*.json.gz
var jtSplashFS embed.FS

// loadSplashes reads every embedded splash variant into memory once at startup.
func loadSplashes() [][]byte {
	entries, err := jtSplashFS.ReadDir(".")
	if err != nil {
		return nil
	}
	var out [][]byte
	for _, e := range entries {
		if b, err := jtSplashFS.ReadFile(e.Name()); err == nil {
			out = append(out, b)
		}
	}
	return out
}

// maxConcurrentSSE bounds live event-stream subscribers so they cannot exhaust
// file descriptors and goroutines. maxConcurrentWatch does the same for the live
// session-watch streams, which tail a cast file each.
const (
	maxConcurrentSSE   = 64
	maxConcurrentWatch = 32
)

// Portal holds the portal's dependencies. It is constructed by New and run by
// Start.
type Portal struct {
	cfg       config.Config
	logger    *event.Logger
	geo       *geo.Resolver
	consoles  map[string]*consoleEntry
	sseGate   chan struct{} // bounds concurrent SSE subscribers
	watchGate chan struct{} // bounds concurrent live session watchers
	splashes  [][]byte      // gzipped boot-splash variants, one picked at random per load
	version   string        // build version, shown in the console
}

// SetVersion records the build version string for display in the console.
func (p *Portal) SetVersion(v string) { p.version = v }

// New builds a Portal from the loaded config and the shared event logger. It does
// not bind a port; call Start for that. When the config names a country database,
// it is loaded here, in the portal plane only, so the honeypot listeners never
// touch it and the egress-deny posture is untouched.
func New(cfg config.Config, logger *event.Logger) *Portal {
	resolver := geo.NewResolver()
	if cfg.GeoIPFile != "" {
		if n, err := resolver.LoadCSV(cfg.GeoIPFile); err != nil {
			logger.System("portal: country database %q could not be loaded: %v", cfg.GeoIPFile, err)
		} else {
			logger.System("portal: country database loaded (%d ranges)", n)
		}
	}
	if cfg.AsnFile != "" {
		if n, err := resolver.LoadASN(cfg.AsnFile); err != nil {
			logger.System("portal: ASN database %q could not be loaded: %v", cfg.AsnFile, err)
		} else {
			logger.System("portal: ASN database loaded (%d ranges)", n)
		}
	}
	return &Portal{
		cfg:       cfg,
		logger:    logger,
		geo:       resolver,
		consoles:  buildConsoles(cfg, logger),
		sseGate:   make(chan struct{}, maxConcurrentSSE),
		watchGate: make(chan struct{}, maxConcurrentWatch),
		splashes:  loadSplashes(),
	}
}

// Start runs the HTTP server on the configured bind and port over plain HTTP. The
// portal binds loopback and is reached over an SSH tunnel that already encrypts,
// so it terminates no TLS of its own. It blocks until the server stops and
// returns its error.
func (p *Portal) Start() error {
	// Explicit timeouts so a slow-header/slow-body client (slowloris) cannot pin
	// portal goroutines. No WriteTimeout: the SSE event feed is a deliberately
	// long-lived response that a blanket write deadline would sever.
	srv := &http.Server{
		Addr:              addr(p.cfg.PortalBind, p.cfg.PortalPort),
		Handler:           p.engine(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	return srv.ListenAndServe()
}

// engine builds the request multiplexer with all routes wired. It is split out
// from Start so tests can exercise the handlers without binding a port. The routes
// carry no login gate: the portal binds loopback and is reached over the SSH
// tunnel, so SSH is the front door and every dashboard route is served openly. The
// mux is reached directly by the operator over that tunnel, so a handler reads the
// real TCP peer rather than a client-supplied X-Forwarded-For.
func (p *Portal) engine() http.Handler {
	mux := http.NewServeMux()
	// The {$} anchor keeps "/" an exact match rather than a catch-all subtree, so
	// an unknown path still returns 404 as it did before.
	mux.HandleFunc("GET /{$}", p.dashboardPage)
	mux.HandleFunc("GET /dashboard", p.dashboardPage)
	mux.HandleFunc("GET /dashboard/events", p.events)
	mux.HandleFunc("GET /dashboard/log", p.logQuery)
	mux.HandleFunc("GET /dashboard/honeytokens", p.honeytokens)
	mux.HandleFunc("GET /dashboard/payloads", p.payloads)
	mux.HandleFunc("GET /dashboard/overview", p.overview)
	mux.HandleFunc("GET /dashboard/consoles", p.consoleList)
	// The console reverse proxy answers every method under its mount, matching the
	// upstream it forwards to.
	mux.HandleFunc("/dashboard/console/", p.console)
	mux.HandleFunc("GET /dashboard/ip/{ip}", p.byIP)
	mux.HandleFunc("GET /dashboard/session/{id}", p.bySession)
	mux.HandleFunc("GET /dashboard/recordings", p.recordings)
	mux.HandleFunc("GET /dashboard/sessions/active", p.activeSessions)
	mux.HandleFunc("GET /dashboard/cast/{id}", p.cast)
	mux.HandleFunc("GET /dashboard/watch/{id}", p.watch)
	mux.HandleFunc("GET /dashboard/jt-prize.jpg", p.jtPrize)
	mux.HandleFunc("GET /dashboard/jt-splash", p.jtSplash)
	return recoverHandler(mux)
}

// recoverHandler turns a panic in any handler into a 500 rather than a dropped
// connection, so a single bad request cannot take the portal down. The proxy's
// http.ErrAbortHandler is deliberately re-raised for net/http's own connection
// teardown to handle.
func recoverHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				if rec == http.ErrAbortHandler {
					panic(rec)
				}
				w.WriteHeader(http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// writeJSON serialises v as the response body with the JSON content type and the
// given status. It mirrors the shape the dashboard's fetch calls expect.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeString writes a plain-text body with the given status.
func writeString(w http.ResponseWriter, status int, s string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, s)
}

// writeData writes a raw body with an explicit content type and status.
func writeData(w http.ResponseWriter, status int, contentType string, b []byte) {
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

// jtPrize serves the embedded celebration portrait for the honeytoken flash. It is
// static and cacheable, and reaches nothing off-host.
func (p *Portal) jtPrize(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=86400")
	writeData(w, http.StatusOK, "image/jpeg", jtPrizeJPG)
}

// jtSplash serves one of the colour-ASCII boot splashes, chosen at random per load
// so a refresh rotates the portrait. Each is stored gzipped and returned with
// Content-Encoding: gzip, which every browser transparently inflates, so the
// dashboard's fetch reads the HTML fragment directly. No-store, so the browser asks
// again each load and the rotation actually happens.
func (p *Portal) jtSplash(w http.ResponseWriter, _ *http.Request) {
	if len(p.splashes) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	pick := p.splashes[mrand.IntN(len(p.splashes))]
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Encoding", "gzip")
	writeData(w, http.StatusOK, "application/json; charset=utf-8", pick)
}

// addr renders the portal bind address. The default bind is loopback, so the
// portal is reachable only through the SSH tunnel; an empty bind means all
// interfaces. The port itself is randomized per instance in config.
func addr(bind string, port int) string {
	return net.JoinHostPort(bind, itoa(port))
}

// dashboardPage serves the single-page dashboard shell. All data is loaded by its
// inline JavaScript from the /dashboard JSON and SSE endpoints.
func (p *Portal) dashboardPage(w http.ResponseWriter, _ *http.Request) {
	writeData(w, http.StatusOK, "text/html; charset=utf-8", []byte(dashboardHTML))
}

// itoa renders a non-negative int without pulling in fmt for a hot path. Ports
// are always non-negative, so the negative case is not reached.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
