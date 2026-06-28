// Package portal serves the management portal: a dark single-page dashboard over
// the honeypot's structured event log. It reads the same JSON log the listeners
// write, so it adds no new storage and stays a pure read side over the event
// stream. The portal binds loopback and serves plain HTTP with no application
// auth; it is reached over an SSH port-forward tunnel, so SSH key auth is the
// only front door and every dashboard route is served openly.
package portal

import (
	"net"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"sweetty/internal/config"
	"sweetty/internal/event"
	"sweetty/internal/geo"
)

// maxConcurrentSSE bounds live event-stream subscribers so they cannot exhaust
// file descriptors and goroutines.
const maxConcurrentSSE = 64

// Portal holds the portal's dependencies. It is constructed by New and run by
// Start.
type Portal struct {
	cfg      config.Config
	logger   *event.Logger
	geo      *geo.Resolver
	consoles map[string]*consoleEntry
	sseGate  chan struct{} // bounds concurrent SSE subscribers
}

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
	return &Portal{
		cfg:      cfg,
		logger:   logger,
		geo:      resolver,
		consoles: buildConsoles(cfg, logger),
		sseGate:  make(chan struct{}, maxConcurrentSSE),
	}
}

// Start runs the gin server on the configured bind and port over plain HTTP. The
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

// engine builds the gin router with all routes wired. It is split out from Start
// so tests can exercise the handlers without binding a port.
func (p *Portal) engine() *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	// Trust no proxies: the portal is reached directly by the operator over the
	// SSH tunnel, so c.ClientIP() returns the real TCP peer rather than a
	// client-supplied X-Forwarded-For.
	_ = r.SetTrustedProxies(nil)
	r.Use(gin.Recovery())

	// No application auth: the portal binds loopback and is reached only through
	// the authenticated SSH tunnel, so SSH is the front door. Serve the dashboard
	// and every data route directly.
	r.GET("/", p.dashboardPage)
	p.dashRoutes(r.Group("/dashboard"))
	return r
}

// dashRoutes wires the read side of the dashboard onto a group. The portal binds
// loopback and is reached over the SSH tunnel, so the routes carry no login gate.
func (p *Portal) dashRoutes(dash *gin.RouterGroup) {
	dash.GET("", p.dashboardPage)
	dash.GET("/events", p.events)
	dash.GET("/log", p.logQuery)
	dash.GET("/honeytokens", p.honeytokens)
	dash.GET("/overview", p.overview)
	dash.GET("/consoles", p.consoleList)
	dash.Any("/console/*rest", p.console)
	dash.GET("/ip/:ip", p.byIP)
	dash.GET("/session/:id", p.bySession)
	dash.GET("/recordings", p.recordings)
	dash.GET("/cast/:id", p.cast)
}

// addr renders the portal bind address. The default bind is loopback, so the
// portal is reachable only through the SSH tunnel; an empty bind means all
// interfaces. The port itself is randomized per instance in config.
func addr(bind string, port int) string {
	return net.JoinHostPort(bind, itoa(port))
}

// dashboardPage serves the single-page dashboard shell. All data is loaded by its
// inline JavaScript from the /dashboard JSON and SSE endpoints.
func (p *Portal) dashboardPage(c *gin.Context) {
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(dashboardHTML))
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
