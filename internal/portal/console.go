package portal

import (
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"

	"sweetty/internal/config"
	"sweetty/internal/event"
)

// consoleMount is the path prefix under which operator consoles are reverse
// proxied. Like the rest of the dashboard, everything below it is reached over
// the same SSH tunnel as the portal.
const consoleMount = "/dashboard/console/"

// consoleEntry is one configured operator console: a display label and the
// reverse proxy that forwards requests to its fixed upstream.
type consoleEntry struct {
	name  string
	label string
	proxy *httputil.ReverseProxy
}

// buildConsoles turns the configured admin consoles into reverse proxies, keyed
// by name. A console whose target is missing, unparseable, or not on the local
// host is skipped with a logged warning, so a misconfiguration can never turn the
// portal into an open proxy onto the wider network. The targets come only from
// the operator's config, never from a request, so the operator reaches exactly
// the consoles the instance listed and nothing else.
func buildConsoles(cfg config.Config, logger *event.Logger) map[string]*consoleEntry {
	out := map[string]*consoleEntry{}
	for _, ac := range cfg.AdminConsoles {
		name := strings.TrimSpace(ac.Name)
		if name == "" || strings.ContainsAny(name, "/ ") {
			logger.System("portal: skipping admin console with invalid name %q", ac.Name)
			continue
		}
		target, err := url.Parse(strings.TrimSpace(ac.Target))
		if err != nil || target.Scheme == "" || target.Host == "" {
			logger.System("portal: skipping admin console %q with invalid target %q", name, ac.Target)
			continue
		}
		if !isLocalTarget(target.Hostname()) {
			logger.System("portal: refusing admin console %q: target %q is not on the local host", name, target.Host)
			continue
		}
		label := ac.Label
		if label == "" {
			label = name
		}
		out[name] = &consoleEntry{name: name, label: label, proxy: newConsoleProxy(name, target, ac.StripPrefix)}
		logger.System("portal: admin console %q proxied to %s", name, target.Redacted())
	}
	return out
}

// newConsoleProxy builds the reverse proxy for one console. The upstream scheme
// and host are fixed from the parsed target, so the request can never be steered
// to another host. By default the full external path is forwarded unchanged, so
// an upstream that emits absolute links (such as the HAProxy stats page) works
// when it is configured to serve under the console's mount path. With
// stripPrefix set, the mount prefix is removed first, for an upstream that only
// serves at its root.
func newConsoleProxy(name string, target *url.URL, stripPrefix bool) *httputil.ReverseProxy {
	prefix := consoleMount + name
	return &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			path := req.URL.Path
			if stripPrefix {
				path = strings.TrimPrefix(path, prefix)
			}
			req.URL.Path = singleJoiningSlash(target.Path, path)
			req.Host = target.Host
			// Never forward any portal-side credentials on to the upstream console;
			// the upstream is reached over the same SSH tunnel as the portal.
			req.Header.Del("Cookie")
			req.Header.Del("Authorization")
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte("console upstream unavailable"))
		},
	}
}

// console dispatches a request to the matching reverse proxy. The console name is
// the first path segment after the mount; a bare console path is redirected to a
// trailing slash so the upstream's relative links resolve under the mount instead
// of escaping it.
func (p *Portal) console(c *gin.Context) {
	rest := strings.TrimPrefix(c.Param("rest"), "/")
	name := rest
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		name = rest[:i]
	}
	entry := p.consoles[name]
	if entry == nil {
		c.String(http.StatusNotFound, "no such console")
		return
	}
	if c.Request.URL.Path == consoleMount+name {
		c.Redirect(http.StatusFound, consoleMount+name+"/")
		return
	}
	entry.proxy.ServeHTTP(c.Writer, c.Request)
}

// consoleList returns the configured consoles for the dashboard to render as
// links. It exposes only the name and label, never the upstream target.
func (p *Portal) consoleList(c *gin.Context) {
	type item struct {
		Name  string `json:"name"`
		Label string `json:"label"`
	}
	items := make([]item, 0, len(p.consoles))
	for _, e := range p.consoles {
		items = append(items, item{Name: e.name, Label: e.label})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	c.JSON(http.StatusOK, gin.H{"consoles": items})
}

// isLocalTarget reports whether a console upstream is on the local host. It
// allows "localhost" and any loopback or private address, and refuses anything
// else (including a hostname it cannot resolve to a private address), so the
// proxy stays a local-administration convenience and never a route to the
// internet.
func isLocalTarget(host string) bool {
	if host == "localhost" {
		return true
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return addr.IsLoopback() || addr.IsPrivate()
}

// singleJoiningSlash joins a and b with exactly one slash between them.
func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		if b == "" {
			return a
		}
		return a + "/" + b
	}
	return a + b
}
