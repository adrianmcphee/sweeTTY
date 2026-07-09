// Command sweetty is the honeypot entry point: it parses the CLI, runs the
// config subcommands, and otherwise loads the config and starts a listener per
// configured port.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"sweetty/internal/config"
	"sweetty/internal/event"
	"sweetty/internal/fakehost"
	"sweetty/internal/haproxy"
	"sweetty/internal/persona"
	"sweetty/internal/portal"
	"sweetty/internal/proto/adb"
	"sweetty/internal/proto/docker"
	"sweetty/internal/proto/ftp"
	httpproto "sweetty/internal/proto/http"
	"sweetty/internal/proto/https"
	"sweetty/internal/proto/mysql"
	"sweetty/internal/proto/redis"
	"sweetty/internal/proto/ssh"
	"sweetty/internal/proto/telnet"
	"sweetty/internal/server"
	"sweetty/internal/vfs"
)

// Build metadata, injected at release time via -ldflags -X (see the Makefile and
// .github/workflows/release.yml). The defaults are what a plain `go build`
// reports, so an unstamped dev build is labelled honestly.
var (
	version   = "dev"
	gitCommit = "none"
	buildDate = "unknown"
)

func main() {
	configPath := flag.String("config", "config.json", "path to config file")
	profileFlag := flag.String("profile", "", "service profile for init (web|edge|infra|legacy|ftp|full|random)")
	hapSocket := flag.String("haproxy-socket", "/run/haproxy/admin.sock", "HAProxy admin socket (hapwatch)")
	hapTable := flag.String("haproxy-table", "st_src", "HAProxy stick-table name (hapwatch)")
	floodThreshold := flag.Int("flood-threshold", 200, "new-connection rate that counts as a flood (hapwatch)")
	floodInterval := flag.Duration("flood-interval", 5*time.Second, "stick-table poll interval (hapwatch)")
	floodCooldown := flag.Duration("flood-cooldown", time.Minute, "per-source flood report cooldown (hapwatch)")
	flag.Parse()

	switch flag.Arg(0) {
	case "init":
		p := persona.GenerateProfile(*profileFlag)
		cfg := config.Generate(p)
		if err := config.Write(cfg, *configPath); err != nil {
			fatal("init", err)
		}
		personaPath := cfg.PersonaPath(*configPath)
		if err := persona.Save(p, personaPath); err != nil {
			fatal("init", err)
		}
		fmt.Printf("Wrote %s and %s\n", *configPath, personaPath)
		fmt.Printf("Instance: %s (%s profile, %s)\n", p.Hostname, p.Profile, p.PrettyName)
		fmt.Printf("Portal:   port %d\n", cfg.PortalPort)
		fmt.Print("Services: ")
		for i, lc := range cfg.Listeners {
			if i > 0 {
				fmt.Print(", ")
			}
			if lc.Persona != "" {
				fmt.Printf("%s/%d(%s)", lc.Protocol, lc.Port, lc.Persona)
			} else {
				fmt.Printf("%s/%d", lc.Protocol, lc.Port)
			}
		}
		fmt.Println()
		if hasProtocol(cfg.Listeners, "ssh") {
			// The SSH shell accepts only this instance's random password (never a
			// constant from the source), so the operator has to be told it to reach
			// or demo the shell. It also lives in persona.json.
			fmt.Printf("SSH login: root / %s   (also %s / %s)\n", p.RootPassword, p.Username, p.UserPassword)
		}
		fmt.Println("Next: ./sweetty")
	case "version":
		fmt.Printf("sweetty %s\n", version)
		fmt.Printf("  commit: %s\n", gitCommit)
		fmt.Printf("  built:  %s\n", buildDate)
		fmt.Printf("  go:     %s %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
	case "hapwatch":
		hapwatch(*configPath, *hapSocket, *hapTable, *floodThreshold, *floodInterval, *floodCooldown)
	case "":
		run(*configPath)
	default:
		fmt.Fprintln(os.Stderr, "unknown subcommand:", flag.Arg(0))
		fmt.Fprintln(os.Stderr, "usage: sweetty [-config path] [init|version|hapwatch]")
		os.Exit(2)
	}
}

// hapwatch polls the optional HAProxy edge's stick-table and logs a FLOOD_BLOCKED
// event whenever a source's new-connection rate crosses the flood threshold, so
// the edge's gentle rate-limiting surfaces in the same event stream the dashboard
// tails. It is a thin management-plane helper: it reads only HAProxy's local admin
// socket and writes only the event log, and systemd keeps it running alongside
// HAProxy. With no HAProxy edge (the direct topology) the socket is simply absent
// and it idles, retrying.
func hapwatch(configPath, socket, table string, threshold int, interval, cooldown time.Duration) {
	cfg, err := config.Load(configPath)
	if err != nil {
		fatal("config", err)
	}
	lg, err := event.New(cfg.LogFile)
	if err != nil {
		fatal("log", err)
	}
	defer lg.Close()

	w := haproxy.NewWatcher(threshold, cooldown)
	lg.System("hapwatch: watching HAProxy table %q for floods over %d conn/10s", table, threshold)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	failing := false
	for {
		srcs, qerr := haproxy.QueryStickTable(socket, table, 3*time.Second)
		if qerr != nil {
			if !failing {
				failing = true
				lg.System("hapwatch: HAProxy stick-table unreachable (%v); retrying", qerr)
			}
		} else {
			if failing {
				failing = false
				lg.System("hapwatch: HAProxy stick-table reachable again")
			}
			for _, s := range w.Flooding(srcs, time.Now()) {
				lg.FloodBlocked(s.IP, s.ConnRate)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func fatal(ctx string, err error) {
	fmt.Fprintln(os.Stderr, ctx+":", err)
	os.Exit(1)
}

// intOr / floatOr return def when the configured value is unset (non-positive),
// so a brute-force config that names only "enabled" still gets sane thresholds.
func intOr(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

func floatOr(v, def float64) float64 {
	if v <= 0 {
		return def
	}
	return v
}

// portalExposedToNetwork reports whether the portal is bound to a non-loopback
// address, exposing the dashboard and the console reverse proxy to anyone who can
// reach the bind. The portal has no application auth, so the intended posture is a
// loopback bind reached over the SSH tunnel; a non-loopback bind is a
// misconfiguration worth warning about loudly.
func portalExposedToNetwork(cfg config.Config) bool {
	switch cfg.PortalBind {
	case "127.0.0.1", "::1", "localhost":
		return false
	case "":
		return true // an empty bind listens on all interfaces
	}
	if ip := net.ParseIP(cfg.PortalBind); ip != nil && ip.IsLoopback() {
		return false
	}
	return true
}

// hasProtocol reports whether any configured listener runs the named protocol.
func hasProtocol(listeners []config.Listener, proto string) bool {
	for _, lc := range listeners {
		if lc.Protocol == proto {
			return true
		}
	}
	return false
}

// buildProtocol maps a listener's protocol name to an implementation, wiring in
// the instance persona and its virtual filesystem. Unknown protocols return nil;
// the caller logs a warning and skips the port. Cases are added as each protocol
// package lands.
func buildProtocol(lc config.Listener, p *persona.Persona, base *vfs.FS) server.Protocol {
	switch lc.Protocol {
	case "telnet":
		style := lc.Persona
		if style == "" {
			style = "ubuntu"
		}
		return telnet.New(base, p, style)
	case "ssh":
		// Persona "tarpit" selects the banner-and-tarpit SSH (zero crypto fingerprint,
		// no session); anything else is the interactive shell over SSH, which is the
		// default. The style otherwise feeds the shell prompt flavour.
		if lc.Persona == "tarpit" {
			return ssh.NewTarpit(p)
		}
		return ssh.New(base, p, lc.Persona)
	case "http":
		style := lc.Persona
		if style == "" {
			style = "nginx-static"
		}
		return httpproto.New(base, p, style)
	case "https":
		return https.New(p)
	case "ftp":
		return ftp.New(p)
	case "adb":
		return adb.New(base, p)
	case "redis":
		return redis.New(p)
	case "docker":
		return docker.New(p)
	case "mysql":
		return mysql.New(p)
	}
	return nil
}

func run(configPath string) {
	// Drop the syscalls the honeypot never needs but a memory-corruption RCE would
	// (exec, ptrace, module load), as the first thing the process does. On a kernel
	// that cannot install the filter, log and continue rather than leave the sensor
	// deaf: under systemd the SystemCallFilter sandbox still applies, and a honeypot
	// that refuses to start protects nothing.
	if err := lockdownSyscalls(); err != nil {
		fatal("seccomp lockdown", err)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		fatal("config", fmt.Errorf("%w (run `sweetty init` first)", err))
	}
	lg, err := event.New(cfg.LogFile)
	if err != nil {
		fatal("log", err)
	}
	defer lg.Close()

	personaPath := cfg.PersonaPath(configPath)
	p, err := persona.LoadOrCreate(personaPath)
	if err != nil {
		fatal("persona", err)
	}
	if cfg.BruteForce.Enabled {
		tries := intOr(cfg.BruteForce.AfterTries, 4)
		after := time.Duration(intOr(cfg.BruteForce.AfterSeconds, 45)) * time.Second
		prob := floatOr(cfg.BruteForce.Probability, 0.4)
		p.SetBruteForce(persona.BruteForceConfig{Enabled: true, AfterTries: tries, After: after, Probability: prob})
		lg.System("bruteforce: a source may be let in with the credential it tried after %d attempts and %s (p=%.2f)", tries, after, prob)
	}
	base, err := fakehost.Load(p)
	if err != nil {
		fatal("fakehost", err)
	}
	fmt.Printf("persona: %s %s (%s)\n", p.Hostname, p.HostIP, p.PrettyName)

	var servers []*server.Server
	// active records which configured ports actually bound, so the console can flag a
	// configured service that never came up (an open edge port with a dead backend).
	active := map[int]bool{}
	for _, lc := range cfg.Listeners {
		proto := buildProtocol(lc, p, base)
		if proto == nil {
			fmt.Fprintf(os.Stderr, "skip :%d unknown protocol %q\n", lc.Port, lc.Protocol)
			continue
		}
		srv := server.New(lc.Port, lg, proto)
		srv.ProxyProtocol = cfg.ProxyProtocol
		srv.SetTrustedProxies(cfg.ProxyTrustedCIDRs)
		srv.RecordDir = cfg.RecordDir
		if err := srv.Listen(); err != nil {
			fmt.Fprintf(os.Stderr, "skip :%d %v\n", lc.Port, err)
			continue
		}
		if lc.Persona != "" {
			fmt.Printf("listening :%d %s (%s)\n", lc.Port, proto.Name(), lc.Persona)
		} else {
			fmt.Printf("listening :%d %s\n", lc.Port, proto.Name())
		}
		active[lc.Port] = true
		servers = append(servers, srv)
	}

	if len(servers) == 0 {
		// No honeypot surface means the sensor is pointless; exit non-zero so the
		// supervisor (systemd Restart=on-failure) retries rather than leaving a live
		// but deaf process.
		lg.System("no listeners started; exiting")
		fmt.Fprintln(os.Stderr, "no listeners started")
		os.Exit(1)
	}

	if portalExposedToNetwork(cfg) {
		// The intended posture is a loopback bind reached over the SSH tunnel. The
		// portal has no application auth, so a non-loopback bind exposes the whole
		// dashboard and the console reverse proxy to anyone who can reach the port;
		// make the misconfiguration impossible to miss in both the log and on the
		// console.
		lg.System("WARNING: portal_bind=%q is not loopback; the dashboard and console proxy are exposed on the network with no authentication. Bind 127.0.0.1 and reach it over the SSH tunnel.", cfg.PortalBind)
		fmt.Fprintf(os.Stderr, "WARNING: portal exposed on the network (portal_bind=%q)\n", cfg.PortalBind)
	} else {
		pt := portal.New(cfg, lg)
		pt.SetVersion(version)
		pt.SetActiveListeners(active)
		go func() {
			if err := pt.Start(); err != nil {
				// The portal is observability, not the core sensor, so a bind failure is
				// logged loudly but does not take the listeners down.
				lg.System("portal failed to start: %v", err)
				fmt.Fprintf(os.Stderr, "portal: %v\n", err)
			}
		}()
	}
	fmt.Printf("portal listening :%d\n", cfg.PortalPort)

	// Run until a termination signal, then shut down cleanly: stop accepting new
	// connections and flush the log (via the deferred lg.Close), so SIGTERM from
	// systemd is a graceful exit rather than an abrupt kill that loses the final
	// writes.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	stop() // a second signal now force-kills, in case shutdown wedges
	lg.System("shutting down on signal; closing %d listeners", len(servers))
	for _, srv := range servers {
		srv.Close()
	}
}
