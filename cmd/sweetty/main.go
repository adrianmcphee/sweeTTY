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
	"path/filepath"
	"runtime"
	"syscall"

	"sweetty/internal/config"
	"sweetty/internal/event"
	"sweetty/internal/fakehost"
	"sweetty/internal/persona"
	"sweetty/internal/portal"
	"sweetty/internal/proto/ftp"
	httpproto "sweetty/internal/proto/http"
	"sweetty/internal/proto/https"
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
	flag.Parse()

	switch flag.Arg(0) {
	case "init":
		p := persona.GenerateProfile(*profileFlag)
		cfg := config.Generate(p)
		if err := config.Write(cfg, *configPath); err != nil {
			fatal("init", err)
		}
		personaPath := filepath.Join(filepath.Dir(*configPath), "persona.json")
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
	case "":
		run(*configPath)
	default:
		fmt.Fprintln(os.Stderr, "unknown subcommand:", flag.Arg(0))
		fmt.Fprintln(os.Stderr, "usage: sweetty [-config path] [init|version]")
		os.Exit(2)
	}
}

func fatal(ctx string, err error) {
	fmt.Fprintln(os.Stderr, ctx+":", err)
	os.Exit(1)
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
		return httpproto.New(p, style)
	case "https":
		return https.New(p)
	case "ftp":
		return ftp.New(p)
	}
	return nil
}

func run(configPath string) {
	cfg, err := config.Load(configPath)
	if err != nil {
		fatal("config", fmt.Errorf("%w (run `sweetty init` first)", err))
	}
	lg, err := event.New(cfg.LogFile)
	if err != nil {
		fatal("log", err)
	}
	defer lg.Close()

	personaPath := filepath.Join(filepath.Dir(configPath), "persona.json")
	p, err := persona.LoadOrCreate(personaPath)
	if err != nil {
		fatal("persona", err)
	}
	base, err := fakehost.Load(p)
	if err != nil {
		fatal("fakehost", err)
	}
	fmt.Printf("persona: %s %s (%s)\n", p.Hostname, p.HostIP, p.PrettyName)

	var servers []*server.Server
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
	}

	pt := portal.New(cfg, lg)
	go func() {
		if err := pt.Start(); err != nil {
			// The portal is observability, not the core sensor, so a bind failure is
			// logged loudly but does not take the listeners down.
			lg.System("portal failed to start: %v", err)
			fmt.Fprintf(os.Stderr, "portal: %v\n", err)
		}
	}()
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
