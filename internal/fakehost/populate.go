package fakehost

import (
	"encoding/base64"
	"fmt"
	"io/fs"
	"math/rand/v2"
	"sort"
	"strings"
	"time"

	"sweetty/internal/persona"
	"sweetty/internal/vfs"
)

type populationPackage struct {
	Name        string
	Version     string
	Section     string
	Description string
	Binaries    []packageBinary
}

type packageBinary struct {
	Path string
	Size int64
}

// populate grafts this instance's generated filesystem population onto the base
// tree. The seed lives in persona.json, so packages, logs, and home clutter are
// stable across restarts while varying between deployed instances.
func populate(f *vfs.FS, p *persona.Persona) {
	r := seededRand(p)
	packages := packagePlan(p, r)
	placePackages(f, p, r, packages)
	placeLogs(f, p, r, packages)
	placeHomeClutter(f, p, r, packages)
}

func seededRand(p *persona.Persona) *rand.Rand {
	seed := seedBytes(p)
	return rand.New(rand.NewChaCha8(seed))
}

func seedBytes(p *persona.Persona) [32]byte {
	var seed [32]byte
	if b, err := base64.RawStdEncoding.DecodeString(p.FSSeed); err == nil && len(b) > 0 {
		copy(seed[:], b)
		if len(b) >= len(seed) {
			return seed
		}
	}
	source := p.MachineID + ":" + p.BootID + ":" + p.Hostname + ":" + p.Profile
	h := uint64(1469598103934665603)
	for i := range seed {
		for j := 0; j < len(source); j++ {
			h ^= uint64(source[j]) + uint64(i)
			h *= 1099511628211
		}
		seed[i] = byte(h >> uint((i%8)*8))
	}
	return seed
}

func packagePlan(p *persona.Persona, r *rand.Rand) []populationPackage {
	packages := basePackages(p)
	pool := profilePackagePool(p.Profile, p)
	if len(pool) == 0 {
		pool = profilePackagePool("web", p)
	}
	r.Shuffle(len(pool), func(i, j int) { pool[i], pool[j] = pool[j], pool[i] })
	target := 4
	if len(pool) > 4 {
		target += r.IntN(3)
	}
	if target > len(pool) {
		target = len(pool)
	}
	packages = append(packages, pool[:target]...)
	return dedupePackages(packages)
}

func basePackages(p *persona.Persona) []populationPackage {
	return []populationPackage{
		{
			Name: "bash", Version: bashVersion(p), Section: "shells",
			Description: "GNU Bourne Again SHell",
			Binaries:    []packageBinary{{Path: "/usr/bin/bash", Size: 1183448}},
		},
		{
			Name: "coreutils", Version: coreutilsVersion(p), Section: "utils",
			Description: "GNU core utilities",
			Binaries: []packageBinary{
				{Path: "/usr/bin/ls", Size: 142144},
				{Path: "/usr/bin/cat", Size: 35280},
				{Path: "/usr/bin/stat", Size: 80528},
			},
		},
		{
			Name: "curl", Version: curlVersion(p), Section: "web",
			Description: "command line tool for transferring data",
			Binaries:    []packageBinary{{Path: "/usr/bin/curl", Size: 280800}},
		},
		{
			Name: "nginx", Version: p.NginxVer + "-0ubuntu1", Section: "httpd",
			Description: "small, powerful, scalable web server",
			Binaries:    []packageBinary{{Path: "/usr/sbin/nginx", Size: 952440}},
		},
		{
			Name: "openssh-server", Version: opensshPackageVersion(p), Section: "net",
			Description: "secure shell server",
			Binaries:    []packageBinary{{Path: "/usr/sbin/sshd", Size: 887392}},
		},
	}
}

func profilePackagePool(profile string, p *persona.Persona) []populationPackage {
	pools := map[string][]populationPackage{
		"web": {
			{Name: "certbot", Version: "2.9.0-1", Section: "web", Description: "automatically configure HTTPS using Let's Encrypt", Binaries: []packageBinary{{Path: "/usr/bin/certbot", Size: 186512}}},
			{Name: "php-cli", Version: p.PHPVer + "-1ubuntu2", Section: "php", Description: "command-line interpreter for PHP", Binaries: []packageBinary{{Path: "/usr/bin/php", Size: 5520832}}},
			{Name: "php-fpm", Version: p.PHPVer + "-1ubuntu2", Section: "php", Description: "server-side HTML-embedded scripting language FPM", Binaries: []packageBinary{{Path: "/usr/sbin/php-fpm", Size: 4732128}}},
			{Name: "mysql-client", Version: "8.0.39-0ubuntu0.22.04.1", Section: "database", Description: "MySQL database client binaries", Binaries: []packageBinary{{Path: "/usr/bin/mysql", Size: 3728120}}},
			{Name: "redis-tools", Version: "5:7.0.15-1", Section: "database", Description: "Redis client utilities", Binaries: []packageBinary{{Path: "/usr/bin/redis-cli", Size: 862136}}},
			{Name: "goaccess", Version: "1:1.7-1", Section: "admin", Description: "real-time web log analyzer", Binaries: []packageBinary{{Path: "/usr/bin/goaccess", Size: 649104}}},
			{Name: "jq", Version: "1.6-2.1ubuntu3", Section: "utils", Description: "lightweight and flexible command-line JSON processor", Binaries: []packageBinary{{Path: "/usr/bin/jq", Size: 61352}}},
		},
		"infra": {
			{Name: "docker.io", Version: "24.0.7-0ubuntu2", Section: "admin", Description: "Linux container runtime", Binaries: []packageBinary{{Path: "/usr/bin/docker", Size: 32407288}}},
			{Name: "prometheus-node-exporter", Version: "1.7.0-1", Section: "net", Description: "Prometheus exporter for machine metrics", Binaries: []packageBinary{{Path: "/usr/bin/prometheus-node-exporter", Size: 11988240}}},
			{Name: "redis-tools", Version: "5:7.0.15-1", Section: "database", Description: "Redis client utilities", Binaries: []packageBinary{{Path: "/usr/bin/redis-cli", Size: 862136}}},
			{Name: "nmap", Version: "7.94+git20230807.3be01efb1+dfsg-3", Section: "net", Description: "network exploration tool", Binaries: []packageBinary{{Path: "/usr/bin/nmap", Size: 2890320}}},
			{Name: "tcpdump", Version: "4.99.4-3ubuntu4", Section: "net", Description: "command-line network traffic analyzer", Binaries: []packageBinary{{Path: "/usr/bin/tcpdump", Size: 1264120}}},
			{Name: "jq", Version: "1.6-2.1ubuntu3", Section: "utils", Description: "lightweight and flexible command-line JSON processor", Binaries: []packageBinary{{Path: "/usr/bin/jq", Size: 61352}}},
		},
		"ftp": {
			{Name: "lftp", Version: "4.9.2-2build2", Section: "net", Description: "sophisticated command-line FTP and HTTP client", Binaries: []packageBinary{{Path: "/usr/bin/lftp", Size: 906400}}},
			{Name: "rsync", Version: "3.2.7-1ubuntu1", Section: "net", Description: "fast, versatile remote file-copying tool", Binaries: []packageBinary{{Path: "/usr/bin/rsync", Size: 554848}}},
			{Name: "vsftpd", Version: "3.0.5-0ubuntu1", Section: "net", Description: "lightweight, efficient FTP server", Binaries: []packageBinary{{Path: "/usr/sbin/vsftpd", Size: 204472}}},
			{Name: "acl", Version: "2.3.2-1build1", Section: "utils", Description: "access control list utilities", Binaries: []packageBinary{{Path: "/usr/bin/getfacl", Size: 39832}, {Path: "/usr/bin/setfacl", Size: 43864}}},
			{Name: "whois", Version: "5.5.23", Section: "net", Description: "intelligent WHOIS client", Binaries: []packageBinary{{Path: "/usr/bin/whois", Size: 151416}}},
		},
		"edge": {
			{Name: "haproxy", Version: "2.8.5-1ubuntu3", Section: "net", Description: "fast and reliable load balancing reverse proxy", Binaries: []packageBinary{{Path: "/usr/sbin/haproxy", Size: 2472344}}},
			{Name: "tcpdump", Version: "4.99.4-3ubuntu4", Section: "net", Description: "command-line network traffic analyzer", Binaries: []packageBinary{{Path: "/usr/bin/tcpdump", Size: 1264120}}},
			{Name: "socat", Version: "1.7.4.4-2ubuntu2", Section: "net", Description: "multipurpose relay for bidirectional data transfer", Binaries: []packageBinary{{Path: "/usr/bin/socat", Size: 411096}}},
			{Name: "conntrack", Version: "1:1.4.8-1ubuntu1", Section: "net", Description: "connection tracking userspace tools", Binaries: []packageBinary{{Path: "/usr/sbin/conntrack", Size: 96704}}},
			{Name: "keepalived", Version: "1:2.2.8-1build2", Section: "admin", Description: "failover and monitoring daemon for LVS clusters", Binaries: []packageBinary{{Path: "/usr/sbin/keepalived", Size: 613464}}},
		},
		"legacy": {
			{Name: "busybox", Version: p.BusyBoxVer + "-1ubuntu1", Section: "utils", Description: "tiny utilities for small and embedded systems", Binaries: []packageBinary{{Path: "/usr/bin/busybox", Size: 1020320}}},
			{Name: "dropbear", Version: "2022.83-1", Section: "net", Description: "lightweight SSH2 server and client", Binaries: []packageBinary{{Path: "/usr/sbin/dropbear", Size: 432320}}},
			{Name: "dnsmasq", Version: "2.90-2", Section: "net", Description: "small caching DNS proxy and DHCP/TFTP server", Binaries: []packageBinary{{Path: "/usr/sbin/dnsmasq", Size: 523424}}},
			{Name: "tftp", Version: "0.17-23build1", Section: "net", Description: "Trivial File Transfer Protocol client", Binaries: []packageBinary{{Path: "/usr/bin/tftp", Size: 35680}}},
			{Name: "telnet", Version: "0.17+2.4-2", Section: "net", Description: "basic telnet client", Binaries: []packageBinary{{Path: "/usr/bin/telnet", Size: 77464}}},
		},
	}
	if profile == "full" {
		var all []populationPackage
		for _, name := range []string{"web", "infra", "ftp", "edge", "legacy"} {
			all = append(all, pools[name]...)
		}
		return all
	}
	return append([]populationPackage(nil), pools[profile]...)
}

func dedupePackages(in []populationPackage) []populationPackage {
	byName := map[string]populationPackage{}
	for _, pkg := range in {
		if existing, ok := byName[pkg.Name]; ok {
			existing.Binaries = mergeBinaries(existing.Binaries, pkg.Binaries)
			byName[pkg.Name] = existing
			continue
		}
		byName[pkg.Name] = pkg
	}
	out := make([]populationPackage, 0, len(byName))
	for _, pkg := range byName {
		out = append(out, pkg)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func mergeBinaries(a, b []packageBinary) []packageBinary {
	seen := map[string]bool{}
	out := make([]packageBinary, 0, len(a)+len(b))
	for _, bin := range append(a, b...) {
		if seen[bin.Path] {
			continue
		}
		seen[bin.Path] = true
		out = append(out, bin)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func placePackages(f *vfs.FS, p *persona.Persona, r *rand.Rand, packages []populationPackage) {
	for _, pkg := range packages {
		mtime := stableMTime(p, r, 24, 120)
		for _, bin := range pkg.Binaries {
			f.PlaceStub(bin.Path, bin.Size, 0o755, 0, 0, "root", "root", mtime)
		}
		for _, generated := range packageConfigFiles(pkg, p) {
			mkdirTreeOwned(f, parentPath(generated.path), 0o755, 0, 0, "root", "root", mtime)
			f.PlaceOwned(generated.path, []byte(generated.body), generated.mode, 0, 0, "root", "root", mtime)
		}
	}
	f.PlaceOwned("/var/lib/dpkg/status", []byte(dpkgStatus(packages, packageArch(p))), 0o644, 0, 0, "root", "root", stableMTime(p, r, 18, 96))
}

type generatedFile struct {
	path string
	body string
	mode fs.FileMode
}

func packageConfigFiles(pkg populationPackage, p *persona.Persona) []generatedFile {
	switch pkg.Name {
	case "certbot":
		return []generatedFile{
			{path: "/etc/letsencrypt/cli.ini", body: "agree-tos = true\nemail = admin@" + p.Domain + "\n", mode: 0o644},
			{path: "/etc/letsencrypt/renewal/" + p.Hostname + ".conf", body: "version = 2.9.0\narchive_dir = /etc/letsencrypt/archive/" + p.Hostname + "\n", mode: 0o644},
		}
	case "php-cli", "php-fpm":
		ver := phpMajorMinor(p)
		return []generatedFile{
			{path: "/etc/php/" + ver + "/cli/php.ini", body: "memory_limit = 256M\nupload_max_filesize = 32M\n", mode: 0o644},
		}
	case "docker.io":
		return []generatedFile{
			{path: "/etc/docker/daemon.json", body: "{\n  \"log-driver\": \"json-file\",\n  \"storage-driver\": \"overlay2\"\n}\n", mode: 0o644},
		}
	case "prometheus-node-exporter":
		return []generatedFile{
			{path: "/etc/default/prometheus-node-exporter", body: "ARGS=\"--collector.systemd --collector.filesystem.mount-points-exclude=^/(sys|proc|dev)($|/)\"\n", mode: 0o644},
		}
	case "vsftpd":
		return []generatedFile{
			{path: "/etc/vsftpd.conf", body: "listen=YES\nanonymous_enable=NO\nlocal_enable=YES\nwrite_enable=YES\n", mode: 0o644},
		}
	case "haproxy":
		return []generatedFile{
			{path: "/etc/haproxy/haproxy.cfg", body: "global\n    daemon\n    maxconn 2048\n\ndefaults\n    mode http\n    timeout connect 5s\n", mode: 0o644},
		}
	case "dropbear":
		return []generatedFile{
			{path: "/etc/dropbear/dropbear.conf", body: "DROPBEAR_PORT=22\nDROPBEAR_EXTRA_ARGS=\"-w\"\n", mode: 0o600},
		}
	}
	return nil
}

func dpkgStatus(packages []populationPackage, arch string) string {
	var b strings.Builder
	for _, pkg := range packages {
		fmt.Fprintf(&b, "Package: %s\n", pkg.Name)
		b.WriteString("Status: install ok installed\n")
		b.WriteString("Priority: optional\n")
		fmt.Fprintf(&b, "Section: %s\n", nonempty(pkg.Section, "utils"))
		fmt.Fprintf(&b, "Installed-Size: %d\n", installedSize(pkg))
		fmt.Fprintf(&b, "Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>\n")
		fmt.Fprintf(&b, "Architecture: %s\n", arch)
		fmt.Fprintf(&b, "Version: %s\n", pkg.Version)
		fmt.Fprintf(&b, "Description: %s\n", pkg.Description)
		b.WriteString(" .\n\n")
	}
	return b.String()
}

func installedSize(pkg populationPackage) int64 {
	size := int64(64)
	for _, bin := range pkg.Binaries {
		size += bin.Size / 1024
	}
	if size < 128 {
		size = 128
	}
	return size
}

func placeLogs(f *vfs.FS, p *persona.Persona, r *rand.Rand, packages []populationPackage) {
	syslogTimes := timeline(p, r, 5, 30, 3*time.Hour)
	syslog := []string{
		fmt.Sprintf("%s %s systemd[1]: Started Daily apt download activities.", syslogStamp(syslogTimes[0]), p.Hostname),
		fmt.Sprintf("%s %s CRON[%d]: pam_unix(cron:session): session opened for user root(uid=0)", syslogStamp(syslogTimes[1]), p.Hostname, 18000+r.IntN(9000)),
		fmt.Sprintf("%s %s rsyslogd: imuxsock: Acquired UNIX socket '/run/systemd/journal/syslog'.", syslogStamp(syslogTimes[2]), p.Hostname),
		fmt.Sprintf("%s %s systemd[1]: Started A high performance web server and a reverse proxy server.", syslogStamp(syslogTimes[3]), p.Hostname),
		fmt.Sprintf("%s %s CRON[%d]: pam_unix(cron:session): session closed for user root", syslogStamp(syslogTimes[4]), p.Hostname, 18000+r.IntN(9000)),
	}
	f.PlaceOwned("/var/log/syslog", []byte(strings.Join(syslog, "\n")+"\n"), 0o640, 0, 4, "root", "adm", syslogTimes[len(syslogTimes)-1])

	oldSyslogTimes := timeline(p, r, 4, 8, 4*time.Hour)
	oldSyslog := []string{
		fmt.Sprintf("%s %s kernel: [    0.000000] Linux version %s", syslogStamp(oldSyslogTimes[0]), p.Hostname, p.KernelRel),
		fmt.Sprintf("%s %s systemd[1]: Started OpenSSH server daemon.", syslogStamp(oldSyslogTimes[1]), p.Hostname),
		fmt.Sprintf("%s %s systemd[1]: Reached target Multi-User System.", syslogStamp(oldSyslogTimes[2]), p.Hostname),
		fmt.Sprintf("%s %s systemd[1]: Started Network Name Resolution.", syslogStamp(oldSyslogTimes[3]), p.Hostname),
	}
	f.PlaceOwned("/var/log/syslog.1", []byte(strings.Join(oldSyslog, "\n")+"\n"), 0o640, 0, 4, "root", "adm", oldSyslogTimes[len(oldSyslogTimes)-1])

	authTimes := timeline(p, r, 6, 36, 45*time.Minute)
	attackerA := publicIP(r)
	attackerB := publicIP(r)
	auth := []string{
		fmt.Sprintf("%s %s sshd[%d]: Accepted publickey for %s from %s port %d ssh2: ED25519 SHA256:redacted", syslogStamp(authTimes[0]), p.Hostname, 23000+r.IntN(4000), p.Username, p.GatewayIP, 42000+r.IntN(20000)),
		fmt.Sprintf("%s %s sshd[%d]: pam_unix(sshd:session): session opened for user %s(uid=%d)", syslogStamp(authTimes[1]), p.Hostname, 23000+r.IntN(4000), p.Username, p.UserUID),
		fmt.Sprintf("%s %s sshd[%d]: Failed password for root from %s port %d ssh2", syslogStamp(authTimes[2]), p.Hostname, 26000+r.IntN(4000), attackerA, 35000+r.IntN(20000)),
		fmt.Sprintf("%s %s sshd[%d]: Failed password for invalid user admin from %s port %d ssh2", syslogStamp(authTimes[3]), p.Hostname, 26000+r.IntN(4000), attackerB, 35000+r.IntN(20000)),
		fmt.Sprintf("%s %s sudo:   %s : TTY=pts/0 ; PWD=/home/%s ; USER=root ; COMMAND=/usr/bin/systemctl reload nginx", syslogStamp(authTimes[4]), p.Hostname, p.Username, p.Username),
		fmt.Sprintf("%s %s sshd[%d]: Disconnected from authenticating user root %s port %d [preauth]", syslogStamp(authTimes[5]), p.Hostname, 26000+r.IntN(4000), attackerA, 35000+r.IntN(20000)),
	}
	f.PlaceOwned("/var/log/auth.log", []byte(strings.Join(auth, "\n")+"\n"), 0o640, 0, 4, "root", "adm", authTimes[len(authTimes)-1])

	oldAuthTimes := timeline(p, r, 3, 16, 2*time.Hour)
	oldAuth := []string{
		fmt.Sprintf("%s %s sshd[%d]: Accepted password for %s from %s port %d ssh2", syslogStamp(oldAuthTimes[0]), p.Hostname, 21000+r.IntN(3000), p.Username, p.GatewayIP, 39000+r.IntN(20000)),
		fmt.Sprintf("%s %s sudo:   %s : TTY=pts/0 ; PWD=/var/www/html ; USER=root ; COMMAND=/usr/bin/tail -f /var/log/nginx/access.log", syslogStamp(oldAuthTimes[1]), p.Hostname, p.Username),
		fmt.Sprintf("%s %s sshd[%d]: pam_unix(sshd:session): session closed for user %s", syslogStamp(oldAuthTimes[2]), p.Hostname, 21000+r.IntN(3000), p.Username),
	}
	f.PlaceOwned("/var/log/auth.log.1", []byte(strings.Join(oldAuth, "\n")+"\n"), 0o640, 0, 4, "root", "adm", oldAuthTimes[len(oldAuthTimes)-1])

	dpkgTimes := timeline(p, r, len(packages), 20, 11*time.Minute)
	var dpkgLines []string
	arch := packageArch(p)
	for i, pkg := range packages {
		dpkgLines = append(dpkgLines, fmt.Sprintf("%s install %s:%s <none> %s", dpkgTimes[i].Format("2006-01-02 15:04:05"), pkg.Name, arch, pkg.Version))
	}
	f.PlaceOwned("/var/log/dpkg.log", []byte(strings.Join(dpkgLines, "\n")+"\n"), 0o644, 0, 0, "root", "root", dpkgTimes[len(dpkgTimes)-1])

	accessTimes := timeline(p, r, 6, 40, 17*time.Minute)
	paths := []string{"/", "/wp-login.php", "/xmlrpc.php", "/.env", "/wp-config.php.bak", "/server-status"}
	agents := []string{"Mozilla/5.0", "curl/" + curlVersion(p), "python-requests/2.31.0", "Mozilla/5.0 (compatible; CensysInspect/1.1)"}
	var access []string
	for i, t := range accessTimes {
		status := 200
		if strings.Contains(paths[i%len(paths)], ".env") || strings.Contains(paths[i%len(paths)], "bak") {
			status = 404
		}
		if strings.Contains(paths[i%len(paths)], "server-status") {
			status = 403
		}
		access = append(access, fmt.Sprintf("%s - - [%s] \"GET %s HTTP/1.1\" %d %d \"-\" \"%s\"",
			publicIP(r), t.Format("02/Jan/2006:15:04:05 -0700"), paths[i%len(paths)], status, 128+r.IntN(6000), agents[r.IntN(len(agents))]))
	}
	f.PlaceOwned("/var/log/nginx/access.log", []byte(strings.Join(access, "\n")+"\n"), 0o640, 33, 4, "www-data", "adm", accessTimes[len(accessTimes)-1])
}

func placeHomeClutter(f *vfs.FS, p *persona.Persona, r *rand.Rand, packages []populationPackage) {
	user := p.Username
	home := "/home/" + user
	userMTime := stableMTime(p, r, 48, 132)
	project := projectName(p, r)
	mkdirTreeOwned(f, home+"/.cache", 0o700, p.UserUID, p.UserUID, user, user, userMTime)
	mkdirTreeOwned(f, home+"/.cache/pip/http", 0o700, p.UserUID, p.UserUID, user, user, userMTime)
	mkdirTreeOwned(f, home+"/.local/share", 0o700, p.UserUID, p.UserUID, user, user, userMTime)
	mkdirTreeOwned(f, home+"/.ssh", 0o700, p.UserUID, p.UserUID, user, user, userMTime)
	mkdirTreeOwned(f, home+"/projects/"+project, 0o755, p.UserUID, p.UserUID, user, user, userMTime)

	f.PlaceOwned(home+"/.cache/motd.legal-displayed", []byte{}, 0o600, p.UserUID, p.UserUID, user, user, stableMTime(p, r, 52, 138))
	f.PlaceOwned(home+"/.cache/pip/selfcheck", []byte(`{"last_check":"`+stableMTime(p, r, 58, 140).Format("2006-01-02T15:04:05Z07:00")+`","pypi_version":"24.0"}`+"\n"), 0o600, p.UserUID, p.UserUID, user, user, stableMTime(p, r, 58, 140))
	f.PlaceOwned(home+"/.local/share/recently-used.xbel", []byte(recentFilesXML(p, packages)), 0o600, p.UserUID, p.UserUID, user, user, stableMTime(p, r, 60, 145))
	f.PlaceOwned(home+"/.ssh/known_hosts", []byte(fmt.Sprintf("%s,%s ssh-ed25519 %s\n", p.BackupHost, p.BackupIP, p.KnownKey)), 0o644, p.UserUID, p.UserUID, user, user, stableMTime(p, r, 62, 146))
	f.PlaceOwned(home+"/.bash_history", []byte(userHistory(p, packages)), 0o600, p.UserUID, p.UserUID, user, user, stableMTime(p, r, 64, 148))
	f.PlaceOwned(home+"/projects/"+project+"/notes.txt", []byte(projectNotes(p)), 0o600, p.UserUID, p.UserUID, user, user, stableMTime(p, r, 70, 150))

	rootMTime := stableMTime(p, r, 50, 130)
	mkdirTreeOwned(f, "/root/.cache", 0o700, 0, 0, "root", "root", rootMTime)
	f.MkdirOwned("/root/.cache", 0o700, 0, 0, "root", "root", rootMTime)
	f.PlaceOwned("/root/.cache/motd.legal-displayed", []byte{}, 0o600, 0, 0, "root", "root", stableMTime(p, r, 54, 136))
	existing := existingFile(f, "/root/.bash_history")
	if len(existing) > 0 && existing[len(existing)-1] != '\n' {
		existing = append(existing, '\n')
	}
	existing = append(existing, []byte(rootHistoryTail(p, packages))...)
	f.PlaceOwned("/root/.bash_history", existing, 0o600, 0, 0, "root", "root", stableMTime(p, r, 66, 150))
}

func existingFile(f *vfs.FS, path string) []byte {
	sess := f.NewSession("/")
	defer sess.Release()
	data, err := sess.ReadFile(path)
	if err != nil {
		return nil
	}
	return append([]byte(nil), data...)
}

func userHistory(p *persona.Persona, packages []populationPackage) string {
	var b strings.Builder
	b.WriteString("ls -la\n")
	b.WriteString("cd /var/www/html\n")
	b.WriteString("git status\n")
	b.WriteString("tail -n 50 /var/log/nginx/access.log\n")
	b.WriteString("sudo systemctl status nginx\n")
	if hasPackage(packages, "mysql-client") {
		fmt.Fprintf(&b, "mysql -h %s -u %s -p %s\n", p.DBIP, p.WPDBUser, p.WPDBName)
	}
	if hasPackage(packages, "redis-tools") {
		b.WriteString("redis-cli -h 127.0.0.1 info\n")
	}
	fmt.Fprintf(&b, "ssh %s@%s\n", p.Username, p.BackupHost)
	b.WriteString("history\n")
	return b.String()
}

func rootHistoryTail(p *persona.Persona, packages []populationPackage) string {
	var lines []string
	if hasPackage(packages, "docker.io") {
		lines = append(lines, "docker ps")
	}
	if hasPackage(packages, "certbot") {
		lines = append(lines, "certbot certificates")
	}
	if hasPackage(packages, "tcpdump") {
		lines = append(lines, "tcpdump -ni any port 22")
	}
	lines = append(lines, "journalctl -u ssh --since today", "tail -n 100 /var/log/auth.log")
	return strings.Join(lines, "\n") + "\n"
}

func recentFilesXML(p *persona.Persona, packages []populationPackage) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString("<xbel version=\"1.0\">\n")
	fmt.Fprintf(&b, "  <bookmark href=\"file:///home/%s/scripts/backup.sh\"/>\n", p.Username)
	if hasPackage(packages, "haproxy") {
		b.WriteString("  <bookmark href=\"file:///etc/haproxy/haproxy.cfg\"/>\n")
	}
	if hasPackage(packages, "docker.io") {
		b.WriteString("  <bookmark href=\"file:///etc/docker/daemon.json\"/>\n")
	}
	b.WriteString("</xbel>\n")
	return b.String()
}

func projectNotes(p *persona.Persona) string {
	return fmt.Sprintf("backup host: %s\nweb root: /var/www/html\ndatabase host: %s\n", p.BackupHost, p.DBHost)
}

func hasPackage(packages []populationPackage, name string) bool {
	for _, pkg := range packages {
		if pkg.Name == name {
			return true
		}
	}
	return false
}

func timeline(p *persona.Persona, r *rand.Rand, count, minHour int, step time.Duration) []time.Time {
	if count <= 0 {
		return nil
	}
	start := stableMTime(p, r, minHour, minHour+24)
	out := make([]time.Time, count)
	for i := range out {
		out[i] = start.Add(time.Duration(i) * step)
	}
	return out
}

func stableMTime(p *persona.Persona, r *rand.Rand, minHour, maxHour int) time.Time {
	if maxHour < minHour {
		maxHour = minHour
	}
	hours := minHour
	if maxHour > minHour {
		hours += r.IntN(maxHour - minHour + 1)
	}
	t := time.Unix(p.BootEpoch, 0).UTC().Add(time.Duration(hours)*time.Hour + time.Duration(r.IntN(3600))*time.Second)
	now := time.Now().UTC()
	if t.After(now) {
		return now.Truncate(time.Second)
	}
	return t
}

func syslogStamp(t time.Time) string {
	return t.Format("Jan _2 15:04:05")
}

func publicIP(r *rand.Rand) string {
	prefixes := []string{"45.155.205", "80.66.83", "141.98.11", "185.220.101", "193.32.162", "92.255.85"}
	return fmt.Sprintf("%s.%d", prefixes[r.IntN(len(prefixes))], 2+r.IntN(240))
}

func mkdirTreeOwned(f *vfs.FS, path string, mode fs.FileMode, uid, gid int, uname, gname string, mtime time.Time) {
	path = strings.Trim(path, "/")
	if path == "" {
		return
	}
	cur := ""
	for _, part := range strings.Split(path, "/") {
		if part == "" {
			continue
		}
		cur += "/" + part
		if dirExists(f, cur) {
			continue
		}
		f.MkdirOwned(cur, mode, uid, gid, uname, gname, mtime)
	}
}

func dirExists(f *vfs.FS, path string) bool {
	sess := f.NewSession("/")
	defer sess.Release()
	n, err := sess.Stat(path)
	return err == nil && n.IsDir()
}

func parentPath(path string) string {
	path = strings.TrimRight(path, "/")
	if path == "" || path == "/" {
		return "/"
	}
	i := strings.LastIndex(path, "/")
	if i <= 0 {
		return "/"
	}
	return path[:i]
}

func projectName(p *persona.Persona, r *rand.Rand) string {
	names := []string{"siteops", "deploy-notes", "maintenance", p.Profile + "-runbook"}
	return names[r.IntN(len(names))]
}

func phpMajorMinor(p *persona.Persona) string {
	parts := strings.Split(p.PHPVer, ".")
	if len(parts) < 2 {
		return "8.1"
	}
	return parts[0] + "." + parts[1]
}

func packageArch(p *persona.Persona) string {
	if p.Embedded() {
		return "arm64"
	}
	return "amd64"
}

func nonempty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func bashVersion(p *persona.Persona) string {
	switch p.OSVersionID() {
	case "20.04":
		return "5.0-6ubuntu1.2"
	case "24.04":
		return "5.2.21-2ubuntu4"
	default:
		return "5.1-6ubuntu1"
	}
}

func coreutilsVersion(p *persona.Persona) string {
	switch p.OSVersionID() {
	case "20.04":
		return "8.30-3ubuntu2"
	case "24.04":
		return "9.4-3ubuntu6"
	default:
		return "8.32-4.1ubuntu1"
	}
}

func curlVersion(p *persona.Persona) string {
	switch p.OSVersionID() {
	case "20.04":
		return "7.68.0-1ubuntu2.22"
	case "24.04":
		return "8.5.0-2ubuntu10"
	default:
		return "7.81.0-1ubuntu1"
	}
}

func opensshPackageVersion(p *persona.Persona) string {
	v := strings.TrimPrefix(p.OpenSSHVer, "OpenSSH_")
	v = strings.Replace(v, " Ubuntu-", "-", 1)
	if v == p.OpenSSHVer {
		return "1:8.9p1-3ubuntu0"
	}
	return "1:" + v
}
