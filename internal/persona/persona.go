// Package persona builds and persists a deployed instance's randomized identity.
// The fakeroot files in the repository are templates with placeholders; each
// instance materializes a concrete persona on first run and persists it
// (gitignored), so two instances look like different real hosts and neither
// matches the public source. The package depends only on the standard library.
package persona

import (
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	mrand "math/rand/v2"
	"os"
	"strings"
	"time"
)

// ServiceSpec is one fake service this instance exposes: a protocol on a port,
// with an optional persona style (the telnet shell flavour, the web stack, etc.).
type ServiceSpec struct {
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	Style    string `json:"style,omitempty"`
}

// Persona is a deployed instance's randomized identity. Only genuinely
// identifying values are randomized. Structural, widely-shared values (the Ubuntu
// version, the conventional "deploy" user) stay fixed because they match millions
// of real boxes and are not a honeypot signature. The software versions and the
// service set are randomized too, so the exact persona an instance wears is not
// predictable from this source.
type Persona struct {
	Hostname    string        `json:"hostname"`
	Domain      string        `json:"domain"`
	Username    string        `json:"username"`
	UserUID     int           `json:"user_uid"`
	PrettyName  string        `json:"pretty_name"`
	KernelRel   string        `json:"kernel_release"`
	KernelVer   string        `json:"kernel_version"`
	Arch        string        `json:"arch"`
	OpenSSHVer  string        `json:"openssh_version"`
	BusyBoxVer  string        `json:"busybox_version"`
	WPVer       string        `json:"wp_version"`
	TomcatVer   string        `json:"tomcat_version"`
	NginxVer    string        `json:"nginx_version"`
	ApacheVer   string        `json:"apache_version"`
	PHPVer      string        `json:"php_version"`
	FTPSoftware string        `json:"ftp_software"`
	FTPVer      string        `json:"ftp_version"`
	Profile     string        `json:"profile"`
	Services    []ServiceSpec `json:"services"`
	HostIP      string        `json:"host_ip"`
	GatewayIP   string        `json:"gateway_ip"`
	GatewayHost string        `json:"gateway_host"`
	DBHost      string        `json:"db_host"`
	DBIP        string        `json:"db_ip"`
	BackupHost  string        `json:"backup_host"`
	BackupIP    string        `json:"backup_ip"`
	MAC         string        `json:"mac"`
	MachineID   string        `json:"machine_id"`
	BootID      string        `json:"boot_id"`
	RootUUID    string        `json:"root_uuid"`
	BootUUID    string        `json:"boot_uuid"`
	RootPwHash  string        `json:"root_pw_hash"`
	UserPwHash  string        `json:"user_pw_hash"`
	// RootPassword and UserPassword are the plaintext credentials that actually log
	// in over SSH. They are generated per instance and persisted only in the
	// gitignored persona file, so the working credential is never a constant readable
	// from the source. They look like a careless human's weak password by design; the
	// box is meant to appear compromised. They are independent of the (uncrackable)
	// /etc/shadow hashes above, exactly like a real strong-hashed weak password.
	RootPassword string `json:"root_password"`
	UserPassword string `json:"user_password"`
	// SSHHostKeySeed is the 32-byte ed25519 seed (base64) for this instance's SSH
	// host key. It is persisted so the host key is stable across restarts; a
	// regenerated host key would trip every reconnecting client's known-hosts
	// warning. It never appears in the source.
	SSHHostKeySeed string   `json:"ssh_host_key_seed"`
	SSHKeyFP       string   `json:"ssh_host_key_fp"`
	KnownKey       string   `json:"known_host_key"`
	RootAuthKey    string   `json:"root_auth_key"`
	RootPrivKey    string   `json:"root_priv_key"`
	WPDBName       string   `json:"wp_db_name"`
	WPDBUser       string   `json:"wp_db_user"`
	WPDBPass       string   `json:"wp_db_pass"`
	WPSalts        []string `json:"wp_salts"`
	BootEpoch      int64    `json:"boot_epoch"`
	// LootPath is this instance's treasure directory on the backup/NAS host: an
	// obscure, alluring, per-instance-random path the breadcrumb trail leads to. It
	// is randomized so no two deployments share a location a scanner could
	// fingerprint, and it is threaded (via {{.LootPath}}) through every breadcrumb
	// — the NAS shell history, the backup script — so the trail stays coherent.
	// Nothing about the name hints at what viewing the files actually reveals.
	LootPath string `json:"loot_path"`

	// bf is the optional, in-memory "let a persistent guesser in" policy. It is not
	// part of the persisted identity (no json tag); it is wired up at startup from
	// the config via SetBruteForce and shared across the telnet and SSH services.
	bf *bruteForce
}

// Save writes the persona to path with mode 0600, overwriting an existing file.
func Save(p *Persona, path string) error {
	out, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0600)
}

// Uname renders the `uname -a` string from the persona for total coherence.
func (p *Persona) Uname() string {
	return fmt.Sprintf("Linux %s %s %s %s %s %s GNU/Linux",
		p.Hostname, p.KernelRel, p.KernelVer, p.Arch, p.Arch, p.Arch)
}

// Embedded reports whether this instance is an embedded/SBC device rather than an
// x86_64 server. Templates and the system-tool generators branch on it so the CPU,
// /proc/cpuinfo, /proc/version, and lscpu all read as ARM instead of contradicting
// the device role (a router/IoT/NAS hostname) with an Intel Xeon.
func (p *Persona) Embedded() bool { return p.Arch != "x86_64" }

// osImage returns the architecture and kernel identity for a profile. Server
// profiles run x86_64 Ubuntu; the legacy (IoT/router/SBC) profile runs the same
// Ubuntu release on 64-bit ARM — the common embedded-device shape (a Raspberry-Pi-
// class board) — so its CPU and kernel cohere as ARM rather than as a Xeon, while
// dpkg/systemd/os-release stay genuine (Ubuntu arm64 is a real, attacked target).
func osImage(profile string) (arch, kernelRel, kernelVer, pretty string) {
	arch = "x86_64"
	if profile == "legacy" {
		arch = "aarch64"
	}
	return arch, "5.15.0-105-generic", "#115-Ubuntu SMP Mon Apr 15 09:52:04 UTC 2024", "Ubuntu 22.04.4 LTS"
}

var (
	envPool = []string{"prod", "prod", "prod", "prd", "stg", "ops", "core"}
	// regionPool are datacenter / region tags real fleets fold into hostnames.
	regionPool = []string{"nyc1", "sfo3", "fra1", "lon1", "ams3", "sgp1", "syd1", "tor1", "use1", "usw2", "euw1", "apse1", "dc1", "dc3"}
	// codenamePool are theme names ops teams reach for (myth, stars, stacks), used
	// for hosts that wear a project name instead of a role.
	codenamePool = []string{"atlas", "orion", "vega", "rigel", "titan", "juno", "hermes", "nyx", "draco", "lyra", "kraken", "hydra", "nimbus", "cobalt", "onyx", "slate", "ember", "helios"}
	dbRoles      = []string{"db", "mysql", "pg", "data", "sql"}
	bkRoles      = []string{"backup", "bkp", "store", "nas", "vault", "archive"}
	domains      = []string{"ec2.internal", "internal", "lan", "corp", "local", "intranet"}

	opensshPool = []string{
		"OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
		"OpenSSH_8.9p1 Ubuntu-3ubuntu0.7",
		"OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
		"OpenSSH_8.9p1 Ubuntu-3ubuntu0.11",
	}
	busyboxPool = []string{"1.30.1", "1.31.1", "1.34.1", "1.35.0", "1.36.1"}
	wpPool      = []string{"6.2.5", "6.3.4", "6.4.3", "6.4.4", "6.5.2"}
	tomcatPool  = []string{"9.0.71", "9.0.83", "9.0.88", "10.1.18"}
	nginxPool   = []string{"1.18.0", "1.22.1", "1.24.0"}
	apachePool  = []string{"2.4.52", "2.4.57", "2.4.58"}
	phpPool     = []string{"7.4.33", "8.1.2", "8.1.27", "8.2.15"}
	// Versions Ubuntu 22.04 (jammy) actually ships, so the FTP banner co-varies
	// with the pinned distro instead of advertising a version no jammy package has
	// (which a package-version database would flag against the OpenSSH/Apache
	// Ubuntu banners).
	ftpVerPool = map[string][]string{
		"vsftpd":    {"3.0.5"},
		"proftpd":   {"1.3.7a"},
		"pure-ftpd": {"1.0.49"},
	}
)

type profileDef struct {
	name  string
	roles []string
	build func() []ServiceSpec
}

func httpStyle() string { return pick([]string{"wordpress", "tomcat", "nginx-static"}) }

func chance(pct int) bool { return mrand.IntN(100) < pct }

// profiles are the realistic host shapes an instance can take. Each picks a
// service subset, so the exact set of exposed services varies per instance.
var profiles = []profileDef{
	{"web", []string{"web", "app", "api", "www", "node"}, func() []ServiceSpec {
		s := []ServiceSpec{{"ssh", 22, ""}, {"http", 80, httpStyle()}, {"https", 443, ""}}
		if chance(40) {
			s = append(s, ServiceSpec{"http", 8080, "tomcat"})
		}
		return s
	}},
	{"edge", []string{"lb", "edge", "proxy", "gw", "rtr"}, func() []ServiceSpec {
		s := []ServiceSpec{{"http", 80, "nginx-static"}, {"https", 443, ""}}
		if chance(60) {
			s = append(s, ServiceSpec{"ssh", 22, ""})
		}
		if chance(25) {
			s = append(s, ServiceSpec{"telnet", 23, "cisco"})
		}
		return s
	}},
	{"infra", []string{"db", "cache", "data", "mq", "ns", "mail"}, func() []ServiceSpec {
		s := []ServiceSpec{{"ssh", 22, ""}}
		if chance(35) {
			s = append(s, ServiceSpec{"http", 80, httpStyle()})
		}
		return s
	}},
	{"legacy", []string{"dvr", "cam", "iot", "router", "nas", "device", "sensor"}, func() []ServiceSpec {
		// Ubuntu on ARM (a Pi-class board): a coherent login banner and full shell.
		// A BusyBox banner over this Ubuntu userland (dpkg/systemd present) never
		// added up, so the appliance wears Ubuntu end to end.
		style := "ubuntu"
		s := []ServiceSpec{{"telnet", 23, style}, {"http", 80, "nginx-static"}}
		if chance(40) {
			s = append(s, ServiceSpec{"ftp", 21, ""})
		}
		if chance(30) {
			s = append(s, ServiceSpec{"telnet", 2323, style})
		}
		return s
	}},
	{"ftp", []string{"ftp", "files", "store", "fileserver"}, func() []ServiceSpec {
		s := []ServiceSpec{{"ftp", 21, ""}, {"ssh", 22, ""}}
		if chance(30) {
			s = append(s, ServiceSpec{"http", 80, "nginx-static"})
		}
		return s
	}},
}

// Loot-path components. The container dirs are real auto-generated cruft a Linux
// fileserver accumulates (Btrfs/Timeshift .snapshots, Samba .recycle, ext4
// lost+found, freedesktop .Trash, .cache), so a stash buried in one reads as
// incidental rather than planted, and finding it takes real spelunking. The
// mounts are ones the NAS already exposes. The leaf is what makes it irresistible
// once found; the trailing token is per-instance so the path is never a constant.
// None of these names hint at the gag the files actually contain.
var (
	lootMounts     = []string{"/srv/backups", "/srv/backups", "/mnt/storage"}
	lootContainers = []string{".snapshots", ".recycle", "lost+found", ".Trash-1000", ".cache"}
	lootLeaves     = []string{"cold_wallet", "keystore", "seed_backup", "treasury", "offsite_keys", "master_keys", "kdbx_export", "crypto_cold"}
)

// makeLootPath builds this instance's obscure-but-alluring treasure directory.
func makeLootPath() string {
	leaf := pick(lootLeaves)
	if chance(45) {
		leaf = "." + leaf // a dot-stash takes one more step to surface
	}
	return pick(lootMounts) + "/" + pick(lootContainers) + "/" + leaf + "_" + randHex(2)
}

func pickProfile() profileDef { return profiles[mrand.IntN(len(profiles))] }

func profileByName(name string) (profileDef, bool) {
	for _, p := range profiles {
		if p.name == name {
			return p, true
		}
	}
	return profileDef{}, false
}

// fullServices exposes every protocol; useful for local testing of all services.
func fullServices() []ServiceSpec {
	return []ServiceSpec{
		{"ftp", 21, ""},
		{"ssh", 22, ""},
		{"telnet", 23, "ubuntu"},
		{"http", 80, "wordpress"},
		{"https", 443, ""},
		{"telnet", 2323, "ubuntu"},
		{"http", 8080, "tomcat"},
	}
}

// Generate builds a fresh randomized persona with a randomly chosen profile.
func Generate() *Persona { return GenerateProfile("") }

// GenerateProfile builds a persona for a named profile. An empty name or
// "random" picks a profile at random; "full" exposes every service; an unknown
// name falls back to random.
func GenerateProfile(name string) *Persona {
	var prof profileDef
	var services []ServiceSpec
	switch name {
	case "full":
		prof = pickProfile()
		prof.name = "full"
		services = fullServices()
	case "", "random":
		prof = pickProfile()
		services = prof.build()
	default:
		if pd, ok := profileByName(name); ok {
			prof = pd
		} else {
			prof = pickProfile()
		}
		services = prof.build()
	}
	role := pick(prof.roles)
	host := makeHostnameFromRole(prof.name, role)
	arch, kernelRel, kernelVer, pretty := osImage(prof.name)

	octet2 := pickInt([]int{0, 0, 1, 10, 16, 20, 30})
	var base string
	switch mrand.IntN(3) {
	case 0:
		base = fmt.Sprintf("10.%d.%d", octet2, mrand.IntN(254))
	case 1:
		base = fmt.Sprintf("172.%d.%d", 16+mrand.IntN(16), mrand.IntN(254))
	default:
		base = fmt.Sprintf("192.168.%d", mrand.IntN(254))
	}

	ftpSw := pick([]string{"vsftpd", "proftpd", "pure-ftpd"})

	p := &Persona{
		Hostname:     host,
		Domain:       pick(domains),
		Username:     "deploy",
		UserUID:      1000,
		PrettyName:   pretty,
		KernelRel:    kernelRel,
		KernelVer:    kernelVer,
		Arch:         arch,
		OpenSSHVer:   pick(opensshPool),
		BusyBoxVer:   pick(busyboxPool),
		WPVer:        pick(wpPool),
		TomcatVer:    pick(tomcatPool),
		NginxVer:     pick(nginxPool),
		ApacheVer:    pick(apachePool),
		PHPVer:       pick(phpPool),
		FTPSoftware:  ftpSw,
		FTPVer:       pick(ftpVerPool[ftpSw]),
		Profile:      prof.name,
		Services:     services,
		HostIP:       fmt.Sprintf("%s.%d", base, 4+mrand.IntN(60)),
		GatewayIP:    base + ".1",
		GatewayHost:  "gw-" + pick([]string{"core", "edge", "rtr"}) + fmt.Sprintf("-%02d", 1+mrand.IntN(4)),
		DBHost:       pick(dbRoles) + "-" + pick(envPool) + fmt.Sprintf("-%02d", 1+mrand.IntN(6)),
		DBIP:         fmt.Sprintf("%s.%d", base, 20+mrand.IntN(30)),
		BackupHost:   pick(bkRoles) + "-" + fmt.Sprintf("%02d", 1+mrand.IntN(6)),
		BackupIP:     fmt.Sprintf("%s.%d", base, 60+mrand.IntN(40)),
		MAC:          randMAC(),
		MachineID:    randHex(16),
		BootID:       randUUID(),
		RootUUID:     randUUID(),
		BootUUID:     randUUID(),
		RootPwHash:   fakeShadowHash(),
		UserPwHash:   fakeShadowHash(),
		RootPassword: weakPassword(host),
		UserPassword: weakPassword(host),
		SSHKeyFP:     "SHA256:" + randStdB64NoPad(32),
		KnownKey:     "AAAAC3NzaC1lZDI1NTE5AAAAI" + randStdB64NoPad(32),
		WPDBName:     "wp_" + pick([]string{"prod", "site", "live", "www", "blog"}),
		WPDBUser:     "wp_" + pick([]string{"user", "admin", "app", "prod"}),
		WPDBPass:     randPassword(18),
		WPSalts:      makeSalts(8),
		BootEpoch:    time.Now().Add(-time.Duration(7+mrand.IntN(110)) * 24 * time.Hour).Unix(),
		LootPath:     makeLootPath(),
	}
	p.RootAuthKey = fmt.Sprintf("ssh-ed25519 %s %s@%s", p.KnownKey, p.Username, p.Hostname)
	p.RootPrivKey = fakePrivKey()
	p.SSHHostKeySeed = base64.RawStdEncoding.EncodeToString(randBytes(ed25519.SeedSize))
	return p
}

// SSHHostKey rebuilds this instance's persistent ed25519 SSH host key from the
// persisted seed. The key is the same on every restart (the seed lives in the
// gitignored persona file), so a reconnecting attacker never sees a changed host
// key. An empty or malformed seed (an older persona generated before this field
// existed) returns an error, and the SSH service degrades to banner-and-tarpit
// rather than starting with an unstable key.
func (p *Persona) SSHHostKey() (ed25519.PrivateKey, error) {
	seed, err := base64.RawStdEncoding.DecodeString(p.SSHHostKeySeed)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("persona: invalid or missing ssh host key seed")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// Accept reports whether a username/password pair logs in over an interactive
// service. Only accounts that exist on this host can authenticate (root and the
// primary user), the way real PAM rejects an unknown user the same as a wrong
// password, and each takes its own per-instance random password. The caller logs
// every attempt regardless of the verdict; this only decides the verdict.
//
// Deliberately, no list of universally-common passwords is accepted here, so the
// only credential that opens an instance is the one random to that instance. The
// trade is that a credential-stuffing bot running a standard wordlist will not land
// a shell; it is still fully captured at the auth layer. Widening this to also
// accept a common-weak-password list (so bots get in and reveal their loaders) is a
// one-line change, kept out by default because the working credential is meant to
// be unpredictable per instance.
func (p *Persona) Accept(user, pass string) bool {
	// Constant-time compare so the accept decision leaks nothing through timing.
	// The credential is intentionally low-entropy and only opens the simulated
	// shell, so this is hygiene rather than a load-bearing defense, but it keeps the
	// auth path honest and free of a byte-by-byte early exit.
	switch user {
	case "root":
		return subtle.ConstantTimeCompare([]byte(pass), []byte(p.RootPassword)) == 1
	case p.Username:
		return subtle.ConstantTimeCompare([]byte(pass), []byte(p.UserPassword)) == 1
	default:
		return false
	}
}

// knownUser reports whether name is one of the two accounts that exist on this
// host, the way real PAM rejects an unknown user regardless of password.
func (p *Persona) knownUser(name string) bool {
	return name == "root" || name == p.Username
}

// SetBruteForce installs the optional "let a persistent guesser in" policy. With
// it unset (the default), AcceptFrom behaves exactly like Accept. Call it once at
// startup before any service uses the persona; it is not safe to change live.
func (p *Persona) SetBruteForce(cfg BruteForceConfig) {
	if !cfg.Enabled {
		p.bf = nil
		return
	}
	p.bf = &bruteForce{cfg: cfg, src: map[string]*srcAuth{}}
}

// AcceptFrom is Accept plus the optional brute-force policy. The real per-instance
// credential always wins. Otherwise, when the policy is enabled and the attempt
// targets a real account, a source that has tried hard enough may be let in with
// the credential it just offered (and that credential is then remembered for it).
// It returns whether the login is accepted and whether it was a brute-force accept
// rather than the real password, so the caller can log the distinction. srcIP
// scopes the policy per source so one persistent attacker cannot crack the box
// open for everyone.
func (p *Persona) AcceptFrom(srcIP, user, pass string) (accepted, bruteForced bool) {
	if p.Accept(user, pass) {
		return true, false
	}
	if p.bf == nil {
		return false, false
	}
	// An appliance persona ships with well-known factory default credentials, the
	// way real IoT/edge devices do and the way Mirai-class loaders get in. For that
	// device class, accept the known defaults outright: it is accurate for the
	// hardware rather than a honeypot tell, and it walks a loader straight to a
	// shell where its next stage can be captured. (Counts as a normal accept, not a
	// brute-force one, because the device genuinely has these credentials.)
	if p.isAppliance() && isApplianceDefaultCred(user, pass) {
		return true, false
	}
	if !p.knownUser(user) {
		return false, false
	}
	if p.bf.consider(srcIP, user, pass) {
		return true, true
	}
	return false, false
}

// isAppliance reports whether this persona impersonates an IoT/edge device (the
// legacy profile, an ARM appliance) rather than a server.
func (p *Persona) isAppliance() bool { return p.Profile == "legacy" }

// IsAppliance is the exported gate for callers outside this package: the shell
// tailors its menu-escape handling to whether the host is an IoT/edge device.
func (p *Persona) IsAppliance() bool { return p.isAppliance() }

// applianceRootDefaults are factory default root passwords real IoT/edge devices
// ship with, the corpus Mirai-class loaders spray. Accepting these on an appliance
// persona is accurate for the hardware, not a tell.
var applianceRootDefaults = map[string]bool{
	"root": true, "admin": true, "password": true, "pass": true, "default": true,
	"1234": true, "12345": true, "123456": true, "1111": true, "0000": true,
	"888888": true, "666666": true, "54321": true, "vizxv": true, "xc3511": true,
	"xmhdipc": true, "juantech": true, "system": true, "realtek": true,
	"klv123": true, "service": true, "supervisor": true, "guest": true,
	"7ujMko0vizxv": true, "7ujMko0admin": true, "ikwb": true, "dreambox": true,
	"meinsm": true, "hi3518": true, "anko": true, "zlxx.": true,
}

// isApplianceDefaultCred reports whether user/pass is a known factory default for
// the appliance persona's root account. Restricted to root, the account that
// exists on the device, so an accepted login stays coherent with /etc/passwd.
func isApplianceDefaultCred(user, pass string) bool {
	return user == "root" && applianceRootDefaults[pass]
}

// makeHostnameFromRole builds a believable per-instance hostname. It draws from
// several naming "schools" real fleets use rather than one template, so there is
// no shared shape to fingerprint as the sweetty default, over a wide vocabulary
// so two instances rarely collide. Appliances (the legacy profile) get
// device-style names; servers get fleet-style ones. The role anchors most names
// to the host's job.
func makeHostnameFromRole(profile, role string) string {
	if profile == "legacy" {
		return makeApplianceHostname(role)
	}
	return makeServerHostname(role)
}

// makeServerHostname names a server the way a real ops team would, picking among
// corporate role/env, region-coded, cloud-default ip-in-name, themed codename,
// and scale-set node shapes.
func makeServerHostname(role string) string {
	env := pick(envPool)
	switch mrand.IntN(8) {
	case 0:
		return fmt.Sprintf("%s-%s-%02d", role, env, 1+mrand.IntN(12)) // api-prod-04
	case 1:
		return fmt.Sprintf("%s%s%02d", env, role, 1+mrand.IntN(9)) // prodapi07
	case 2:
		return fmt.Sprintf("%s-%s-%02d", pick(regionPool), role, 1+mrand.IntN(12)) // nyc1-api-04
	case 3:
		return fmt.Sprintf("%s-%s%d", env, role, 1+mrand.IntN(6)) // prod-api3
	case 4:
		return fmt.Sprintf("ip-10-%d-%d-%d", mrand.IntN(64), mrand.IntN(254), 1+mrand.IntN(253)) // ip-10-40-2-13
	case 5:
		c := pick(codenamePool)
		if chance(55) {
			return fmt.Sprintf("%s-%02d", c, 1+mrand.IntN(9)) // orion-03
		}
		return c // atlas
	case 6:
		return fmt.Sprintf("%s-%s-pool%d-%s", env, role, 1+mrand.IntN(3), randHex(2)) // prod-api-pool1-9f3a
	default:
		return fmt.Sprintf("%s-%02d", role, 1+mrand.IntN(20)) // api-16 (plain, now rare)
	}
}

// makeApplianceHostname names a consumer/edge appliance (DVR, camera, router,
// NAS) the way its firmware would: a short model-ish tag with a serial or hex
// suffix, not a datacenter name.
func makeApplianceHostname(role string) string {
	up := strings.ToUpper(role)
	switch mrand.IntN(4) {
	case 0:
		return fmt.Sprintf("%s-%s", up, strings.ToUpper(randHex(2))) // DVR-3F9A
	case 1:
		return fmt.Sprintf("%s%04d", up, mrand.IntN(10000)) // CAM0451
	case 2:
		return fmt.Sprintf("%s-%02d", role, 1+mrand.IntN(20)) // router-07
	default:
		return fmt.Sprintf("%s-%s", role, randHex(3)) // nas-9f3a1c
	}
}

// ---- persistence ----

// LoadOrCreate reads the instance persona from path, generating and persisting a
// new one only on a genuine first run (file absent). The persona file is
// gitignored, so the instance identity never lives in source. If the file exists
// but is unreadable or invalid, it refuses to clobber it and returns an error: a
// silently regenerated identity would hand a reconnecting attacker a changed SSH
// host key (a loud client warning) and break cross-session log correlation.
func LoadOrCreate(path string) (*Persona, error) {
	data, err := os.ReadFile(path)
	switch {
	case err == nil && len(strings.TrimSpace(string(data))) > 0:
		var p Persona
		if jerr := json.Unmarshal(data, &p); jerr == nil && p.Hostname != "" {
			return &p, nil
		}
		return nil, fmt.Errorf("persona file %s exists but is invalid; refusing to overwrite the instance identity (move it aside to regenerate)", path)
	case err != nil && !os.IsNotExist(err):
		return nil, fmt.Errorf("read persona %s: %w", path, err)
	}
	// Genuinely first run (the file is absent or empty): generate and persist it
	// atomically, so an interrupted write can never leave a half-file that the
	// refuse-to-clobber path above would then reject on the next start.
	p := Generate()
	out, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return nil, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, 0600); err != nil {
		return nil, err
	}
	// WriteFile only sets the mode when it creates the file; a stale tmp left loose
	// by an interrupted run would keep its old perms, so pin 0600 explicitly before
	// the rename exposes it as the persona (which holds the SSH host key seed).
	if err := os.Chmod(tmp, 0600); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return nil, err
	}
	return p, nil
}

// ---- random helpers ----

const cryptAlphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
const passAlphabet = "0123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := crand.Read(b); err != nil {
		for i := range b {
			b[i] = byte(mrand.IntN(256))
		}
	}
	return b
}

func randHex(nBytes int) string { return hex.EncodeToString(randBytes(nBytes)) }

func randStdB64NoPad(nBytes int) string {
	return base64.RawStdEncoding.EncodeToString(randBytes(nBytes))
}

func randFromAlphabet(alphabet string, n int) string {
	b := randBytes(n)
	out := make([]byte, n)
	for i := range b {
		out[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(out)
}

func fakeShadowHash() string {
	return "$6$" + randFromAlphabet(cryptAlphabet, 16) + "$" + randFromAlphabet(cryptAlphabet, 86)
}

func randPassword(n int) string { return randFromAlphabet(passAlphabet, n) }

var (
	pwWords = []string{
		"admin", "server", "welcome", "password", "root", "login", "linux",
		"ubuntu", "backup", "support", "manager", "office", "secure", "master",
		"system", "service", "default", "changeme", "letmein", "access",
		"cluster", "deploy", "passw0rd", "monitor", "console", "network",
	}
	pwSeps = []string{"", "", "", "@", "#", "_", "-", "."}
)

// weakPassword builds a human-looking but per-instance-random password, so the
// working credential resembles what a careless operator would set yet is never a
// constant readable from the source. Shapes look like "Server2023", "backup@4471",
// or "Welcome_88!". It sometimes builds off this host's own name ("Prodiot2024"),
// the way an admin reaches for something in front of them. It is intentionally
// weak: the host is meant to look already compromised, but no two instances share
// the same one.
func weakPassword(host string) string {
	w := pwWords[mrand.IntN(len(pwWords))]
	if h := hostnameBase(host); h != "" && chance(30) {
		w = h
	}
	if chance(50) {
		w = strings.ToUpper(w[:1]) + w[1:]
	}
	sep := pwSeps[mrand.IntN(len(pwSeps))]
	digits := 2 + mrand.IntN(3) // 2..4 digits
	var num strings.Builder
	for range digits {
		num.WriteByte(byte('0' + mrand.IntN(10)))
	}
	pw := w + sep + num.String()
	if chance(20) {
		pw += "!"
	}
	return pw
}

// hostnameBase returns the leading alphabetic run of a hostname ("web-prod-03" ->
// "web", "prodiot04" -> "prodiot"), a believable base for a hostname-derived
// password. It returns "" if the name does not start with a letter, or if that
// run is shorter than three letters: an "ip"- or "db"-style stub makes a poor,
// telling password word, so the caller falls back to its word list.
func hostnameBase(host string) string {
	i := 0
	for i < len(host) {
		c := host[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
			break
		}
		i++
	}
	if i < 3 {
		return ""
	}
	return strings.ToLower(host[:i])
}

func makeSalts(n int) []string {
	s := make([]string, n)
	for i := range s {
		s[i] = randFromAlphabet(cryptAlphabet+"!@#$%^&*()-_ +=,.;:", 64)
	}
	return s
}

func randUUID() string {
	b := randBytes(16)
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func randMAC() string {
	b := randBytes(5)
	// Locally-administered / cloud-style prefix.
	prefix := pick([]string{"0a", "02", "06", "0e"})
	return fmt.Sprintf("%s:%02x:%02x:%02x:%02x:%02x", prefix, b[0], b[1], b[2], b[3], b[4])
}

func fakePrivKey() string {
	var sb strings.Builder
	sb.WriteString("-----BEGIN OPENSSH PRIVATE KEY-----\n")
	body := base64.StdEncoding.EncodeToString(randBytes(384))
	for i := 0; i < len(body); i += 70 {
		end := i + 70
		if end > len(body) {
			end = len(body)
		}
		sb.WriteString(body[i:end])
		sb.WriteByte('\n')
	}
	sb.WriteString("-----END OPENSSH PRIVATE KEY-----\n")
	return sb.String()
}

func pick(pool []string) string { return pool[mrand.IntN(len(pool))] }

func pickInt(pool []int) int { return pool[mrand.IntN(len(pool))] }
