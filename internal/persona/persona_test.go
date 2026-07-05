package persona

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

var validProtocols = map[string]bool{
	"adb": true, "ftp": true, "ssh": true, "telnet": true, "http": true, "https": true, "redis": true,
}

func TestGenerateIsComplete(t *testing.T) {
	p := Generate()
	for name, v := range map[string]string{
		"hostname": p.Hostname, "host_ip": p.HostIP, "profile": p.Profile,
		"openssh": p.OpenSSHVer, "busybox": p.BusyBoxVer, "wp": p.WPVer,
		"tomcat": p.TomcatVer, "nginx": p.NginxVer, "php": p.PHPVer,
		"ftp_software": p.FTPSoftware, "ftp_version": p.FTPVer, "redis": p.RedisVer,
		"root_hash": p.RootPwHash, "ssh_fp": p.SSHKeyFP, "machine_id": p.MachineID,
		"fs_seed": p.FSSeed,
	} {
		if v == "" {
			t.Errorf("persona field %q is empty", name)
		}
	}
	if len(p.Services) == 0 {
		t.Fatal("persona has no services")
	}
	for _, s := range p.Services {
		if !validProtocols[s.Protocol] {
			t.Errorf("invalid service protocol %q", s.Protocol)
		}
		if s.Port <= 0 || s.Port > 65535 {
			t.Errorf("invalid service port %d", s.Port)
		}
	}
	if !strings.Contains(p.Uname(), p.Hostname) || !strings.Contains(p.Uname(), p.Arch) {
		t.Errorf("uname incoherent: %q", p.Uname())
	}
}

func TestFSSeedIsPopulatedAndVaries(t *testing.T) {
	const n = 16
	seen := map[string]bool{}
	for range n {
		p := Generate()
		seed, err := base64.RawStdEncoding.DecodeString(p.FSSeed)
		if err != nil {
			t.Fatalf("FSSeed is not raw base64: %v", err)
		}
		if len(seed) != 32 {
			t.Fatalf("FSSeed decodes to %d bytes, want 32", len(seed))
		}
		seen[p.FSSeed] = true
	}
	if len(seen) != n {
		t.Fatalf("FSSeed repeated across %d generations: saw %d distinct values", n, len(seen))
	}
}

func TestGenerateProfileFullHasEveryProtocol(t *testing.T) {
	p := GenerateProfile("full")
	if p.Profile != "full" {
		t.Fatalf("profile = %q", p.Profile)
	}
	seen := map[string]bool{}
	for _, s := range p.Services {
		seen[s.Protocol] = true
	}
	for _, proto := range []string{"adb", "ftp", "ssh", "telnet", "http", "https", "redis"} {
		if !seen[proto] {
			t.Errorf("full profile missing %s", proto)
		}
	}
}

func TestLegacyProfileExposesADB(t *testing.T) {
	p := GenerateProfile("legacy")
	for _, s := range p.Services {
		if s.Protocol == "adb" && s.Port == 5555 {
			return
		}
	}
	t.Fatalf("legacy profile should expose ADB on 5555, services: %+v", p.Services)
}

func TestInfraProfileExposesRedis(t *testing.T) {
	p := GenerateProfile("infra")
	for _, s := range p.Services {
		if s.Protocol == "redis" && s.Port == 6379 {
			return
		}
	}
	t.Fatalf("infra profile should expose Redis on 6379, services: %+v", p.Services)
}

func TestGenerateProfileNamed(t *testing.T) {
	p := GenerateProfile("web")
	if p.Profile != "web" {
		t.Fatalf("profile = %q, want web", p.Profile)
	}
	seen := map[string]bool{}
	for _, s := range p.Services {
		seen[s.Protocol] = true
	}
	if !seen["http"] || !seen["https"] || !seen["ssh"] {
		t.Errorf("web profile missing a core service: %v", seen)
	}
}

func TestUnknownProfileFallsBackToRandom(t *testing.T) {
	p := GenerateProfile("not-a-real-profile")
	if p.Profile == "" || len(p.Services) == 0 {
		t.Fatal("fallback persona is incomplete")
	}
}

func TestTwoPersonasDiffer(t *testing.T) {
	a, b := Generate(), Generate()
	if a.Hostname == b.Hostname && a.HostIP == b.HostIP && a.RootPwHash == b.RootPwHash && a.MachineID == b.MachineID {
		t.Fatal("two generated personas are identical; identity is not randomized")
	}
}

func TestProfileVarietyAcrossRuns(t *testing.T) {
	// Over many generations we should see more than one profile, proving the
	// service set is not fixed.
	seen := map[string]bool{}
	for range 50 {
		seen[Generate().Profile] = true
	}
	if len(seen) < 2 {
		t.Fatalf("only saw profiles %v across 50 runs; not varied", seen)
	}
}

// TestEveryIdentityFieldVaries proves that no identifying field is pinned to a
// constant. Every field must vary across generations; the high-entropy fields
// (hashes, UUIDs, keys, salts) must be unique across all generations.
func TestEveryIdentityFieldVaries(t *testing.T) {
	const N = 20
	ps := make([]*Persona, N)
	for i := range ps {
		ps[i] = Generate()
	}

	distinct := func(get func(*Persona) string) int {
		set := map[string]bool{}
		for _, p := range ps {
			set[get(p)] = true
		}
		return len(set)
	}

	// These must vary (more than one observed value) but may collide.
	varyOnly := map[string]func(*Persona) string{
		"MAC":       func(p *Persona) string { return p.MAC },
		"MachineID": func(p *Persona) string { return p.MachineID },
		"HostIP":    func(p *Persona) string { return p.HostIP },
		"WPDBPass":  func(p *Persona) string { return p.WPDBPass },
		"BootEpoch": func(p *Persona) string { return fmt.Sprintf("%d", p.BootEpoch) },
	}
	for name, get := range varyOnly {
		if n := distinct(get); n < 2 {
			t.Errorf("field %s observed only %d distinct value(s) over %d gens; looks pinned", name, n, N)
		}
	}

	// High-entropy fields must be unique across every generation.
	allDistinct := map[string]func(*Persona) string{
		"SSHKeyFP":    func(p *Persona) string { return p.SSHKeyFP },
		"KnownKey":    func(p *Persona) string { return p.KnownKey },
		"RootAuthKey": func(p *Persona) string { return p.RootAuthKey },
		"RootPrivKey": func(p *Persona) string { return p.RootPrivKey },
		"BootID":      func(p *Persona) string { return p.BootID },
		"RootUUID":    func(p *Persona) string { return p.RootUUID },
		"BootUUID":    func(p *Persona) string { return p.BootUUID },
		"FSSeed":      func(p *Persona) string { return p.FSSeed },
		"RootPwHash":  func(p *Persona) string { return p.RootPwHash },
		"UserPwHash":  func(p *Persona) string { return p.UserPwHash },
	}
	for name, get := range allDistinct {
		if n := distinct(get); n != N {
			t.Errorf("high-entropy field %s has %d distinct values over %d gens; want all %d distinct", name, n, N, N)
		}
	}

	// Each WP salt index must be present and unique across every generation.
	saltCount := len(ps[0].WPSalts)
	if saltCount == 0 {
		t.Fatal("persona has no WP salts")
	}
	for idx := 0; idx < saltCount; idx++ {
		set := map[string]bool{}
		for _, p := range ps {
			if idx >= len(p.WPSalts) {
				t.Fatalf("persona missing WPSalts[%d]", idx)
			}
			set[p.WPSalts[idx]] = true
		}
		if len(set) != N {
			t.Errorf("WPSalts[%d] has %d distinct values over %d gens; want all %d distinct", idx, len(set), N, N)
		}
	}
}

// TestSoftwareVersionsVaryAndAreInPool proves the advertised software versions
// are randomized from their source pools and are not pinned to a single value.
func TestSoftwareVersionsVaryAndAreInPool(t *testing.T) {
	const N = 20
	fields := []struct {
		name string
		get  func(*Persona) string
		pool []string
	}{
		{"OpenSSHVer", func(p *Persona) string { return p.OpenSSHVer }, opensshPool},
		{"BusyBoxVer", func(p *Persona) string { return p.BusyBoxVer }, busyboxPool},
		{"WPVer", func(p *Persona) string { return p.WPVer }, wpPool},
		{"TomcatVer", func(p *Persona) string { return p.TomcatVer }, tomcatPool},
		{"NginxVer", func(p *Persona) string { return p.NginxVer }, nginxPool},
		{"ApacheVer", func(p *Persona) string { return p.ApacheVer }, apachePool},
		{"PHPVer", func(p *Persona) string { return p.PHPVer }, phpPool},
		{"RedisVer", func(p *Persona) string { return p.RedisVer }, redisPool},
	}
	ps := make([]*Persona, N)
	for i := range ps {
		ps[i] = Generate()
	}
	for _, f := range fields {
		poolSet := map[string]bool{}
		for _, v := range f.pool {
			poolSet[v] = true
		}
		seen := map[string]bool{}
		for _, p := range ps {
			v := f.get(p)
			if !poolSet[v] {
				t.Errorf("%s value %q is not a member of its source pool", f.name, v)
			}
			seen[v] = true
		}
		if len(seen) < 2 {
			t.Errorf("%s took only %d distinct value over %d gens; want >= 2", f.name, len(seen), N)
		}
	}
}

func TestOpenSSHVersionCarriesMatchingUbuntuRelease(t *testing.T) {
	for _, rel := range osReleasePool {
		p := &Persona{OpenSSHVer: rel.openSSH}
		if p.OSVersionID() != rel.version {
			t.Errorf("%s maps to VERSION_ID %q, want %q", rel.openSSH, p.OSVersionID(), rel.version)
		}
		if p.OSCodename() != rel.codename {
			t.Errorf("%s maps to codename %q, want %q", rel.openSSH, p.OSCodename(), rel.codename)
		}
		if p.GCCPackage() != rel.gccPkg || p.DigVersion() != rel.dig {
			t.Errorf("%s maps to incoherent tool versions: gcc=%q dig=%q", rel.openSSH, p.GCCPackage(), p.DigVersion())
		}
	}

	for range 80 {
		p := Generate()
		rel := osReleaseFor(p.OpenSSHVer)
		if p.PrettyName != rel.pretty {
			t.Fatalf("generated OpenSSH %q with PrettyName %q, want %q", p.OpenSSHVer, p.PrettyName, rel.pretty)
		}
		if p.KernelRel != rel.kernel {
			t.Fatalf("generated OpenSSH %q with kernel %q, want %q", p.OpenSSHVer, p.KernelRel, rel.kernel)
		}
	}
}
