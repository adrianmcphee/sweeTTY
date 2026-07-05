package shell

import (
	"encoding/base64"
	"strings"
	"testing"

	"sweetty/internal/fakehost"
	"sweetty/internal/persona"
	"sweetty/internal/server"
)

// TestInstalledPackagesAgreeWithDpkgAndWhich drives the package story through the
// shell, the way an attacker checking whether the box is real would: `dpkg -l`
// names installed packages, and the command binaries those packages imply resolve
// through PATH against the same VFS.
func TestInstalledPackagesAgreeWithDpkgAndWhich(t *testing.T) {
	p := persona.GenerateProfile("full")
	p.FSSeed = shellTestSeed(0x5a)
	fsys, err := fakehost.Load(p)
	if err != nil {
		t.Fatal(err)
	}

	out, code := RunOnceCaptured(shellTestSession(), fsys, p, "root", "ubuntu", nil, "dpkg -l")
	if code != 0 {
		t.Fatalf("dpkg -l exit = %d, output:\n%s", code, out)
	}
	installed := dpkgInstalled(out)
	if len(installed) < 6 {
		t.Fatalf("dpkg -l reported too few packages:\n%s", out)
	}

	probes := map[string][]string{
		"acl":                      {"getfacl", "setfacl"},
		"bash":                     {"bash"},
		"busybox":                  {"busybox"},
		"certbot":                  {"certbot"},
		"conntrack":                {"conntrack"},
		"coreutils":                {"ls", "cat", "stat"},
		"curl":                     {"curl"},
		"dnsmasq":                  {"dnsmasq"},
		"docker.io":                {"docker"},
		"dropbear":                 {"dropbear"},
		"goaccess":                 {"goaccess"},
		"haproxy":                  {"haproxy"},
		"jq":                       {"jq"},
		"keepalived":               {"keepalived"},
		"lftp":                     {"lftp"},
		"mysql-client":             {"mysql"},
		"nginx":                    {"nginx"},
		"nmap":                     {"nmap"},
		"openssh-server":           {"sshd"},
		"php-cli":                  {"php"},
		"php-fpm":                  {"php-fpm"},
		"prometheus-node-exporter": {"prometheus-node-exporter"},
		"redis-tools":              {"redis-cli"},
		"rsync":                    {"rsync"},
		"socat":                    {"socat"},
		"tcpdump":                  {"tcpdump"},
		"telnet":                   {"telnet"},
		"tftp":                     {"tftp"},
		"vsftpd":                   {"vsftpd"},
		"whois":                    {"whois"},
	}

	checked := 0
	vfsSession := fsys.NewSession("/")
	defer vfsSession.Release()
	for pkg := range installed {
		bins, ok := probes[pkg]
		if !ok {
			t.Fatalf("installed package %s has no attacker-facing which probe", pkg)
		}
		for _, bin := range bins {
			out, code := RunOnceCaptured(shellTestSession(), fsys, p, "root", "ubuntu", nil, "which "+bin)
			if code != 0 {
				t.Fatalf("package %s is installed but which %s failed with code %d", pkg, bin, code)
			}
			path := strings.TrimSpace(strings.ReplaceAll(out, "\r", ""))
			if !strings.HasSuffix(path, "/"+bin) {
				t.Fatalf("which %s returned %q for package %s", bin, path, pkg)
			}
			if _, err := vfsSession.Stat(path); err != nil {
				t.Fatalf("which %s returned %s, but stat failed: %v", bin, path, err)
			}
			checked++
		}
	}
	if checked < 6 {
		t.Fatalf("checked only %d package command mappings; dpkg output was:\n%s", checked, out)
	}
}

func dpkgInstalled(out string) map[string]bool {
	installed := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 5 && fields[0] == "ii" {
			installed[fields[1]] = true
		}
	}
	return installed
}

func shellTestSession() *server.Session {
	return &server.Session{SrcIP: "198.51.100.24"}
}

func shellTestSeed(fill byte) string {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = fill + byte(i)
	}
	return base64.RawStdEncoding.EncodeToString(seed)
}
