package fakehost

import (
	"bytes"
	"encoding/base64"
	"path"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"sweetty/internal/persona"
	"sweetty/internal/vfs"
)

// templatedFiles are the embedded files that carry persona placeholders. Each
// must render fully (no residual "{{") against any generated persona.
var templatedFiles = []string{
	"/etc/hostname",
	"/etc/hosts",
	"/etc/issue",
	"/etc/os-release",
	"/etc/shadow",
	"/etc/fstab",
	"/etc/machine-id",
	"/proc/version",
	"/root/.bash_history",
	"/root/.ssh/authorized_keys",
	"/root/.ssh/known_hosts",
	"/var/www/html/wp-config.php",
	"/home/deploy/scripts/backup.sh",
	"/var/log/auth.log",
	"/var/lib/dpkg/status",
	"/var/log/syslog",
	"/var/log/dpkg.log",
	"/home/deploy/.bash_history",
	"/home/deploy/.local/share/recently-used.xbel",
}

func TestLoadRendersInstanceIdentity(t *testing.T) {
	p := persona.Generate()
	fsys, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	sess := fsys.NewSession("/")

	host, err := sess.ReadFile("/etc/hostname")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(host)); got != p.Hostname {
		t.Fatalf("/etc/hostname = %q, want instance hostname %q", got, p.Hostname)
	}

	shadow, err := sess.ReadFile("/etc/shadow")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(shadow, []byte(p.RootPwHash)) {
		t.Fatal("/etc/shadow does not contain the generated root hash")
	}

	hosts, err := sess.ReadFile("/etc/hosts")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(hosts, []byte(p.HostIP)) || !bytes.Contains(hosts, []byte(p.DBHost)) {
		t.Fatal("/etc/hosts not rendered with instance addresses")
	}
}

func TestReleaseFilesRenderPersonaRelease(t *testing.T) {
	p := persona.Generate()
	fsys, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	sess := fsys.NewSession("/")

	osr, err := sess.ReadFile("/etc/os-release")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`PRETTY_NAME="` + p.PrettyName + `"`,
		`VERSION_ID="` + p.OSVersionID() + `"`,
		`VERSION_CODENAME=` + p.OSCodename(),
	} {
		if !bytes.Contains(osr, []byte(want)) {
			t.Fatalf("/etc/os-release missing %q:\n%s", want, osr)
		}
	}

	proc, err := sess.ReadFile("/proc/version")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{p.KernelRel, p.GCCPackage(), p.BinutilsVersion()} {
		if !bytes.Contains(proc, []byte(want)) {
			t.Fatalf("/proc/version missing %q:\n%s", want, proc)
		}
	}
}

func TestNASReleaseFileRendersPersonaRelease(t *testing.T) {
	p := persona.Generate()
	fsys, err := LoadNAS(p)
	if err != nil {
		t.Fatal(err)
	}
	sess := fsys.NewSession("/")
	osr, err := sess.ReadFile("/etc/os-release")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{p.PrettyName, p.OSVersionID(), p.OSCodename()} {
		if !bytes.Contains(osr, []byte(want)) {
			t.Fatalf("NAS /etc/os-release missing %q:\n%s", want, osr)
		}
	}
}

func TestNoResidualPlaceholders(t *testing.T) {
	p := persona.Generate()
	fsys, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	sess := fsys.NewSession("/")
	for _, path := range templatedFiles {
		b, err := sess.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if bytes.Contains(b, []byte("{{")) {
			t.Fatalf("%s still contains a template placeholder:\n%s", path, b)
		}
	}
}

func TestTwoInstancesDiffer(t *testing.T) {
	// Reading the source must not predict a live instance: two personas yield
	// different identities.
	a := persona.Generate()
	b := persona.Generate()
	if a.Hostname == b.Hostname && a.HostIP == b.HostIP && a.RootPwHash == b.RootPwHash {
		t.Fatal("two generated personas are identical; identity is not randomized")
	}
}

func TestPopulationVariesPerInstance(t *testing.T) {
	a := seededPersona("web", 0x11)
	b := *a
	b.FSSeed = encodedSeed(0x99)

	fsa, err := Load(a)
	if err != nil {
		t.Fatal(err)
	}
	fsb, err := Load(&b)
	if err != nil {
		t.Fatal(err)
	}
	sa := fsa.NewSession("/")
	defer sa.Release()
	sb := fsb.NewSession("/")
	defer sb.Release()

	statusA, err := sa.ReadFile("/var/lib/dpkg/status")
	if err != nil {
		t.Fatal(err)
	}
	statusB, err := sb.ReadFile("/var/lib/dpkg/status")
	if err != nil {
		t.Fatal(err)
	}
	syslogA, err := sa.ReadFile("/var/log/syslog")
	if err != nil {
		t.Fatal(err)
	}
	syslogB, err := sb.ReadFile("/var/log/syslog")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(statusA, statusB) && bytes.Equal(syslogA, syslogB) {
		t.Fatal("different FSSeed values produced identical generated package and log content")
	}
}

func TestPopulationIsStableWithinInstance(t *testing.T) {
	p := seededPersona("infra", 0x42)
	a, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	sa := snapshotPopulation(t, a, p)
	sb := snapshotPopulation(t, b, p)
	if !reflect.DeepEqual(sa, sb) {
		t.Fatalf("population changed between loads:\nfirst=%#v\nsecond=%#v", sa, sb)
	}
}

func TestPopulatedMtimesFollowBootEpoch(t *testing.T) {
	p := seededPersona("ftp", 0x25)
	fsys, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	sess := fsys.NewSession("/")
	defer sess.Release()
	boot := time.Unix(p.BootEpoch, 0)
	now := time.Now().Add(time.Second)
	for _, path := range populatedPaths(p) {
		n, err := sess.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		if n.Mtime().Before(boot) || n.Mtime().After(now) {
			t.Errorf("%s mtime %s is outside boot window [%s, %s]", path, n.Mtime(), boot, now)
		}
	}
}

func TestHomeClutterOwnedByUser(t *testing.T) {
	p := seededPersona("web", 0x73)
	fsys, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	sess := fsys.NewSession("/")
	defer sess.Release()

	for _, path := range []string{
		"/home/" + p.Username + "/.bash_history",
		"/home/" + p.Username + "/.cache",
		"/home/" + p.Username + "/.cache/pip",
		"/home/" + p.Username + "/.local",
		"/home/" + p.Username + "/.local/share/recently-used.xbel",
		"/home/" + p.Username + "/.ssh/known_hosts",
	} {
		assertOwner(t, sess, path, p.UserUID, p.UserUID, p.Username, p.Username)
	}
	for _, path := range []string{"/root/.bash_history", "/root/.cache", "/root/.cache/motd.legal-displayed"} {
		assertOwner(t, sess, path, 0, 0, "root", "root")
	}
}

type populationSnap struct {
	body  string
	mode  uint32
	uid   int
	gid   int
	uname string
	gname string
	mtime int64
	size  int64
}

func snapshotPopulation(t *testing.T, fsys *vfs.FS, p *persona.Persona) map[string]populationSnap {
	t.Helper()
	sess := fsys.NewSession("/")
	defer sess.Release()
	out := map[string]populationSnap{}
	for _, path := range populatedPaths(p) {
		n, err := sess.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		var body []byte
		if !n.IsDir() {
			body, err = sess.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
		}
		out[path] = populationSnap{
			body: string(body), mode: uint32(n.Mode()), uid: n.Uid(), gid: n.Gid(),
			uname: n.Uname(), gname: n.Gname(), mtime: n.Mtime().UnixNano(), size: n.Size(),
		}
	}
	return out
}

func populatedPaths(p *persona.Persona) []string {
	return []string{
		"/var/lib/dpkg/status",
		"/var/log/syslog",
		"/var/log/syslog.1",
		"/var/log/auth.log",
		"/var/log/auth.log.1",
		"/var/log/dpkg.log",
		"/var/log/nginx/access.log",
		"/home/" + p.Username + "/.bash_history",
		"/home/" + p.Username + "/.cache/motd.legal-displayed",
		"/home/" + p.Username + "/.local/share/recently-used.xbel",
		"/home/" + p.Username + "/.ssh/known_hosts",
		"/root/.bash_history",
		"/root/.cache/motd.legal-displayed",
	}
}

func assertOwner(t *testing.T, sess *vfs.Session, path string, uid, gid int, uname, gname string) {
	t.Helper()
	n, err := sess.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if n.Uid() != uid || n.Gid() != gid || n.Uname() != uname || n.Gname() != gname {
		t.Fatalf("%s owner = %d:%d %s:%s, want %d:%d %s:%s", path, n.Uid(), n.Gid(), n.Uname(), n.Gname(), uid, gid, uname, gname)
	}
}

func seededPersona(profile string, fill byte) *persona.Persona {
	p := persona.GenerateProfile(profile)
	p.FSSeed = encodedSeed(fill)
	return p
}

func encodedSeed(fill byte) string {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = fill + byte(i)
	}
	return base64.RawStdEncoding.EncodeToString(seed)
}

// TestOwnershipMatchesPasswdAndGroup walks every node in the rendered filesystem
// and proves its numeric uid/gid agrees with the symbolic owner name, resolved
// through /etc/passwd and /etc/group. `stat` prints both the number and the name
// on one line (Uid: ( 33/www-data)), so a node owned by uid 0 but named "www-data",
// or grouped "shadow" while numerically 0, is a single-command tell. It also
// catches an owner name that no /etc/passwd entry backs (e.g. a group referenced
// but missing from /etc/group).
func TestOwnershipMatchesPasswdAndGroup(t *testing.T) {
	p := persona.Generate()
	fsys, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	sess := fsys.NewSession("/")
	uidByName := idTable(t, sess, "/etc/passwd")
	gidByName := idTable(t, sess, "/etc/group")

	var walk func(dir string)
	walk = func(dir string) {
		entries, err := sess.ReadDir(dir)
		if err != nil {
			return
		}
		for _, n := range entries {
			p := path.Join(dir, n.Name())
			if uid, ok := uidByName[n.Uname()]; !ok {
				t.Errorf("%s is owned by user %q, which has no /etc/passwd entry", p, n.Uname())
			} else if uid != n.Uid() {
				t.Errorf("%s: numeric uid %d but owner name %q is uid %d in /etc/passwd", p, n.Uid(), n.Uname(), uid)
			}
			if gid, ok := gidByName[n.Gname()]; !ok {
				t.Errorf("%s is grouped %q, which has no /etc/group entry", p, n.Gname())
			} else if gid != n.Gid() {
				t.Errorf("%s: numeric gid %d but group name %q is gid %d in /etc/group", p, n.Gid(), n.Gname(), gid)
			}
			if n.IsDir() && !n.IsLink() {
				walk(p)
			}
		}
	}
	walk("/")
}

// idTable parses a passwd/group-style file into a name->id map (field 0 -> field 2).
func idTable(t *testing.T, sess *vfs.Session, file string) map[string]int {
	t.Helper()
	data, err := sess.ReadFile(file)
	if err != nil {
		t.Fatalf("read %s: %v", file, err)
	}
	out := map[string]int{}
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) < 3 {
			continue
		}
		if id, err := strconv.Atoi(f[2]); err == nil {
			out[f[0]] = id
		}
	}
	return out
}

func TestCoherentOwnershipAndModes(t *testing.T) {
	p := persona.Generate()
	fsys, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	sess := fsys.NewSession("/")

	// A root shell can read its own shadow and key; both exist and are tight.
	shadow, _ := sess.Stat("/etc/shadow")
	if shadow == nil || shadow.Mode().Perm() != 0o640 {
		t.Fatalf("/etc/shadow mode wrong: %v", shadow)
	}
	root, _ := sess.Stat("/root")
	if root == nil || root.Mode().Perm() != 0o700 {
		t.Fatalf("/root mode wrong: %v", root)
	}
	// www-data owns the web root.
	www, _ := sess.Stat("/var/www/html")
	if www == nil || www.Uname() != "www-data" {
		t.Fatalf("/var/www/html owner wrong: %v", www)
	}
	// /bin resolves through the usr-merge symlink to a populated /usr/bin.
	bash, err := sess.Stat("/bin/bash")
	if err != nil || bash == nil {
		t.Fatalf("/bin/bash not resolvable via symlink: %v", err)
	}
}
