package shell

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func reconShell(t *testing.T) *Shell {
	t.Helper()
	p, fs := loadHost(t)
	return &Shell{p: p, fs: fs.NewSession("/root"), user: "root", expandBudget: maxExpandBytes}
}

// TestHashsumHashesRealContent proves sha256sum digests the actual file content, so
// the digest is coherent with what cat shows rather than a canned constant.
func TestHashsumHashesRealContent(t *testing.T) {
	sh := reconShell(t)
	data, err := sh.readFile(sh.fs.Resolve("/etc/passwd"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	want := hex.EncodeToString(sum[:]) + "  /etc/passwd\n"
	if got, _ := sh.cmdHashsum([]string{"sha256sum", "/etc/passwd"}); got != want {
		t.Errorf("sha256sum = %q, want %q", got, want)
	}
}

// TestPingResolvesAndReports proves ping produces a real-looking transcript and that
// an IP argument is shown as itself rather than re-resolved to something else.
func TestPingResolvesAndReports(t *testing.T) {
	sh := reconShell(t)
	out, code := sh.cmdPing([]string{"ping", "-c", "3", "8.8.8.8"})
	if code != 0 || !strings.Contains(out, "3 packets transmitted, 3 received") {
		t.Errorf("ping stats missing:\n%s", out)
	}
	if !strings.Contains(out, "from 8.8.8.8") {
		t.Errorf("ping of an IP must show that IP, not a re-resolved one:\n%s", out)
	}
}

// TestDigResolves proves dig returns an answer section with a resolved address.
func TestDigResolves(t *testing.T) {
	sh := reconShell(t)
	out, _ := sh.cmdResolve([]string{"dig", "example.com"})
	if !strings.Contains(out, "ANSWER SECTION") || !strings.Contains(out, "IN\tA") {
		t.Errorf("dig output missing an answer section:\n%s", out)
	}
}

// TestIdAndGroupsAgree proves id and groups render the same membership from the
// group file, and that id is no longer a fixed string that omits supplementary groups.
func TestIdAndGroupsAgree(t *testing.T) {
	sh := reconShell(t)
	id := sh.cmdId([]string{"id"})
	groupsOut, _ := sh.cmdGroups([]string{"groups"})
	for _, g := range strings.Fields(strings.TrimSpace(groupsOut)) {
		if !strings.Contains(id, "("+g+")") {
			t.Errorf("group %q from `groups` is missing from `id`:\nid=%s\ngroups=%s", g, id, groupsOut)
		}
	}
	if !strings.HasPrefix(id, "uid=0(root)") {
		t.Errorf("id for root should start uid=0(root): %s", id)
	}
}
