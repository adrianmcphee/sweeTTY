package shell

import (
	"strings"
	"testing"
)

func userShell(t *testing.T, user, cwd string) *Shell {
	t.Helper()
	p, fs := loadHost(t)
	home := "/root"
	if user != "root" {
		home = "/home/" + user
	}
	return &Shell{p: p, fs: fs.NewSession(cwd), user: user, env: map[string]string{"HOME": home, "USER": user}, expandBudget: maxExpandBytes}
}

// TestReadPermissionEnforced proves a non-root user is denied a root-only file like
// /etc/shadow while still reading world-readable files, and that becoming root (via
// the elevation path) then grants the read.
func TestReadPermissionEnforced(t *testing.T) {
	sh := userShell(t, "lowpriv", "/tmp")

	if out, code := sh.cmdCat([]string{"cat", "/etc/shadow"}); code == 0 || !strings.Contains(out, "Permission denied") {
		t.Errorf("non-root cat /etc/shadow should be denied, got (%q, %d)", out, code)
	}
	if out, code := sh.cmdCat([]string{"cat", "/etc/passwd"}); code != 0 || !strings.Contains(out, "root:") {
		t.Errorf("non-root cat /etc/passwd should work (world-readable), got (%q, %d)", out, code)
	}

	sh.becomeRoot()
	if out, code := sh.cmdCat([]string{"cat", "/etc/shadow"}); code != 0 || strings.Contains(out, "Permission denied") {
		t.Errorf("root cat /etc/shadow should work, got (%q, %d)", out, code)
	}
	if sh.user != "root" || sh.env["HOME"] != "/root" {
		t.Errorf("becomeRoot did not update the identity: user=%s home=%s", sh.user, sh.env["HOME"])
	}
}

// TestCanReadMatrix checks the permission predicate directly across the cases that
// matter: root reads all; a non-root user reads world-readable and files it owns,
// and is denied an owner-only file it does not own.
func TestCanReadMatrix(t *testing.T) {
	p, fs := loadHost(t)
	root := &Shell{p: p, fs: fs.NewSession("/"), user: "root"}
	user := &Shell{p: p, fs: fs.NewSession("/"), user: "bob"}

	shadow, err := user.fs.Stat("/etc/shadow")
	if err != nil {
		t.Fatal(err)
	}
	passwd, _ := user.fs.Stat("/etc/passwd")
	if !root.canRead(shadow) {
		t.Error("root must read /etc/shadow")
	}
	if user.canRead(shadow) {
		t.Error("non-owner non-root must not read 0640 /etc/shadow")
	}
	if !user.canRead(passwd) {
		t.Error("non-root must read world-readable /etc/passwd")
	}
}

// TestHistoryMergesFileAndSession proves history shows the ~/.bash_history prefix
// plus the commands run this session, so `history` and `cat ~/.bash_history` agree
// on the shared prefix and the session's own commands appear.
func TestHistoryMergesFileAndSession(t *testing.T) {
	sh := userShell(t, "root", "/root")
	sh.hist = []string{"uname -a", "cat /etc/shadow"}

	out, _ := sh.cmdHistory([]string{"history"})
	if !strings.Contains(out, "uname -a") || !strings.Contains(out, "cat /etc/shadow") {
		t.Errorf("history omits the session's own commands:\n%s", out)
	}
	if data, err := sh.fs.ReadFile("/root/.bash_history"); err == nil && len(data) > 0 {
		first := lines(string(data))[0]
		if !strings.Contains(out, first) {
			t.Errorf("history omits the ~/.bash_history prefix line %q:\n%s", first, out)
		}
	}
}
