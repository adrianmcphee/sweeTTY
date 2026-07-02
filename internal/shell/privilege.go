package shell

import (
	"strings"

	"sweetty/internal/vfs"
)

// This file gives the shell a minimal but coherent privilege model. Before it,
// sudo re-ran the command as the same user (so `sudo whoami` said the invoking
// user, not root) and nothing enforced read permissions (so `cat /etc/shadow`
// dumped the hashes for any user), both easy tells for anyone who logged in as the
// unprivileged account.

// elevateShells are the sudo/su targets that hand back a root shell rather than run
// a single command, so `sudo -i`, `sudo su`, and `sudo bash` become root for the rest
// of the session.
var elevateShells = map[string]bool{"su": true, "bash": true, "sh": true, "-bash": true, "zsh": true}

// cmdSudo prompts for a password when the caller is not already root (capturing it
// as a credential), then runs the target command as root, or elevates the whole
// session to root for an interactive `sudo -i` / `sudo su`.
func (sh *Shell) cmdSudo(args []string, stdin string) (string, int) {
	i := 1
	interactive := false
	for i < len(args) {
		a := args[i]
		switch {
		case a == "-u" && i+1 < len(args):
			i += 2 // target user parsed but always root here; the honeypot models one privileged account
		case strings.HasPrefix(a, "-u"):
			i++
		case a == "-i" || a == "-s":
			interactive = true
			i++
		case strings.HasPrefix(a, "-"): // -E -H -k -n and friends
			i++
		default:
			goto done
		}
	}
done:
	cmd := args[i:]
	if sh.user != "root" {
		if pass, ok := sh.s.Prompt("[sudo] password for " + sh.user + ": "); ok {
			sh.s.LogCredential("sudo:"+sh.user, pass)
		}
	}
	if len(cmd) == 0 || interactive || elevateShells[cmd[0]] {
		sh.becomeRoot()
		return "", 0
	}
	// Run the single command as root, then drop back.
	prev := sh.user
	sh.user = "root"
	out, code := sh.runCommand(cmd, stdin)
	sh.user = prev
	return out, code
}

// cmdSu switches the session user. `su` / `su root` / `su -` become root (prompting
// for a password we capture); `su <other>` switches to that account.
func (sh *Shell) cmdSu(args []string) (string, int) {
	target := "root"
	for _, a := range args[1:] {
		if a == "-" || a == "-l" || strings.HasPrefix(a, "-") {
			continue
		}
		target = a
		break
	}
	if sh.user != target {
		if pass, ok := sh.s.Prompt("Password: "); ok {
			sh.s.LogCredential("su:"+target, pass)
		}
	}
	if target == "root" {
		sh.becomeRoot()
	} else {
		sh.user = target
		sh.env["HOME"] = "/home/" + target
		sh.env["USER"] = target
	}
	return "", 0
}

// becomeRoot promotes the session to root, so whoami, id, the prompt, and the
// permission checks all reflect the elevation for the rest of the session.
func (sh *Shell) becomeRoot() {
	sh.user = "root"
	sh.env["HOME"] = "/root"
	sh.env["USER"] = "root"
}

// canRead reports whether the current shell user may read a node, enforcing the
// basic owner/other read bits: root reads anything, a non-root user is denied a
// file like /etc/shadow (0640 root) unless it is world-readable or they own it.
func (sh *Shell) canRead(n *vfs.Node) bool {
	if sh.user == "root" {
		return true
	}
	m := n.Mode().Perm()
	if m&0o004 != 0 {
		return true
	}
	return n.Uname() == sh.user && m&0o400 != 0
}
