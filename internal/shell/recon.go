package shell

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// This file implements the network and hashing recon tools the manifest advertises
// under /usr/bin: ping, dig/nslookup/host, du, md5sum/sha1sum/sha256sum, and
// groups. They previously fell through to "command not found" even though `which`
// reported a path for them, an obvious contradiction a prober hits immediately.

// resolveForDisplay returns the address to show for a host: the host itself if it
// already parses as an IP, otherwise a stable plausible routable address. The box
// never actually reaches the network; this is display theatre like the downloads.
func resolveForDisplay(host string) string {
	if _, err := netip.ParseAddr(host); err == nil {
		return host
	}
	return fakeResolveIP(host)
}

func (sh *Shell) cmdPing(args []string) (string, int) {
	count := 4
	host := ""
	for i := 1; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-c" && i+1 < len(args):
			i++
			count, _ = strconv.Atoi(args[i])
		case strings.HasPrefix(a, "-c"):
			count, _ = strconv.Atoi(a[2:])
		case strings.HasPrefix(a, "-"):
		default:
			host = a
		}
	}
	if host == "" {
		return "ping: usage error: Destination address required\n", 1
	}
	if count <= 0 || count > 10 {
		count = 4 // real ping runs until interrupted; cap so the tarpit does not hang
	}
	ip := resolveForDisplay(host)
	h := fnv32(host)
	var b strings.Builder
	fmt.Fprintf(&b, "PING %s (%s) 56(84) bytes of data.\n", host, ip)
	var min, max, sum float64
	for i := 0; i < count; i++ {
		rtt := 6.0 + float64((h+uint32(i)*13)%380)/10
		fmt.Fprintf(&b, "64 bytes from %s: icmp_seq=%d ttl=54 time=%.1f ms\n", ip, i+1, rtt)
		if i == 0 || rtt < min {
			min = rtt
		}
		if rtt > max {
			max = rtt
		}
		sum += rtt
	}
	avg := sum / float64(count)
	fmt.Fprintf(&b, "\n--- %s ping statistics ---\n", host)
	fmt.Fprintf(&b, "%d packets transmitted, %d received, 0%% packet loss, time %dms\n", count, count, count*1000-1)
	fmt.Fprintf(&b, "rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms\n", min, avg, max, (max-min)/2)
	return b.String(), 0
}

// cmdResolve backs dig, nslookup, and host with a canned answer resolving the name
// to its display address, in the format of whichever tool was invoked.
func (sh *Shell) cmdResolve(args []string) (string, int) {
	tool := args[0]
	name := ""
	for _, a := range args[1:] {
		if strings.HasPrefix(a, "-") || strings.HasPrefix(a, "@") || a == "A" || a == "any" {
			continue
		}
		name = a
		break
	}
	if name == "" {
		return tool + ": couldn't get address for '': not found\n", 1
	}
	ip := resolveForDisplay(name)
	switch tool {
	case "nslookup":
		return fmt.Sprintf("Server:\t\t%s\nAddress:\t%s#53\n\nNon-authoritative answer:\nName:\t%s\nAddress: %s\n",
			sh.p.GatewayIP, sh.p.GatewayIP, name, ip), 0
	case "host":
		return fmt.Sprintf("%s has address %s\n", name, ip), 0
	default: // dig
		return fmt.Sprintf("; <<>> DiG %s <<>> %s\n"+
			";; global options: +cmd\n;; Got answer:\n"+
			";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: %d\n"+
			";; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1\n\n"+
			";; QUESTION SECTION:\n;%s.\t\t\tIN\tA\n\n"+
			";; ANSWER SECTION:\n%s.\t300\tIN\tA\t%s\n\n"+
			";; Query time: %d msec\n;; SERVER: %s#53(%s) (UDP)\n;; MSG SIZE  rcvd: %d\n",
			sh.p.DigVersion(), name, fnv32(name)%65535, name, name, ip, int(fnv32(name)%40)+8, sh.p.GatewayIP, sh.p.GatewayIP, len(name)+45), 0
	}
}

// cmdDu reports disk usage. It answers -s/-h with a stable plausible size derived
// from the path, rather than being unavailable.
func (sh *Shell) cmdDu(args []string) (string, int) {
	human, summary := false, false
	var paths []string
	for _, a := range args[1:] {
		switch {
		case strings.Contains(a, "s") && strings.HasPrefix(a, "-"):
			summary = true
			human = human || strings.Contains(a, "h")
		case strings.Contains(a, "h") && strings.HasPrefix(a, "-"):
			human = true
		case strings.HasPrefix(a, "-"):
		default:
			paths = append(paths, a)
		}
	}
	if len(paths) == 0 {
		paths = []string{"."}
	}
	var b strings.Builder
	for _, p := range paths {
		abs := sh.fs.Resolve(p)
		h := fnv32(abs)
		kb := 4 + int(h%9_000_000) // up to ~9 GB
		size := strconv.Itoa(kb)
		if human {
			size = humanBytes(kb * 1024)
		}
		fmt.Fprintf(&b, "%s\t%s\n", size, p)
		_ = summary
	}
	return b.String(), 0
}

// cmdHashsum backs md5sum, sha1sum, and sha256sum by hashing the actual file
// content from the virtual filesystem, so the digest is coherent with what cat
// shows rather than a canned constant.
func (sh *Shell) cmdHashsum(args []string) (string, int) {
	tool := args[0]
	var files []string
	for _, a := range args[1:] {
		if strings.HasPrefix(a, "-") {
			continue
		}
		files = append(files, a)
	}
	if len(files) == 0 {
		return "", 0 // reads stdin in reality; nothing to hash here
	}
	var b strings.Builder
	code := 0
	for _, f := range files {
		data, err := sh.readFile(sh.fs.Resolve(f))
		if err != nil {
			fmt.Fprintf(&b, "%s: %s: No such file or directory\n", tool, f)
			code = 1
			continue
		}
		var sum string
		switch tool {
		case "md5sum":
			h := md5.Sum(data)
			sum = hex.EncodeToString(h[:])
		case "sha1sum":
			h := sha1.Sum(data)
			sum = hex.EncodeToString(h[:])
		default: // sha256sum
			h := sha256.Sum256(data)
			sum = hex.EncodeToString(h[:])
		}
		fmt.Fprintf(&b, "%s  %s\n", sum, f)
	}
	return b.String(), code
}

// cmdGroups prints the groups a user belongs to, read from /etc/group, so it agrees
// with id and with the group file rather than being command-not-found.
func (sh *Shell) cmdGroups(args []string) (string, int) {
	user := sh.user
	if len(args) > 1 {
		user = args[1]
	}
	groups := sh.groupsOf(user)
	return strings.Join(groups, " ") + "\n", 0
}

type grp struct {
	name string
	gid  string
}

// groupsWithGID resolves a user's group memberships from /etc/passwd (primary) and
// /etc/group (supplementary), primary group first, so id and groups agree with the
// files rather than each other.
func (sh *Shell) groupsWithGID(user string) []grp {
	var primaryGID string
	if data, err := sh.fs.ReadFile("/etc/passwd"); err == nil {
		for _, line := range lines(string(data)) {
			f := strings.Split(line, ":")
			if len(f) >= 4 && f[0] == user {
				primaryGID = f[3]
			}
		}
	}
	var out []grp
	seen := map[string]bool{}
	add := func(name, gid string) {
		if name != "" && !seen[gid] {
			seen[gid] = true
			out = append(out, grp{name, gid})
		}
	}
	if data, err := sh.fs.ReadFile("/etc/group"); err == nil {
		gl := lines(string(data))
		for _, line := range gl { // primary group first, like real `groups`
			f := strings.Split(line, ":")
			if len(f) >= 3 && f[2] == primaryGID {
				add(f[0], f[2])
			}
		}
		for _, line := range gl {
			f := strings.Split(line, ":")
			if len(f) < 4 {
				continue
			}
			for _, m := range strings.Split(f[3], ",") {
				if m == user {
					add(f[0], f[2])
				}
			}
		}
	}
	return out
}

func (sh *Shell) groupsOf(user string) []string {
	gs := sh.groupsWithGID(user)
	if len(gs) == 0 {
		return []string{user}
	}
	out := make([]string, len(gs))
	for i, g := range gs {
		out[i] = g.name
	}
	return out
}

// cmdId renders id coherently with groups and the passwd/group files, including the
// supplementary groups the old fixed string omitted.
func (sh *Shell) cmdId(args []string) string {
	user := sh.user
	if len(args) > 1 && !strings.HasPrefix(args[1], "-") {
		user = args[1]
	}
	uid := "0"
	if user != "root" {
		uid = strconv.Itoa(sh.p.UserUID)
	}
	gs := sh.groupsWithGID(user)
	if len(gs) == 0 {
		gs = []grp{{user, uid}}
	}
	primary := gs[0]
	var groups []string
	for _, g := range gs {
		groups = append(groups, g.gid+"("+g.name+")")
	}
	return fmt.Sprintf("uid=%s(%s) gid=%s(%s) groups=%s\n",
		uid, user, primary.gid, primary.name, strings.Join(groups, ","))
}
