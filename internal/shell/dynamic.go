package shell

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"sweetty/internal/persona"
)

// These generators synthesize system-tool output from the persona and the
// session uptime. They never read the real host: every number is computed, and
// volatile fields (uptime, RX/TX counters) grow over time so repeated calls
// differ the way a live box does.

func uptimeOf(p *persona.Persona) time.Duration {
	return time.Since(time.Unix(p.BootEpoch, 0))
}

// deviceFor returns the stat Device field (hex/dec of st_dev) for the mount a path
// falls under, so stat agrees with lsblk and df instead of always naming sda1.
func deviceFor(p *persona.Persona, abs string) string {
	major, minor := 202, 1 // xvda1, the cloud root
	switch {
	case p.Embedded():
		major, minor = 179, 1 // mmcblk0p1
	case strings.HasPrefix(abs, "/var/lib/mysql"):
		major, minor = 202, 17 // xvdb1, the data volume
	}
	dev := major<<8 | minor
	return fmt.Sprintf("%xh/%dd", dev, dev)
}

// linkLocalFromMAC derives the stable EUI-64 fe80:: address from the interface MAC
// the way the kernel does, so ifconfig and ip addr show the same link-local and it
// does not drift between calls (the old value was built from uptime and changed).
func linkLocalFromMAC(mac string) string {
	parts := strings.Split(mac, ":")
	if len(parts) != 6 {
		return "fe80::1"
	}
	b := make([]int64, 6)
	for i, p := range parts {
		b[i], _ = strconv.ParseInt(p, 16, 0)
	}
	b[0] ^= 0x02 // flip the universal/local bit
	return fmt.Sprintf("fe80::%02x%02x:%02xff:fe%02x:%02x%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}

func bcast(ip string) string {
	if i := strings.LastIndexByte(ip, '.'); i >= 0 {
		return ip[:i] + ".255"
	}
	return ip
}

func (sh *Shell) cmdPs(args []string) string {
	full := false
	for _, a := range args[1:] {
		if strings.Contains(a, "a") && strings.Contains(a, "u") || strings.Contains(a, "e") || strings.Contains(a, "f") {
			full = true
		}
	}
	return psStr(sh.p, full, sh.login)
}

// procRow is one line of the synthetic process table that backs both `ps aux` and
// `systemctl status`, so the two can never name a different PID for the same
// daemon. Boot daemons take their START from the persona's boot epoch; session
// processes (the attacker's shell and ps) start "now", so START agrees with
// uptime no matter how long ago this instance booted.
type procRow struct {
	user    string
	pid     int
	cpu     string
	mem     string
	vsz     int
	rss     int
	tty     string
	stat    string
	atBoot  bool // START derives from BootEpoch; otherwise it is HH:MM today
	cpuTime string
	command string
}

// shellPID is the pid of the session's own -bash, referenced both by ps (the -bash
// row) and by `echo $$`, so the two agree.
const shellPID = 2841

// procTable is the single source of truth for the running processes. The daemon
// PIDs are fixed per build (a real box's are stable across a session too), and the
// master/worker split matters: systemd's "Main PID" is the master row.
func procTable(p *persona.Persona) []procRow {
	rows := []procRow{
		{"root", 1, "0.0", "0.4", 168140, 11200, "?", "Ss", true, "0:24", "/sbin/init"},
	}
	// Kernel threads: bracketed names, zero VSZ/RSS the way real kernel threads show
	// in ps. Their absence (a userspace-only listing) is a classic honeypot tell.
	kthreads := []string{
		"[kthreadd]", "[rcu_gp]", "[rcu_par_gp]", "[kworker/0:0H-events_highpri]", "[mm_percpu_wq]",
		"[ksoftirqd/0]", "[rcu_sched]", "[migration/0]", "[cpuhp/0]", "[cpuhp/1]", "[migration/1]",
		"[ksoftirqd/1]", "[kworker/1:0H-events_highpri]", "[kdevtmpfs]", "[netns]", "[kauditd]",
		"[khungtaskd]", "[oom_reaper]", "[writeback]", "[kcompactd0]", "[ksmd]", "[khugepaged]",
		"[kintegrityd]", "[kblockd]", "[ata_sff]", "[md]", "[edac-poller]", "[devfreq_wq]",
		"[watchdogd]", "[kswapd0]", "[kthrotld]", "[ipv6_addrconf]", "[kstrp]", "[jbd2/xvda1-8]",
		"[ext4-rsv-conver]", "[kworker/0:2-events]", "[kworker/1:2-events]", "[kworker/u4:1-flush-202:0]",
	}
	pid := 2
	for _, name := range kthreads {
		stat := "I<"
		if strings.HasPrefix(name, "[ksoftirqd") || strings.HasPrefix(name, "[migration") || strings.HasPrefix(name, "[rcu_sched") {
			stat = "S"
		}
		rows = append(rows, procRow{"root", pid, "0.0", "0.0", 0, 0, "?", stat, true, "0:00", name})
		pid += 2
	}
	// Standard system daemons a real Ubuntu server always runs, so the listing is not
	// a suspiciously clean LAMP-only set.
	rows = append(rows,
		procRow{"root", 412, "0.0", "0.2", 93776, 6020, "?", "Ss", true, "0:01", "/lib/systemd/systemd-journald"},
		procRow{"root", 440, "0.0", "0.2", 25004, 6600, "?", "Ss", true, "0:00", "/lib/systemd/systemd-udevd"},
		procRow{"systemd+", 520, "0.0", "0.2", 90120, 5900, "?", "Ssl", true, "0:02", "/lib/systemd/systemd-networkd"},
		procRow{"systemd+", 522, "0.0", "0.3", 25376, 12100, "?", "Ss", true, "0:03", "/lib/systemd/systemd-resolved"},
		procRow{"root", 540, "0.0", "0.1", 8892, 3200, "?", "Ss", true, "0:00", "/usr/sbin/cron -f"},
		procRow{"message+", 544, "0.0", "0.1", 9160, 4800, "?", "Ss", true, "0:01", "/usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile"},
		procRow{"root", 560, "0.0", "0.2", 16948, 7400, "?", "Ss", true, "0:00", "/lib/systemd/systemd-logind"},
		procRow{"syslog", 566, "0.0", "0.1", 222440, 5000, "?", "Ssl", true, "0:00", "/usr/sbin/rsyslogd -n -iNONE"},
		procRow{"root", 498, "0.0", "0.1", 15852, 4800, "?", "Ss", true, "0:00", "/usr/sbin/sshd -D"},
		procRow{"mysql", 611, "0.3", "9.1", 1820400, 184220, "?", "Ssl", true, "8:42", "/usr/sbin/mysqld"},
		procRow{"root", 719, "0.0", "0.5", 208880, 11400, "?", "Ss", true, "0:00", "nginx: master process"},
		procRow{"www-data", 720, "0.0", "1.2", 209360, 25240, "?", "S", true, "0:11", "nginx: worker process"},
		procRow{"www-data", 721, "0.0", "1.2", 209360, 24980, "?", "S", true, "0:09", "nginx: worker process"},
		procRow{"www-data", 880, "0.0", "2.1", 294500, 43120, "?", "S", true, "0:33", "php-fpm: pool www"},
		procRow{"root", 1408, "0.0", "0.1", 5828, 1900, "tty1", "Ss+", true, "0:00", "/sbin/agetty -o -p -- \\u --noclear tty1 linux"},
		procRow{"root", shellPID, "0.0", "0.2", 21380, 5360, "pts/0", "Ss", false, "0:00", "-bash"},
		procRow{"root", 2900, "0.0", "0.1", 19208, 3600, "pts/0", "R+", false, "0:00", "ps aux"},
	)
	return rows
}

// psStartField formats the ps START column for a row: a boot daemon shows the boot
// date (e.g. Jun01) when the box booted before today, or HH:MM if it booted today;
// a session process shows a recent HH:MM. This is what keeps ps from contradicting
// uptime.
func psStartField(p *persona.Persona, atBoot bool, login time.Time) string {
	if !atBoot {
		// A session process (the attacker's shell and ps) started when the session
		// logged in, so its START agrees with w/who/last rather than a fixed offset.
		return login.Format("15:04")
	}
	boot := time.Unix(p.BootEpoch, 0)
	if time.Since(boot) < 24*time.Hour {
		return boot.Format("15:04")
	}
	return boot.Format("Jan02")
}

func psStr(p *persona.Persona, full bool, login time.Time) string {
	if !full {
		return "    PID TTY          TIME CMD\n   2841 pts/0    00:00:00 bash\n   2899 pts/0    00:00:00 ps\n"
	}
	var b strings.Builder
	b.WriteString("USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n")
	for _, r := range procTable(p) {
		fmt.Fprintf(&b, "%-8s %5d %4s %4s %6d %5d %-8s %-4s %-5s %s %s\n",
			r.user, r.pid, r.cpu, r.mem, r.vsz, r.rss, r.tty, r.stat,
			psStartField(p, r.atBoot, login), r.cpuTime, r.command)
	}
	return b.String()
}

// Swap totals, shared so free, top, and /proc/meminfo never disagree on them.
const (
	swapTotalKiB = 2097148
	swapUsedKiB  = 86040
	swapFreeKiB  = swapTotalKiB - swapUsedKiB
)

// memNumbers is the single source of truth for RAM figures, in KiB, so free, top,
// and /proc/meminfo all render from one set and can never contradict each other.
// The used figure drifts with uptime so repeated calls differ the way a live box's do.
func memNumbers(p *persona.Persona) (total, used, free, buff, avail int) {
	total = 4030836
	used = 1740000 + int(uptimeOf(p).Minutes())%90000
	free = 240000
	buff = total - used - free
	avail = total - used + 600000
	return
}

func freeStr(p *persona.Persona) string {
	total, used, free, buff, avail := memNumbers(p)
	return fmt.Sprintf(`               total        used        free      shared  buff/cache   available
Mem:        %8d    %8d    %8d      199116    %8d    %8d
Swap:     %10d  %10d  %10d
`, total, used, free, buff, avail, swapTotalKiB, swapUsedKiB, swapFreeKiB)
}

// diskSize pairs the size lsblk prints for a device with the 1K-block count its
// filesystem reports - the device is always a touch larger than the formatted fs,
// the way a real mkfs leaves overhead, so df and lsblk agree without being equal.
type diskSize struct {
	human  string
	blocks int
}

var (
	sdCards   = []diskSize{{"14.8G", 15193088}, {"29.7G", 30041088}, {"59.6G", 61071360}}
	cloudVols = []diskSize{{"20G", 20509264}, {"40G", 41019200}, {"60G", 62543872}, {"80G", 83361792}, {"100G", 104210432}}
	dataVols  = []diskSize{{"49G", 51475068}, {"98G", 104805376}, {"196G", 209715200}}
)

// diskHash derives a stable per-instance seed from the persona, so the disk
// geometry differs between instances (doctrine #7: two boxes never show identical
// df/lsblk output) yet is identical on every call within one instance - df, lsblk
// and the partition table can never disagree.
func diskHash(p *persona.Persona) uint32 {
	h := uint32(2166136261)
	for i := 0; i < len(p.MachineID); i++ {
		h = (h ^ uint32(p.MachineID[i])) * 16777619
	}
	return h
}

// usage splits a filesystem's blocks into used/available at a per-instance fill
// level, so two boxes with the same disk size still report different free space.
func usage(blocks int, h uint32) (used, avail, pct int) {
	pct = 14 + int(h%60) // 14..73% full
	used = blocks * pct / 100
	avail = blocks - used
	return
}

func pick3[T any](s []T, h uint32) T { return s[int(h)%len(s)] }

func dfStr(p *persona.Persona) string {
	h := diskHash(p)
	if p.Embedded() {
		// A single SD card, root only - no Xen data disk on an SBC.
		root := pick3(sdCards, h)
		ru, ra, rp := usage(root.blocks, h>>3)
		return fmt.Sprintf(`Filesystem     1K-blocks     Used Available Use%% Mounted on
tmpfs             403084     1280    401804   1%% /run
%-14s %9d %8d %9d %3d%% /
tmpfs            2015416        0   2015416   0%% /dev/shm
tmpfs               5120        0      5120   0%% /run/lock
tmpfs             403080        4    403076   1%% /run/user/0
`, "/dev/mmcblk0p1", root.blocks, ru, ra, rp)
	}
	root := pick3(cloudVols, h)
	data := pick3(dataVols, h>>5)
	ru, ra, rp := usage(root.blocks, h>>3)
	du, da, dp := usage(data.blocks, h>>11)
	return fmt.Sprintf(`Filesystem     1K-blocks     Used Available Use%% Mounted on
tmpfs             403084     1280    401804   1%% /run
%-14s %9d %8d %9d %3d%% /
tmpfs            2015416        0   2015416   0%% /dev/shm
tmpfs               5120        0      5120   0%% /run/lock
%-14s %9d %8d %9d %3d%% /var/lib/mysql
tmpfs             403080        4    403076   1%% /run/user/0
`, "/dev/xvda1", root.blocks, ru, ra, rp, "/dev/xvdb1", data.blocks, du, da, dp)
}

func uptimeStr(p *persona.Persona) string {
	up := uptimeOf(p)
	days := int(up.Hours()) / 24
	hh := int(up.Hours()) % 24
	mm := int(up.Minutes()) % 60
	return fmt.Sprintf(" %s up %d days, %2d:%02d,  1 user,  load average: 0.%02d, 0.%02d, 0.%02d\n",
		time.Now().Format("15:04:05"), days, hh, mm, 8+days%30, 12+days%20, 5+days%15)
}

// wStr renders `w` with the live session shown as itself: logged in from the real
// attacker source at the moment it connected, so a source that connects and
// immediately runs `w` sees its own address and a near-zero idle time rather than
// a fabricated past login from the gateway (the classic just-connected tell).
func wStr(p *persona.Persona, user, srcIP string, login time.Time) string {
	idle := idleField(login)
	return strings.TrimSuffix(uptimeStr(p), "\n") +
		"\nUSER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n" +
		fmt.Sprintf("%-8s pts/0    %-15s %s    %s  0.04s  0.00s -bash\n", user, srcIP, login.Format("15:04"), idle)
}

// idleField formats the w IDLE column from how long ago the session logged in,
// so it advances with real elapsed time instead of being a constant.
func idleField(login time.Time) string {
	s := int(time.Since(login).Seconds())
	if s < 60 {
		return fmt.Sprintf("%2d.00s", s)
	}
	m := s / 60
	if m < 60 {
		return fmt.Sprintf("%5dm", m)
	}
	return fmt.Sprintf("%2d:%02d", m/60, m%60)
}

func lastStr(p *persona.Persona, user, srcIP string, login time.Time) string {
	now := time.Now()
	return fmt.Sprintf(`%-8s pts/0        %-15s %s   still logged in
%-8s pts/0        %-15s %s - %s  (00:42)
%-8s pts/0        %-15s %s - %s  (01:18)
deploy   pts/1        %-15s %s - %s  (00:09)

wtmp begins %s
`,
		user, srcIP, login.Format("Mon Jan _2 15:04"),
		user, p.GatewayIP, now.Add(-26*time.Hour).Format("Mon Jan _2 15:04"), now.Add(-26*time.Hour).Add(42*time.Minute).Format("15:04"),
		user, p.GatewayIP, now.Add(-50*time.Hour).Format("Mon Jan _2 15:04"), now.Add(-50*time.Hour).Add(78*time.Minute).Format("15:04"),
		p.BackupIP, now.Add(-74*time.Hour).Format("Mon Jan _2 15:04"), now.Add(-74*time.Hour).Add(9*time.Minute).Format("15:04"),
		time.Unix(p.BootEpoch, 0).Add(-72*time.Hour).Format("Mon Jan _2 15:04:05 2006"))
}

func ifconfigStr(p *persona.Persona) string {
	up := int(uptimeOf(p).Seconds())
	rxp := 184000 + up*7
	txp := 142000 + up*5
	rxb := int64(rxp) * 812
	txb := int64(txp) * 690
	return fmt.Sprintf(`eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet %s  netmask 255.255.255.0  broadcast %s
        inet6 %s  prefixlen 64  scopeid 0x20<link>
        ether %s  txqueuelen 1000  (Ethernet)
        RX packets %d  bytes %d (%.1f MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets %d  bytes %d (%.1f MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets %d  bytes %d (%.1f MiB)
        TX packets %d  bytes %d (%.1f MiB)
`,
		p.HostIP, bcast(p.HostIP), linkLocalFromMAC(p.MAC), p.MAC,
		rxp, rxb, float64(rxb)/1048576, txp, txb, float64(txb)/1048576,
		up*3, int64(up)*3*98, float64(int64(up)*3*98)/1048576, up*3, int64(up)*3*98, float64(int64(up)*3*98)/1048576)
}

func ipAddrStr(p *persona.Persona) string {
	return fmt.Sprintf(`1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether %s brd ff:ff:ff:ff:ff:ff
    inet %s/24 brd %s scope global eth0
       valid_lft forever preferred_lft forever
    inet6 %s/64 scope link
       valid_lft forever preferred_lft forever
`, p.MAC, p.HostIP, bcast(p.HostIP), linkLocalFromMAC(p.MAC))
}

func ipRouteStr(p *persona.Persona) string {
	net := p.HostIP[:strings.LastIndexByte(p.HostIP, '.')] + ".0"
	return fmt.Sprintf("default via %s dev eth0 proto static\n%s/24 dev eth0 proto kernel scope link src %s\n", p.GatewayIP, net, p.HostIP)
}

func ipLinkStr(p *persona.Persona) string {
	return fmt.Sprintf(`1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000
    link/ether %s brd ff:ff:ff:ff:ff:ff
`, p.MAC)
}

// listenPorts is the set of externally-bound TCP ports this instance serves,
// taken straight from persona.Services so netstat/ss can never advertise a port
// the box does not actually expose (or omit one it does). The database listens
// only on loopback and is added separately by the generators.
func listenPorts(p *persona.Persona) []int {
	seen := map[int]bool{}
	var ports []int
	for _, s := range p.Services {
		switch s.Protocol {
		case "ssh", "telnet", "http", "https", "ftp":
			if !seen[s.Port] {
				seen[s.Port] = true
				ports = append(ports, s.Port)
			}
		}
	}
	sort.Ints(ports)
	return ports
}

// mgmtPort is the port the (fake) established admin connections are shown on: the
// SSH port if this instance runs SSH, otherwise its lowest listening port, so the
// established sessions are coherent with the services that actually answer.
func mgmtPort(p *persona.Persona) int {
	for _, s := range p.Services {
		if s.Protocol == "ssh" {
			return s.Port
		}
	}
	if ports := listenPorts(p); len(ports) > 0 {
		return ports[0]
	}
	return 22
}

func netstatStr(p *persona.Persona) string {
	var b strings.Builder
	b.WriteString("Active Internet connections (servers and established)\n")
	b.WriteString("Proto Recv-Q Send-Q Local Address           Foreign Address         State\n")
	for _, port := range listenPorts(p) {
		fmt.Fprintf(&b, "tcp        0      0 %-23s %-23s LISTEN\n", fmt.Sprintf("0.0.0.0:%d", port), "0.0.0.0:*")
	}
	// The database listens only on loopback (internal), matching the mysqld in ps.
	fmt.Fprintf(&b, "tcp        0      0 %-23s %-23s LISTEN\n", "127.0.0.1:3306", "0.0.0.0:*")
	mp := mgmtPort(p)
	fmt.Fprintf(&b, "tcp        0      0 %-23s %-23s ESTABLISHED\n", fmt.Sprintf("%s:%d", p.HostIP, mp), fmt.Sprintf("%s:51224", p.GatewayIP))
	fmt.Fprintf(&b, "tcp        0    140 %-23s %-23s ESTABLISHED\n", fmt.Sprintf("%s:%d", p.HostIP, mp), fmt.Sprintf("%s:43122", p.BackupIP))
	return b.String()
}

func ssStr(p *persona.Persona) string {
	var b strings.Builder
	b.WriteString("State    Recv-Q   Send-Q     Local Address:Port       Peer Address:Port\n")
	for _, port := range listenPorts(p) {
		fmt.Fprintf(&b, "LISTEN   0        128        %-24s %s\n", fmt.Sprintf("0.0.0.0:%d", port), "0.0.0.0:*")
	}
	fmt.Fprintf(&b, "LISTEN   0        70         %-24s %s\n", "127.0.0.1:3306", "0.0.0.0:*")
	return b.String()
}

func lscpuStr(p *persona.Persona) string {
	if p.Embedded() {
		return `Architecture:            aarch64
  CPU op-mode(s):        32-bit, 64-bit
  Byte Order:            Little Endian
CPU(s):                  2
  On-line CPU(s) list:   0,1
Vendor ID:               ARM
  Model name:            Cortex-A72
    Model:               3
    Thread(s) per core:  1
    Core(s) per socket:  2
    Socket(s):           1
    Stepping:            r0p3
    BogoMIPS:            108.00
    Flags:               fp asimd evtstrm aes pmull sha1 sha2 crc32 cpuid
Caches (sum of all):
  L1d:                   128 KiB (2 instances)
  L1i:                   96 KiB (2 instances)
  L2:                    2 MiB (2 instances)
`
	}
	return `Architecture:            x86_64
  CPU op-mode(s):        32-bit, 64-bit
  Byte Order:            Little Endian
CPU(s):                  2
  On-line CPU(s) list:   0,1
Vendor ID:               GenuineIntel
  Model name:            Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz
    CPU family:          6
    Model:               79
    Thread(s) per core:  1
    Core(s) per socket:  2
    Socket(s):           1
    Stepping:            1
    BogoMIPS:            4799.99
Virtualization features:
  Hypervisor vendor:     Xen
  Virtualization type:   full
Caches (sum of all):
  L1d:                   64 KiB (2 instances)
  L1i:                   64 KiB (2 instances)
  L2:                    512 KiB (2 instances)
  L3:                    35 MiB (1 instance)
`
}

func lsblkStr(p *persona.Persona) string {
	h := diskHash(p)
	if p.Embedded() {
		root := pick3(sdCards, h)
		return fmt.Sprintf(`NAME        MAJ:MIN RM   SIZE RO TYPE MOUNTPOINTS
mmcblk0     179:0    0 %5s  0 disk
└─mmcblk0p1 179:1    0 %5s  0 part /
`, root.human, root.human)
	}
	root := pick3(cloudVols, h)
	data := pick3(dataVols, h>>5)
	return fmt.Sprintf(`NAME    MAJ:MIN RM  SIZE RO TYPE MOUNTPOINTS
xvda    202:0    0 %5s  0 disk
└─xvda1 202:1    0 %5s  0 part /
xvdb    202:16   0 %5s  0 disk
└─xvdb1 202:17   0 %5s  0 part /var/lib/mysql
`, root.human, root.human, data.human, data.human)
}

func mountStr(p *persona.Persona) string {
	if p.Embedded() {
		return `sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)
proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)
udev on /dev type devtmpfs (rw,nosuid,relatime,size=1981624k,nr_inodes=495406,mode=755)
/dev/mmcblk0p1 on / type ext4 (rw,relatime)
tmpfs on /run type tmpfs (rw,nosuid,nodev,noexec,relatime,size=403084k,mode=755)
tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev)
tmpfs on /run/lock type tmpfs (rw,nosuid,nodev,noexec,relatime,size=5120k)
`
	}
	return `sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)
proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)
udev on /dev type devtmpfs (rw,nosuid,relatime,size=1981624k,nr_inodes=495406,mode=755)
/dev/xvda1 on / type ext4 (rw,relatime)
/dev/xvdb1 on /var/lib/mysql type ext4 (rw,relatime)
tmpfs on /run type tmpfs (rw,nosuid,nodev,noexec,relatime,size=403084k,mode=755)
tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev)
tmpfs on /run/lock type tmpfs (rw,nosuid,nodev,noexec,relatime,size=5120k)
`
}

func dmesgStr(p *persona.Persona) string {
	if p.Embedded() {
		// A bare-metal ARM board boots off a device tree and an SD card - no
		// vmlinuz/UUID command line, no Xen, no x86 FPU registers.
		return `[    0.000000] Linux version ` + p.KernelRel + `
[    0.000000] Machine model: Generic DT based system
[    0.000000] efi: UEFI not found.
[    0.000000] CPU: ARMv8 Processor [410fd083] revision 3
[    0.000000] psci: probing for conduit method from DT.
[    0.123456] EXT4-fs (mmcblk0p1): mounted filesystem with ordered data mode
[    1.234567] systemd[1]: Detected architecture arm64.
[    2.345678] mmc0: new ultra high speed SDR104 SDHC card at address aaaa
[    5.678901] IPv6: ADDRCONF(NETDEV_CHANGE): eth0: link becomes ready
`
	}
	return `[    0.000000] Linux version ` + p.KernelRel + `
[    0.000000] Command line: BOOT_IMAGE=/boot/vmlinuz-` + p.KernelRel + ` root=UUID=` + p.RootUUID + ` ro console=tty1
[    0.004000] KERNEL supported cpus: Intel GenuineIntel
[    0.008000] x86/fpu: Supporting XSAVE feature 0x001: 'x87 floating point registers'
[    1.234567] EXT4-fs (xvda1): mounted filesystem with ordered data mode
[    2.345678] systemd[1]: Detected virtualization xen.
[    3.456789] systemd[1]: Detected architecture x86-64.
[    4.567890] eth0: renamed from tmp0
[    5.678901] IPv6: ADDRCONF(NETDEV_CHANGE): eth0: link becomes ready
`
}
