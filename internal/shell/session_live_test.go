package shell

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"sweetty/internal/persona"
)

// TestSessionShownLiveFromRealSource proves w and last render the current session
// as itself: from the real attacker source IP, at the moment it logged in. A source
// that connects and immediately runs w/who/last must not see a fabricated past login
// from the gateway, which is the classic just-connected honeypot tell.
func TestSessionShownLiveFromRealSource(t *testing.T) {
	p := persona.Generate()
	src := "203.0.113.9"
	login := time.Now()

	w := wStr(p, "root", src, login)
	if !strings.Contains(w, src) {
		t.Errorf("w does not show the real source IP %q:\n%s", src, w)
	}
	if strings.Contains(w, p.GatewayIP) {
		t.Errorf("w attributes the live session to the gateway %q, not the attacker:\n%s", p.GatewayIP, w)
	}
	if !strings.Contains(w, login.Format("15:04")) {
		t.Errorf("w LOGIN@ is not the session login time %s:\n%s", login.Format("15:04"), w)
	}

	last := lastStr(p, "root", src, login)
	first := last[:strings.IndexByte(last, '\n')]
	if !strings.Contains(first, src) || !strings.Contains(first, "still logged in") {
		t.Errorf("last's live row must be the real source, still logged in:\n%s", first)
	}
}

// TestProcUptimeCoherent proves cat /proc/uptime is synthesized from the boot epoch
// and carries an idle time consistent with a 2-core box, so it agrees with `uptime`
// and does not silently imply a different CPU count than lscpu/nproc/cpuinfo report.
func TestProcUptimeCoherent(t *testing.T) {
	p := persona.Generate()
	sh := &Shell{p: p}

	got, ok := sh.procDynamic("/proc/uptime")
	if !ok {
		t.Fatal("/proc/uptime is not synthesized")
	}
	fields := strings.Fields(strings.TrimSpace(got))
	if len(fields) != 2 {
		t.Fatalf("/proc/uptime has %d fields, want 2: %q", len(fields), got)
	}
	up, _ := strconv.ParseFloat(fields[0], 64)
	idle, _ := strconv.ParseFloat(fields[1], 64)

	wantUp := uptimeOf(p).Seconds()
	if d := up - wantUp; d < -2 || d > 2 {
		t.Errorf("/proc/uptime up=%.0f disagrees with uptime %.0f", up, wantUp)
	}
	// idle/up must be near the core count (2), never the ~8 a static value implied.
	if r := idle / up; r < 1.5 || r > 2.5 {
		t.Errorf("idle/uptime ratio %.2f implies the wrong CPU count (want ~2)", r)
	}
}
