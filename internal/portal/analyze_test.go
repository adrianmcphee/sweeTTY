package portal

import (
	"strings"
	"testing"
	"time"

	"sweetty/internal/event"
)

// at builds an entry stamped at base+offset milliseconds, so a test can lay out
// a realistic cadence without hand-writing timestamps.
func at(base, offMs int64, ev string) event.Entry {
	ms := base + offMs
	return event.Entry{
		EpochMs: ms,
		Time:    time.UnixMilli(ms).UTC().Format(time.RFC3339),
		Event:   ev,
	}
}

func reasonsContain(reasons []string, sub string) bool {
	for _, r := range reasons {
		if strings.Contains(r, sub) {
			return true
		}
	}
	return false
}

// A real SSH botnet sprays credentials, gets in, then runs its kit at machine
// speed: a key drop and a root-password change. That is a loader, with high
// confidence, having reached the exploit phase.
func TestAnalyzeLoaderScriptIsBotLoader(t *testing.T) {
	const b = 1_700_000_000_000
	c := func(off int64, cmd string) event.Entry { e := at(b, off, "COMMAND"); e.Command = cmd; return e }
	cred := func(off int64, u, p string) event.Entry {
		e := at(b, off, "CREDENTIAL")
		e.Username, e.Password = u, p
		return e
	}
	entries := []event.Entry{
		at(b, 0, "SESSION_START"),
		cred(50, "root", "123456"),
		cred(120, "root", "admin"),
		at(b, 200, "SESSION_START"),
		cred(260, "root", "1qazxc"),
		c(300, `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAA" > .ssh/authorized_keys`),
		c(360, `echo "root:i0v3SAFnF6wM"|chpasswd|bash`),
		c(420, "uname -a"),
	}
	a := analyzeSource(entries)
	if a.Kind != kindLoader {
		t.Fatalf("kind = %q, want %q (reasons: %v)", a.Kind, kindLoader, a.Reasons)
	}
	if a.Confidence < 90 {
		t.Errorf("confidence = %d, want >= 90 for a clear loader", a.Confidence)
	}
	if !containsStr(a.Phases, phaseExploit) {
		t.Errorf("phases = %v, want to include %q", a.Phases, phaseExploit)
	}
	if a.CadenceMs == 0 || a.CadenceMs >= fastCommandMs {
		t.Errorf("cadence_ms = %d, want a sub-%d machine burst", a.CadenceMs, fastCommandMs)
	}
	if !reasonsContain(a.Reasons, "loader/persistence") {
		t.Errorf("reasons = %v, want the loader/persistence evidence", a.Reasons)
	}
}

// Offering 345gs5662d34 is a honeypot-detection probe, so even with no commands
// run the source is automated.
func TestAnalyzeSentinelCredIsBot(t *testing.T) {
	const b = 1_700_000_100_000
	cred := func(off int64, u, p string) event.Entry {
		e := at(b, off, "CREDENTIAL")
		e.Username, e.Password = u, p
		return e
	}
	entries := []event.Entry{
		at(b, 0, "SESSION_START"),
		cred(40, "root", "toor"),
		at(b, 80, "SESSION_START"),
		cred(120, "345gs5662d34", "345gs5662d34"),
	}
	a := analyzeSource(entries)
	if !strings.HasPrefix(a.Kind, "bot") {
		t.Fatalf("kind = %q, want a bot verdict (reasons: %v)", a.Kind, a.Reasons)
	}
	if !reasonsContain(a.Reasons, "honeypot-probe credential") {
		t.Errorf("reasons = %v, want the honeypot-probe-credential evidence", a.Reasons)
	}
}

// A Mirai-class telnet loader probes BusyBox with a nonce applet, then writes a
// dropper with echo -ne. Both are bot tells, and the echo-loader is exploitation.
func TestAnalyzeBusyboxProbeIsLoader(t *testing.T) {
	const b = 1_700_000_200_000
	c := func(off int64, cmd string) event.Entry { e := at(b, off, "COMMAND"); e.Command = cmd; return e }
	entries := []event.Entry{
		at(b, 0, "SESSION_START"),
		c(40, "enable"),
		c(80, "/bin/busybox aBye4G3e"),
		c(120, `/bin/busybox echo -ne '\x50\x6f\x72\x74' > /tmp/.none`),
	}
	a := analyzeSource(entries)
	if a.Kind != kindLoader {
		t.Fatalf("kind = %q, want %q (reasons: %v)", a.Kind, kindLoader, a.Reasons)
	}
	if !reasonsContain(a.Reasons, "BusyBox presence probe") {
		t.Errorf("reasons = %v, want the BusyBox-probe evidence", a.Reasons)
	}
}

// A source that only connects and sends nothing is a scanner, no more.
func TestAnalyzeScanOnlyIsScanner(t *testing.T) {
	const b = 1_700_000_300_000
	entries := []event.Entry{
		at(b, 0, "PORT_SCAN"),
		at(b, 10, "PORT_SCAN"),
	}
	a := analyzeSource(entries)
	if a.Kind != kindScanner {
		t.Fatalf("kind = %q, want %q", a.Kind, kindScanner)
	}
	if len(a.Phases) != 1 || a.Phases[0] != phaseRecon {
		t.Errorf("phases = %v, want only %q", a.Phases, phaseRecon)
	}
}

// Varied, multi-second typing with no bot tell is the one shape that reads as a
// tentative human, and only ever tentatively (the kind keeps its question mark,
// the confidence stays modest).
func TestAnalyzeHumanPacingIsTentativeHuman(t *testing.T) {
	const b = 1_700_000_400_000
	c := func(off int64, cmd string) event.Entry { e := at(b, off, "COMMAND"); e.Command = cmd; return e }
	entries := []event.Entry{
		at(b, 0, "SESSION_START"),
		c(2_000, "ls -la"),
		c(6_500, "cd /var/www"),
		c(13_000, "cat config.php"),
		c(20_000, "whoami"),
	}
	a := analyzeSource(entries)
	if a.Kind != kindHuman {
		t.Fatalf("kind = %q, want %q (reasons: %v)", a.Kind, kindHuman, a.Reasons)
	}
	if a.Confidence <= 0 || a.Confidence > 70 {
		t.Errorf("confidence = %d, want a modest (0,70] for a hypothesis", a.Confidence)
	}
}

// A pasted burst can land two commands in the same millisecond. That 0ms gap is
// the strongest script tell, so it must survive a later, larger gap rather than be
// mistaken for an unset minimum and overwritten.
func TestAnalyzeZeroGapBurstKeepsCadenceZero(t *testing.T) {
	const b = 1_700_000_600_000
	c := func(off int64, cmd string) event.Entry { e := at(b, off, "COMMAND"); e.Command = cmd; return e }
	entries := []event.Entry{
		at(b, 0, "SESSION_START"),
		c(1000, "a"),
		c(1000, "b"), // same millisecond as the previous command: a 0ms gap
		c(4000, "c"), // a later, larger gap that must not overwrite the 0
	}
	a := analyzeSource(entries)
	if a.CadenceMs != 0 {
		t.Fatalf("cadence_ms = %d, want 0 (the same-millisecond burst must survive)", a.CadenceMs)
	}
}

// A bot can run its kit at varied, multi-second intervals, which trips the
// human-pacing signal. The verdict must stay a bot, and the human-pacing reason
// must not appear alongside the bot evidence.
func TestAnalyzeBotDoesNotShowHumanReason(t *testing.T) {
	const b = 1_700_000_700_000
	c := func(off int64, cmd string) event.Entry { e := at(b, off, "COMMAND"); e.Command = cmd; return e }
	entries := []event.Entry{
		at(b, 0, "SESSION_START"),
		c(2_000, "uname -a"),
		c(5_000, "cat /proc/cpuinfo"),
		c(9_000, `echo "root:x"|chpasswd|bash`),
	}
	a := analyzeSource(entries)
	if a.Kind != kindLoader {
		t.Fatalf("kind = %q, want %q", a.Kind, kindLoader)
	}
	if reasonsContain(a.Reasons, "human") {
		t.Errorf("a bot verdict must not carry a human-pacing reason: %v", a.Reasons)
	}
}

// Two activity spans split by a long idle gap are two visits, and a source that
// scanned and later came back to engage is flagged returning.
func TestAnalyzeSegmentsVisitsAndReturning(t *testing.T) {
	const b = 1_700_000_500_000
	const hour = int64(60 * 60 * 1000)
	c := func(off int64, cmd string) event.Entry { e := at(b, off, "COMMAND"); e.Command = cmd; return e }
	entries := []event.Entry{
		at(b, 0, "PORT_SCAN"),
		// Comes back an hour later to log in and run a command.
		at(b, hour, "SESSION_START"),
		c(hour+2_000, "uname -a"),
	}
	a := analyzeSource(entries)
	if len(a.Visits) != 2 {
		t.Fatalf("visits = %d, want 2 (split by the idle gap)", len(a.Visits))
	}
	if !a.Returning {
		t.Errorf("returning = false, want true (scanned, then came back to engage)")
	}
	if a.Visits[0].Phase != phaseRecon || a.Visits[1].Phase != phaseAccess {
		t.Errorf("visit phases = [%q, %q], want [recon, access]", a.Visits[0].Phase, a.Visits[1].Phase)
	}
}
