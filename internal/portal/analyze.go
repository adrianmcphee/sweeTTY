package portal

import (
	"strings"
	"time"

	"sweetty/internal/event"
)

// visitGapMs is the idle gap that separates one visit from the next: a source
// whose consecutive events straddle a gap this long is treated as having come
// back. Thirty minutes reads a single noisy campaign as one visit and a genuine
// return after stepping away as a new one.
const visitGapMs = 30 * 60 * 1000

// fastCommandMs is the inter-command gap below which two commands could not have
// been typed by a human: it is a pasted or scripted burst.
const fastCommandMs = 400

// Source kinds. The verdict is deliberately conservative: a source stays
// kindUnknown unless the evidence is clear, and kindHuman always carries a
// question mark because it is a hypothesis, never an assertion.
const (
	kindUnknown    = "unknown"
	kindScanner    = "scanner"
	kindBruteforce = "bot:bruteforce"
	kindLoader     = "bot:loader"
	kindHuman      = "human?"
)

// Attack phases, in escalation order.
const (
	phaseRecon   = "recon"
	phaseBrute   = "bruteforce"
	phaseAccess  = "access"
	phaseExploit = "exploit"
)

// Visit is one contiguous span of a source's activity, bounded by an idle gap.
type Visit struct {
	Start    string `json:"start"`
	End      string `json:"end"`
	Events   int    `json:"events"`
	Phase    string `json:"phase"`    // deepest phase reached in this visit
	Accepted bool   `json:"accepted"` // the source ran a command, so it got a shell
}

// Assessment is the portal's read on one source: what it is, how sure we are,
// why, the phases it reached, and how its activity breaks into visits.
type Assessment struct {
	Kind       string   `json:"kind"`
	Confidence int      `json:"confidence"`
	Reasons    []string `json:"reasons"`
	Phases     []string `json:"phases"`
	Visits     []Visit  `json:"visits"`
	CadenceMs  int64    `json:"cadence_ms"` // smallest gap between two commands, 0 if under two
	Returning  bool     `json:"returning"`
}

// sourceSignals accumulates the per-source evidence the classifier reads. Both
// the full per-IP analysis and the overview rollup fold each event through
// observe, so the Sources-list tag and the drawer verdict can never disagree.
type sourceSignals struct {
	commands     int
	credentials  int
	sessions     int
	uniqueCmds   int
	scanned      bool
	hasExec      bool
	hasDownload  bool
	hasBait      bool
	sentinelCred bool // a honeypot-probe credential was offered
	probeCmd     bool // a BusyBox presence probe was run
	loaderCmd    bool // a loader/persistence command was run
	fastBurst    bool // two commands fired closer than a human can type

	// Rolling timing state, folded as commands stream past.
	lastCmdMs int64
	minCmdGap int64
	maxCmdGap int64
	sawGap    bool // a gap has been measured, so minCmdGap of 0 is a real 0ms burst
	seen      map[string]bool
}

// observe folds one event into the running signals. It reads only fields the log
// already carries and never reaches outside the entry.
func (s *sourceSignals) observe(e event.Entry) {
	switch e.Event {
	case "PORT_SCAN":
		s.scanned = true
	case "SESSION_START":
		s.sessions++
	case "CREDENTIAL":
		s.credentials++
		if isSentinelCred(e.Username, e.Password) {
			s.sentinelCred = true
		}
	case "COMMAND":
		s.commands++
		if s.seen == nil {
			s.seen = map[string]bool{}
		}
		if len(s.seen) < maxUniqueCommands && !s.seen[e.Command] {
			s.seen[e.Command] = true
			s.uniqueCmds++
		}
		if isLoaderCommand(e.Command) {
			s.loaderCmd = true
		}
		if isBusyboxProbe(e.Command) {
			s.probeCmd = true
		}
		ms := entryMs(e)
		if s.lastCmdMs != 0 && ms != 0 {
			if gap := ms - s.lastCmdMs; gap >= 0 {
				// Track the smallest gap; sawGap distinguishes an unset minimum from a
				// real 0ms burst (two commands in the same millisecond), which is the
				// strongest pasted-script tell and must not be clobbered.
				if !s.sawGap || gap < s.minCmdGap {
					s.minCmdGap = gap
				}
				s.sawGap = true
				if gap > s.maxCmdGap {
					s.maxCmdGap = gap
				}
				if gap < fastCommandMs {
					s.fastBurst = true
				}
			}
		}
		if ms != 0 {
			s.lastCmdMs = ms
		}
	case "EXEC_ATTEMPT":
		s.hasExec = true
	case "DOWNLOAD_ATTEMPT":
		s.hasDownload = true
	case "HONEYTOKEN":
		s.hasBait = true
	}
}

// humanPacing is true when commands came at varied, multi-second intervals with
// no machine-fast burst: the cadence of someone typing, not a script.
func (s sourceSignals) humanPacing() bool {
	return s.maxCmdGap > 1500 && !s.fastBurst && s.commands >= 3
}

// verdict turns accumulated signals into a kind, a confidence, and the evidence
// behind it. Bot signals are weighted and summed; the kind is chosen by the
// strongest evidence, and a source stays unknown when nothing is conclusive.
func verdict(s sourceSignals) (kind string, confidence int, reasons []string) {
	add := func(r string) { reasons = append(reasons, r) }

	bot := 0
	if s.loaderCmd {
		bot += 3
		add("ran loader/persistence commands (chpasswd, key drop, or echoloader)")
	}
	if s.sentinelCred {
		bot += 3
		add("offered a honeypot-probe credential a real user never types")
	}
	if s.probeCmd {
		bot += 3
		add("ran a BusyBox presence probe to fingerprint the box")
	}
	if s.fastBurst {
		bot += 2
		add("fired commands faster than a human can type")
	}
	if s.hasExec {
		bot++
		add("attempted to execute a dropped payload")
	}
	if s.hasDownload {
		bot++
		add("attempted to pull a second-stage payload")
	}

	human := 0
	if s.humanPacing() {
		human++
	}

	switch {
	case s.loaderCmd || (s.hasExec && bot >= 3):
		kind = kindLoader
	case bot >= 3:
		kind = kindBruteforce
	case s.commands == 0 && s.credentials >= 4:
		kind = kindBruteforce
		add("sprayed credentials without ever running a command")
	case s.commands == 0 && s.credentials == 0 && !s.hasExec && !s.hasDownload:
		kind = kindScanner
		if s.scanned {
			add("connected and sent nothing (a bare port scan)")
		} else {
			add("probed without authenticating or running a command")
		}
	case human > 0 && bot == 0:
		kind = kindHuman
		add("paced commands at human, varied intervals")
	default:
		kind = kindUnknown
	}

	switch kind {
	case kindLoader:
		confidence = clamp(70+bot*8, 0, 99)
	case kindBruteforce:
		if bot >= 3 {
			confidence = clamp(70+bot*6, 0, 99)
		} else {
			confidence = clamp(45+s.credentials*3, 0, 90)
		}
	case kindScanner:
		confidence = 75
	case kindHuman:
		confidence = clamp(35+human*15, 0, 70)
	default:
		confidence = 0
	}
	return kind, confidence, reasons
}

// sourceAnalyzer folds one source's chronological event history into the
// assessment one entry at a time, so a caller streaming a large history never
// has to hold it in memory.
type sourceAnalyzer struct {
	sig     sourceSignals
	visits  []Visit
	prevMs  int64
	reached map[string]bool
	seenAny bool
}

// observe folds the next entry of the source's history. Entries must arrive in
// chronological (file) order, the order the log carries them.
func (a *sourceAnalyzer) observe(e event.Entry) {
	ms := entryMs(e)
	if !a.seenAny || (a.prevMs != 0 && ms != 0 && ms-a.prevMs > visitGapMs) {
		if len(a.visits) < maxProjectedDetails {
			a.visits = append(a.visits, Visit{Start: e.Time})
		}
	}
	a.seenAny = true
	cur := &a.visits[len(a.visits)-1]
	cur.End = e.Time
	cur.Events++
	if ph := phaseOf(e); ph != "" {
		if a.reached == nil {
			a.reached = map[string]bool{}
		}
		a.reached[ph] = true
		if phaseRank(ph) > phaseRank(cur.Phase) {
			cur.Phase = ph
		}
	}
	if e.Event == "COMMAND" {
		cur.Accepted = true
	}
	a.sig.observe(e)
	if ms != 0 {
		a.prevMs = ms
	}
}

// assessment returns the verdict over everything observed so far.
func (a *sourceAnalyzer) assessment() Assessment {
	kind, confidence, reasons := verdict(a.sig)
	returning := len(a.visits) >= 2 || (a.sig.scanned && (a.sig.commands > 0 || a.sig.sessions > 0))
	return Assessment{
		Kind:       kind,
		Confidence: confidence,
		Reasons:    reasons,
		Phases:     orderedPhases(a.reached),
		Visits:     a.visits,
		CadenceMs:  a.sig.minCmdGap,
		Returning:  returning,
	}
}

// analyzeSource reads one source's full event history (chronological) and returns
// the assessment: visit segmentation, the phases it reached, and the conservative
// bot/human verdict with its evidence.
func analyzeSource(entries []event.Entry) Assessment {
	var a sourceAnalyzer
	for _, e := range entries {
		a.observe(e)
	}
	return a.assessment()
}

// phaseOf maps one entry to the attack phase it represents, or "" if it is not
// phase-bearing.
func phaseOf(e event.Entry) string {
	switch e.Event {
	case "PORT_SCAN", "HTTP_REQUEST", "HTTP_POST", "TLS_HELLO":
		return phaseRecon
	case "CREDENTIAL":
		return phaseBrute
	case "COMMAND":
		if isLoaderCommand(e.Command) {
			return phaseExploit
		}
		return phaseAccess
	case "EXEC_ATTEMPT", "DOWNLOAD_ATTEMPT", "DROPPER", "HONEYTOKEN":
		return phaseExploit
	}
	return ""
}

func phaseRank(p string) int {
	switch p {
	case phaseRecon:
		return 1
	case phaseBrute:
		return 2
	case phaseAccess:
		return 3
	case phaseExploit:
		return 4
	}
	return 0
}

// orderedPhases returns the reached phases in escalation order.
func orderedPhases(reached map[string]bool) []string {
	var out []string
	for _, p := range []string{phaseRecon, phaseBrute, phaseAccess, phaseExploit} {
		if reached[p] {
			out = append(out, p)
		}
	}
	return out
}

// isSentinelCred reports whether a credential exists only to make a permissive
// honeypot reveal itself: a real user never types it, so offering one is a
// honeypot-detection probe and the source is automated by definition.
func isSentinelCred(user, pass string) bool {
	for _, v := range []string{user, pass} {
		if strings.Contains(v, "345gs5662d34") {
			return true
		}
	}
	return false
}

// loaderMarkers are command fragments only a botnet loader runs: changing root's
// password to lock the owner out, clearing and rewriting the SSH key store for
// persistence, and the BusyBox echo-loader that writes a dropper byte by byte.
var loaderMarkers = []string{
	"chpasswd",
	"chattr -ia",
	"authorized_keys",
	"echo -ne",
	"echo -e '\\x",
	`echo -e "\x`,
}

// isLoaderCommand reports whether a command is a loader/persistence action or a
// fetch piped straight into a shell.
func isLoaderCommand(cmd string) bool {
	for _, m := range loaderMarkers {
		if strings.Contains(cmd, m) {
			return true
		}
	}
	return strings.Contains(cmd, "|sh") || strings.Contains(cmd, "| sh") ||
		strings.Contains(cmd, "|bash") || strings.Contains(cmd, "| bash")
}

// commonApplets are the BusyBox commands a real loader actually invokes. Any
// other lone token after "/bin/busybox" is a presence probe, run only to read
// back "applet not found" and confirm the box is a genuine BusyBox device.
var commonApplets = map[string]bool{
	"cat": true, "ls": true, "echo": true, "wget": true, "tftp": true,
	"cp": true, "chmod": true, "rm": true, "ps": true, "kill": true,
	"hostname": true, "sh": true, "dd": true, "mount": true, "umount": true,
	"free": true, "df": true, "ifconfig": true, "reboot": true,
}

// isBusyboxProbe reports whether a command is the Mirai-style BusyBox presence
// probe: "/bin/busybox" followed by a single alphanumeric nonce.
func isBusyboxProbe(cmd string) bool {
	f := strings.Fields(cmd)
	if len(f) != 2 || f[0] != "/bin/busybox" {
		return false
	}
	tok := f[1]
	if commonApplets[tok] || len(tok) < 3 {
		return false
	}
	for _, r := range tok {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

// entryMs returns an entry's millisecond timestamp, preferring the stamped
// epoch_ms and falling back to parsing the RFC3339 time so a log or test without
// epoch_ms still segments and paces correctly.
func entryMs(e event.Entry) int64 {
	if e.EpochMs != 0 {
		return e.EpochMs
	}
	if t, err := time.Parse(time.RFC3339, e.Time); err == nil {
		return t.UnixMilli()
	}
	return 0
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
