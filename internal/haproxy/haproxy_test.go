package haproxy

import (
	"strings"
	"testing"
	"time"
)

func TestParseStickTable(t *testing.T) {
	out := "# table: st_src, type: ip, size:1048576, used:3\n" +
		"0x55a1: key=1.2.3.4 use=0 exp=599000 conn_cur=5 conn_rate(10000)=250\n" +
		"0x55a2: key=8.8.8.8 use=1 exp=590000 conn_cur=1 conn_rate(10000)=3\n" +
		"\n" +
		"not a table line\n" +
		"0x55a3: key=9.9.9.9 use=0 exp=10 conn_cur=0 conn_rate(10000)=0\n"

	got := ParseStickTable(strings.NewReader(out))
	want := []Source{
		{IP: "1.2.3.4", ConnCur: 5, ConnRate: 250},
		{IP: "8.8.8.8", ConnCur: 1, ConnRate: 3},
		{IP: "9.9.9.9", ConnCur: 0, ConnRate: 0},
	}
	if len(got) != len(want) {
		t.Fatalf("parsed %d sources, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("source %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestParseStickTableCapsSources(t *testing.T) {
	var b strings.Builder
	for i := 0; i < maxStickSources+100; i++ {
		b.WriteString("0x1: key=192.0.2.1 use=0 exp=1 conn_cur=1 conn_rate(10000)=1\n")
	}
	if got := len(ParseStickTable(strings.NewReader(b.String()))); got != maxStickSources {
		t.Fatalf("parsed %d stick-table sources, want cap %d", got, maxStickSources)
	}
}

func TestTableNameIsStrict(t *testing.T) {
	for _, name := range []string{"st_src", "backend-rate-1"} {
		if !validTableName(name) {
			t.Errorf("valid table name %q rejected", name)
		}
	}
	for _, name := range []string{"show table st_src", "../escape", ""} {
		if validTableName(name) {
			t.Errorf("unsafe table name %q accepted", name)
		}
	}
}

func TestWatcherReportsAndCoolsDown(t *testing.T) {
	w := NewWatcher(200, time.Minute)
	t0 := time.Unix(1_700_000_000, 0)

	flood := []Source{{IP: "1.2.3.4", ConnRate: 250}, {IP: "8.8.8.8", ConnRate: 100}}

	// First poll: only the over-threshold source is reported.
	due := w.Flooding(flood, t0)
	if len(due) != 1 || due[0].IP != "1.2.3.4" {
		t.Fatalf("first poll due = %+v, want just 1.2.3.4", due)
	}

	// Same source still flooding within the cooldown: not reported again.
	if due := w.Flooding(flood, t0.Add(10*time.Second)); len(due) != 0 {
		t.Errorf("within cooldown reported %+v, want none", due)
	}

	// After the cooldown, a sustained flood reports again.
	if due := w.Flooding(flood, t0.Add(70*time.Second)); len(due) != 1 || due[0].IP != "1.2.3.4" {
		t.Errorf("after cooldown due = %+v, want 1.2.3.4 again", due)
	}

	// The source drops back under the threshold: nothing reported, and its
	// bookkeeping is forgotten...
	calm := []Source{{IP: "1.2.3.4", ConnRate: 20}}
	if due := w.Flooding(calm, t0.Add(80*time.Second)); len(due) != 0 {
		t.Errorf("calm source reported %+v, want none", due)
	}
	// ...so a fresh flood reports immediately rather than waiting out the cooldown.
	if due := w.Flooding(flood, t0.Add(85*time.Second)); len(due) != 1 || due[0].IP != "1.2.3.4" {
		t.Errorf("fresh flood due = %+v, want immediate 1.2.3.4", due)
	}
}
