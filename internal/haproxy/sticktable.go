// Package haproxy reads the optional HAProxy edge's runtime state for the
// management plane. It is used only by the hapwatch helper, never by the honeypot
// listeners, and reaches only HAProxy's local admin socket, so it adds no
// attacker-reachable surface.
package haproxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	maxStickSources = 10000
	maxTableName    = 64
	maxTableBytes   = 8 << 20
)

// Source is one stick-table entry: a tracked source address and its current
// concurrent-connection count and new-connection rate over the table's window.
type Source struct {
	IP       string
	ConnCur  int
	ConnRate int
}

// ParseStickTable parses the output of HAProxy's "show table <name>" runtime
// command into per-source counters. A typical data line is:
//
//	0x55a...: key=1.2.3.4 use=0 exp=599000 conn_cur=5 conn_rate(10000)=250
//
// The header line, blank lines, and any line without a key are skipped, so a new
// HAProxy field or a banner never breaks the parse.
func ParseStickTable(r io.Reader) []Source {
	out := make([]Source, 0, 256)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key := field(line, "key=")
		if key == "" {
			continue
		}
		out = append(out, Source{
			IP:       key,
			ConnCur:  atoi(field(line, "conn_cur=")),
			ConnRate: connRate(line),
		})
		if len(out) >= maxStickSources {
			break
		}
	}
	return out
}

// field returns the whitespace-delimited token following prefix, e.g. field(line,
// "key=") on "... key=1.2.3.4 use=0" returns "1.2.3.4".
func field(line, prefix string) string {
	i := strings.Index(line, prefix)
	if i < 0 {
		return ""
	}
	rest := line[i+len(prefix):]
	if j := strings.IndexByte(rest, ' '); j >= 0 {
		rest = rest[:j]
	}
	return rest
}

// connRate reads conn_rate, whose key carries the window in parentheses, e.g.
// "conn_rate(10000)=250".
func connRate(line string) int {
	i := strings.Index(line, "conn_rate(")
	if i < 0 {
		return 0
	}
	rest := line[i:]
	eq := strings.IndexByte(rest, '=')
	if eq < 0 {
		return 0
	}
	val := rest[eq+1:]
	if j := strings.IndexByte(val, ' '); j >= 0 {
		val = val[:j]
	}
	return atoi(val)
}

func atoi(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

// QueryStickTable dials HAProxy's local admin socket, runs "show table <table>",
// and returns the parsed sources. The socket runs one command per connection and
// closes, so reading to EOF yields the whole table.
func QueryStickTable(socketPath, table string, timeout time.Duration) ([]Source, error) {
	if !validTableName(table) {
		return nil, fmt.Errorf("invalid HAProxy table name")
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	conn, err := net.DialTimeout("unix", socketPath, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte("show table " + table + "\n")); err != nil {
		return nil, err
	}
	return ParseStickTable(io.LimitReader(conn, maxTableBytes)), nil
}

func validTableName(table string) bool {
	if table == "" || len(table) > maxTableName {
		return false
	}
	for _, r := range table {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}
