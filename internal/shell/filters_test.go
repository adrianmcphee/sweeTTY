package shell

import "testing"

// TestFiltersRunForReal proves the text filters attackers pipe recon through
// actually transform their input, rather than passing stdin unchanged (which made
// `cut -d: -f1` print the whole file and `tr a-z A-Z` a no-op, both tells).
func TestFiltersRunForReal(t *testing.T) {
	sh := &Shell{}
	passwd := "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"

	cases := []struct {
		name  string
		args  []string
		stdin string
		want  string
		fn    func([]string, string) string
	}{
		{"cut -d: -f1", []string{"cut", "-d:", "-f1"}, passwd, "root\ndaemon\n", sh.cmdCut},
		{"cut -d: -f1,7", []string{"cut", "-d:", "-f1,7"}, passwd, "root:/bin/bash\ndaemon:/usr/sbin/nologin\n", sh.cmdCut},
		{"tr a-z A-Z", []string{"tr", "a-z", "A-Z"}, "hello world\n", "HELLO WORLD\n", sh.cmdTr},
		{"tr -d", []string{"tr", "-d", "aeiou"}, "hello\n", "hll\n", sh.cmdTr},
		{"sort -rn", []string{"sort", "-rn"}, "3\n1\n20\n2\n", "20\n3\n2\n1\n", sh.cmdSort},
		{"sort", []string{"sort"}, "b\na\nc\n", "a\nb\nc\n", sh.cmdSort},
		{"uniq -c", []string{"uniq", "-c"}, "a\na\nb\n", "2 a\n1 b\n", sh.cmdUniq},
		{"awk -F: print $1", []string{"awk", "-F:", "{print $1}"}, passwd, "root\ndaemon\n", sh.cmdAwk},
		{"awk print $1,$7", []string{"awk", "-F:", "{print $1,$7}"}, passwd, "root /bin/bash\ndaemon /usr/sbin/nologin\n", sh.cmdAwk},
		{"sed s/o/0/g", []string{"sed", "s/o/0/g"}, "root\nboot\n", "r00t\nb00t\n", sh.cmdSed},
		{"sed /daemon/d", []string{"sed", "/daemon/d"}, passwd, "root:x:0:0:root:/root:/bin/bash\n", sh.cmdSed},
	}
	for _, c := range cases {
		if got := c.fn(c.args, c.stdin); got != c.want {
			t.Errorf("%s = %q, want %q", c.name, got, c.want)
		}
	}
}

// TestPipelineComposes proves a real recon pipeline composes end to end:
// cut the shells column, sort, uniq -c, sort -rn.
func TestPipelineComposes(t *testing.T) {
	sh := &Shell{}
	in := "a:1:/bin/bash\nb:2:/usr/sbin/nologin\nc:3:/bin/bash\nd:4:/usr/sbin/nologin\ne:5:/bin/bash\n"
	shells := sh.cmdCut([]string{"cut", "-d:", "-f3"}, in)
	sorted := sh.cmdSort([]string{"sort"}, shells)
	counted := sh.cmdUniq([]string{"uniq", "-c"}, sorted)
	top := sh.cmdSort([]string{"sort", "-rn"}, counted)
	want := "3 /bin/bash\n2 /usr/sbin/nologin\n"
	if top != want {
		t.Errorf("pipeline = %q, want %q", top, want)
	}
}
