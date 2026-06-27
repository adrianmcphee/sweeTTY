package shell

import (
	"reflect"
	"testing"
)

// TestParseChainingQuotingEnv exercises the parser subset: chaining operators,
// pipelines, leading assignments, redirects, and quoting.
func TestParseChainingQuotingEnv(t *testing.T) {
	t.Run("chaining", func(t *testing.T) {
		cases := []struct {
			line      string
			wantCount int
			wantChain string // chain operator that follows the FIRST statement
		}{
			{"a; b", 2, ";"},
			{"a && b", 2, "&&"},
			{"a || b", 2, "||"},
		}
		for _, c := range cases {
			stmts := parse(c.line)
			if len(stmts) != c.wantCount {
				t.Errorf("%q: got %d statements, want %d", c.line, len(stmts), c.wantCount)
				continue
			}
			if stmts[0].chain != c.wantChain {
				t.Errorf("%q: first chain = %q, want %q", c.line, stmts[0].chain, c.wantChain)
			}
			if last := stmts[len(stmts)-1].chain; last != "" {
				t.Errorf("%q: last chain = %q, want empty", c.line, last)
			}
		}
	})

	t.Run("pipeline", func(t *testing.T) {
		stmts := parse("a | b")
		if len(stmts) != 1 {
			t.Fatalf("got %d statements, want 1", len(stmts))
		}
		if len(stmts[0].stages) != 2 {
			t.Fatalf("got %d pipeline stages, want 2", len(stmts[0].stages))
		}
		if got := stmts[0].stages[0].args; !reflect.DeepEqual(got, []string{"a"}) {
			t.Errorf("stage 0 args = %v, want [a]", got)
		}
		if got := stmts[0].stages[1].args; !reflect.DeepEqual(got, []string{"b"}) {
			t.Errorf("stage 1 args = %v, want [b]", got)
		}
	})

	t.Run("assignments", func(t *testing.T) {
		// VAR=val cmd: the assignment is captured and cmd is the first arg.
		stmts := parse("VAR=val cmd")
		if len(stmts) != 1 || len(stmts[0].stages) != 1 {
			t.Fatalf("VAR=val cmd: unexpected shape %+v", stmts)
		}
		st := stmts[0].stages[0]
		if st.assigns["VAR"] != "val" {
			t.Errorf("VAR=val cmd: assigns = %v, want VAR=val", st.assigns)
		}
		if !reflect.DeepEqual(st.args, []string{"cmd"}) {
			t.Errorf("VAR=val cmd: args = %v, want [cmd]", st.args)
		}

		// Standalone VAR=val: assignment-only stage with no args.
		stmts = parse("VAR=val")
		if len(stmts) != 1 || len(stmts[0].stages) != 1 {
			t.Fatalf("VAR=val: unexpected shape %+v", stmts)
		}
		st = stmts[0].stages[0]
		if st.assigns["VAR"] != "val" {
			t.Errorf("VAR=val: assigns = %v, want VAR=val", st.assigns)
		}
		if len(st.args) != 0 {
			t.Errorf("VAR=val: args = %v, want none", st.args)
		}
	})

	t.Run("redirects", func(t *testing.T) {
		st := parse("cmd > f")[0].stages[0]
		if st.outFile != "f" || st.appendT || st.outNull {
			t.Errorf("cmd > f: outFile=%q append=%v null=%v", st.outFile, st.appendT, st.outNull)
		}

		st = parse("cmd >> f")[0].stages[0]
		if st.outFile != "f" || !st.appendT {
			t.Errorf("cmd >> f: outFile=%q append=%v", st.outFile, st.appendT)
		}

		st = parse("cmd > /dev/null")[0].stages[0]
		if !st.outNull || st.outFile != "" {
			t.Errorf("cmd > /dev/null: null=%v outFile=%q", st.outNull, st.outFile)
		}

		st = parse("cmd 2>/dev/null")[0].stages[0]
		if !reflect.DeepEqual(st.args, []string{"cmd"}) {
			t.Errorf("cmd 2>/dev/null: args = %v, want [cmd] (command must survive stderr redirect)", st.args)
		}
	})

	t.Run("quoting", func(t *testing.T) {
		// Internal spaces inside double quotes are preserved as one word.
		var words []string
		for _, tk := range tokenize(`echo "a   b"`) {
			if !tk.op {
				words = append(words, tk.val)
			}
		}
		if !reflect.DeepEqual(words, []string{"echo", "a   b"}) {
			t.Errorf("tokenize words = %q, want [echo, \"a   b\"]", words)
		}
		args := parse(`echo "a   b"`)[0].stages[0].args
		if !reflect.DeepEqual(args, []string{"echo", "a   b"}) {
			t.Errorf("parse args = %q, want [echo, \"a   b\"]", args)
		}

		// Adjacent quoted atoms join into a single word.
		args = parse(`'echo' "x"'y'`)[0].stages[0].args
		if !reflect.DeepEqual(args, []string{"echo", "xy"}) {
			t.Errorf("adjacency args = %q, want [echo, xy]", args)
		}
	})
}

// TestLooksLikeCommand checks the heuristic that decides whether decoded base64
// content should be executed as a loader one-liner.
func TestLooksLikeCommand(t *testing.T) {
	truthy := []string{
		"wget http://x",
		"curl http://x",
		"bash -c id",
		"/bin/sh",
		"chmod +x x",
	}
	for _, s := range truthy {
		if !looksLikeCommand(s) {
			t.Errorf("looksLikeCommand(%q) = false, want true", s)
		}
	}
	falsy := []string{
		"hello world",
		"just text",
	}
	for _, s := range falsy {
		if looksLikeCommand(s) {
			t.Errorf("looksLikeCommand(%q) = true, want false", s)
		}
	}
}
