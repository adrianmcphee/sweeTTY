package event

// Doctrine #4: the log must stay honest under concurrency. Many connections log at
// once, so a torn or interleaved write would corrupt the record an analyst relies
// on, and a newline smuggled into a captured field must not forge an event even
// when writes race. Run under -race to also exercise the Logger mutex.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestConcurrentLogWritesStayWholeAndUnforgeable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "concurrent.log")
	lg, err := New(path)
	if err != nil {
		t.Fatalf("logger: %v", err)
	}

	const goroutines, perG = 50, 20
	var wg sync.WaitGroup
	for g := range goroutines {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := range perG {
				// The command carries a newline + a forged-event payload: it must be
				// escaped onto one line no matter how the writes interleave.
				lg.Log(Entry{Event: "COMMAND", IP: "10.0.0.1:4444",
					Command: fmt.Sprintf("g%d-i%d\n{\"event\":\"FORGED\"}", g, i)})
			}
		}(g)
	}
	wg.Wait()
	lg.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != goroutines*perG {
		t.Fatalf("wrote %d physical lines, want exactly %d: writes were torn or interleaved", len(lines), goroutines*perG)
	}
	for _, ln := range lines {
		var e Entry
		if err := json.Unmarshal([]byte(ln), &e); err != nil {
			t.Fatalf("a log line is not valid JSON (a torn concurrent write): %q: %v", ln, err)
		}
		if e.Event == "FORGED" {
			t.Fatal("a newline in a command forged a second event, even under concurrency")
		}
	}
}
