package event

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLogFileIsNotWorldReadable proves the captured log (credentials, commands,
// payloads) is created 0600, so another local user on the sensor host cannot read
// what attackers submitted.
func TestLogFileIsNotWorldReadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ev.log")
	lg, err := New(path)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer lg.Close()
	lg.Log(Entry{Event: "CREDENTIAL", IP: "1.2.3.4:1", Username: "root", Password: "hunter2"})

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("log file mode = %v, want 0600: captured secrets must not be world-readable", perm)
	}
}

// TestLogWriteFailureIsCountedNotSwallowed proves a failed write increments the
// dropped counter instead of vanishing silently - the log is the product, so a
// lost event must be observable rather than invisible.
func TestLogWriteFailureIsCountedNotSwallowed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ev.log")
	lg, err := New(path)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	lg.file.Close() // break the descriptor so subsequent writes fail

	lg.Log(Entry{Event: "COMMAND", IP: "1.2.3.4:1", Command: "id"})
	if lg.dropped == 0 {
		t.Fatal("a failed log write was silently swallowed instead of counted")
	}
	if !lg.warned {
		t.Fatal("the first write failure was not surfaced")
	}
}
