package server

// Doctrine: degrade to a believable failure, never a dropped record. A panic in any
// protocol handler must still produce a clean SESSION_END (and a logged PANIC) under
// the same session id, carrying the session state accrued before the crash, so an
// attacker cannot blank the record by tripping a bug.

import (
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sweetty/internal/event"
)

// panicStub accrues some session state and then panics, like a real handler hitting
// a bug mid-session.
type panicStub struct{}

func (panicStub) Name() string      { return "panicstub" }
func (panicStub) ClientFirst() bool { return false }
func (panicStub) Handle(s *Session) {
	s.CmdCount = 3
	panic("boom in a handler")
}

func TestSessionEndSurvivesPanic(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "panic.log")
	lg, err := event.New(logPath)
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	defer lg.Close()

	client, srv := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() {
		RunConn(srv, lg, panicStub{})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RunConn did not return after a panicking handler: the panic was not recovered")
	}

	entries := readLog(t, logPath)
	start := filterEvent(entries, "SESSION_START")
	pan := filterEvent(entries, "PANIC")
	end := filterEvent(entries, "SESSION_END")
	if len(start) != 1 || len(pan) != 1 || len(end) != 1 {
		t.Fatalf("want exactly one SESSION_START, PANIC and SESSION_END; got %d/%d/%d", len(start), len(pan), len(end))
	}
	id := start[0].Session
	if id == "" {
		t.Fatal("SESSION_START has no session id")
	}
	if pan[0].Session != id || end[0].Session != id {
		t.Fatalf("events are not correlated under one session id: start=%q panic=%q end=%q", id, pan[0].Session, end[0].Session)
	}
	if !strings.Contains(pan[0].Data, "boom") {
		t.Fatalf("PANIC did not capture the recovered value: %q", pan[0].Data)
	}
	if end[0].CmdCount != 3 {
		t.Fatalf("SESSION_END lost the session's command count across the panic: got %d, want 3", end[0].CmdCount)
	}
}
