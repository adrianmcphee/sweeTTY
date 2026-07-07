package server

import "testing"

// TestConnLimiterCapsConcurrency proves the process-wide cap admits up to its size,
// refuses past it (without blocking), and re-admits after a release - the backstop
// that stops a botnet spread across many source IPs from exhausting file
// descriptors past the per-IP cap.
func TestConnLimiterCapsConcurrency(t *testing.T) {
	l := newConnLimiter(2)
	if !l.tryAcquire() {
		t.Fatal("limiter refused the first connection below its cap")
	}
	if !l.tryAcquire() {
		t.Fatal("limiter refused the second connection below its cap")
	}
	if l.tryAcquire() {
		t.Fatal("limiter admitted a connection past its cap")
	}
	l.release()
	if !l.tryAcquire() {
		t.Fatal("limiter did not re-admit after a release")
	}
}
