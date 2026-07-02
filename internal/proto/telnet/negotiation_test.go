package telnet_test

// Bot-fidelity pins for the telnet handshake (the first hop of the slice). A real
// telnetd answers a client's option negotiation; silently swallowing it is a
// near-unique honeypot tell that a one-RTT nmap/zgrab2 probe catches. The server
// now opens with a realistic burst (DO TTYPE/TSPEED/XDISPLOC/NEW-ENVIRON, WILL SGA,
// DO NAWS), so these prove it (1) refuses an option it does not drive (DO -> WONT),
// (2) declines a client's own offer it did not solicit (WILL -> DONT), (3) stays
// silent on acknowledgements of the options it itself requested/offered (answering
// would contradict the request and can loop).

import (
	"strings"
	"testing"
	"time"
)

func TestTelnetRefusesOfferedOption(t *testing.T) {
	h, _ := setup(t, "ubuntu")
	if _, ok := h.ReadUntil("login:", 2*time.Second); !ok {
		t.Fatal("never saw login prompt")
	}
	// IAC DO LINEMODE (0x22): an option the server neither drives nor offered, so it
	// must refuse rather than black-hole the request.
	h.SendBytes([]byte{0xff, 0xfd, 0x22})
	out := h.ReadFor(400 * time.Millisecond)
	if !strings.Contains(out, "\xff\xfc\x22") { // IAC WONT LINEMODE
		t.Fatalf("server did not refuse the offered option (negotiation black hole): % x", []byte(out))
	}
}

func TestTelnetDeclinesClientOption(t *testing.T) {
	h, _ := setup(t, "ubuntu")
	if _, ok := h.ReadUntil("login:", 2*time.Second); !ok {
		t.Fatal("never saw login prompt")
	}
	// IAC WILL STATUS (0x05): a client offer the server never solicited; it declines.
	h.SendBytes([]byte{0xff, 0xfb, 0x05})
	out := h.ReadFor(400 * time.Millisecond)
	if !strings.Contains(out, "\xff\xfe\x05") { // IAC DONT STATUS
		t.Fatalf("server did not decline the client option: % x", []byte(out))
	}
}

// TestTelnetAcksItsOwnBurstSilently proves the server does NOT answer the
// acknowledgement of an option it requested in the opening burst: WILL TTYPE (ack of
// our DO TTYPE) must draw no reply, or the negotiation would contradict itself and
// could loop.
func TestTelnetAcksItsOwnBurstSilently(t *testing.T) {
	h, _ := setup(t, "ubuntu")
	if _, ok := h.ReadUntil("login:", 2*time.Second); !ok {
		t.Fatal("never saw login prompt")
	}
	h.SendBytes([]byte{0xff, 0xfb, 0x18}) // IAC WILL TTYPE (ack of our DO TTYPE)
	out := h.ReadFor(300 * time.Millisecond)
	if strings.ContainsRune(out, 0xff) {
		t.Fatalf("server answered an ack of its own burst option (can loop/contradict): % x", []byte(out))
	}
}

// TestTelnetRefusesSGA proves the server refuses suppress-go-ahead (DO SGA -> WONT
// SGA). It stays in line mode on purpose: offering SGA without ECHO is what drops a
// BSD/macOS client into kludge line mode and echoes a stray ^M at the prompt.
func TestTelnetRefusesSGA(t *testing.T) {
	h, _ := setup(t, "ubuntu")
	if _, ok := h.ReadUntil("login:", 2*time.Second); !ok {
		t.Fatal("never saw login prompt")
	}
	h.SendBytes([]byte{0xff, 0xfd, 0x03}) // IAC DO SGA
	out := h.ReadFor(300 * time.Millisecond)
	if !strings.Contains(out, "\xff\xfc\x03") { // IAC WONT SGA
		t.Fatalf("server did not refuse SGA with WONT SGA; got % x", []byte(out))
	}
}

// TestTelnetDoesNotLoopOnNawsAck proves the server stays silent when the client
// acknowledges the NAWS it solicited (IAC WILL NAWS), rather than answering and
// risking an endless negotiation exchange.
func TestTelnetDoesNotLoopOnNawsAck(t *testing.T) {
	h, _ := setup(t, "ubuntu")
	if _, ok := h.ReadUntil("login:", 2*time.Second); !ok {
		t.Fatal("never saw login prompt")
	}
	h.SendBytes([]byte{0xff, 0xfb, 0x1f}) // IAC WILL NAWS
	out := h.ReadFor(300 * time.Millisecond)
	if strings.ContainsRune(out, 0xff) {
		t.Fatalf("server answered the NAWS acknowledgement; this can loop: % x", []byte(out))
	}
}

// TestUnterminatedSubnegotiationDoesNotHang is the hostile-input pin for the IAC
// reader: a client that opens a subnegotiation (IAC SB) and then streams bytes with
// no terminating IAC SE must not pin the reader on the socket. The scan is bounded,
// so an oversized subnegotiation ends the read and the session promptly instead of
// looping until the idle timeout.
func TestUnterminatedSubnegotiationDoesNotHang(t *testing.T) {
	h, _ := setup(t, "ubuntu")
	if _, ok := h.ReadUntil("login:", 2*time.Second); !ok {
		t.Fatal("never saw login prompt")
	}
	// IAC SB followed by a long run with no IAC SE — never terminates.
	junk := []byte{0xff, 0xfa} // IAC SB
	for range 1024 {
		junk = append(junk, 'A')
	}
	h.SendBytes(junk)
	if _, ok := h.WaitEvent("SESSION_END", 3*time.Second); !ok {
		t.Fatal("an unterminated subnegotiation did not end the session (the IAC reader hung)")
	}
}
