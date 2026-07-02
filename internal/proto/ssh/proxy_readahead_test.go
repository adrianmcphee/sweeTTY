package ssh_test

import (
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"sweetty/internal/event"
	"sweetty/internal/fakehost"
	"sweetty/internal/persona"
	"sweetty/internal/proto/ssh"
	"sweetty/internal/server"
)

// TestHandshakeSurvivesProxyHeaderReadAhead reproduces the HAProxy-edge failure
// where the client's identification string arrives in the same segment as the
// PROXY header: the header parse pulls both into the session's buffered reader,
// so a handshake that then reads the bare socket never sees the banner, misreads
// the following KEXINIT as the identification line, and closes the connection
// ("Connection closed by <host> port 22" for every client that raced the parse).
// The client here glues the PROXY header to its banner in one write, which lands
// them in one segment deterministically.
func TestHandshakeSurvivesProxyHeaderReadAhead(t *testing.T) {
	p := persona.Generate()
	fs, err := fakehost.Load(p)
	if err != nil {
		t.Fatalf("load fakehost: %v", err)
	}
	lg, err := event.New(filepath.Join(t.TempDir(), "events.log"))
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	t.Cleanup(func() { lg.Close() })

	srv := server.New(0, lg, ssh.New(fs, p, ""))
	srv.ProxyProtocol = true
	if err := srv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { srv.Close() })

	conn, err := net.Dial("tcp", srv.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	cfg := &gossh.ClientConfig{
		User:            "root",
		Auth:            []gossh.AuthMethod{gossh.Password(p.RootPassword)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	glued := &headerGluedConn{
		Conn:   conn,
		header: []byte("PROXY TCP4 203.0.113.9 198.51.100.2 51122 22\r\n"),
	}
	cc, chans, reqs, err := gossh.NewClientConn(glued, srv.Addr(), cfg)
	if err != nil {
		t.Fatalf("handshake failed behind a PROXY header glued to the client banner: %v", err)
	}
	client := gossh.NewClient(cc, chans, reqs)
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	out, err := sess.CombinedOutput("whoami")
	if err != nil {
		t.Fatalf("exec command: %v", err)
	}
	if !strings.Contains(string(out), "root") {
		t.Errorf("whoami did not report root: %q", out)
	}
}

// headerGluedConn prepends the PROXY header to the client's first write, so the
// header and the SSH identification string share one TCP segment, exactly like a
// fast client relayed through a local HAProxy hop.
type headerGluedConn struct {
	net.Conn
	header []byte
}

func (c *headerGluedConn) Write(b []byte) (int, error) {
	if h := c.header; h != nil {
		c.header = nil
		if _, err := c.Conn.Write(append(h, b...)); err != nil {
			return 0, err
		}
		return len(b), nil
	}
	return c.Conn.Write(b)
}
