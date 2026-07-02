package https_test

// Cast-readability pin for the HTTPS surface. The wire carries a binary TLS
// ClientHello, and the raw input tee used to write it into the cast, where the
// live watch and replay rendered it as mojibake (and the JSON marshal destroyed
// the invalid-UTF8 bytes, so the cast preserved nothing faithful either; the hex
// of record lives in the TLS_HELLO event). The protocol now records a readable
// classification frame instead. This runs the full server path because only it
// installs the recording tap; the in-memory harness does not record.

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sweetty/internal/event"
	"sweetty/internal/persona"
	"sweetty/internal/proto/https"
	"sweetty/internal/server"
)

func TestCastRecordsReadableHelloNotRawBytes(t *testing.T) {
	server.SetFastMode(true)
	recDir := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "https.log")
	lg, err := event.New(logPath)
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	defer lg.Close()

	srv := server.New(0, lg, https.New(persona.Generate()))
	srv.RecordDir = recDir
	if err := srv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, port, _ := net.SplitHostPort(srv.Addr())
	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", port))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	// A ClientHello-shaped record whose body includes invalid-UTF8 bytes (0x8f,
	// 0xfe), the shape that rendered as mojibake when raw-teed. The trailing
	// newline lets the line-based capture return promptly.
	payload := []byte{0x16, 0x03, 0x01, 0x00, 0x2c, 0x8f, 0xfe, 0x01, 0x00, 0x28, 0x03, 0x03, '\n'}
	conn.Write(payload)
	conn.Close()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		ents, _ := os.ReadDir(recDir)
		for _, e := range ents {
			if !strings.HasSuffix(e.Name(), ".cast") {
				continue
			}
			data, _ := os.ReadFile(filepath.Join(recDir, e.Name()))
			cast := string(data)
			if !strings.Contains(cast, "TLS ClientHello") {
				continue // header written, summary frame not yet
			}
			if !strings.Contains(cast, "16 03 01") {
				t.Fatalf("cast summary carries no hex dump:\n%s", cast)
			}
			if strings.Contains(cast, "�") {
				t.Fatalf("cast still carries raw binary (replacement runes):\n%s", cast)
			}
			return // success
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("no cast with a readable ClientHello summary appeared")
}
