package mysql

import (
	"encoding/binary"
	"encoding/hex"
	"io"
	"strings"
	"testing"
	"time"

	"sweetty/internal/persona"
	"sweetty/internal/testharness"
)

func TestMySQLHandshakeMatchesPersona(t *testing.T) {
	h, p := setupMySQL(t)

	pkt := mysqlReadPacket(t, h)
	if pkt.seq != 0 {
		t.Fatalf("handshake sequence = %d, want 0", pkt.seq)
	}
	greeting := parseMySQLGreeting(t, pkt.payload)
	if greeting.version != p.MySQLVer {
		t.Fatalf("server version = %q, want persona version %q", greeting.version, p.MySQLVer)
	}
	if greeting.protocol != 10 {
		t.Fatalf("protocol version = %d, want 10", greeting.protocol)
	}
	if greeting.plugin != "mysql_native_password" {
		t.Fatalf("auth plugin = %q, want mysql_native_password", greeting.plugin)
	}
	if !greeting.hasCapability(clientProtocol41) || !greeting.hasCapability(clientSecureConnection) || !greeting.hasCapability(clientPluginAuth) {
		t.Fatalf("handshake capabilities %#x do not include protocol41, secure connection, and plugin auth", greeting.capabilities)
	}
}

func TestMySQLCapturesLoginAndRejects(t *testing.T) {
	h, _ := setupMySQL(t)
	_ = mysqlReadPacket(t, h)
	auth := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02}

	mysqlSendPacket(t, h, 1, mysqlLoginPayload("wp_admin", auth))

	resp := mysqlReadPacket(t, h)
	if resp.seq != 2 {
		t.Fatalf("error sequence = %d, want 2", resp.seq)
	}
	code, state, msg := parseMySQLError(t, resp.payload)
	if code != 1045 || state != "28000" {
		t.Fatalf("error = code %d state %q, want 1045/28000", code, state)
	}
	if !strings.Contains(msg, "Access denied for user 'wp_admin'") || !strings.Contains(msg, "using password: YES") {
		t.Fatalf("error message does not look like MySQL auth rejection: %q", msg)
	}

	cred, ok := h.WaitEvent("CREDENTIAL", 2*time.Second)
	if !ok {
		t.Fatal("MySQL login did not log a credential")
	}
	if cred.Username != "wp_admin" {
		t.Fatalf("credential username = %q, want wp_admin", cred.Username)
	}
	if cred.Password != hex.EncodeToString(auth) {
		t.Fatalf("credential password = %q, want auth response hex %q", cred.Password, hex.EncodeToString(auth))
	}
	if cred.Note != "rejected" {
		t.Fatalf("credential note = %q, want rejected", cred.Note)
	}
	if h.HasEvent("COMMAND") || h.HasEvent("DOWNLOAD_ATTEMPT") || h.HasEvent("DROPPER") || h.HasEvent("EXEC_ATTEMPT") {
		t.Fatal("MySQL login reached a post-auth capability path")
	}
}

func TestMySQLMalformedPacketStaysInert(t *testing.T) {
	h, _ := setupMySQL(t)
	_ = mysqlReadPacket(t, h)

	h.SendBytes(mysqlPacketHeader(0xffffff, 1))
	_ = h.ReadFor(200 * time.Millisecond)

	if _, ok := h.WaitEvent("MYSQL_MALFORMED", 2*time.Second); !ok {
		t.Fatal("malformed MySQL packet was not logged")
	}
	if h.HasEvent("CREDENTIAL") {
		t.Fatal("malformed MySQL packet reached credential handling")
	}
	if h.HasEvent("COMMAND") || h.HasEvent("DOWNLOAD_ATTEMPT") || h.HasEvent("DROPPER") || h.HasEvent("EXEC_ATTEMPT") {
		t.Fatal("malformed MySQL packet reached an attacker capability path")
	}
}

func setupMySQL(t *testing.T) (*testharness.Harness, *persona.Persona) {
	t.Helper()
	p := persona.GenerateProfile("infra")
	h, err := testharness.New(New(p))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.Close)
	return h, p
}

type mysqlPacket struct {
	seq     byte
	payload []byte
}

func mysqlReadPacket(t *testing.T, h *testharness.Harness) mysqlPacket {
	t.Helper()
	h.Client.SetReadDeadline(time.Now().Add(2 * time.Second))
	var header [4]byte
	if _, err := io.ReadFull(h.Client, header[:]); err != nil {
		t.Fatalf("read MySQL packet header: %v", err)
	}
	n := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
	if n > 1<<20 {
		t.Fatalf("server sent oversized MySQL packet length %d", n)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(h.Client, payload); err != nil {
		t.Fatalf("read MySQL packet payload: %v", err)
	}
	return mysqlPacket{seq: header[3], payload: payload}
}

func mysqlSendPacket(t *testing.T, h *testharness.Harness, seq byte, payload []byte) {
	t.Helper()
	out := append(mysqlPacketHeader(len(payload), seq), payload...)
	h.SendBytes(out)
}

func mysqlPacketHeader(n int, seq byte) []byte {
	return []byte{byte(n), byte(n >> 8), byte(n >> 16), seq}
}

type mysqlGreeting struct {
	protocol     byte
	version      string
	capabilities uint32
	plugin       string
}

func (g mysqlGreeting) hasCapability(flag uint32) bool { return g.capabilities&flag == flag }

func parseMySQLGreeting(t *testing.T, payload []byte) mysqlGreeting {
	t.Helper()
	if len(payload) < 34 {
		t.Fatalf("handshake payload too short: %d", len(payload))
	}
	end := strings.IndexByte(string(payload[1:]), 0)
	if end < 0 {
		t.Fatalf("handshake has no NUL-terminated server version: %q", payload)
	}
	version := string(payload[1 : 1+end])
	pos := 1 + end + 1
	if len(payload) < pos+4+8+1+2+1+2+2+1+10 {
		t.Fatalf("handshake payload truncated after server version: %q", payload)
	}
	pos += 4 + 8 + 1
	lower := binary.LittleEndian.Uint16(payload[pos : pos+2])
	pos += 2 + 1 + 2
	upper := binary.LittleEndian.Uint16(payload[pos : pos+2])
	pos += 2
	authLen := int(payload[pos])
	pos += 1 + 10
	pluginStart := pos
	if authLen > 8 {
		pos += authLen - 8
	} else {
		pos += 13
	}
	if pos > len(payload) {
		t.Fatalf("handshake auth data overruns payload")
	}
	pluginBytes := payload[pluginStart:]
	if i := strings.LastIndexByte(string(pluginBytes), 0); i >= 0 {
		pluginBytes = pluginBytes[:i]
	}
	if i := strings.LastIndexByte(string(pluginBytes), 0); i >= 0 {
		pluginBytes = pluginBytes[i+1:]
	}
	return mysqlGreeting{
		protocol:     payload[0],
		version:      version,
		capabilities: uint32(lower) | uint32(upper)<<16,
		plugin:       string(pluginBytes),
	}
}

func mysqlLoginPayload(user string, auth []byte) []byte {
	caps := uint32(clientProtocol41 | clientSecureConnection | clientPluginAuth)
	out := make([]byte, 4+4+1+23)
	binary.LittleEndian.PutUint32(out[0:4], caps)
	binary.LittleEndian.PutUint32(out[4:8], 16*1024*1024)
	out[8] = 33
	out = append(out, user...)
	out = append(out, 0)
	out = append(out, byte(len(auth)))
	out = append(out, auth...)
	out = append(out, "mysql_native_password"...)
	out = append(out, 0)
	return out
}

func parseMySQLError(t *testing.T, payload []byte) (uint16, string, string) {
	t.Helper()
	if len(payload) < 9 || payload[0] != 0xff || payload[3] != '#' {
		t.Fatalf("payload is not a MySQL ERR packet: %q", payload)
	}
	code := binary.LittleEndian.Uint16(payload[1:3])
	return code, string(payload[4:9]), string(payload[9:])
}
