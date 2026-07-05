// Package mysql implements a MySQL credential-trap surface. It emits a real
// protocol-10 greeting, captures the username and scrambled auth response, and
// rejects the login. It never opens a database session or grants query capability.
package mysql

import (
	crand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sync/atomic"

	"sweetty/internal/persona"
	"sweetty/internal/server"
)

const (
	clientLongPassword     = 0x00000001
	clientLongFlag         = 0x00000004
	clientProtocol41       = 0x00000200
	clientTransactions     = 0x00002000
	clientSecureConnection = 0x00008000
	clientPluginAuth       = 0x00080000

	mysqlStatusAutocommit = 0x0002
	mysqlCharsetUTF8      = 33
	maxMySQLPayload       = 1 << 20
	authSaltPart1Len      = 8
	authSaltPart2Len      = 12
	authSaltLen           = authSaltPart1Len + authSaltPart2Len
)

type Protocol struct {
	persona *persona.Persona
}

var connectionCounter = randomConnectionID()

func New(p *persona.Persona) server.Protocol {
	return &Protocol{persona: p}
}

func (pr *Protocol) Name() string { return "mysql" }

func (pr *Protocol) ClientFirst() bool { return false }

func (pr *Protocol) Handle(s *server.Session) {
	s.Persona = pr.persona
	pr.writeHandshake(s)

	pkt, ok := readPacket(s)
	if !ok {
		return
	}
	login, err := parseLogin(pkt.payload)
	if err != nil {
		malformed(s, err.Error())
		return
	}
	s.LogCredentialResult(login.user, hex.EncodeToString(login.auth), false, false)
	pr.writeAccessDenied(s, pkt.seq+1, login.user, len(login.auth) > 0)
}

func (pr *Protocol) writeHandshake(s *server.Session) {
	const plugin = "mysql_native_password"
	salt := randomASCII(authSaltLen)
	salt1 := salt[:authSaltPart1Len]
	salt2 := salt[authSaltPart1Len:]
	caps := uint32(clientLongPassword | clientLongFlag | clientProtocol41 | clientTransactions | clientSecureConnection | clientPluginAuth)

	var payload []byte
	payload = append(payload, 10)
	payload = append(payload, pr.persona.MySQLVer...)
	payload = append(payload, 0)
	payload = appendUint32(payload, nextConnectionID())
	payload = append(payload, salt1...)
	payload = append(payload, 0)
	payload = appendUint16(payload, uint16(caps))
	payload = append(payload, mysqlCharsetUTF8)
	payload = appendUint16(payload, mysqlStatusAutocommit)
	payload = appendUint16(payload, uint16(caps>>16))
	payload = append(payload, byte(len(salt1)+len(salt2)+1))
	payload = append(payload, make([]byte, 10)...)
	payload = append(payload, salt2...)
	payload = append(payload, 0)
	payload = append(payload, plugin...)
	payload = append(payload, 0)
	writePacket(s, 0, payload)
}

func (pr *Protocol) writeAccessDenied(s *server.Session, seq byte, user string, usingPassword bool) {
	passwordText := "NO"
	if usingPassword {
		passwordText = "YES"
	}
	host := s.SrcIP
	if host == "" {
		host = "localhost"
	}
	msg := fmt.Sprintf("Access denied for user '%s'@'%s' (using password: %s)", user, host, passwordText)
	payload := []byte{0xff, 0x15, 0x04, '#', '2', '8', '0', '0', '0'}
	payload = append(payload, msg...)
	writePacket(s, seq, payload)
}

type packet struct {
	seq     byte
	payload []byte
}

func readPacket(s *server.Session) (packet, bool) {
	header := s.ReadN(4)
	if len(header) != 4 {
		return packet{}, false
	}
	n := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
	if n > maxMySQLPayload {
		malformed(s, fmt.Sprintf("packet length %d exceeds limit", n))
		return packet{}, false
	}
	payload := s.ReadN(n)
	if len(payload) != n {
		malformed(s, "short packet")
		return packet{}, false
	}
	return packet{seq: header[3], payload: payload}, true
}

type login struct {
	user string
	auth []byte
}

func parseLogin(payload []byte) (login, error) {
	if len(payload) < 32 {
		return login{}, fmt.Errorf("login packet too short")
	}
	caps := binary.LittleEndian.Uint32(payload[:4])
	if caps&clientProtocol41 == 0 {
		return login{}, fmt.Errorf("login packet missing protocol 4.1 capability")
	}
	pos := 4 + 4 + 1 + 23
	user, next, ok := readNullString(payload, pos)
	if !ok {
		return login{}, fmt.Errorf("login packet missing username terminator")
	}
	pos = next
	var auth []byte
	if caps&clientSecureConnection != 0 {
		if pos >= len(payload) {
			return login{}, fmt.Errorf("login packet missing auth length")
		}
		n := int(payload[pos])
		pos++
		if pos+n > len(payload) {
			return login{}, fmt.Errorf("login packet auth response is truncated")
		}
		auth = append([]byte(nil), payload[pos:pos+n]...)
	} else {
		pass, _, ok := readNullString(payload, pos)
		if !ok {
			return login{}, fmt.Errorf("login packet missing old-password terminator")
		}
		auth = []byte(pass)
	}
	return login{user: user, auth: auth}, nil
}

func readNullString(payload []byte, pos int) (string, int, bool) {
	for i := pos; i < len(payload); i++ {
		if payload[i] == 0 {
			return string(payload[pos:i]), i + 1, true
		}
	}
	return "", pos, false
}

func malformed(s *server.Session, msg string) {
	s.LogRaw("MYSQL_MALFORMED", msg)
}

func writePacket(s *server.Session, seq byte, payload []byte) {
	if len(payload) > 0xffffff {
		payload = payload[:0xffffff]
	}
	header := []byte{byte(len(payload)), byte(len(payload) >> 8), byte(len(payload) >> 16), seq}
	s.WriteBytes(append(header, payload...))
}

func appendUint16(out []byte, v uint16) []byte {
	return append(out, byte(v), byte(v>>8))
}

func appendUint32(out []byte, v uint32) []byte {
	return append(out, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

func randomConnectionID() uint32 {
	var b [4]byte
	if _, err := crand.Read(b[:]); err != nil {
		return 1
	}
	id := binary.LittleEndian.Uint32(b[:])
	if id == 0 {
		return 1
	}
	return id
}

func nextConnectionID() uint32 {
	id := atomic.AddUint32(&connectionCounter, 1)
	if id == 0 {
		id = atomic.AddUint32(&connectionCounter, 1)
	}
	return id
}

func randomASCII(n int) []byte {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	out := make([]byte, n)
	buf := make([]byte, n)
	if _, err := crand.Read(buf); err != nil {
		for i := range out {
			out[i] = alphabet[i%len(alphabet)]
		}
		return out
	}
	for i, b := range buf {
		out[i] = alphabet[int(b)%len(alphabet)]
	}
	return out
}
