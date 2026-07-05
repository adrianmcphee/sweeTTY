// Package adb implements a small Android Debug Bridge honeypot surface. It
// accepts the ADB connection handshake and the two attacker-relevant services:
// shell commands and sync pushes. Commands run through the same inert shell as
// telnet and SSH, and pushed bytes are logged as droppers. Nothing is fetched,
// executed, or written to the host filesystem.
package adb

import (
	"encoding/binary"
	"fmt"
	"strings"

	"sweetty/internal/persona"
	"sweetty/internal/server"
	"sweetty/internal/shell"
	"sweetty/internal/vfs"
)

const (
	cmdCNXN = "CNXN"
	cmdOPEN = "OPEN"
	cmdOKAY = "OKAY"
	cmdWRTE = "WRTE"
	cmdCLSE = "CLSE"

	adbVersion     = 0x01000000
	adbMaxData     = 4096
	maxADBPayload  = 64 * 1024
	maxSyncPayload = 1 << 20
)

type Protocol struct {
	fs      *vfs.FS
	persona *persona.Persona
}

func New(base *vfs.FS, p *persona.Persona) server.Protocol {
	return &Protocol{fs: base, persona: p}
}

func (pr *Protocol) Name() string { return "adb" }

func (pr *Protocol) ClientFirst() bool { return true }

func (pr *Protocol) Handle(s *server.Session) {
	s.Persona = pr.persona
	s.SetLineEnding("\n")

	pkt, ok := readPacket(s)
	if !ok {
		return
	}
	if pkt.command != cmdCNXN {
		s.LogRaw("ADB_MALFORMED", "expected CNXN, got "+pkt.command)
		return
	}
	writePacket(s, cmdCNXN, adbVersion, adbMaxData, []byte(pr.banner()))

	streams := map[uint32]*syncStream{}
	nextServerID := uint32(1)
	for {
		pkt, ok := readPacket(s)
		if !ok {
			return
		}
		switch pkt.command {
		case cmdOPEN:
			service := strings.TrimRight(string(pkt.payload), "\x00")
			serverID := nextServerID
			nextServerID++
			writePacket(s, cmdOKAY, serverID, pkt.arg0, nil)
			switch {
			case strings.HasPrefix(service, "shell:"):
				pr.handleShell(s, serverID, pkt.arg0, strings.TrimPrefix(service, "shell:"))
			case service == "sync:":
				streams[pkt.arg0] = &syncStream{serverID: serverID, clientID: pkt.arg0}
			default:
				writePacket(s, cmdCLSE, serverID, pkt.arg0, nil)
			}
		case cmdWRTE:
			st := streams[pkt.arg0]
			if st == nil || pkt.arg1 != st.serverID {
				writePacket(s, cmdCLSE, pkt.arg1, pkt.arg0, nil)
				continue
			}
			if st.consume(s, pkt.payload) {
				delete(streams, pkt.arg0)
				writePacket(s, cmdOKAY, st.serverID, st.clientID, nil)
				writePacket(s, cmdCLSE, st.serverID, st.clientID, nil)
			} else {
				writePacket(s, cmdOKAY, st.serverID, st.clientID, nil)
			}
		case cmdCLSE:
			delete(streams, pkt.arg0)
		default:
			s.LogRaw("ADB_MALFORMED", "unexpected "+pkt.command)
			return
		}
	}
}

func (pr *Protocol) banner() string {
	return fmt.Sprintf("device::ro.product.name=%s;ro.product.model=%s;ro.product.device=%s;ro.product.cpu.abi=%s;features=shell_v2,cmd,sync",
		pr.persona.Hostname, pr.persona.Hostname, pr.persona.Hostname, adbABI(pr.persona))
}

func adbABI(p *persona.Persona) string {
	switch p.Arch {
	case "aarch64":
		return "arm64-v8a"
	case "armv7l", "armv6l":
		return "armeabi-v7a"
	case "x86_64":
		return "x86_64"
	default:
		return "armeabi-v7a"
	}
}

func (pr *Protocol) handleShell(s *server.Session, serverID, clientID uint32, cmd string) {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		writePacket(s, cmdCLSE, serverID, clientID, nil)
		return
	}
	s.LogCommandNote(cmd, "adb-shell")
	out, _ := shell.RunOnceCaptured(s, pr.fs, pr.persona, "root", "ubuntu", nil, cmd)
	for len(out) > 0 {
		n := adbMaxData
		if len(out) < n {
			n = len(out)
		}
		writePacket(s, cmdWRTE, serverID, clientID, []byte(out[:n]))
		if !readStreamOKAY(s, serverID, clientID) {
			return
		}
		out = out[n:]
	}
	writePacket(s, cmdCLSE, serverID, clientID, nil)
}

func readStreamOKAY(s *server.Session, serverID, clientID uint32) bool {
	pkt, ok := readPacket(s)
	if !ok {
		return false
	}
	if pkt.command != cmdOKAY || pkt.arg0 != clientID || pkt.arg1 != serverID {
		s.LogRaw("ADB_MALFORMED", "expected stream OKAY")
		return false
	}
	return true
}

type packet struct {
	command string
	arg0    uint32
	arg1    uint32
	payload []byte
}

func readPacket(s *server.Session) (packet, bool) {
	header := s.ReadN(24)
	if len(header) != 24 {
		return packet{}, false
	}
	command := string(header[:4])
	length := binary.LittleEndian.Uint32(header[12:16])
	if length > maxADBPayload {
		s.LogRaw("ADB_MALFORMED", fmt.Sprintf("%s payload length %d exceeds limit", command, length))
		return packet{}, false
	}
	wantMagic := commandValue(command) ^ 0xffffffff
	if got := binary.LittleEndian.Uint32(header[20:24]); got != wantMagic {
		s.LogRaw("ADB_MALFORMED", fmt.Sprintf("%s bad magic %#x", command, got))
		return packet{}, false
	}
	payload := s.ReadN(int(length))
	if len(payload) != int(length) {
		return packet{}, false
	}
	if got, want := binary.LittleEndian.Uint32(header[16:20]), checksum(payload); got != want {
		s.LogRaw("ADB_MALFORMED", fmt.Sprintf("%s bad checksum %#x", command, got))
		return packet{}, false
	}
	return packet{
		command: command,
		arg0:    binary.LittleEndian.Uint32(header[4:8]),
		arg1:    binary.LittleEndian.Uint32(header[8:12]),
		payload: payload,
	}, true
}

func writePacket(s *server.Session, command string, arg0, arg1 uint32, payload []byte) {
	out := make([]byte, 24+len(payload))
	copy(out[:4], command)
	binary.LittleEndian.PutUint32(out[4:8], arg0)
	binary.LittleEndian.PutUint32(out[8:12], arg1)
	binary.LittleEndian.PutUint32(out[12:16], uint32(len(payload)))
	binary.LittleEndian.PutUint32(out[16:20], checksum(payload))
	binary.LittleEndian.PutUint32(out[20:24], commandValue(command)^0xffffffff)
	copy(out[24:], payload)
	s.WriteBytes(out)
}

func commandValue(command string) uint32 {
	return binary.LittleEndian.Uint32([]byte(command))
}

func checksum(payload []byte) uint32 {
	var sum uint32
	for _, b := range payload {
		sum += uint32(b)
	}
	return sum
}

type syncStream struct {
	serverID uint32
	clientID uint32
	path     string
	content  []byte
}

func (st *syncStream) consume(s *server.Session, payload []byte) bool {
	for len(payload) >= 8 {
		id := string(payload[:4])
		size := binary.LittleEndian.Uint32(payload[4:8])
		payload = payload[8:]
		switch id {
		case "SEND":
			if size > uint32(len(payload)) {
				return false
			}
			n := int(size)
			if len(payload) < n {
				return false
			}
			name := string(payload[:n])
			payload = payload[n:]
			if i := strings.LastIndexByte(name, ','); i >= 0 {
				name = name[:i]
			}
			st.path = name
		case "DATA":
			if size > uint32(len(payload)) {
				return false
			}
			n := int(size)
			if len(payload) < n {
				return false
			}
			room := maxSyncPayload - len(st.content)
			if room > 0 {
				chunk := payload[:n]
				if len(chunk) > room {
					chunk = chunk[:room]
				}
				st.content = append(st.content, chunk...)
			}
			payload = payload[n:]
		case "DONE":
			if st.path == "" {
				st.path = "adb-sync-push"
			}
			s.LogDropper(st.path, "adb sync push", st.content)
			return true
		default:
			s.LogRaw("ADB_MALFORMED", "bad sync record "+id)
			return false
		}
	}
	return false
}
