package adversary

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"

	"sweetty/internal/fakehost"
	"sweetty/internal/persona"
	"sweetty/internal/proto/ftp"
	httpproto "sweetty/internal/proto/http"
	sshproto "sweetty/internal/proto/ssh"
	"sweetty/internal/proto/telnet"
	"sweetty/internal/server"
	"sweetty/internal/testharness"
	"sweetty/internal/vfs"
)

type adversaryHost struct {
	p  *persona.Persona
	fs *vfs.FS
}

func TestSSHAlgorithmOfferMatchesBanner(t *testing.T) {
	for key, want := range expectedSSHProfiles {
		t.Run(key, func(t *testing.T) {
			host := newAdversaryHost(t)
			host.p.OpenSSHVer = "OpenSSH_" + key + "p1 Ubuntu-test"
			host.fs = loadFakehost(t, host.p)
			h := startSSH(t, host)

			banner, offer := readServerKexInit(t, h.Addr())
			if wantBanner := "SSH-2.0-" + host.p.OpenSSHVer + "\r\n"; banner != wantBanner {
				t.Fatalf("banner = %q, want %q", banner, wantBanner)
			}
			assertOfferMatchesProfile(t, offer, want)
		})
	}
}

func TestSSHOfferIsStableAcrossHandshakes(t *testing.T) {
	host := newAdversaryHost(t)
	h := startSSH(t, host)

	bannerA, offerA := readServerKexInit(t, h.Addr())
	bannerB, offerB := readServerKexInit(t, h.Addr())

	if bannerA != bannerB {
		t.Fatalf("SSH banner changed across handshakes: %q then %q", bannerA, bannerB)
	}
	if !reflect.DeepEqual(offerA, offerB) {
		t.Fatalf("SSH offer changed across handshakes:\nfirst:  %+v\nsecond: %+v", offerA, offerB)
	}
}

func TestBannersAgreeAcrossServices(t *testing.T) {
	host := newAdversaryHost(t)

	sshBanner := firstResponse(t, sshproto.New(host.fs, host.p, ""), "")
	if !strings.Contains(sshBanner, "SSH-2.0-"+host.p.OpenSSHVer) {
		t.Fatalf("ssh banner missing OpenSSH version %q: %q", host.p.OpenSSHVer, sshBanner)
	}

	ftpBanner := firstResponse(t, ftp.New(host.p), "")
	if !strings.HasPrefix(ftpBanner, "220") {
		t.Fatalf("ftp did not greet with 220: %q", ftpBanner)
	}
	if host.p.FTPSoftware != "pure-ftpd" && !strings.Contains(ftpBanner, host.p.FTPVer) {
		t.Fatalf("ftp banner missing persona version %q: %q", host.p.FTPVer, ftpBanner)
	}

	get := "GET / HTTP/1.1\r\nHost: attacker.invalid\r\n\r\n"
	wp := firstResponse(t, httpproto.New(host.fs, host.p, "wordpress"), get)
	for _, want := range []string{
		"Apache/" + host.p.ApacheVer + " (Ubuntu)",
		"PHP/" + host.p.PHPVer,
		"WordPress " + host.p.WPVer,
	} {
		if !strings.Contains(wp, want) {
			t.Fatalf("wordpress response missing %q", want)
		}
	}

	nginx := firstResponse(t, httpproto.New(host.fs, host.p, "nginx-static"), get)
	if !strings.Contains(nginx, "Server: nginx/"+host.p.NginxVer+"\r\n") {
		t.Fatalf("nginx response missing version %q: %q", host.p.NginxVer, firstLine(nginx))
	}

	tomcat := firstResponse(t, httpproto.New(host.fs, host.p, "tomcat"), get)
	if !strings.Contains(tomcat, "Apache Tomcat/"+host.p.TomcatVer) {
		t.Fatalf("tomcat response missing version %q", host.p.TomcatVer)
	}

	telnetStory := telnetShellOutput(t, host, "uname -a; cat /etc/hostname; cat /etc/os-release")
	for _, want := range []string{host.p.KernelRel, host.p.Hostname, host.p.PrettyName} {
		if !strings.Contains(telnetStory, want) {
			t.Fatalf("telnet story missing %q:\n%s", want, telnetStory)
		}
	}
}

func TestListingAndReadNeverDisagree(t *testing.T) {
	host := newAdversaryHost(t)
	h := startSSH(t, host)
	client := sshClient(t, h, host.p)
	defer client.Close()

	run := func(cmd string) (string, error) {
		return sshExec(t, client, cmd)
	}
	dirs := []string{"/etc", "/var/log", "/var/lib/dpkg"}
	if err := probeListingAndRead(run, dirs); err != nil {
		t.Fatal(err)
	}

	t.Run("detects size mismatch", func(t *testing.T) {
		lyingRun := func(cmd string) (string, error) {
			switch cmd {
			case "ls -l /etc":
				return "-rw-r--r--  1 root     root            5 Jan  2 03:04 passwd\n", nil
			case "cat /etc/passwd":
				return "abc", nil
			default:
				return "", fmt.Errorf("unexpected command %q", cmd)
			}
		}
		if err := probeListingAndRead(lyingRun, []string{"/etc"}); err == nil {
			t.Fatal("probe accepted a listing/read size mismatch")
		}
	})
}

func TestRepeatedListingsAreStable(t *testing.T) {
	host := newAdversaryHost(t)
	h := startSSH(t, host)
	client := sshClient(t, h, host.p)
	defer client.Close()

	for _, dir := range []string{"/etc", "/var/log", "/var/lib/dpkg"} {
		t.Run(dir, func(t *testing.T) {
			assertRepeatedListingStable(t, client, dir)
		})
	}
}

func TestNoServiceLeaksHostIdentity(t *testing.T) {
	host := newAdversaryHost(t)
	tokens := realHostLeakTokens(t, host.p)
	if len(tokens) == 0 {
		t.Skip("no useful real host identity tokens to compare")
	}

	h := startSSH(t, host)
	client := sshClient(t, h, host.p)
	defer client.Close()

	outputs := map[string]string{}
	outputs["ssh-release-probe"] = mustSSHExec(t, client, "uname -a; cat /etc/hostname; cat /proc/version; cat /proc/cpuinfo | head -20")
	outputs["ssh-banner"] = string(client.ServerVersion())
	outputs["ftp-banner"] = firstResponse(t, ftp.New(host.p), "")
	outputs["http-wordpress"] = firstResponse(t, httpproto.New(host.fs, host.p, "wordpress"), "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	outputs["telnet-release-probe"] = telnetShellOutput(t, host, "uname -a; cat /etc/hostname; cat /proc/version")

	for name, out := range outputs {
		for _, token := range tokens {
			if strings.Contains(out, token) {
				t.Fatalf("%s leaked real host token %q:\n%s", name, token, out)
			}
		}
	}
}

func newAdversaryHost(t *testing.T) adversaryHost {
	t.Helper()
	p := persona.GenerateProfile("full")
	return adversaryHost{p: p, fs: loadFakehost(t, p)}
}

func loadFakehost(t *testing.T, p *persona.Persona) *vfs.FS {
	t.Helper()
	fs, err := fakehost.Load(p)
	if err != nil {
		t.Fatalf("load fakehost: %v", err)
	}
	return fs
}

func startSSH(t *testing.T, host adversaryHost) *testharness.Harness {
	t.Helper()
	h, err := testharness.NewListener(sshproto.New(host.fs, host.p, ""))
	if err != nil {
		t.Fatalf("start ssh harness: %v", err)
	}
	t.Cleanup(h.Close)
	return h
}

func sshClient(t *testing.T, h *testharness.Harness, p *persona.Persona) *gossh.Client {
	t.Helper()
	cfg := &gossh.ClientConfig{
		User:            "root",
		Auth:            []gossh.AuthMethod{gossh.Password(p.RootPassword)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	client, err := gossh.Dial("tcp", h.Addr(), cfg)
	if err != nil {
		t.Fatalf("ssh auth failed: %v", err)
	}
	return client
}

func sshExec(t *testing.T, client *gossh.Client, cmd string) (string, error) {
	t.Helper()
	sess, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("open ssh session: %w", err)
	}
	defer sess.Close()
	out, err := sess.CombinedOutput(cmd)
	if err != nil {
		return string(out), fmt.Errorf("run %q: %w", cmd, err)
	}
	return string(out), nil
}

func mustSSHExec(t *testing.T, client *gossh.Client, cmd string) string {
	t.Helper()
	out, err := sshExec(t, client, cmd)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func firstResponse(t *testing.T, proto server.Protocol, request string) string {
	t.Helper()
	h, err := testharness.New(proto)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.Close)
	if request != "" {
		h.Send(request)
	}
	return h.ReadFor(600 * time.Millisecond)
}

func telnetShellOutput(t *testing.T, host adversaryHost, cmd string) string {
	t.Helper()
	h, err := testharness.New(telnet.New(host.fs, host.p, "ubuntu"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.Close)
	h.ReadUntil("login:", 2*time.Second)
	h.SendLine("root")
	h.ReadUntil("Password:", 2*time.Second)
	h.SendLine(host.p.RootPassword)
	h.ReadFor(400 * time.Millisecond)
	h.SendLine(cmd)
	return h.ReadFor(700 * time.Millisecond)
}

type commandRunner func(string) (string, error)

func probeListingAndRead(run commandRunner, dirs []string) error {
	for _, dir := range dirs {
		listing, err := run("ls -l " + dir)
		if err != nil {
			return err
		}
		entry, err := firstRegularFile(listing)
		if err != nil {
			return fmt.Errorf("%s: %w", dir, err)
		}
		cat, err := run("cat " + dir + "/" + entry.name)
		if err != nil {
			return err
		}
		if got := len([]byte(cat)); got != entry.size {
			return fmt.Errorf("%s/%s: ls reported %d bytes, cat returned %d", dir, entry.name, entry.size, got)
		}
	}
	return nil
}

type listedFile struct {
	name string
	size int
}

func firstRegularFile(listing string) (listedFile, error) {
	for _, line := range strings.Split(listing, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 9 || !strings.HasPrefix(fields[0], "-") {
			continue
		}
		size, err := strconv.Atoi(fields[4])
		if err != nil {
			continue
		}
		return listedFile{name: fields[8], size: size}, nil
	}
	return listedFile{}, fmt.Errorf("no regular file in listing:\n%s", listing)
}

func assertRepeatedListingStable(t *testing.T, client *gossh.Client, dir string) {
	t.Helper()
	const marker = "__SWEETTY_ADVERSARY_LISTING_SPLIT__"
	out := mustSSHExec(t, client, "ls -la "+dir+"; echo "+marker+"; ls -la "+dir)
	parts := strings.Split(out, marker+"\n")
	if len(parts) != 2 {
		t.Fatalf("could not split repeated listing for %s:\n%s", dir, out)
	}
	if parts[0] != parts[1] {
		t.Fatalf("listing for %s changed within one session:\nfirst:\n%s\nsecond:\n%s", dir, parts[0], parts[1])
	}
}

func firstLine(s string) string {
	if i := strings.Index(s, "\r\n"); i >= 0 {
		return s[:i]
	}
	return s
}

type sshProfile struct {
	kex     []string
	ciphers []string
	macs    []string
}

var expectedSSHProfiles = map[string]sshProfile{
	"8.2": {
		kex: []string{
			"curve25519-sha256", "curve25519-sha256@libssh.org",
			"ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
			"diffie-hellman-group-exchange-sha256",
			"diffie-hellman-group16-sha512",
			"diffie-hellman-group14-sha256",
		},
		ciphers: []string{
			"chacha20-poly1305@openssh.com",
			"aes128-ctr", "aes192-ctr", "aes256-ctr",
			"aes128-gcm@openssh.com", "aes256-gcm@openssh.com",
		},
		macs: []string{
			"hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com",
			"hmac-sha1",
			"hmac-sha2-256", "hmac-sha2-512",
		},
	},
	"8.9": {
		kex: []string{
			"curve25519-sha256", "curve25519-sha256@libssh.org",
			"ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
			"diffie-hellman-group16-sha512",
			"diffie-hellman-group14-sha256",
		},
		ciphers: []string{
			"chacha20-poly1305@openssh.com",
			"aes128-gcm@openssh.com", "aes256-gcm@openssh.com",
			"aes128-ctr", "aes192-ctr", "aes256-ctr",
		},
		macs: []string{
			"hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com",
			"hmac-sha2-256", "hmac-sha2-512",
		},
	},
	"9.0": {
		kex: []string{
			"curve25519-sha256", "curve25519-sha256@libssh.org",
			"ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
			"diffie-hellman-group16-sha512",
			"diffie-hellman-group14-sha256",
		},
		ciphers: []string{
			"chacha20-poly1305@openssh.com",
			"aes128-gcm@openssh.com", "aes256-gcm@openssh.com",
			"aes128-ctr", "aes192-ctr", "aes256-ctr",
		},
		macs: []string{
			"hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com",
			"hmac-sha2-256", "hmac-sha2-512",
		},
	},
	"9.6": {
		kex: []string{
			"curve25519-sha256", "curve25519-sha256@libssh.org",
			"ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
			"diffie-hellman-group16-sha512",
		},
		ciphers: []string{
			"chacha20-poly1305@openssh.com",
			"aes128-gcm@openssh.com", "aes256-gcm@openssh.com",
			"aes128-ctr", "aes192-ctr", "aes256-ctr",
		},
		macs: []string{
			"hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com",
			"hmac-sha2-256", "hmac-sha2-512",
		},
	},
}

func assertOfferMatchesProfile(t *testing.T, offer kexInitOffer, want sshProfile) {
	t.Helper()
	if got := withoutKexExtensions(offer.kex); !slices.Equal(got, want.kex) {
		t.Fatalf("KEX offer:\n got %v\nwant %v", got, want.kex)
	}
	if !slices.Equal(offer.ciphersClientServer, want.ciphers) || !slices.Equal(offer.ciphersServerClient, want.ciphers) {
		t.Fatalf("cipher offer:\n c2s %v\n s2c %v\nwant %v", offer.ciphersClientServer, offer.ciphersServerClient, want.ciphers)
	}
	if !slices.Equal(offer.macsClientServer, want.macs) || !slices.Equal(offer.macsServerClient, want.macs) {
		t.Fatalf("MAC offer:\n c2s %v\n s2c %v\nwant %v", offer.macsClientServer, offer.macsServerClient, want.macs)
	}
}

type kexInitOffer struct {
	kex                 []string
	ciphersClientServer []string
	ciphersServerClient []string
	macsClientServer    []string
	macsServerClient    []string
}

func readServerKexInit(t *testing.T, addr string) (string, kexInitOffer) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial ssh listener: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	br := bufio.NewReader(conn)
	banner, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read server banner: %v", err)
	}
	if _, err := conn.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n")); err != nil {
		t.Fatalf("write client banner: %v", err)
	}

	var lenBuf [4]byte
	if _, err := io.ReadFull(br, lenBuf[:]); err != nil {
		t.Fatalf("read packet length: %v", err)
	}
	packetLen := binary.BigEndian.Uint32(lenBuf[:])
	packet := make([]byte, packetLen)
	if _, err := io.ReadFull(br, packet); err != nil {
		t.Fatalf("read KEXINIT packet: %v", err)
	}
	if len(packet) < 2 {
		t.Fatalf("short SSH packet: %x", packet)
	}
	paddingLen := int(packet[0])
	if paddingLen+1 >= len(packet) {
		t.Fatalf("invalid SSH packet padding: packet len %d padding %d", len(packet), paddingLen)
	}
	payload := packet[1 : len(packet)-paddingLen]
	if len(payload) < 17 || payload[0] != 20 {
		t.Fatalf("first server packet is not SSH_MSG_KEXINIT: %x", payload)
	}

	rest := payload[17:]
	var offer kexInitOffer
	offer.kex, rest = readNameList(t, rest, "kex")
	_, rest = readNameList(t, rest, "host keys")
	offer.ciphersClientServer, rest = readNameList(t, rest, "ciphers client-server")
	offer.ciphersServerClient, rest = readNameList(t, rest, "ciphers server-client")
	offer.macsClientServer, rest = readNameList(t, rest, "macs client-server")
	offer.macsServerClient, rest = readNameList(t, rest, "macs server-client")
	return banner, offer
}

func readNameList(t *testing.T, b []byte, field string) ([]string, []byte) {
	t.Helper()
	if len(b) < 4 {
		t.Fatalf("short %s name-list length", field)
	}
	n := int(binary.BigEndian.Uint32(b[:4]))
	b = b[4:]
	if len(b) < n {
		t.Fatalf("short %s name-list: need %d bytes, have %d", field, n, len(b))
	}
	if n == 0 {
		return nil, b
	}
	return strings.Split(string(b[:n]), ","), b[n:]
}

func withoutKexExtensions(kex []string) []string {
	out := make([]string, 0, len(kex))
	for _, name := range kex {
		if strings.HasPrefix(name, "kex-strict-") {
			continue
		}
		out = append(out, name)
	}
	return out
}

func realHostLeakTokens(t *testing.T, p *persona.Persona) []string {
	t.Helper()
	var tokens []string
	if host, err := os.Hostname(); err == nil {
		tokens = appendUsefulHostToken(tokens, host)
	}
	var uts unix.Utsname
	if err := unix.Uname(&uts); err == nil {
		tokens = appendUsefulHostToken(tokens, unixString(uts.Nodename[:]))
		tokens = appendUsefulHostToken(tokens, unixString(uts.Release[:]))
		tokens = appendUsefulHostToken(tokens, unixString(uts.Version[:]))
	}
	var out []string
	for _, token := range tokens {
		if token == p.Hostname || token == p.KernelRel || token == p.KernelVer {
			continue
		}
		out = append(out, token)
	}
	return slices.Compact(out)
}

func appendUsefulHostToken(tokens []string, token string) []string {
	token = strings.TrimSpace(token)
	if len(token) < 6 {
		return tokens
	}
	switch strings.ToLower(token) {
	case "localhost", "ubuntu", "darwin", "linux":
		return tokens
	default:
		return append(tokens, token)
	}
}

func unixString(b []byte) string {
	if i := slices.Index(b, byte(0)); i >= 0 {
		b = b[:i]
	}
	return string(b)
}
