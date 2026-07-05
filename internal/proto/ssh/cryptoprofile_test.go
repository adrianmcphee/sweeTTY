package ssh

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"sweetty/internal/fakehost"
	"sweetty/internal/persona"
	"sweetty/internal/testharness"
)

func TestProfileForParsesVersion(t *testing.T) {
	for _, tt := range []struct {
		in      string
		wantKey string
	}{
		{"OpenSSH_8.9p1 Ubuntu-3ubuntu0.7", "8.9"},
		{"OpenSSH_9.6p1", "9.6"},
		{"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11", "8.2"},
		{"garbage", ""},
		{"", ""},
	} {
		if got := profileKey(tt.in); got != tt.wantKey {
			t.Errorf("profileKey(%q) = %q, want %q", tt.in, got, tt.wantKey)
		}
	}

	want := cryptoProfiles[newestCryptoProfile].clone()
	if got := profileFor("not-openssh"); !reflect.DeepEqual(got, want) {
		t.Fatalf("unknown OpenSSH version did not fall back to newest profile:\n got %+v\nwant %+v", got, want)
	}
}

func TestCryptoProfileVariesAcrossVersions(t *testing.T) {
	seen := map[string]string{}
	for key, prof := range cryptoProfiles {
		fp := strings.Join(prof.kex, ",") + "|" + strings.Join(prof.ciphers, ",") + "|" + strings.Join(prof.macs, ",")
		seen[fp] = key
	}
	if len(seen) < 2 {
		t.Fatalf("crypto profiles do not vary across versions: %v", seen)
	}
}

func TestCryptoProfileMatchesBannerVersion(t *testing.T) {
	for key, prof := range cryptoProfiles {
		t.Run(key, func(t *testing.T) {
			h, p := newProfileSSH(t, key)
			banner, offer := readServerKexInit(t, h.Addr())

			if want := "SSH-2.0-" + p.OpenSSHVer + "\r\n"; banner != want {
				t.Fatalf("server banner = %q, want %q", banner, want)
			}
			if got := withoutKexExtensions(offer.kex); !slices.Equal(got, prof.kex) {
				t.Fatalf("KEX offer for %s:\n got %v\nwant %v", p.OpenSSHVer, got, prof.kex)
			}
			if !slices.Equal(offer.ciphersClientServer, prof.ciphers) || !slices.Equal(offer.ciphersServerClient, prof.ciphers) {
				t.Fatalf("cipher offer for %s:\n c2s %v\n s2c %v\nwant %v", p.OpenSSHVer, offer.ciphersClientServer, offer.ciphersServerClient, prof.ciphers)
			}
			if !slices.Equal(offer.macsClientServer, prof.macs) || !slices.Equal(offer.macsServerClient, prof.macs) {
				t.Fatalf("MAC offer for %s:\n c2s %v\n s2c %v\nwant %v", p.OpenSSHVer, offer.macsClientServer, offer.macsServerClient, prof.macs)
			}
		})
	}
}

func TestOfferedAlgorithmsAreImplemented(t *testing.T) {
	for key, prof := range cryptoProfiles {
		t.Run(key, func(t *testing.T) {
			h, p := newProfileSSH(t, key)
			for _, kex := range prof.kex {
				t.Run("kex/"+kex, func(t *testing.T) {
					algs := dialWithAlgorithms(t, h, p, gossh.Config{
						KeyExchanges: []string{kex},
						Ciphers:      prof.ciphers,
						MACs:         prof.macs,
					})
					if algs.KeyExchange != kex {
						t.Fatalf("negotiated KEX = %q, want %q", algs.KeyExchange, kex)
					}
				})
			}
			for _, cipher := range prof.ciphers {
				t.Run("cipher/"+cipher, func(t *testing.T) {
					algs := dialWithAlgorithms(t, h, p, gossh.Config{
						KeyExchanges: prof.kex,
						Ciphers:      []string{cipher},
						MACs:         prof.macs,
					})
					if algs.Read.Cipher != cipher || algs.Write.Cipher != cipher {
						t.Fatalf("negotiated cipher read/write = %q/%q, want %q", algs.Read.Cipher, algs.Write.Cipher, cipher)
					}
				})
			}
			for _, mac := range prof.macs {
				t.Run("mac/"+mac, func(t *testing.T) {
					algs := dialWithAlgorithms(t, h, p, gossh.Config{
						KeyExchanges: prof.kex,
						Ciphers:      []string{"aes128-ctr"},
						MACs:         []string{mac},
					})
					if algs.Read.MAC != mac || algs.Write.MAC != mac {
						t.Fatalf("negotiated MAC read/write = %q/%q, want %q", algs.Read.MAC, algs.Write.MAC, mac)
					}
				})
			}
		})
	}
}

func newProfileSSH(t *testing.T, key string) (*testharness.Harness, *persona.Persona) {
	t.Helper()
	p := persona.Generate()
	p.OpenSSHVer = "OpenSSH_" + key + "p1 Ubuntu-test"
	fs, err := fakehost.Load(p)
	if err != nil {
		t.Fatalf("load fakehost: %v", err)
	}
	h, err := testharness.NewListener(New(fs, p, ""))
	if err != nil {
		t.Fatalf("start ssh harness: %v", err)
	}
	t.Cleanup(h.Close)
	return h, p
}

func dialWithAlgorithms(t *testing.T, h *testharness.Harness, p *persona.Persona, algos gossh.Config) gossh.NegotiatedAlgorithms {
	t.Helper()
	client, err := gossh.Dial("tcp", h.Addr(), &gossh.ClientConfig{
		Config:          algos,
		User:            "root",
		Auth:            []gossh.AuthMethod{gossh.Password(p.RootPassword)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("handshake with %+v failed: %v", algos, err)
	}
	defer client.Close()
	algConn, ok := client.Conn.(gossh.AlgorithmsConnMetadata)
	if !ok {
		t.Fatal("client connection does not expose negotiated algorithms")
	}
	return algConn.Algorithms()
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
