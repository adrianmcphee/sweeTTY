package ssh

import (
	"slices"
	"strings"
)

// cryptoProfile is the SSH algorithm offer for one advertised OpenSSH release,
// reduced to the names x/crypto can negotiate as a server and kept in
// OpenSSH-style preference order. Names OpenSSH offers but x/crypto lacks, such as
// sntrup and umac, stay omitted as the documented cost of completing a real
// handshake.
type cryptoProfile struct {
	kex     []string
	ciphers []string
	macs    []string
}

func (p cryptoProfile) clone() cryptoProfile {
	return cryptoProfile{
		kex:     slices.Clone(p.kex),
		ciphers: slices.Clone(p.ciphers),
		macs:    slices.Clone(p.macs),
	}
}

const newestCryptoProfile = "9.6"

var cryptoProfiles = map[string]cryptoProfile{
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

func profileFor(openSSHVer string) cryptoProfile {
	if prof, ok := cryptoProfiles[profileKey(openSSHVer)]; ok {
		return prof.clone()
	}
	return cryptoProfiles[newestCryptoProfile].clone()
}

func profileKey(openSSHVer string) string {
	s := openSSHVer
	const marker = "OpenSSH_"
	if strings.HasPrefix(s, marker) {
		s = strings.TrimPrefix(s, marker)
	} else if i := strings.Index(s, marker); i >= 0 {
		s = s[i+len(marker):]
	}
	if s == "" || !isDigit(s[0]) {
		return ""
	}
	end := 0
	for end < len(s) && (isDigit(s[end]) || s[end] == '.') {
		end++
	}
	parts := strings.Split(s[:end], ".")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return ""
	}
	return parts[0] + "." + parts[1]
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }
