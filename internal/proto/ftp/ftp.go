// Package ftp implements an interactive FTP banner-and-tarpit service. It greets
// the client with a realistic server banner derived from the instance persona,
// then accepts the login dialogue far enough to capture submitted credentials.
// Every login is rejected and no filesystem command is ever honored, so nothing
// is fetched, executed, or written: the service only records and stalls.
package ftp

import (
	"fmt"
	"strings"
	"time"

	"sweetty/internal/persona"
	"sweetty/internal/server"
)

// maxFailedLogins is how many rejected PASS attempts are allowed before the
// service stalls and drops the connection, mimicking a server giving up.
const maxFailedLogins = 3

// passDelay mimics the brief pause a real server takes verifying credentials and
// slows down brute-force clients.
const passDelay = 1 * time.Second

// lockoutDelay holds the connection after too many failures before closing.
const lockoutDelay = 3 * time.Second

// FEAT lists captured from the real daemons (vsftpd 3.0.x and Pure-FTPd verbatim;
// ProFTPD from its documented default). They differ enough that one shared list
// would disqualify a non-vsftpd banner — Pure-FTPd/ProFTPD advertise MLST/MLSD,
// which vsftpd does not. The TLS-related lines (AUTH TLS/PBSZ/PROT) are omitted
// because the tarpit never negotiates TLS, matching the no-[TLS] banner.
const (
	featVsftpd = "211-Features:\r\n EPRT\r\n EPSV\r\n MDTM\r\n PASV\r\n REST STREAM\r\n SIZE\r\n TVFS\r\n UTF8\r\n211 End\r\n"

	featPureFTPd = "211-Extensions supported:\r\n UTF8\r\n EPRT\r\n IDLE\r\n MDTM\r\n SIZE\r\n MFMT\r\n REST STREAM\r\n" +
		" MLST type*;size*;sizd*;modify*;UNIX.mode*;UNIX.uid*;UNIX.gid*;unique*;\r\n MLSD\r\n PRET\r\n TVFS\r\n ESTA\r\n PASV\r\n EPSV\r\n211 End.\r\n"

	featProFTPD = "211-Features:\r\n EPRT\r\n EPSV\r\n MDTM\r\n MFMT\r\n" +
		" MLST modify*;perm*;size*;type*;unique*;UNIX.group*;UNIX.mode*;UNIX.owner*;\r\n MLSD\r\n LANG en-US.UTF-8\r\n REST STREAM\r\n SIZE\r\n TVFS\r\n UTF8\r\n211 End\r\n"
)

// knownVerbs are standard FTP commands a real daemon recognises. ProFTPD answers an
// unknown verb with "500 ... not understood" but a recognised one (pre-login) with
// 530; vsftpd and Pure-FTPd answer 530 to everything pre-login, so this map only
// distinguishes the ProFTPD case.
var knownVerbs = map[string]bool{
	"CWD": true, "CDUP": true, "PWD": true, "LIST": true, "NLST": true,
	"RETR": true, "STOR": true, "STOU": true, "APPE": true, "DELE": true,
	"MKD": true, "RMD": true, "RNFR": true, "RNTO": true, "TYPE": true,
	"PASV": true, "EPSV": true, "PORT": true, "EPRT": true, "SIZE": true,
	"MDTM": true, "MLSD": true, "MLST": true, "REST": true, "ABOR": true,
	"STAT": true, "ACCT": true, "SITE": true, "HELP": true, "MODE": true,
	"STRU": true, "ALLO": true, "OPTS": true, "AUTH": true,
}

// Protocol is the FTP banner-and-tarpit. It carries the instance persona so the
// advertised server software and version match the rest of the host's identity.
type Protocol struct {
	persona *persona.Persona
}

// New returns an FTP protocol bound to the given persona.
func New(p *persona.Persona) server.Protocol {
	return &Protocol{persona: p}
}

// Name reports the protocol label used in logs and startup output.
func (pr *Protocol) Name() string { return "ftp" }

// ClientFirst is false: an FTP server sends its banner first.
func (pr *Protocol) ClientFirst() bool { return false }

// Handle greets the client, then loops over the login dialogue, capturing any
// credentials and rejecting every login until the connection ends or the failure
// limit is reached.
func (pr *Protocol) Handle(s *server.Session) {
	s.Persona = pr.persona

	s.Write(pr.banner())

	var user string
	failed := 0
	for {
		line, ok := s.ReadLine()
		if !ok {
			return
		}
		cmd, arg := splitCommand(line)
		switch cmd {
		case "USER":
			user = arg
			s.Write("331 Please specify the password.\r\n")
		case "PASS":
			if user == "" {
				// PASS before USER: real daemons reject the sequence, not the login.
				s.Write("503 Login with USER first.\r\n")
				continue
			}
			// A real server takes a beat to check credentials; the pause also
			// throttles brute-force clients.
			time.Sleep(passDelay)
			s.LogCredential(user, arg)
			s.Write("530 Login incorrect.\r\n")
			failed++
			if failed >= maxFailedLogins {
				time.Sleep(lockoutDelay)
				return
			}
		case "QUIT":
			s.Write("221 Goodbye.\r\n")
			return
		case "SYST":
			// vsftpd gates SYST behind login (530); ProFTPD and Pure-FTPd answer it
			// pre-login (215), as captured from the real daemons.
			if pr.software() == "vsftpd" {
				s.Write("530 Please login with USER and PASS.\r\n")
			} else {
				s.Write("215 UNIX Type: L8\r\n")
			}
		case "FEAT":
			s.Write(pr.feat())
		case "NOOP":
			s.Write("200 NOOP ok.\r\n")
		default:
			s.Write(pr.unhandled(cmd))
		}
	}
}

// banner renders a realistic greeting for the persona's FTP software and
// version. An unknown or empty software name falls back to a generic vsFTPd
// banner, the most common default on Linux hosts.
func (pr *Protocol) banner() string {
	ver := pr.persona.FTPVer
	switch pr.persona.FTPSoftware {
	case "proftpd":
		// Real ProFTPD greets with the version, the ServerName, and the connecting
		// address: "220 ProFTPD <ver> Server (<name>) [<ip>]". "Server ready." is
		// not a form ProFTPD ever emits.
		return fmt.Sprintf("220 ProFTPD %s Server (%s) [::ffff:%s]\r\n", ver, pr.persona.Hostname, pr.persona.HostIP)
	case "pure-ftpd":
		// No [TLS] tag: the tarpit never negotiates TLS, so advertising the
		// capability and then refusing AUTH TLS would be a contradiction.
		return "220---------- Welcome to Pure-FTPd [privsep] ----------\r\n" +
			"220-This is a private system - No anonymous login\r\n" +
			"220 You are user number 1 of 50 allowed.\r\n"
	case "vsftpd":
		return fmt.Sprintf("220 (vsFTPd %s)\r\n", ver)
	default:
		if ver == "" {
			ver = "3.0.5"
		}
		return fmt.Sprintf("220 (vsFTPd %s)\r\n", ver)
	}
}

// software returns the persona's FTP daemon, defaulting to vsftpd (the most common
// Linux default) for an unknown or empty value.
func (pr *Protocol) software() string {
	switch pr.persona.FTPSoftware {
	case "proftpd", "pure-ftpd":
		return pr.persona.FTPSoftware
	default:
		return "vsftpd"
	}
}

// feat returns the daemon-specific FEAT response.
func (pr *Protocol) feat() string {
	switch pr.software() {
	case "pure-ftpd":
		return featPureFTPd
	case "proftpd":
		return featProFTPD
	default:
		return featVsftpd
	}
}

// unhandled returns the reply for a command the tarpit does not service. vsftpd and
// Pure-FTPd answer 530 to everything pre-login (with their own text); ProFTPD
// answers 530 to a recognised command but "500 ... not understood" to an unknown
// verb — the one-packet differentials a honeypot-aware client probes.
func (pr *Protocol) unhandled(cmd string) string {
	switch pr.software() {
	case "pure-ftpd":
		return "530 You aren't logged in.\r\n"
	case "proftpd":
		if knownVerbs[cmd] {
			return "530 Please login with USER and PASS first.\r\n"
		}
		return "500 " + cmd + " not understood.\r\n"
	default: // vsftpd
		return "530 Please login with USER and PASS.\r\n"
	}
}

// splitCommand splits an FTP command line into an upper-cased verb and its
// argument. The verb is case-insensitive per the protocol; the argument is left
// untouched so captured usernames and passwords keep their original case.
func splitCommand(line string) (cmd, arg string) {
	line = strings.TrimSpace(line)
	if i := strings.IndexByte(line, ' '); i >= 0 {
		return strings.ToUpper(line[:i]), strings.TrimSpace(line[i+1:])
	}
	return strings.ToUpper(line), ""
}
