// Package redis implements an unauthenticated Redis honeypot surface. It speaks
// enough RESP for the write-primitive chain attackers use: CONFIG SET dir,
// CONFIG SET dbfilename, SET payload, and SAVE. The chain is recorded as a
// dropper and never writes a byte to the host filesystem.
package redis

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"sweetty/internal/persona"
	"sweetty/internal/server"
)

const (
	defaultDir        = "/var/lib/redis"
	defaultDBFilename = "dump.rdb"
	maxRedisArgs      = 64
	maxRedisBulk      = 64 * 1024
)

type Protocol struct {
	persona *persona.Persona
}

func New(p *persona.Persona) server.Protocol {
	return &Protocol{persona: p}
}

func (pr *Protocol) Name() string { return "redis" }

func (pr *Protocol) ClientFirst() bool { return true }

func (pr *Protocol) Handle(s *server.Session) {
	s.Persona = pr.persona
	state := redisState{dir: defaultDir, dbfilename: defaultDBFilename}

	for {
		args, ok := readCommand(s)
		if !ok {
			return
		}
		if len(args) == 0 {
			continue
		}
		cmd := strings.ToUpper(args[0])
		s.LogCommand(commandLine(args))
		switch cmd {
		case "PING":
			if len(args) > 1 {
				writeBulk(s, args[1])
			} else {
				writeSimple(s, "PONG")
			}
		case "INFO":
			writeBulk(s, pr.info())
		case "CONFIG":
			handleConfig(s, &state, args)
		case "AUTH":
			handleAuth(s, args)
		case "SELECT":
			writeSimple(s, "OK")
		case "SET":
			handleSet(s, &state, args)
		case "SAVE", "BGSAVE":
			handleSave(s, &state)
		case "QUIT":
			writeSimple(s, "OK")
			return
		default:
			writeError(s, "ERR unknown command '"+args[0]+"'")
		}
	}
}

type redisState struct {
	dir        string
	dbfilename string
	lastKey    string
	lastValue  string
}

func (pr *Protocol) info() string {
	uptime := int64(0)
	if pr.persona.BootEpoch > 0 {
		uptime = time.Now().Unix() - pr.persona.BootEpoch
		if uptime < 0 {
			uptime = 0
		}
	}
	return fmt.Sprintf(`# Server
redis_version:%s
redis_git_sha1:00000000
redis_git_dirty:0
redis_build_id:7f5f2d0f4d4c9a1b
redis_mode:standalone
os:Linux %s %s
arch_bits:64
tcp_port:6379
uptime_in_seconds:%d

# Clients
connected_clients:1

# Memory
used_memory_human:3.12M

# Replication
role:master
connected_slaves:0

# Persistence
loading:0
`, pr.persona.RedisVer, pr.persona.KernelRel, pr.persona.Arch, uptime)
}

func handleConfig(s *server.Session, st *redisState, args []string) {
	if len(args) < 2 {
		writeError(s, "ERR wrong number of arguments for 'config' command")
		return
	}
	switch strings.ToUpper(args[1]) {
	case "GET":
		if len(args) < 3 {
			writeError(s, "ERR wrong number of arguments for 'config get' command")
			return
		}
		switch strings.ToLower(args[2]) {
		case "dir":
			writeArray(s, []string{"dir", st.dir})
		case "dbfilename":
			writeArray(s, []string{"dbfilename", st.dbfilename})
		default:
			writeArray(s, nil)
		}
	case "SET":
		if len(args) < 4 {
			writeError(s, "ERR wrong number of arguments for 'config set' command")
			return
		}
		switch strings.ToLower(args[2]) {
		case "dir":
			st.dir = args[3]
		case "dbfilename":
			st.dbfilename = args[3]
		}
		writeSimple(s, "OK")
	default:
		writeError(s, "ERR unsupported CONFIG subcommand")
	}
}

func handleAuth(s *server.Session, args []string) {
	switch len(args) {
	case 2:
		s.LogCredential("default", args[1])
	case 3:
		s.LogCredential(args[1], args[2])
	default:
		writeError(s, "ERR wrong number of arguments for 'auth' command")
		return
	}
	writeSimple(s, "OK")
}

func handleSet(s *server.Session, st *redisState, args []string) {
	if len(args) < 3 {
		writeError(s, "ERR wrong number of arguments for 'set' command")
		return
	}
	st.lastKey = args[1]
	st.lastValue = args[2]
	if raw, host := firstURL(args[2]); raw != "" {
		s.LogDownload("redis set "+args[1], raw, host, "")
	}
	writeSimple(s, "OK")
}

func handleSave(s *server.Session, st *redisState) {
	if st.lastValue != "" {
		s.LogDropper(redisTarget(st.dir, st.dbfilename), "redis save "+st.lastKey, []byte(st.lastValue))
	}
	writeSimple(s, "OK")
}

func redisTarget(dir, filename string) string {
	if filename == "" {
		filename = defaultDBFilename
	}
	if strings.HasPrefix(filename, "/") {
		return filename
	}
	dir = strings.TrimRight(dir, "/")
	if dir == "" {
		return "/" + filename
	}
	return dir + "/" + filename
}

func readCommand(s *server.Session) ([]string, bool) {
	line, ok := s.ReadLine()
	if !ok {
		return nil, false
	}
	if line == "" {
		return nil, true
	}
	if !strings.HasPrefix(line, "*") {
		return strings.Fields(line), true
	}
	count, err := strconv.Atoi(strings.TrimPrefix(line, "*"))
	if err != nil || count < 0 || count > maxRedisArgs {
		malformed(s, "bad array length "+line)
		return nil, false
	}
	args := make([]string, 0, count)
	for range count {
		bulkHeader, ok := s.ReadLine()
		if !ok {
			return nil, false
		}
		if !strings.HasPrefix(bulkHeader, "$") {
			malformed(s, "expected bulk string, got "+bulkHeader)
			return nil, false
		}
		n, err := strconv.Atoi(strings.TrimPrefix(bulkHeader, "$"))
		if err != nil || n < 0 || n > maxRedisBulk {
			malformed(s, "bad bulk length "+bulkHeader)
			return nil, false
		}
		raw := s.ReadN(n + 2)
		if len(raw) != n+2 || raw[n] != '\r' || raw[n+1] != '\n' {
			malformed(s, "short bulk string")
			return nil, false
		}
		args = append(args, string(raw[:n]))
	}
	return args, true
}

func malformed(s *server.Session, msg string) {
	s.LogRaw("REDIS_MALFORMED", msg)
	writeError(s, "ERR Protocol error")
}

func writeSimple(s *server.Session, msg string) {
	s.Write("+" + msg + "\r\n")
}

func writeError(s *server.Session, msg string) {
	s.Write("-" + msg + "\r\n")
}

func writeBulk(s *server.Session, msg string) {
	s.Write("$" + strconv.Itoa(len(msg)) + "\r\n" + msg + "\r\n")
}

func writeArray(s *server.Session, values []string) {
	s.Write("*" + strconv.Itoa(len(values)) + "\r\n")
	for _, v := range values {
		writeBulk(s, v)
	}
}

func commandLine(args []string) string {
	var b strings.Builder
	for i, arg := range args {
		if i > 0 {
			b.WriteByte(' ')
		}
		if strings.ContainsAny(arg, " \t\r\n") {
			b.WriteString(strconv.Quote(arg))
		} else {
			b.WriteString(arg)
		}
	}
	return b.String()
}

func firstURL(s string) (string, string) {
	for _, f := range strings.Fields(s) {
		token := strings.Trim(f, `"'()<>[]{};,`)
		if !strings.HasPrefix(token, "http://") && !strings.HasPrefix(token, "https://") {
			continue
		}
		u, err := url.Parse(token)
		if err != nil || u.Host == "" {
			continue
		}
		return token, u.Hostname()
	}
	return "", ""
}
