// Package docker implements an unauthenticated Docker Engine API honeypot
// surface. It answers the discovery endpoints scanners read, captures image pull
// and container-escape attempts, and grants no container capability.
package docker

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"sweetty/internal/persona"
	"sweetty/internal/server"
)

const (
	maxHeaders      = 64
	maxHeaderBytes  = 128 * 1024
	maxRequestBytes = 2 * 1024 * 1024
	maxBodyBytes    = 1 << 20
)

type Protocol struct {
	persona *persona.Persona
}

func New(p *persona.Persona) server.Protocol {
	return &Protocol{persona: p}
}

func (pr *Protocol) Name() string { return "docker" }

func (pr *Protocol) ClientFirst() bool { return true }

func (pr *Protocol) Handle(s *server.Session) {
	s.Persona = pr.persona
	for {
		budget := server.NewInputBudget(maxRequestBytes)
		requestLine, ok := s.ReadLine()
		if !ok && requestLine == "" {
			budget.Release()
			return
		}
		if !budget.Reserve(len(requestLine)) {
			budget.Release()
			pr.writeText(s, 431, "Request Header Fields Too Large", "")
			return
		}
		method, target, valid := parseRequestLine(requestLine)
		if !valid {
			budget.Release()
			pr.writeText(s, 400, "Bad Request", "Bad Request\n")
			return
		}
		headers, headersOK := readHeaders(s, budget)
		if !headersOK {
			budget.Release()
			pr.writeText(s, 431, "Request Header Fields Too Large", "")
			return
		}
		body := ""
		if method == "POST" {
			bodyLen := atoiSafe(headers["content-length"])
			if bodyLen > maxBodyBytes {
				bodyLen = maxBodyBytes
			}
			if !budget.Reserve(bodyLen) {
				budget.Release()
				pr.writeText(s, 413, "Payload Too Large", "")
				return
			}
			body = string(s.ReadN(bodyLen))
		}
		pr.respond(s, method, target, body)
		budget.Release()
		if strings.EqualFold(headers["connection"], "close") {
			return
		}
	}
}

func (pr *Protocol) respond(s *server.Session, method, target, body string) {
	u, err := url.ParseRequestURI(target)
	if err != nil {
		pr.writeText(s, 400, "Bad Request", "Bad Request\n")
		return
	}
	path := dockerPath(u.Path)
	switch {
	case method == "HEAD" && path == "/_ping":
		pr.writeText(s, 200, "OK", "")
	case method == "GET" && path == "/_ping":
		pr.writeText(s, 200, "OK", "OK")
	case method == "GET" && path == "/version":
		pr.writeJSON(s, 200, "OK", map[string]any{
			"Version":       pr.persona.DockerVer,
			"ApiVersion":    dockerAPIVersion(pr.persona.DockerVer),
			"MinAPIVersion": "1.24",
			"GitCommit":     "659604f9ee",
			"GoVersion":     "go1.20.13",
			"Os":            "linux",
			"Arch":          pr.persona.Arch,
			"KernelVersion": pr.persona.KernelRel,
			"BuildTime":     "2024-04-16T12:00:00.000000000+00:00",
		})
	case method == "GET" && path == "/info":
		pr.writeJSON(s, 200, "OK", map[string]any{
			"ID":                pr.persona.MachineID,
			"Containers":        0,
			"ContainersRunning": 0,
			"Images":            2,
			"Driver":            "overlay2",
			"DockerRootDir":     "/var/lib/docker",
			"OperatingSystem":   pr.persona.PrettyName,
			"KernelVersion":     pr.persona.KernelRel,
			"Architecture":      pr.persona.Arch,
			"NCPU":              2,
			"MemTotal":          4127576064,
			"ServerVersion":     pr.persona.DockerVer,
			"Name":              pr.persona.Hostname,
		})
	case method == "GET" && path == "/containers/json":
		pr.writeJSON(s, 200, "OK", []any{})
	case method == "GET" && path == "/images/json":
		pr.writeJSON(s, 200, "OK", []map[string]any{
			{
				"Id":          "sha256:" + pr.persona.MachineID,
				"RepoTags":    []string{"ubuntu:" + pr.persona.OSCodename()},
				"Size":        77824256,
				"VirtualSize": 77824256,
			},
		})
	case method == "POST" && path == "/images/create":
		ref := imageRef(u.Query())
		if ref == "" {
			pr.writeText(s, 400, "Bad Request", "missing image reference\n")
			return
		}
		host, name := imageParts(ref)
		s.LogDownload("docker pull "+ref, ref, host, name)
		stream := fmt.Sprintf("{\"status\":\"Pulling from %s\"}\r\n{\"status\":\"Downloaded newer image for %s\"}\r\n", name, ref)
		pr.writeText(s, 200, "OK", stream)
	case method == "POST" && path == "/containers/create":
		s.LogRaw("DOCKER_CREATE", body)
		pr.writeJSON(s, 201, "Created", map[string]any{
			"Id":       "8f4f3d2c1b0a9e807060504030201000",
			"Warnings": []string{},
		})
	default:
		pr.writeJSON(s, 404, "Not Found", map[string]any{"message": "page not found"})
	}
}

func dockerPath(path string) string {
	rest := strings.TrimPrefix(path, "/")
	seg, tail, ok := strings.Cut(rest, "/")
	if !ok || !strings.HasPrefix(seg, "v") {
		return path
	}
	version := strings.TrimPrefix(seg, "v")
	if version == "" {
		return path
	}
	for _, r := range version {
		if (r < '0' || r > '9') && r != '.' {
			return path
		}
	}
	return "/" + tail
}

func parseRequestLine(line string) (method, target string, ok bool) {
	fields := strings.Fields(line)
	if len(fields) != 3 || !strings.HasPrefix(fields[2], "HTTP/") {
		return "", "", false
	}
	return strings.ToUpper(fields[0]), fields[1], true
}

func readHeaders(s *server.Session, budget *server.InputBudget) (map[string]string, bool) {
	headers := map[string]string{}
	headerBytes := 0
	for range maxHeaders {
		line, ok := s.ReadLine()
		if line == "" {
			break
		}
		headerBytes += len(line)
		if headerBytes > maxHeaderBytes || !budget.Reserve(len(line)) {
			return nil, false
		}
		if i := strings.IndexByte(line, ':'); i >= 0 {
			headers[strings.ToLower(strings.TrimSpace(line[:i]))] = strings.TrimSpace(line[i+1:])
		}
		if !ok {
			break
		}
	}
	return headers, true
}

func atoiSafe(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 0 {
		return 0
	}
	if n > 1<<20 {
		return 1 << 20
	}
	return n
}

func (pr *Protocol) writeJSON(s *server.Session, status int, reason string, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		pr.writeText(s, 500, "Internal Server Error", "{}")
		return
	}
	pr.writeResponse(s, status, reason, "application/json", string(data))
}

func (pr *Protocol) writeText(s *server.Session, status int, reason, body string) {
	pr.writeResponse(s, status, reason, "text/plain; charset=utf-8", body)
}

func (pr *Protocol) writeResponse(s *server.Session, status int, reason, contentType, body string) {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", status, reason)
	fmt.Fprintf(&b, "Api-Version: %s\r\n", dockerAPIVersion(pr.persona.DockerVer))
	b.WriteString("Docker-Experimental: false\r\n")
	b.WriteString("Ostype: linux\r\n")
	b.WriteString("Server: Docker\r\n")
	fmt.Fprintf(&b, "Content-Type: %s\r\n", contentType)
	fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
	b.WriteString("Connection: keep-alive\r\n\r\n")
	b.WriteString(body)
	s.Write(b.String())
}

func dockerAPIVersion(ver string) string {
	switch {
	case strings.HasPrefix(ver, "20.10"):
		return "1.41"
	case strings.HasPrefix(ver, "23."):
		return "1.42"
	case strings.HasPrefix(ver, "24."):
		return "1.43"
	case strings.HasPrefix(ver, "25."):
		return "1.44"
	default:
		return "1.43"
	}
}

func imageRef(values url.Values) string {
	ref := values.Get("fromImage")
	if ref == "" {
		ref = values.Get("fromSrc")
	}
	tag := values.Get("tag")
	if ref != "" && tag != "" && !strings.Contains(lastPathPart(ref), ":") {
		ref += ":" + tag
	}
	return ref
}

func imageParts(ref string) (host, name string) {
	parts := strings.SplitN(ref, "/", 2)
	if len(parts) == 2 && looksLikeRegistry(parts[0]) {
		return parts[0], parts[1]
	}
	return "", ref
}

func lastPathPart(ref string) string {
	if i := strings.LastIndexByte(ref, '/'); i >= 0 {
		return ref[i+1:]
	}
	return ref
}

func looksLikeRegistry(s string) bool {
	return strings.Contains(s, ".") || strings.Contains(s, ":") || s == "localhost"
}
