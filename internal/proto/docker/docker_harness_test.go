package docker

import (
	"encoding/json"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"sweetty/internal/persona"
	"sweetty/internal/testharness"
)

func TestDockerVersionInfoAndListingsMatchPersona(t *testing.T) {
	h, p := setupDocker(t)
	defer h.Close()

	status, body := dockerRequest(t, h, "HEAD", "/_ping", "")
	if status != "HTTP/1.1 200 OK" || body != "" {
		t.Fatalf("HEAD /_ping = %q %q, want 200 with empty body", status, body)
	}
	status, body = dockerRequest(t, h, "GET", "/_ping", "")
	if status != "HTTP/1.1 200 OK" || body != "OK" {
		t.Fatalf("GET /_ping = %q %q, want 200 OK", status, body)
	}

	status, headers, body := dockerRequestFull(t, h, "GET", "/version", "")
	if status != "HTTP/1.1 200 OK" {
		t.Fatalf("GET /version status = %q", status)
	}
	var version struct {
		Version       string `json:"Version"`
		APIVersion    string `json:"ApiVersion"`
		KernelVersion string `json:"KernelVersion"`
		Os            string `json:"Os"`
		Arch          string `json:"Arch"`
	}
	mustJSON(t, body, &version)
	if version.Version != p.DockerVer || version.KernelVersion != p.KernelRel || version.Os != "linux" || version.Arch != p.Arch {
		t.Fatalf("/version does not match persona: %+v, persona docker=%q kernel=%q arch=%q", version, p.DockerVer, p.KernelRel, p.Arch)
	}
	if version.APIVersion == "" {
		t.Fatal("/version did not advertise an API version")
	}
	if headers["api-version"] != version.APIVersion {
		t.Fatalf("Api-Version header = %q, want body ApiVersion %q", headers["api-version"], version.APIVersion)
	}

	status, body = dockerRequest(t, h, "GET", "/info", "")
	if status != "HTTP/1.1 200 OK" {
		t.Fatalf("GET /info status = %q", status)
	}
	var info struct {
		ServerVersion   string `json:"ServerVersion"`
		OperatingSystem string `json:"OperatingSystem"`
		KernelVersion   string `json:"KernelVersion"`
		Architecture    string `json:"Architecture"`
		DockerRootDir   string `json:"DockerRootDir"`
	}
	mustJSON(t, body, &info)
	if info.ServerVersion != p.DockerVer || info.OperatingSystem != p.PrettyName || info.KernelVersion != p.KernelRel || info.Architecture != p.Arch {
		t.Fatalf("/info does not match persona: %+v", info)
	}
	if info.DockerRootDir != "/var/lib/docker" {
		t.Fatalf("/info DockerRootDir = %q", info.DockerRootDir)
	}

	status, body = dockerRequest(t, h, "GET", "/v1.43/containers/json", "")
	if status != "HTTP/1.1 200 OK" || strings.TrimSpace(body) != "[]" {
		t.Fatalf("GET /v1.43/containers/json = %q %q, want 200 []", status, body)
	}
	status, body = dockerRequest(t, h, "GET", "/v1.43/images/json", "")
	if status != "HTTP/1.1 200 OK" || !strings.Contains(body, "ubuntu") {
		t.Fatalf("GET /v1.43/images/json = %q %q, want persona image listing", status, body)
	}
}

func TestDockerImagePullLogsDownloadWithoutDialing(t *testing.T) {
	h, _ := setupDocker(t)
	defer h.Close()
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
	refBase := ln.Addr().String() + "/bot/malware"
	ref := refBase + ":latest"

	status, body := dockerRequest(t, h, "POST", "/v1.43/images/create?fromImage="+url.QueryEscape(refBase)+"&tag=latest", "")
	if status != "HTTP/1.1 200 OK" || !strings.Contains(body, "Downloaded newer image") {
		t.Fatalf("image create response = %q %q", status, body)
	}
	dl, ok := h.WaitEvent("DOWNLOAD_ATTEMPT", 2*time.Second)
	if !ok {
		t.Fatal("Docker image pull did not log DOWNLOAD_ATTEMPT")
	}
	if dl.URL != ref {
		t.Fatalf("download URL = %q, want image ref %q", dl.URL, ref)
	}
	if dl.Host != ln.Addr().String() {
		t.Fatalf("download host = %q, want %q", dl.Host, ln.Addr().String())
	}
	if dl.Filename != "bot/malware:latest" {
		t.Fatalf("download filename = %q, want bot/malware:latest", dl.Filename)
	}
	time.Sleep(200 * time.Millisecond)
	if atomic.LoadInt32(&accepted) != 0 {
		t.Fatal("Docker image pull opened a real outbound connection")
	}
}

func TestDockerContainerCreateCapturesEscapeAttempt(t *testing.T) {
	h, _ := setupDocker(t)
	defer h.Close()
	body := `{"Image":"alpine:latest","Cmd":["sh","-c","cat /host/etc/shadow"],"HostConfig":{"Privileged":true,"Binds":["/:/host:rw"]}}`

	status, resp := dockerRequest(t, h, "POST", "/v1.43/containers/create?name=escape", body)
	if status != "HTTP/1.1 201 Created" || !strings.Contains(resp, `"Id"`) {
		t.Fatalf("container create response = %q %q", status, resp)
	}
	ev, ok := h.WaitEvent("DOCKER_CREATE", 2*time.Second)
	if !ok {
		t.Fatal("Docker container create was not logged")
	}
	if !strings.Contains(ev.Data, `"Privileged":true`) || !strings.Contains(ev.Data, `/:/host:rw`) {
		t.Fatalf("DOCKER_CREATE did not capture escape body: %q", ev.Data)
	}
	if h.HasEvent("EXEC_ATTEMPT") {
		t.Fatal("Docker container create logged an exec attempt; it should only capture intent")
	}
}

func TestDockerMalformedRequestStaysInert(t *testing.T) {
	h, _ := setupDocker(t)
	defer h.Close()

	h.Send("GARBAGE\r\n\r\n")
	resp := h.ReadFor(500 * time.Millisecond)
	if !strings.HasPrefix(resp, "HTTP/1.1 400 Bad Request") {
		t.Fatalf("malformed request response = %q", resp)
	}
	if h.HasEvent("DOWNLOAD_ATTEMPT") {
		t.Fatal("malformed Docker request reached image-pull handling")
	}
	if h.HasEvent("DOCKER_CREATE") {
		t.Fatal("malformed Docker request reached container-create handling")
	}
}

func setupDocker(t *testing.T) (*testharness.Harness, *persona.Persona) {
	t.Helper()
	p := persona.GenerateProfile("infra")
	h, err := testharness.New(New(p))
	if err != nil {
		t.Fatal(err)
	}
	return h, p
}

func dockerRequest(t *testing.T, h *testharness.Harness, method, path, body string) (string, string) {
	t.Helper()
	status, _, respBody := dockerRequestFull(t, h, method, path, body)
	return status, respBody
}

func dockerRequestFull(t *testing.T, h *testharness.Harness, method, path, body string) (string, map[string]string, string) {
	t.Helper()
	var req strings.Builder
	req.WriteString(method + " " + path + " HTTP/1.1\r\n")
	req.WriteString("Host: docker\r\n")
	if body != "" {
		req.WriteString("Content-Type: application/json\r\n")
		req.WriteString("Content-Length: " + strconv.Itoa(len(body)) + "\r\n")
	}
	req.WriteString("\r\n")
	req.WriteString(body)
	h.Send(req.String())
	resp := h.ReadFor(2 * time.Second)
	status, rest, ok := strings.Cut(resp, "\r\n")
	if !ok {
		t.Fatalf("response has no status line: %q", resp)
	}
	headerBlock, body, ok := strings.Cut(rest, "\r\n\r\n")
	if !ok {
		t.Fatalf("response has no body separator: %q", resp)
	}
	headers := map[string]string{}
	for _, line := range strings.Split(headerBlock, "\r\n") {
		name, value, ok := strings.Cut(line, ":")
		if ok {
			headers[strings.ToLower(name)] = strings.TrimSpace(value)
		}
	}
	return status, headers, body
}

func mustJSON(t *testing.T, body string, v any) {
	t.Helper()
	if err := json.Unmarshal([]byte(body), v); err != nil {
		t.Fatalf("decode JSON %q: %v", body, err)
	}
}
