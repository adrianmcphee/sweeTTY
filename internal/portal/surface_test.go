package portal

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"sweetty/internal/config"
)

// TestOverviewSurface checks the exposed-services view: every configured listener
// appears (even with no traffic), ordered by the public port attackers reach, with
// the bound port carried alongside, live hit and scan tallies folded in, and a
// configured port that never bound shown as not serving so a dead backend behind an
// open edge port stands out.
func TestOverviewSurface(t *testing.T) {
	p := newTestPortal(t)
	p.cfg.Listeners = []config.Listener{
		{Port: 10022, Protocol: "ssh", PublicPort: 22},
		{Port: 13306, Protocol: "mysql", PublicPort: 3306},
		{Port: 16379, Protocol: "redis", PublicPort: 6379},
	}
	// ssh and mysql bound; redis did not, standing for an open edge port whose backend
	// is dead.
	p.SetActiveListeners(map[int]bool{10022: true, 13306: true})

	lines := []string{
		`{"time":"2026-06-27T10:00:00Z","event":"SESSION_START","src_ip":"8.8.8.8","ip":"8.8.8.8:2222","session":"s1","port":10022,"protocol":"ssh"}`,
		`{"time":"2026-06-27T10:00:01Z","event":"PORT_SCAN","src_ip":"9.9.9.9","ip":"9.9.9.9:3333","port":10022,"protocol":"ssh"}`,
	}
	if err := os.WriteFile(p.cfg.LogFile, []byte(strings.Join(lines, "\n")+"\n"), 0600); err != nil {
		t.Fatalf("write log: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/dashboard/overview", nil)
	w := httptest.NewRecorder()
	p.engine().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("overview: status %d", w.Code)
	}

	var body struct {
		Surface []struct {
			PublicPort int    `json:"public_port"`
			Port       int    `json:"port"`
			Protocol   string `json:"protocol"`
			Listening  bool   `json:"listening"`
			Hits       int    `json:"hits"`
			Scans      int    `json:"scans"`
		} `json:"surface"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Surface) != 3 {
		t.Fatalf("surface entries = %d, want 3: %s", len(body.Surface), w.Body.String())
	}
	if body.Surface[0].PublicPort != 22 || body.Surface[1].PublicPort != 3306 || body.Surface[2].PublicPort != 6379 {
		t.Fatalf("surface not ordered by public port: %+v", body.Surface)
	}
	ssh := body.Surface[0]
	if ssh.Port != 10022 || ssh.Protocol != "ssh" || !ssh.Listening {
		t.Fatalf("ssh entry wrong: %+v", ssh)
	}
	if ssh.Hits < 1 || ssh.Scans < 1 {
		t.Fatalf("ssh traffic not folded in: hits=%d scans=%d", ssh.Hits, ssh.Scans)
	}
	if !body.Surface[1].Listening {
		t.Fatalf("mysql should be serving: %+v", body.Surface[1])
	}
	if redis := body.Surface[2]; redis.Protocol != "redis" || redis.Listening {
		t.Fatalf("redis should be shown not serving: %+v", redis)
	}
}
