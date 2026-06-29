package http

import (
	"strings"
	"testing"

	"sweetty/internal/persona"
)

// TestWPGateLetsInPersistentGuesser checks the door opens only after enough
// attempts from one source, and that the break-in does not leak to other sources.
func TestWPGateLetsInPersistentGuesser(t *testing.T) {
	pr := New(persona.Generate(), "wordpress").(*Protocol)
	src := "203.0.113.7"
	for i := 1; i < wpBreakInAfter; i++ {
		if pr.wpLetIn(src) {
			t.Fatalf("source let in on attempt %d, before the %d-attempt gate", i, wpBreakInAfter)
		}
	}
	if !pr.wpLetIn(src) {
		t.Fatalf("source not let in on attempt %d", wpBreakInAfter)
	}
	if !pr.wpBrokenIn(src) {
		t.Fatal("source should be marked broken-in once the gate opened")
	}
	if pr.wpBrokenIn("198.51.100.9") {
		t.Fatal("a different source must not inherit the break-in")
	}
}

// TestWPLoginRevealsOnlyAfterWork walks the full trap: wp-admin bounces to login
// until a source has done the work, then a successful login lands it on the
// dashboard that carries the embedded reveal.
func TestWPLoginRevealsOnlyAfterWork(t *testing.T) {
	pr := New(persona.Generate(), "wordpress").(*Protocol)
	src := "203.0.113.20"
	body := "log=admin&pwd=password123&wp-submit=Log+In"

	resp, _ := pr.respondWordPress(nil, src, "GET", "/wp-admin/", "")
	if !strings.HasPrefix(resp, "HTTP/1.1 302") || !strings.Contains(resp, "Location: /wp-login.php") {
		t.Fatalf("wp-admin before break-in should redirect to login: %q", firstLine(resp))
	}
	for i := 1; i < wpBreakInAfter; i++ {
		resp, _ = pr.respondWordPress(nil, src, "POST", "/wp-login.php", body)
		if !strings.Contains(resp, "error=invalid_credentials") {
			t.Fatalf("login attempt %d should still be rejected: %q", i, firstLine(resp))
		}
	}

	resp, _ = pr.respondWordPress(nil, src, "POST", "/wp-login.php", body)
	if !strings.HasPrefix(resp, "HTTP/1.1 302") || !strings.Contains(resp, "Location: /wp-admin/") {
		t.Fatalf("the gating attempt should 302 to wp-admin: %q", firstLine(resp))
	}
	if !strings.Contains(resp, "Set-Cookie: wordpress_logged_in_") {
		t.Fatalf("a successful login should set the logged-in cookie: %q", resp)
	}

	resp, _ = pr.respondWordPress(nil, src, "GET", "/wp-admin/", "")
	if !strings.HasPrefix(resp, "HTTP/1.1 200") {
		t.Fatalf("wp-admin after break-in should be 200: %q", firstLine(resp))
	}
	if !strings.Contains(resp, "You did the work") {
		t.Fatalf("dashboard chrome is missing: %q", firstLine(resp))
	}
	if !strings.Contains(resp, jtArtBody) {
		t.Fatal("the reveal page does not contain the embedded art")
	}
}

// TestJTArtEmbedded confirms the art is compiled in and stripped to its body.
func TestJTArtEmbedded(t *testing.T) {
	if len(jtArtBody) < 1000 {
		t.Fatalf("embedded art looks too small: %d bytes", len(jtArtBody))
	}
	if !strings.Contains(jtArtBody, "<span") {
		t.Fatal("embedded art is not the colour-span document")
	}
	if strings.Contains(jtArtBody, "<head>") || strings.Contains(jtArtBody, "libcaca") {
		t.Fatal("art body should have its html/head wrapper stripped")
	}
}
