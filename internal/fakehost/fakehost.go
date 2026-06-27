// Package fakehost embeds the fake filesystem and renders it against an
// instance persona, so the live virtual filesystem carries this host's own
// randomized identity and nothing identifying is fixed in the source.
package fakehost

import (
	"bytes"
	"embed"
	"strings"
	"text/template"

	"sweetty/internal/persona"
	"sweetty/internal/vfs"
)

//go:embed all:fakeroot
var fakerootFS embed.FS

const root = "fakeroot"

// Load builds the virtual filesystem for an instance, rendering every embedded
// template against the persona.
func Load(p *persona.Persona) (*vfs.FS, error) {
	return vfs.Load(fakerootFS, root, renderer(p))
}

// renderer rewrites any file containing a template placeholder against the
// persona. A file with no placeholder is returned untouched, and a malformed
// template falls back to its raw bytes (the fakehost tests assert that no
// shipped template is malformed or leaves a residual placeholder).
// binaryExt are file extensions whose bytes must be served verbatim (never run
// through the template engine), so an exfiltrated image reconstructs exactly.
var binaryExt = []string{".png", ".jpg", ".jpeg", ".gif", ".pdf", ".gz", ".tgz", ".zip", ".tar", ".bin", ".ico", ".so"}

func isBinaryPath(path string) bool {
	low := strings.ToLower(path)
	for _, ext := range binaryExt {
		if strings.HasSuffix(low, ext) {
			return true
		}
	}
	return false
}

func renderer(p *persona.Persona) vfs.Transform {
	return func(path string, content []byte) []byte {
		if isBinaryPath(path) || !bytes.Contains(content, []byte("{{")) {
			return content
		}
		t, err := template.New(path).Option("missingkey=error").Parse(string(content))
		if err != nil {
			return content
		}
		var buf bytes.Buffer
		if err := t.Execute(&buf, p); err != nil {
			return content
		}
		return buf.Bytes()
	}
}
