package portal

import (
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
)

// safeID reports whether id is a plain session identifier (the base58 ids the
// server mints), so it can be used as a filename without any path traversal: no
// slashes, dots, or other separators are admitted.
func safeID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

// recordings lists the session ids that have a cast recording on disk, so the
// drawer shows a replay control only where one exists.
func (p *Portal) recordings(c *gin.Context) {
	ids := []string{}
	if p.cfg.RecordDir != "" {
		if ents, err := os.ReadDir(p.cfg.RecordDir); err == nil {
			for _, e := range ents {
				if id, ok := strings.CutSuffix(e.Name(), ".cast"); ok && safeID(id) {
					ids = append(ids, id)
				}
			}
		}
	}
	sort.Strings(ids)
	c.JSON(http.StatusOK, gin.H{"recordings": ids})
}

// cast serves one session's asciinema recording for the inline player. The id is
// validated to a bare session identifier before it ever touches the filesystem.
func (p *Portal) cast(c *gin.Context) {
	id := c.Param("id")
	if p.cfg.RecordDir == "" || !safeID(id) {
		c.Status(http.StatusNotFound)
		return
	}
	data, err := os.ReadFile(filepath.Join(p.cfg.RecordDir, id+".cast"))
	if err != nil {
		c.Status(http.StatusNotFound)
		return
	}
	c.Data(http.StatusOK, "application/x-asciicast; charset=utf-8", data)
}
