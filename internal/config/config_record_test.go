package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeCfg(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestRecordingDefaultsOn proves recording is on by default (quota-bound), a
// custom dir is honoured, and only an explicit "record": false disables it.
func TestRecordingDefaultsOn(t *testing.T) {
	base := `"log_file":"x.log","listeners":[{"port":2323,"protocol":"telnet"}]`

	// no record fields -> on, default dir
	if c, err := Load(writeCfg(t, "{"+base+"}")); err != nil || c.RecordDir != "recordings" {
		t.Errorf("default: RecordDir=%q err=%v, want recordings", c.RecordDir, err)
	}
	// explicit dir alone is honoured
	if c, _ := Load(writeCfg(t, `{`+base+`,"record_dir":"/opt/sweetty/recordings"}`)); c.RecordDir != "/opt/sweetty/recordings" {
		t.Errorf("explicit dir without record field = %q, want /opt/sweetty/recordings", c.RecordDir)
	}
	// record:true with no dir uses the default
	if c, _ := Load(writeCfg(t, `{`+base+`,"record":true}`)); c.RecordDir != "recordings" {
		t.Errorf("record:true default dir = %q, want recordings", c.RecordDir)
	}
	// explicit dir with record:true is honoured
	if c, _ := Load(writeCfg(t, `{`+base+`,"record":true,"record_dir":"/opt/sweetty/recordings"}`)); c.RecordDir != "/opt/sweetty/recordings" {
		t.Errorf("explicit dir not honoured: %q", c.RecordDir)
	}
	// record:false -> disabled
	if c, _ := Load(writeCfg(t, `{`+base+`,"record":false}`)); c.RecordDir != "" {
		t.Errorf("record:false should disable, got %q", c.RecordDir)
	}
	// record:false wins even with a dir set
	if c, _ := Load(writeCfg(t, `{`+base+`,"record":false,"record_dir":"/x"}`)); c.RecordDir != "" {
		t.Errorf("record:false should override an explicit dir, got %q", c.RecordDir)
	}
}
