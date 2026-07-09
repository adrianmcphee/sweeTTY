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

// TestRecordingDefaultsOff proves recording is opt-in, a custom dir is honoured
// only with "record": true, and "record": false disables it.
func TestRecordingDefaultsOff(t *testing.T) {
	base := `"log_file":"x.log","listeners":[{"port":2323,"protocol":"telnet"}]`

	// no record fields -> disabled
	if c, err := Load(writeCfg(t, "{"+base+"}")); err != nil || c.RecordDir != "" {
		t.Errorf("default: RecordDir=%q err=%v, want empty", c.RecordDir, err)
	}
	// explicit dir is ignored until recording is explicitly enabled
	if c, _ := Load(writeCfg(t, `{`+base+`,"record_dir":"/opt/sweetty/recordings"}`)); c.RecordDir != "" {
		t.Errorf("dir without record:true should be disabled, got %q", c.RecordDir)
	}
	// record:true with no dir uses the opt-in default
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
