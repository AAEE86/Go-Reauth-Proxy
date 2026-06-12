package waf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go-reauth-proxy/pkg/logger"
	"go-reauth-proxy/pkg/models"
)

func enableDebugLogForWAFTest(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	t.Cleanup(func() {
		logger.Setup()
		logger.SetDebugAdminPortForRedaction(0)
	})
	t.Setenv(logger.DebugLogEnv, "1")
	t.Setenv(logger.DebugLogDirEnv, dir)
	logger.Setup()
	return dir
}

func TestDebugLogRecordsWAFReloadWithAdminPortRedaction(t *testing.T) {
	dir := enableDebugLogForWAFTest(t)
	logger.SetDebugAdminPortForRedaction(7996)

	rt := NewRuntime(models.WAFConfig{Enabled: false, Mode: ModeOff}, t.TempDir())
	if _, err := rt.Reload(models.WAFConfig{Enabled: false, Mode: ModeOff}, "bundle", "http://127.0.0.1:7996/bundle"); err != nil {
		t.Fatalf("Reload returned error: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, time.Now().Format("2006-01-02")+".log"))
	if err != nil {
		t.Fatalf("failed to read debug log: %v", err)
	}
	got := string(data)
	if !strings.Contains(got, `"component":"waf"`) || !strings.Contains(got, `"event":"reload_end"`) {
		t.Fatalf("expected WAF reload debug events, got %q", got)
	}
	if !strings.Contains(got, `[admin-port]`) || strings.Contains(got, "7996") {
		t.Fatalf("expected admin port to be redacted, got %q", got)
	}
}
