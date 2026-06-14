package iptables

import (
	stderrors "errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go-reauth-proxy/pkg/logger"
)

type debugTestRunner struct{}

func (debugTestRunner) CombinedOutput(command string, args ...string) ([]byte, error) {
	for _, arg := range args {
		if arg == "-D" {
			return []byte("not found"), stderrors.New("not found")
		}
	}
	return []byte("ok"), nil
}

func (debugTestRunner) CombinedOutputWithInput(input string, command string, args ...string) ([]byte, error) {
	return []byte("ok"), nil
}

func enableDebugLogForIptablesTest(t *testing.T) string {
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

func TestDebugLogRecordsIptablesOperationWithAdminPortRedaction(t *testing.T) {
	dir := enableDebugLogForIptablesTest(t)
	logger.SetDebugAdminPortForRedaction(7996)

	manager := NewManager(Options{Tables: []string{"iptables"}})
	manager.runner = debugTestRunner{}

	if err := manager.EnsureTCPRedirect(7996, 7999); err != nil {
		t.Fatalf("EnsureTCPRedirect returned error: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, time.Now().Format("2006-01-02")+".log"))
	if err != nil {
		t.Fatalf("failed to read debug log: %v", err)
	}
	got := string(data)
	if !strings.Contains(got, `"component":"iptables"`) || !strings.Contains(got, `"event":"tcp_redirect_ensure_end"`) {
		t.Fatalf("expected iptables debug events, got %q", got)
	}
	if !strings.Contains(got, `[admin-port]`) || strings.Contains(got, "7996") {
		t.Fatalf("expected admin port to be redacted, got %q", got)
	}
}
