package proxy

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"go-reauth-proxy/pkg/logger"
	"go-reauth-proxy/pkg/models"
)

func enableDebugLogForTest(t *testing.T) string {
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

func TestDebugLogRecordsProxyLifecycleWithRedaction(t *testing.T) {
	dir := enableDebugLogForTest(t)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	_, portText, err := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "http://"))
	if err != nil {
		t.Fatalf("failed to parse upstream port: %v", err)
	}
	adminPort, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("failed to parse upstream port: %v", err)
	}
	logger.SetDebugAdminPortForRedaction(adminPort)

	handler := &Handler{
		Rules: []models.Rule{
			{Path: "/app", Target: upstream.URL},
		},
		AdminPort: adminPort,
	}
	handler.publishRequestSnapshotLocked()

	req := httptest.NewRequest(http.MethodGet, "http://example.com/app/?token=supersecret&ok=1", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	req.Header.Set("Cookie", "sid=secret-cookie")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}

	logPath := filepath.Join(dir, time.Now().Format("2006-01-02")+".log")
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read debug log: %v", err)
	}
	got := string(data)
	for _, want := range []string{
		`"event":"request_start"`,
		`"event":"route_match_evaluated"`,
		`"event":"reverse_proxy_start"`,
		`"event":"request_end"`,
		`[admin-port]`,
		`"Authorization":"[redacted]"`,
		`"Cookie":"[redacted]"`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected debug log to contain %s, got %q", want, got)
		}
	}
	for _, forbidden := range []string{
		portText,
		"supersecret",
		"secret-token",
		"secret-cookie",
	} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("debug log leaked %q: %q", forbidden, got)
		}
	}
}
