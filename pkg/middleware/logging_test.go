package middleware

import (
	"bytes"
	"go-reauth-proxy/pkg/logger"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"
)

func TestLoggerDisabledByDefault(t *testing.T) {
	t.Setenv(AdminHTTPLogEnv, "")
	t.Setenv(logger.ConsoleLogEnv, "")

	var buf bytes.Buffer
	restoreLogger(t, &buf)

	handler := Logger(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/waf/events/drain", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if got := buf.String(); got != "" {
		t.Fatalf("expected no admin HTTP log by default, got %q", got)
	}
}

func TestLoggerEnabledByEnvironment(t *testing.T) {
	t.Setenv(AdminHTTPLogEnv, "1")
	t.Setenv(logger.ConsoleLogEnv, "")

	var buf bytes.Buffer
	restoreLogger(t, &buf)

	handler := Logger(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/waf/events/drain", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("User-Agent", "node")
	handler.ServeHTTP(httptest.NewRecorder(), req)

	got := buf.String()
	for _, want := range []string{
		`"component":"admin_http"`,
		`"method":"POST"`,
		`"path":"/api/waf/events/drain"`,
		`"status":200`,
		`"user_agent":"node"`,
		`"remote_ip":"127.0.0.1"`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected log to contain %s, got %q", want, got)
		}
	}
}

func TestLoggerEnabledByGlobalEnvironment(t *testing.T) {
	t.Setenv(AdminHTTPLogEnv, "")
	t.Setenv(logger.ConsoleLogEnv, "1")

	var buf bytes.Buffer
	restoreLogger(t, &buf)

	handler := Logger(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/traffic", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if got := buf.String(); !strings.Contains(got, `"component":"admin_http"`) {
		t.Fatalf("expected global logging env to enable admin HTTP logs, got %q", got)
	}
}

func restoreLogger(t *testing.T, buf *bytes.Buffer) {
	t.Helper()

	original := zlog.Logger
	zlog.Logger = zerolog.New(buf)
	t.Cleanup(func() {
		zlog.Logger = original
	})
}
