package logger

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBoolEnv(t *testing.T) {
	for _, value := range []string{"1", "true", "TRUE", "t", "yes", "y", "on", " On "} {
		t.Setenv("GO_REPROXY_TEST_BOOL", value)
		if !BoolEnv("GO_REPROXY_TEST_BOOL") {
			t.Fatalf("expected %q to enable bool env", value)
		}
	}

	for _, value := range []string{"", "0", "false", "no", "off", "anything"} {
		t.Setenv("GO_REPROXY_TEST_BOOL", value)
		if BoolEnv("GO_REPROXY_TEST_BOOL") {
			t.Fatalf("expected %q to disable bool env", value)
		}
	}
}

func TestDebugLogDisabledByDefault(t *testing.T) {
	t.Setenv(DebugLogEnv, "")
	t.Setenv(DebugLogDirEnv, t.TempDir())
	t.Cleanup(func() {
		setDebugLogger(false, io.Discard)
		SetDebugAdminPortForRedaction(0)
	})

	Setup()

	if DebugEnabled() {
		t.Fatal("expected debug logging to be disabled")
	}
	if event := DebugEvent("test", "disabled"); event != nil {
		t.Fatal("expected disabled debug event to be nil")
	}
}

func TestDebugLogWritesDailyJSONL(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(DebugLogEnv, "1")
	t.Setenv(DebugLogDirEnv, dir)
	t.Cleanup(func() {
		setDebugLogger(false, io.Discard)
		SetDebugAdminPortForRedaction(0)
	})

	Setup()

	event := DebugEvent("test_component", "test_event")
	if event == nil {
		t.Fatal("expected enabled debug event")
	}
	event.Str("field", "value").Send()

	logPath := filepath.Join(dir, time.Now().Format(debugDateLayout)+".log")
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read debug log %s: %v", logPath, err)
	}
	got := string(data)
	for _, want := range []string{
		`"level":"debug"`,
		`"component":"test_component"`,
		`"event":"test_event"`,
		`"field":"value"`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected debug log to contain %s, got %q", want, got)
		}
	}
}

func TestDebugRedaction(t *testing.T) {
	SetDebugAdminPortForRedaction(7996)
	t.Cleanup(func() {
		SetDebugAdminPortForRedaction(0)
	})

	if got := SanitizePort(7996); got != "[admin-port]" {
		t.Fatalf("admin port sanitized to %#v, want [admin-port]", got)
	}
	if got := SanitizePort(7999); got != 7999 {
		t.Fatalf("proxy port sanitized to %#v, want 7999", got)
	}

	url := SanitizeURL("http://127.0.0.1:7996/path?token=secret&ok=1")
	if strings.Contains(url, "7996") || strings.Contains(url, "secret") {
		t.Fatalf("expected URL to redact admin port and token, got %q", url)
	}
	if !strings.Contains(url, "[admin-port]") || !strings.Contains(url, "token=%5Bredacted%5D") {
		t.Fatalf("expected URL to include redaction markers, got %q", url)
	}

	msg := SanitizeLogString("cannot target local admin port 7996")
	if strings.Contains(msg, "7996") || !strings.Contains(msg, "[admin-port]") {
		t.Fatalf("expected error string to redact admin port, got %q", msg)
	}

	headers := SanitizeHeader(http.Header{
		"Authorization": []string{"Bearer secret"},
		"Cookie":        []string{"sid=secret"},
		"X-Api-Key":     []string{"secret"},
		"User-Agent":    []string{"curl"},
	})
	if headers["Authorization"] != "[redacted]" || headers["Cookie"] != "[redacted]" || headers["X-Api-Key"] != "[redacted]" {
		t.Fatalf("expected sensitive headers to be redacted, got %#v", headers)
	}
	if got := headers["User-Agent"]; len(got.([]string)) != 1 || got.([]string)[0] != "curl" {
		t.Fatalf("expected user agent to be preserved, got %#v", got)
	}
}
