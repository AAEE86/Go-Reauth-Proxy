package proxy

import (
	"go-reauth-proxy/pkg/models"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTrafficStatsIncludesHostBreakdown(t *testing.T) {
	handler := &Handler{
		HostRules: []models.HostRule{{Host: "app.example.com"}},
	}
	metrics := &requestTrafficMetrics{statusCode: http.StatusOK}
	metrics.bindHost(handler, "App.Example.COM:443")

	body := &trafficReadCloser{
		ReadCloser: io.NopCloser(strings.NewReader("request")),
		handler:    handler,
		metrics:    metrics,
	}
	if _, err := io.ReadAll(body); err != nil {
		t.Fatalf("read request body: %v", err)
	}

	writer := &trafficResponseWriter{
		ResponseWriter: httptest.NewRecorder(),
		handler:        handler,
		metrics:        metrics,
	}
	if _, err := writer.Write([]byte("response")); err != nil {
		t.Fatalf("write response body: %v", err)
	}
	metrics.add5xx()

	stats := handler.GetTrafficStats(time.Now())
	if stats.TotalIn != 7 {
		t.Fatalf("TotalIn = %d, want 7", stats.TotalIn)
	}
	if stats.TotalOut != 8 {
		t.Fatalf("TotalOut = %d, want 8", stats.TotalOut)
	}
	if len(stats.ByHost) != 1 {
		t.Fatalf("ByHost length = %d, want 1: %#v", len(stats.ByHost), stats.ByHost)
	}

	hostStats := stats.ByHost[0]
	if hostStats.Host != "app.example.com" {
		t.Fatalf("Host = %q, want app.example.com", hostStats.Host)
	}
	if hostStats.TotalIn != 7 {
		t.Fatalf("host TotalIn = %d, want 7", hostStats.TotalIn)
	}
	if hostStats.TotalOut != 8 {
		t.Fatalf("host TotalOut = %d, want 8", hostStats.TotalOut)
	}
	if hostStats.Error5xx != 1 {
		t.Fatalf("host Error5xx = %d, want 1", hostStats.Error5xx)
	}
}
