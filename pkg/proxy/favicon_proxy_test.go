package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"go-reauth-proxy/pkg/models"
)

func TestHostRuleProxiesRootFaviconPathToUpstream(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/favicon-32x32.png" {
			t.Fatalf("upstream path = %q, want /favicon-32x32.png", r.URL.Path)
		}
		w.Header().Set("Content-Type", "image/png")
		_, _ = io.WriteString(w, "upstream-favicon")
	}))
	defer upstream.Close()

	handler := &Handler{
		HostRules: []models.HostRule{
			{
				Host:   "app.example.com",
				Target: upstream.URL,
			},
		},
		authCache:      newAuthStateCache(),
		preflightCache: newPreflightStateCache(),
	}
	handler.publishRequestSnapshotLocked()

	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/favicon-32x32.png", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	if got := rec.Body.String(); got != "upstream-favicon" {
		t.Fatalf("body = %q, want upstream favicon response", got)
	}
}
