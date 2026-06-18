package proxy

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"go-reauth-proxy/pkg/models"
)

func disabledGatewayPortalConfigForProxyTest(t *testing.T) models.GatewayPortalConfig {
	t.Helper()

	var cfg models.GatewayPortalConfig
	if err := json.Unmarshal([]byte(`{"enabled":false}`), &cfg); err != nil {
		t.Fatalf("unmarshal disabled gateway portal config: %v", err)
	}
	return cfg
}

func testServerPort(t *testing.T, rawURL string) int {
	t.Helper()

	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	_, port, err := net.SplitHostPort(parsed.Host)
	if err != nil {
		t.Fatalf("split server host %q: %v", parsed.Host, err)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("parse server port %q: %v", port, err)
	}
	return n
}

func newToolbarHTMLTarget(t *testing.T) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, "<!doctype html><html><body><main>public app</main></body></html>")
	}))
}

func newPublicHostToolbarHandler(targetURL string, authPort int) *Handler {
	h := &Handler{
		HostRules: []models.HostRule{
			{
				Host:    "public.example.com",
				Target:  targetURL,
				UseAuth: false,
			},
		},
		AuthConfig: models.AuthConfig{
			AuthPort: authPort,
			AuthURL:  "/api/auth/verify",
		},
		authCache:      newAuthStateCache(),
		preflightCache: newPreflightStateCache(),
	}
	h.publishRequestSnapshotLocked()
	return h
}

func TestPublicHostRuleInjectsToolbarWhenAuthCookieIsAuthenticated(t *testing.T) {
	var verifyCalls int32
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead && r.URL.Path == "/api/auth/preflight" {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method != http.MethodGet || r.URL.Path != "/api/auth/verify" {
			t.Fatalf("unexpected auth request %s %s", r.Method, r.URL.Path)
		}
		atomic.AddInt32(&verifyCalls, 1)
		if !strings.Contains(r.Header.Get("Cookie"), authSessionCookieName+"=ok") {
			t.Fatalf("auth request Cookie = %q, want %s=ok", r.Header.Get("Cookie"), authSessionCookieName)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"success":true}`)
	}))
	defer authServer.Close()

	target := newToolbarHTMLTarget(t)
	defer target.Close()

	handler := newPublicHostToolbarHandler(target.URL, testServerPort(t, authServer.URL))
	req := httptest.NewRequest(http.MethodGet, "http://public.example.com/", nil)
	req.AddCookie(&http.Cookie{Name: authSessionCookieName, Value: "ok"})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	if got := atomic.LoadInt32(&verifyCalls); got != 1 {
		t.Fatalf("verify calls = %d, want 1", got)
	}
	if body := rec.Body.String(); !strings.Contains(body, "reauth-proxy-toolbar") {
		t.Fatalf("response body did not include toolbar: %s", body)
	}
}

func TestPublicHostRuleDoesNotProbeOrInjectToolbarForWebSocketTarget(t *testing.T) {
	var verifyCalls int32
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/api/auth/verify" {
			atomic.AddInt32(&verifyCalls, 1)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"success":true}`)
	}))
	defer authServer.Close()

	target := newToolbarHTMLTarget(t)
	defer target.Close()

	webSocketTargetURL := strings.Replace(target.URL, "http://", "ws://", 1)
	handler := newPublicHostToolbarHandler(webSocketTargetURL, testServerPort(t, authServer.URL))
	req := httptest.NewRequest(http.MethodGet, "http://public.example.com/", nil)
	req.AddCookie(&http.Cookie{Name: authSessionCookieName, Value: "ok"})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	if got := atomic.LoadInt32(&verifyCalls); got != 0 {
		t.Fatalf("verify calls = %d, want 0 for WebSocket target toolbar probe", got)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "public app") {
		t.Fatalf("response body did not include upstream HTML: %s", body)
	}
	if strings.Contains(body, "reauth-proxy-toolbar") {
		t.Fatalf("response body included toolbar for WebSocket target: %s", body)
	}
}

func TestPublicHostRuleDoesNotProbeOrInjectToolbarWhenPortalDisabled(t *testing.T) {
	var verifyCalls int32
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead && r.URL.Path == "/api/auth/preflight" {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/api/auth/verify" {
			atomic.AddInt32(&verifyCalls, 1)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"success":true}`)
	}))
	defer authServer.Close()

	target := newToolbarHTMLTarget(t)
	defer target.Close()

	handler := newPublicHostToolbarHandler(target.URL, testServerPort(t, authServer.URL))
	handler.mu.Lock()
	handler.GatewayPortal = disabledGatewayPortalConfigForProxyTest(t)
	handler.publishRequestSnapshotLocked()
	handler.mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "http://public.example.com/", nil)
	req.AddCookie(&http.Cookie{Name: authSessionCookieName, Value: "ok"})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	if got := atomic.LoadInt32(&verifyCalls); got != 0 {
		t.Fatalf("verify calls = %d, want 0 when portal is disabled", got)
	}
	if body := rec.Body.String(); strings.Contains(body, "reauth-proxy-toolbar") {
		t.Fatalf("response body included toolbar while portal disabled: %s", body)
	}
}

func TestPublicHostRuleDoesNotInjectToolbarWithoutAuthIdentity(t *testing.T) {
	var verifyCalls int32
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead && r.URL.Path == "/api/auth/preflight" {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/api/auth/verify" {
			atomic.AddInt32(&verifyCalls, 1)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"success":true}`)
	}))
	defer authServer.Close()

	target := newToolbarHTMLTarget(t)
	defer target.Close()

	handler := newPublicHostToolbarHandler(target.URL, testServerPort(t, authServer.URL))
	req := httptest.NewRequest(http.MethodGet, "http://public.example.com/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	if got := atomic.LoadInt32(&verifyCalls); got != 0 {
		t.Fatalf("verify calls = %d, want 0", got)
	}
	if body := rec.Body.String(); strings.Contains(body, "reauth-proxy-toolbar") {
		t.Fatalf("response body included toolbar for anonymous public request: %s", body)
	}
}

func TestPublicHostRuleDoesNotProbeToolbarAuthForOrdinaryCookie(t *testing.T) {
	var verifyCalls int32
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead && r.URL.Path == "/api/auth/preflight" {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/api/auth/verify" {
			atomic.AddInt32(&verifyCalls, 1)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"success":true}`)
	}))
	defer authServer.Close()

	target := newToolbarHTMLTarget(t)
	defer target.Close()

	handler := newPublicHostToolbarHandler(target.URL, testServerPort(t, authServer.URL))
	req := httptest.NewRequest(http.MethodGet, "http://public.example.com/", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: "business-app"})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	if got := atomic.LoadInt32(&verifyCalls); got != 0 {
		t.Fatalf("verify calls = %d, want 0", got)
	}
	if body := rec.Body.String(); strings.Contains(body, "reauth-proxy-toolbar") {
		t.Fatalf("response body included toolbar for ordinary public cookie: %s", body)
	}
}

func TestPublicHostRuleDoesNotInjectToolbarWhenAuthCookieIsRejected(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead && r.URL.Path == "/api/auth/preflight" {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method != http.MethodGet || r.URL.Path != "/api/auth/verify" {
			t.Fatalf("unexpected auth request %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"success":false,"message":"expired"}`)
	}))
	defer authServer.Close()

	target := newToolbarHTMLTarget(t)
	defer target.Close()

	handler := newPublicHostToolbarHandler(target.URL, testServerPort(t, authServer.URL))
	req := httptest.NewRequest(http.MethodGet, "http://public.example.com/", nil)
	req.AddCookie(&http.Cookie{Name: authSessionCookieName, Value: "expired"})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want public upstream response; body = %s", rec.Code, rec.Body.String())
	}
	if location := rec.Header().Get("Location"); location != "" {
		t.Fatalf("Location = %q, want no redirect for public route", location)
	}
	if body := rec.Body.String(); strings.Contains(body, "reauth-proxy-toolbar") {
		t.Fatalf("response body included toolbar for rejected auth cookie: %s", body)
	}
}
