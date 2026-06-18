package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"go-reauth-proxy/pkg/models"
)

func TestAuthLogoutRouteTakesPrecedenceOverHostRule(t *testing.T) {
	var targetHits int32
	var logoutHits int32

	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead && r.URL.Path == "/api/auth/preflight" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodGet || r.URL.Path != "/api/auth/logout" {
			t.Fatalf("unexpected auth request %s %s", r.Method, r.URL.Path)
		}
		atomic.AddInt32(&logoutHits, 1)
		if !strings.Contains(r.Header.Get("Cookie"), authSessionCookieName+"=ok") {
			t.Fatalf("auth logout Cookie = %q, want %s=ok", r.Header.Get("Cookie"), authSessionCookieName)
		}
		_, _ = io.WriteString(w, "logged-out")
	}))
	defer authServer.Close()

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&targetHits, 1)
		http.Error(w, "host target should not be reached", http.StatusTeapot)
	}))
	defer target.Close()

	handler := &Handler{
		HostRules: []models.HostRule{
			{
				Host:       "fnknock.example.com",
				Target:     target.URL,
				UseAuth:    true,
				AccessMode: "login_first",
			},
		},
		AuthConfig: models.AuthConfig{
			AuthPort:  testServerPort(t, authServer.URL),
			AuthURL:   "/api/auth/verify",
			LogoutURL: "/api/auth/logout",
		},
		authCache:      newAuthStateCache(),
		preflightCache: newPreflightStateCache(),
	}
	handler.publishRequestSnapshotLocked()

	req := httptest.NewRequest(http.MethodGet, "http://fnknock.example.com/__auth__/logout", nil)
	req.AddCookie(&http.Cookie{Name: authSessionCookieName, Value: "ok"})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); body != "logged-out" {
		t.Fatalf("body = %q, want logged-out", body)
	}
	if got := atomic.LoadInt32(&logoutHits); got != 1 {
		t.Fatalf("logout hits = %d, want 1", got)
	}
	if got := atomic.LoadInt32(&targetHits); got != 0 {
		t.Fatalf("target hits = %d, want 0", got)
	}
}

func TestHostRuleAuthVerifyReceivesSessionCookie(t *testing.T) {
	var verifyHits int32
	var targetHits int32

	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodHead && r.URL.Path == "/api/auth/preflight":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/api/auth/verify":
			atomic.AddInt32(&verifyHits, 1)
			if !strings.Contains(r.Header.Get("Cookie"), authSessionCookieName+"=ok") {
				t.Fatalf("auth verify Cookie = %q, want %s=ok", r.Header.Get("Cookie"), authSessionCookieName)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"success":true}`)
		default:
			t.Fatalf("unexpected auth request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer authServer.Close()

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&targetHits, 1)
		if !strings.Contains(r.Header.Get("Cookie"), authSessionCookieName+"=ok") {
			t.Fatalf("target Cookie = %q, want %s=ok", r.Header.Get("Cookie"), authSessionCookieName)
		}
		_, _ = io.WriteString(w, "panel")
	}))
	defer target.Close()

	handler := &Handler{
		HostRules: []models.HostRule{
			{
				Host:       "fnknock.example.com",
				Target:     target.URL,
				UseAuth:    true,
				AccessMode: "login_first",
			},
		},
		AuthConfig: models.AuthConfig{
			AuthPort:     testServerPort(t, authServer.URL),
			AuthURL:      "/api/auth/verify",
			PreflightURL: "/api/auth/preflight",
		},
		authCache:      newAuthStateCache(),
		preflightCache: newPreflightStateCache(),
	}
	handler.publishRequestSnapshotLocked()

	req := httptest.NewRequest(http.MethodGet, "http://fnknock.example.com/", nil)
	req.AddCookie(&http.Cookie{Name: authSessionCookieName, Value: "ok"})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); body != "panel" {
		t.Fatalf("body = %q, want panel", body)
	}
	if got := atomic.LoadInt32(&verifyHits); got != 1 {
		t.Fatalf("verify hits = %d, want 1", got)
	}
	if got := atomic.LoadInt32(&targetHits); got != 1 {
		t.Fatalf("target hits = %d, want 1", got)
	}
}
