package proxy

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"go-reauth-proxy/pkg/models"
)

func expectedBasicAuth(username string, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
}

func newBasicAuthTestHandler(targetURL string, basicAuth models.BasicAuthConfig) *Handler {
	handler := &Handler{
		HostRules: []models.HostRule{
			{
				Host:      "app.example.com",
				Target:    targetURL,
				UseAuth:   false,
				BasicAuth: basicAuth,
			},
		},
		authCache:      newAuthStateCache(),
		preflightCache: newPreflightStateCache(),
	}
	handler.publishRequestSnapshotLocked()
	return handler
}

func TestHostRuleInjectsBasicAuthHeader(t *testing.T) {
	var gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	handler := newBasicAuthTestHandler(upstream.URL, models.BasicAuthConfig{
		Enabled:  true,
		Username: "admin",
		Password: "s3cret",
	})
	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	if want := expectedBasicAuth("admin", "s3cret"); gotAuth != want {
		t.Fatalf("Authorization = %q, want %q", gotAuth, want)
	}
}

func TestHostRuleBasicAuthOverridesClientAuthorization(t *testing.T) {
	var gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	handler := newBasicAuthTestHandler(upstream.URL, models.BasicAuthConfig{
		Enabled:  true,
		Username: "admin",
		Password: "s3cret",
	})
	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
	req.Header.Set("Authorization", "Bearer client-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	if want := expectedBasicAuth("admin", "s3cret"); gotAuth != want {
		t.Fatalf("Authorization = %q, want %q", gotAuth, want)
	}
}

func TestHostRuleBasicAuthDisabledDoesNotAddAuthorization(t *testing.T) {
	var gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	handler := newBasicAuthTestHandler(upstream.URL, models.BasicAuthConfig{})
	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	if gotAuth != "" {
		t.Fatalf("Authorization = %q, want empty", gotAuth)
	}
}

func TestSetHostRulesRejectsInvalidBasicAuthInjection(t *testing.T) {
	tests := []struct {
		name      string
		basicAuth models.BasicAuthConfig
	}{
		{
			name: "missing username",
			basicAuth: models.BasicAuthConfig{
				Enabled:  true,
				Password: "s3cret",
			},
		},
		{
			name: "missing password",
			basicAuth: models.BasicAuthConfig{
				Enabled:  true,
				Username: "admin",
			},
		},
		{
			name: "username contains colon",
			basicAuth: models.BasicAuthConfig{
				Enabled:  true,
				Username: "ad:min",
				Password: "s3cret",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := &Handler{}
			err := handler.SetHostRules([]models.HostRule{
				{
					Host:      "app.example.com",
					Target:    "http://127.0.0.1:8080",
					UseAuth:   false,
					BasicAuth: tt.basicAuth,
				},
			})
			if err == nil {
				t.Fatal("SetHostRules returned nil error, want validation error")
			}
		})
	}
}

func TestFnosPortIconHijackWebSocketHeaderInjectsBasicAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/websocket", nil)
	req.Header.Set("Authorization", "Bearer client-token")
	targetURL, err := url.Parse("http://127.0.0.1:8080")
	if err != nil {
		t.Fatalf("parse target URL: %v", err)
	}
	upstreamURL, err := url.Parse("ws://127.0.0.1:8080/websocket")
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}

	headers := buildFnosPortIconHijackWebSocketHeader(req, fnosPortIconHijackWebSocketOptions{
		targetURL: targetURL,
		basicAuth: models.BasicAuthConfig{
			Enabled:  true,
			Username: "admin",
			Password: "s3cret",
		},
	}, upstreamURL)

	if want := expectedBasicAuth("admin", "s3cret"); headers.Get("Authorization") != want {
		t.Fatalf("Authorization = %q, want %q", headers.Get("Authorization"), want)
	}
}
