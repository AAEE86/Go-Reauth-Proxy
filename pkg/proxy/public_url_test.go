package proxy

import (
	"context"
	"go-reauth-proxy/pkg/models"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func requestWithLocalPort(req *http.Request, port int) *http.Request {
	return req.WithContext(context.WithValue(
		req.Context(),
		http.LocalAddrContextKey,
		&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: port},
	))
}

func TestBuildHTTPSRedirectURLDoesNotUseLocalOriginPort(t *testing.T) {
	req := requestWithLocalPort(
		httptest.NewRequest(http.MethodGet, "http://auth.fnknock.cn/", nil),
		7999,
	)

	got := BuildHTTPSRedirectURL(req, models.AuthConfig{})
	if got != "https://auth.fnknock.cn/" {
		t.Fatalf("BuildHTTPSRedirectURL() = %q, want %q", got, "https://auth.fnknock.cn/")
	}
}

func TestBuildHTTPSRedirectURLKeepsExplicitPublicPorts(t *testing.T) {
	tests := []struct {
		name       string
		rawURL     string
		authConfig models.AuthConfig
		headers    map[string]string
		want       string
	}{
		{
			name:       "configured public https port",
			rawURL:     "http://auth.fnknock.cn/app?x=1",
			authConfig: models.AuthConfig{PublicHTTPSPort: 8443},
			want:       "https://auth.fnknock.cn:8443/app?x=1",
		},
		{
			name:    "forwarded port",
			rawURL:  "http://auth.fnknock.cn/app?x=1",
			headers: map[string]string{"X-Forwarded-Port": "9443"},
			want:    "https://auth.fnknock.cn:9443/app?x=1",
		},
		{
			name:   "host port",
			rawURL: "http://auth.fnknock.cn:10443/app?x=1",
			want:   "https://auth.fnknock.cn:10443/app?x=1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := requestWithLocalPort(httptest.NewRequest(http.MethodGet, tt.rawURL, nil), 7999)
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			if got := BuildHTTPSRedirectURL(req, tt.authConfig); got != tt.want {
				t.Fatalf("BuildHTTPSRedirectURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIsPublicHTTPSRequestUsesForwardedScheme(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
	}{
		{
			name:    "forwarded header",
			headers: map[string]string{"Forwarded": `for=192.0.2.1;proto=https;host=auth.fnknock.cn`},
		},
		{
			name:    "x forwarded proto",
			headers: map[string]string{"X-Forwarded-Proto": "https"},
		},
		{
			name:    "x forwarded scheme",
			headers: map[string]string{"X-Forwarded-Scheme": "https"},
		},
		{
			name:    "x original proto",
			headers: map[string]string{"X-Original-Proto": "https"},
		},
		{
			name:    "cloudflare visitor",
			headers: map[string]string{"CF-Visitor": `{"scheme":"https"}`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://auth.fnknock.cn/", nil)
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			if !IsPublicHTTPSRequest(req) {
				t.Fatalf("IsPublicHTTPSRequest() = false, want true")
			}
		})
	}
}

func TestShouldRedirectHTTPToHTTPSRequiresTrustedForwardedProto(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://auth.fnknock.cn/", nil)
	req.Header.Set("X-Forwarded-Proto", "https")

	if !ShouldRedirectHTTPToHTTPS(req, models.AuthConfig{}) {
		t.Fatal("ShouldRedirectHTTPToHTTPS() = false without trust_forwarded_proto, want true")
	}
	if ShouldRedirectHTTPToHTTPS(req, models.AuthConfig{TrustForwardedProto: true}) {
		t.Fatal("ShouldRedirectHTTPToHTTPS() = true with trusted forwarded https, want false")
	}
}

func TestBuildPublicAuthLoginURLDoesNotAppendLocalOriginPort(t *testing.T) {
	req := requestWithLocalPort(
		httptest.NewRequest(http.MethodGet, "http://auth.fnknock.cn/private?x=1", nil),
		7999,
	)
	req.Header.Set("X-Forwarded-Proto", "https")

	originalURL := buildPublicRequestURL(req, models.AuthConfig{}, "")
	loginURL := buildPublicAuthLoginURL(models.AuthConfig{
		PublicAuthBaseURL: "https://auth.fnknock.cn",
		LoginURL:          "/#/login",
	}, req, originalURL)
	if loginURL == nil {
		t.Fatal("buildPublicAuthLoginURL() returned nil")
	}
	if strings.Contains(loginURL.Host, ":7999") {
		t.Fatalf("login URL host = %q, must not contain local origin port", loginURL.Host)
	}
	redirectURI := loginURL.Query().Get("redirect_uri")
	if redirectURI != "https://auth.fnknock.cn/private?x=1" {
		t.Fatalf("redirect_uri = %q, want %q", redirectURI, "https://auth.fnknock.cn/private?x=1")
	}
}
