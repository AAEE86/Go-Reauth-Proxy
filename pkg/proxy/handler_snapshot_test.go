package proxy

import (
	"go-reauth-proxy/pkg/models"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequestSnapshotIsPublishedImmutableCopy(t *testing.T) {
	handler := &Handler{
		Rules: []models.Rule{
			{Path: "/app", Target: "http://127.0.0.1:8080"},
		},
		HostRules: []models.HostRule{
			{Host: "app.example.com", Target: "http://127.0.0.1:8080"},
		},
		DefaultRoute: "/app",
	}
	handler.publishRequestSnapshotLocked()

	handler.Rules[0].Path = "/mutated"
	handler.HostRules[0].Host = "mutated.example.com"

	snapshot := handler.snapshotForRequest()
	if got := snapshot.rules[0].Path; got != "/app" {
		t.Fatalf("snapshot rule path = %q, want /app", got)
	}
	if got := snapshot.hostRules[0].Host; got != "app.example.com" {
		t.Fatalf("snapshot host rule = %q, want app.example.com", got)
	}
}

func TestMatchHostRuleUsesPublishedHostMap(t *testing.T) {
	handler := &Handler{
		HostRules: []models.HostRule{
			{Host: "app.example.com", Target: "http://127.0.0.1:8080"},
		},
	}
	handler.publishRequestSnapshotLocked()

	req := httptest.NewRequest("GET", "http://fallback.example.com/", nil)
	req.Header.Set("X-Forwarded-Host", "App.Example.COM:443")

	rule := matchHostRule(req, handler.snapshotForRequest())
	if rule == nil {
		t.Fatal("expected host rule match")
	}
	if got := rule.Target; got != "http://127.0.0.1:8080" {
		t.Fatalf("target = %q, want http://127.0.0.1:8080", got)
	}
}

func TestMatchRuleUsesCompiledLongestPrefix(t *testing.T) {
	handler := &Handler{
		Rules: []models.Rule{
			{Path: "/app", Target: "http://127.0.0.1:8080"},
			{Path: "/app/api", Target: "http://127.0.0.1:8081"},
		},
	}
	handler.publishRequestSnapshotLocked()

	req := httptest.NewRequest(http.MethodGet, "http://example.com/app/api/users", nil)
	rule, redirect := matchRule(req, handler.snapshotForRequest())
	if redirect != "" {
		t.Fatalf("redirect = %q, want empty", redirect)
	}
	if rule == nil {
		t.Fatal("expected path rule match")
	}
	if got := rule.Path; got != "/app/api" {
		t.Fatalf("path = %q, want /app/api", got)
	}
}

func TestMatchRuleUsesCompiledSlashRedirect(t *testing.T) {
	handler := &Handler{
		Rules: []models.Rule{
			{Path: "/app/", Target: "http://127.0.0.1:8080"},
		},
	}
	handler.publishRequestSnapshotLocked()

	req := httptest.NewRequest(http.MethodGet, "http://example.com/app", nil)
	rule, redirect := matchRule(req, handler.snapshotForRequest())
	if rule != nil {
		t.Fatalf("rule = %#v, want nil while redirecting", rule)
	}
	if redirect != "/app/" {
		t.Fatalf("redirect = %q, want /app/", redirect)
	}
}

func TestAddProxyPathCookieIfChangedSkipsCurrentCookie(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/app/", nil)
	req.AddCookie(&http.Cookie{Name: proxyPathCookieName, Value: "/app"})
	resp := &http.Response{Header: http.Header{}}

	addProxyPathCookieIfChanged(resp, req, "/app")

	if values := resp.Header.Values("Set-Cookie"); len(values) != 0 {
		t.Fatalf("Set-Cookie values = %#v, want none", values)
	}
}

func TestAddProxyPathCookieIfChangedAddsMissingCookie(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/app/", nil)
	resp := &http.Response{Header: http.Header{}}

	addProxyPathCookieIfChanged(resp, req, "/app")

	values := resp.Header.Values("Set-Cookie")
	if len(values) != 1 {
		t.Fatalf("Set-Cookie count = %d, want 1: %#v", len(values), values)
	}
	if !strings.Contains(values[0], proxyPathCookieName+"=/app") {
		t.Fatalf("Set-Cookie = %q, want proxy path cookie", values[0])
	}
}

func TestAddProxyPathCookieIfChangedStripsUpstreamProxyPathCookie(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/app/", nil)
	req.AddCookie(&http.Cookie{Name: proxyPathCookieName, Value: "/app"})
	resp := &http.Response{Header: http.Header{}}
	resp.Header.Add("Set-Cookie", "session_id=abc; Path=/; HttpOnly")
	resp.Header.Add("Set-Cookie", proxyPathCookieName+"=/other; Path=/")

	addProxyPathCookieIfChanged(resp, req, "/app")

	values := resp.Header.Values("Set-Cookie")
	if len(values) != 1 {
		t.Fatalf("Set-Cookie count = %d, want only upstream session cookie: %#v", len(values), values)
	}
	if values[0] != "session_id=abc; Path=/; HttpOnly" {
		t.Fatalf("Set-Cookie = %#v, want only upstream session cookie", values)
	}
}

func TestAddProxyPathCookieIfChangedReplacesUpstreamProxyPathCookie(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/app/", nil)
	resp := &http.Response{Header: http.Header{}}
	resp.Header.Add("Set-Cookie", "session_id=abc; Path=/; HttpOnly")
	resp.Header.Add("Set-Cookie", proxyPathCookieName+"=/other; Path=/")

	addProxyPathCookieIfChanged(resp, req, "/app")

	values := resp.Header.Values("Set-Cookie")
	if len(values) != 2 {
		t.Fatalf("Set-Cookie count = %d, want session plus proxy path cookie: %#v", len(values), values)
	}
	if values[0] != "session_id=abc; Path=/; HttpOnly" {
		t.Fatalf("first Set-Cookie = %q, want upstream session cookie", values[0])
	}
	if !strings.Contains(values[1], proxyPathCookieName+"=/app") {
		t.Fatalf("second Set-Cookie = %q, want canonical proxy path cookie", values[1])
	}
}

func TestRewriteHTMLAbsolutePathsUsesBytes(t *testing.T) {
	body := []byte(`<html><a href="/home"><img src="/logo.png"><form action="/save"><base href="/"></form></html>`)

	got := string(rewriteHTMLAbsolutePaths(body, "/app"))

	for _, want := range []string{
		`href="/app/home"`,
		`src="/app/logo.png"`,
		`action="/app/save"`,
		`<base href="/app/">`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("rewritten HTML %q does not contain %q", got, want)
		}
	}
}

func TestInjectToolbarIntoHTMLBytesFindsBodyCaseInsensitively(t *testing.T) {
	body := []byte(`<HTML><BODY>content</BODY></HTML>`)

	got := string(injectToolbarIntoHTMLBytes(body, `<script>toolbar()</script>`))

	if !strings.Contains(got, `content<script>toolbar()</script></BODY>`) {
		t.Fatalf("injected HTML = %q", got)
	}
}

func TestInjectToolbarIntoHTMLBytesAppendsForHTMLWithoutBodyClose(t *testing.T) {
	body := []byte(`<!doctype html><html><head></head>`)

	got := string(injectToolbarIntoHTMLBytes(body, `<script>toolbar()</script>`))

	if !strings.HasSuffix(got, `<script>toolbar()</script>`) {
		t.Fatalf("injected HTML = %q, want toolbar appended", got)
	}
}
