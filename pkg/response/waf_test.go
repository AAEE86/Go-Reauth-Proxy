package response

import (
	"encoding/json"
	"go-reauth-proxy/pkg/i18n"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWAFBlockedJSONResponse(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.test/search", nil)
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()

	WAFBlocked(rec, req, WAFBlockPageOptions{
		Status:  http.StatusForbidden,
		TraceID: "waf_test_trace",
	})

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d", rec.Code)
	}
	if rec.Header().Get("X-Fn-Knock-WAF-Blocked") != "1" {
		t.Fatalf("missing WAF blocked header")
	}
	if rec.Header().Get("X-Fn-Knock-WAF-Trace-ID") != "waf_test_trace" {
		t.Fatalf("missing trace header")
	}
	var body struct {
		Success bool   `json:"success"`
		Code    string `json:"code"`
		Message string `json:"message"`
		TraceID string `json:"trace_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Success ||
		body.Code != "WAF_BLOCKED" ||
		body.Message != "请求已被 WAF 拦截" ||
		body.TraceID != "waf_test_trace" {
		t.Fatalf("unexpected body: %#v", body)
	}
	if rec.Header().Get("Content-Language") != "zh-CN" {
		t.Fatalf("unexpected content language: %q", rec.Header().Get("Content-Language"))
	}
}

func TestWAFBlockedHTMLResponse(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.test/search", nil)
	req.Header.Set("Accept", "text/html")
	rec := httptest.NewRecorder()

	WAFBlocked(rec, req, WAFBlockPageOptions{
		Status:  http.StatusTeapot,
		TraceID: "waf_html_trace",
	})

	if rec.Code != http.StatusTeapot {
		t.Fatalf("expected status 418, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "请求已拦截") ||
		!strings.Contains(body, "访问被安全策略拒绝。") ||
		!strings.Contains(body, "waf_html_trace") {
		t.Fatalf("expected title and trace in HTML body: %s", body)
	}
}

func TestWAFBlockedHTMLResponseUsesGlobalDefaultLocale(t *testing.T) {
	i18n.SetDefaultLocale(i18n.LocaleEn)
	t.Cleanup(func() {
		i18n.SetDefaultLocale(i18n.DefaultLocale)
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.test/search", nil)
	req.Header.Set("Accept", "text/html")
	req.Header.Set("X-Fn-Knock-Locale", "zh-CN")
	rec := httptest.NewRecorder()

	WAFBlocked(rec, req, WAFBlockPageOptions{
		Status:  http.StatusForbidden,
		TraceID: "waf_en_trace",
	})

	body := rec.Body.String()
	if rec.Header().Get("Content-Language") != "en" {
		t.Fatalf("unexpected content language: %q", rec.Header().Get("Content-Language"))
	}
	if !strings.Contains(body, "Request blocked") ||
		!strings.Contains(body, "Access denied by security policy.") ||
		!strings.Contains(body, "waf_en_trace") {
		t.Fatalf("expected English WAF body: %s", body)
	}
}
