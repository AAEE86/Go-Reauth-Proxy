package response

import (
	"encoding/json"
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
		TraceID string `json:"trace_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Success || body.Code != "WAF_BLOCKED" || body.TraceID != "waf_test_trace" {
		t.Fatalf("unexpected body: %#v", body)
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
	if !strings.Contains(body, "Request blocked") ||
		!strings.Contains(body, "Access denied by security policy.") ||
		!strings.Contains(body, "waf_html_trace") {
		t.Fatalf("expected title and trace in HTML body: %s", body)
	}
}
