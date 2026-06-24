package response

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAccessDeniedJSONResponse(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://app.example.test/private", nil)
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()

	AccessDenied(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body = %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("X-Fn-Knock-Access-Denied") != "scope" {
		t.Fatalf("missing access denied header")
	}
	var body struct {
		Success bool   `json:"success"`
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Success || body.Code != "ACCESS_DENIED" || body.Message == "" {
		t.Fatalf("unexpected body: %#v", body)
	}
}

func TestAccessDeniedHTMLResponseIncludesRequestTarget(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://app.example.test/private/path?x=1", nil)
	rec := httptest.NewRecorder()

	AccessDenied(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body = %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"权限不足", "app.example.test", "/private/path?x=1", "/__auth__/api/auth/logout"} {
		if !strings.Contains(body, want) {
			t.Fatalf("body missing %q: %s", want, body)
		}
	}
	if strings.Contains(body, "/__select__") {
		t.Fatalf("body should not include select page link: %s", body)
	}
}
