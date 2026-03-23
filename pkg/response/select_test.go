package response

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go-reauth-proxy/pkg/models"
)

func TestSelectPageRendersHostRulesWhenProvided(t *testing.T) {
	recorder := httptest.NewRecorder()

	SelectPage(
		recorder,
		[]models.Rule{{Path: "/path-only-test", Target: "http://127.0.0.1:8080"}},
		[]models.HostRule{{Host: "demo.example.com", Target: "http://127.0.0.1:5173"}},
	)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}

	body := recorder.Body.String()
	if !strings.Contains(body, `data-host="demo.example.com"`) {
		t.Fatalf("expected host rule to be rendered, body=%q", body)
	}
	if strings.Contains(body, `/path-only-test`) {
		t.Fatalf("expected host rules to take precedence over path rules, body=%q", body)
	}
}

func TestSelectPageRendersPathRulesWhenNoHostRulesExist(t *testing.T) {
	recorder := httptest.NewRecorder()

	SelectPage(
		recorder,
		[]models.Rule{{Path: "/app", Target: "http://127.0.0.1:8080"}},
		nil,
	)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}

	body := recorder.Body.String()
	if !strings.Contains(body, `href="/app/" class="route-card"`) {
		t.Fatalf("expected path rule to be rendered, body=%q", body)
	}
}
