package response

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go-reauth-proxy/pkg/models"
)

func disabledGatewayPortalConfigForSelectTest(t *testing.T) models.GatewayPortalConfig {
	t.Helper()

	var cfg models.GatewayPortalConfig
	if err := json.Unmarshal([]byte(`{"enabled":false}`), &cfg); err != nil {
		t.Fatalf("unmarshal disabled gateway portal config: %v", err)
	}
	return cfg
}

func TestSelectPageRemainsAvailableWhenPortalToolbarDisabled(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://gateway.example.com/__select__", nil)
	rec := httptest.NewRecorder()

	SelectPage(
		rec,
		req,
		nil,
		[]models.HostRule{{Host: "app.example.com", Target: "http://127.0.0.1:3000"}},
		disabledGatewayPortalConfigForSelectTest(t),
	)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "app.example.com") {
		t.Fatalf("select page did not include host rule while portal disabled: %s", body)
	}
	if strings.Contains(body, "reauth-proxy-toolbar") {
		t.Fatalf("select page included toolbar while portal disabled: %s", body)
	}
}
