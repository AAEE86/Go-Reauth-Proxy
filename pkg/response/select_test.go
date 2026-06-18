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

func TestSelectPageFiltersWebSocketHostRules(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://gateway.example.com/__select__", nil)
	rec := httptest.NewRecorder()

	SelectPage(
		rec,
		req,
		nil,
		[]models.HostRule{
			{Host: "app.example.com", Target: "https://127.0.0.1:3000"},
			{Host: "socket.example.com", Target: "wss://127.0.0.1:3001"},
		},
		models.GatewayPortalConfig{},
	)

	body := rec.Body.String()
	if !strings.Contains(body, "app.example.com") {
		t.Fatalf("select page did not include HTTP(S) host rule: %s", body)
	}
	if strings.Contains(body, "socket.example.com") || strings.Contains(body, "wss://127.0.0.1:3001") {
		t.Fatalf("select page included WebSocket host rule: %s", body)
	}
}

func TestSelectPageFiltersWebSocketPathRules(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://gateway.example.com/__select__", nil)
	rec := httptest.NewRecorder()

	SelectPage(
		rec,
		req,
		[]models.Rule{
			{Path: "/app", Target: "http://127.0.0.1:3000"},
			{Path: "/socket", Target: "ws://127.0.0.1:3001"},
		},
		nil,
		models.GatewayPortalConfig{},
	)

	body := rec.Body.String()
	if !strings.Contains(body, "/app") {
		t.Fatalf("select page did not include HTTP(S) path rule: %s", body)
	}
	if strings.Contains(body, "/socket") || strings.Contains(body, "ws://127.0.0.1:3001") {
		t.Fatalf("select page included WebSocket path rule: %s", body)
	}
}
