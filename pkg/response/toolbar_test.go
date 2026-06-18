package response

import (
	"encoding/json"
	"strings"
	"testing"

	"go-reauth-proxy/pkg/models"
)

func disabledGatewayPortalConfigForToolbarTest(t *testing.T) models.GatewayPortalConfig {
	t.Helper()

	var cfg models.GatewayPortalConfig
	if err := json.Unmarshal([]byte(`{"enabled":false}`), &cfg); err != nil {
		t.Fatalf("unmarshal disabled gateway portal config: %v", err)
	}
	return cfg
}

func TestGenerateToolbarWithHostsEscapesDynamicRouteData(t *testing.T) {
	toolbar := GenerateToolbarWithHosts(
		[]models.Rule{{Path: `/app</script><script>alert("path")</script>`}},
		[]models.HostRule{{
			Host:    `evil.example</script><script>alert("host")</script>`,
			Title:   `Evil</script><script>alert("title")</script>`,
			Favicon: `data:image/png;base64,AAA</script><script>alert("icon")</script>`,
		}},
		`/app</script><script>alert("current")</script>`,
		`evil.example</script><script>alert("current-host")</script>`,
		"",
		models.GatewayPortalConfig{DisplayStyle: models.GatewayPortalDisplayStyleTitle, ShowAppIcon: true},
	)

	if count := strings.Count(toolbar, "</script>"); count != 1 {
		t.Fatalf("toolbar contains %d raw closing script tags, want only wrapper close: %s", count, toolbar)
	}
	for _, forbidden := range []string{
		`<script>alert("path")</script>`,
		`<script>alert("host")</script>`,
		`<script>alert("title")</script>`,
		`<script>alert("icon")</script>`,
		`<script>alert("current")</script>`,
		`<script>alert("current-host")</script>`,
	} {
		if strings.Contains(toolbar, forbidden) {
			t.Fatalf("toolbar contains unescaped dynamic script fragment %q: %s", forbidden, toolbar)
		}
	}
	if !strings.Contains(toolbar, `\u003c/script\u003e`) {
		t.Fatalf("toolbar does not contain JSON-escaped dynamic script delimiters: %s", toolbar)
	}
}

func TestGenerateToolbarWithHostsReturnsEmptyWhenPortalDisabled(t *testing.T) {
	toolbar := GenerateToolbarWithHosts(
		nil,
		[]models.HostRule{{Host: "app.example.com", Title: "App Portal"}},
		"",
		"",
		"",
		disabledGatewayPortalConfigForToolbarTest(t),
	)

	if toolbar != "" {
		t.Fatalf("toolbar = %q, want empty when portal is disabled", toolbar)
	}
}

func TestGenerateToolbarWithHostsFiltersWebSocketTargets(t *testing.T) {
	toolbar := GenerateToolbarWithHosts(
		[]models.Rule{
			{Path: "/app", Target: "http://127.0.0.1:3000"},
			{Path: "/socket", Target: "ws://127.0.0.1:3001"},
		},
		[]models.HostRule{
			{Host: "app.example.com", Target: "https://127.0.0.1:3000"},
			{Host: "socket.example.com", Target: "wss://127.0.0.1:3001"},
		},
		"",
		"",
		"",
		models.GatewayPortalConfig{DisplayStyle: models.GatewayPortalDisplayStyleTitle},
	)

	for _, want := range []string{`"path":"/app"`, `"host":"app.example.com"`} {
		if !strings.Contains(toolbar, want) {
			t.Fatalf("toolbar missing HTTP(S) route %q: %s", want, toolbar)
		}
	}
	for _, forbidden := range []string{`/socket`, `socket.example.com`} {
		if strings.Contains(toolbar, forbidden) {
			t.Fatalf("toolbar included WebSocket route %q: %s", forbidden, toolbar)
		}
	}
}

func TestGenerateToolbarWithHostsIncludesFaviconOnlyWhenEnabled(t *testing.T) {
	icon := "data:image/png;base64,AAAA"
	hostRules := []models.HostRule{{Host: "app.example.com", Title: "App Portal", Favicon: icon}}

	disabled := GenerateToolbarWithHosts(
		nil,
		hostRules,
		"",
		"",
		"",
		models.GatewayPortalConfig{DisplayStyle: models.GatewayPortalDisplayStyleTitle},
	)
	if strings.Contains(disabled, icon) {
		t.Fatalf("toolbar included favicon while app icon display disabled: %s", disabled)
	}

	enabled := GenerateToolbarWithHosts(
		nil,
		hostRules,
		"",
		"",
		"",
		models.GatewayPortalConfig{DisplayStyle: models.GatewayPortalDisplayStyleTitle, ShowAppIcon: true},
	)
	if !strings.Contains(enabled, `"favicon":"`+icon+`"`) {
		t.Fatalf("toolbar did not include favicon while app icon display enabled: %s", enabled)
	}
	if !strings.Contains(enabled, `"show_app_icon":true`) {
		t.Fatalf("toolbar did not mark app icon display as enabled: %s", enabled)
	}
}

func TestGenerateToolbarWithHostsOmitsEmptyFavicon(t *testing.T) {
	toolbar := GenerateToolbarWithHosts(
		nil,
		[]models.HostRule{{Host: "app.example.com", Title: "App Portal", Favicon: "   "}},
		"",
		"",
		"",
		models.GatewayPortalConfig{DisplayStyle: models.GatewayPortalDisplayStyleTitle, ShowAppIcon: true},
	)

	if strings.Contains(toolbar, `"favicon":`) {
		t.Fatalf("toolbar included empty favicon field: %s", toolbar)
	}
}

func TestGenerateToolbarWithHostsUsesPortalTitleDisplay(t *testing.T) {
	toolbar := GenerateToolbarWithHosts(
		nil,
		[]models.HostRule{{Host: "app.example.com", Title: "App Portal"}},
		"",
		"",
		"",
		models.GatewayPortalConfig{DisplayStyle: models.GatewayPortalDisplayStyleTitle},
	)

	if !strings.Contains(toolbar, `"host":"app.example.com"`) {
		t.Fatalf("toolbar did not retain host for navigation: %s", toolbar)
	}
	if !strings.Contains(toolbar, `"label":"App Portal"`) {
		t.Fatalf("toolbar did not use title label: %s", toolbar)
	}
}

func TestGenerateToolbarWithHostsFallsBackToHostWhenTitleEmpty(t *testing.T) {
	toolbar := GenerateToolbarWithHosts(
		nil,
		[]models.HostRule{{Host: "app.example.com", Title: "   "}},
		"",
		"",
		"",
		models.GatewayPortalConfig{DisplayStyle: models.GatewayPortalDisplayStyleTitle},
	)

	if !strings.Contains(toolbar, `"label":"app.example.com"`) {
		t.Fatalf("toolbar did not fall back to host label: %s", toolbar)
	}
}
