package response

import (
	"strings"
	"testing"

	"go-reauth-proxy/pkg/models"
)

func TestGenerateToolbarWithHostsEscapesDynamicRouteData(t *testing.T) {
	toolbar := GenerateToolbarWithHosts(
		[]models.Rule{{Path: `/app</script><script>alert("path")</script>`}},
		[]models.HostRule{{
			Host:  `evil.example</script><script>alert("host")</script>`,
			Title: `Evil</script><script>alert("title")</script>`,
		}},
		`/app</script><script>alert("current")</script>`,
		`evil.example</script><script>alert("current-host")</script>`,
		"",
		models.GatewayPortalConfig{DisplayStyle: models.GatewayPortalDisplayStyleTitle},
	)

	if count := strings.Count(toolbar, "</script>"); count != 1 {
		t.Fatalf("toolbar contains %d raw closing script tags, want only wrapper close: %s", count, toolbar)
	}
	for _, forbidden := range []string{
		`<script>alert("path")</script>`,
		`<script>alert("host")</script>`,
		`<script>alert("title")</script>`,
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
