package response

import (
	"strings"
	"testing"

	"go-reauth-proxy/pkg/models"
)

func TestGenerateToolbarWithHostsEscapesDynamicRouteData(t *testing.T) {
	toolbar := GenerateToolbarWithHosts(
		[]models.Rule{{Path: `/app</script><script>alert("path")</script>`}},
		[]models.HostRule{{Host: `evil.example</script><script>alert("host")</script>`}},
		`/app</script><script>alert("current")</script>`,
		`evil.example</script><script>alert("current-host")</script>`,
		"",
	)

	if count := strings.Count(toolbar, "</script>"); count != 1 {
		t.Fatalf("toolbar contains %d raw closing script tags, want only wrapper close: %s", count, toolbar)
	}
	for _, forbidden := range []string{
		`<script>alert("path")</script>`,
		`<script>alert("host")</script>`,
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
