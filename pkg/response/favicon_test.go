package response

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFaviconPathsUseReservedNamespace(t *testing.T) {
	for _, path := range []string{
		"/favicon-16x16.png",
		"/favicon-32x32.png",
		"/apple-touch-icon.png",
		"/android-chrome-192x192.png",
		"/android-chrome-512x512.png",
		"/site.webmanifest",
	} {
		if IsFaviconPath(path) {
			t.Fatalf("IsFaviconPath(%q) = true, want false for root favicon path", path)
		}
	}

	for _, path := range []string{
		"/__assets__/favicon/favicon-16x16.png",
		"/__assets__/favicon/favicon-32x32.png",
		"/__assets__/favicon/apple-touch-icon.png",
		"/__assets__/favicon/android-chrome-192x192.png",
		"/__assets__/favicon/android-chrome-512x512.png",
		"/__assets__/favicon/site.webmanifest",
	} {
		if !IsFaviconPath(path) {
			t.Fatalf("IsFaviconPath(%q) = false, want true for reserved favicon path", path)
		}
	}
}

func TestGatewayPagesUseReservedFaviconLinks(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://gateway.example.com/", nil)
	rec := httptest.NewRecorder()

	Welcome(rec, req, nil)

	body := rec.Body.String()
	for _, want := range []string{
		`href="/__assets__/favicon/apple-touch-icon.png"`,
		`href="/__assets__/favicon/favicon-32x32.png"`,
		`href="/__assets__/favicon/favicon-16x16.png"`,
		`href="/__assets__/favicon/site.webmanifest"`,
		`src="/__assets__/favicon/android-chrome-512x512.png"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("gateway page missing reserved favicon link %q: %s", want, body)
		}
	}

	for _, forbidden := range []string{
		`href="/apple-touch-icon.png"`,
		`href="/favicon-32x32.png"`,
		`href="/favicon-16x16.png"`,
		`href="/site.webmanifest"`,
		`src="/android-chrome-512x512.png"`,
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("gateway page still includes root favicon link %q: %s", forbidden, body)
		}
	}
}

func TestFaviconManifestUsesReservedIconSources(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://gateway.example.com/__assets__/favicon/site.webmanifest", nil)
	rec := httptest.NewRecorder()

	ServeFavicon(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	var manifest struct {
		Icons []struct {
			Src string `json:"src"`
		} `json:"icons"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &manifest); err != nil {
		t.Fatalf("decode manifest: %v\n%s", err, rec.Body.String())
	}
	if len(manifest.Icons) == 0 {
		t.Fatal("manifest icons are empty")
	}
	for _, icon := range manifest.Icons {
		if !strings.HasPrefix(icon.Src, "/__assets__/favicon/") {
			t.Fatalf("manifest icon src = %q, want reserved favicon path", icon.Src)
		}
	}
}
