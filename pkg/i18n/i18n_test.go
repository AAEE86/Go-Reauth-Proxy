package i18n

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNormalizeLocaleAliases(t *testing.T) {
	tests := map[string]string{
		"zh":        LocaleZhCN,
		"zh-Hans":   LocaleZhCN,
		"zh_CN":     LocaleZhCN,
		"zh-TW":     LocaleZhHant,
		"zh-Hant":   LocaleZhHant,
		"en-US":     LocaleEn,
		"ko":        LocaleKoKR,
		"ko_KR":     LocaleKoKR,
		"fr":        "",
		"   zh-HK ": LocaleZhHant,
	}

	for input, want := range tests {
		if got := NormalizeLocale(input); got != want {
			t.Fatalf("NormalizeLocale(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestResolveAcceptLanguage(t *testing.T) {
	if got := ResolveAcceptLanguage("fr-FR, en-US;q=0.9, zh-TW;q=0.8"); got != LocaleEn {
		t.Fatalf("ResolveAcceptLanguage preferred %q, want %q", got, LocaleEn)
	}
	if got := ResolveAcceptLanguage("zh-TW, en;q=0.9"); got != LocaleZhHant {
		t.Fatalf("ResolveAcceptLanguage preferred %q, want %q", got, LocaleZhHant)
	}
	if got := ResolveAcceptLanguage("ko-KR, en;q=0.9"); got != LocaleKoKR {
		t.Fatalf("ResolveAcceptLanguage preferred %q, want %q", got, LocaleKoKR)
	}
}

func TestResolveRequestLocaleUsesGlobalDefault(t *testing.T) {
	SetDefaultLocale(LocaleEn)
	t.Cleanup(func() {
		SetDefaultLocale(DefaultLocale)
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.test/?lang=zh-Hant", nil)
	req.Header.Set(LocaleHeaderName, LocaleZhCN)
	req.Header.Set("Accept-Language", "zh-TW, en;q=0.9")
	req.AddCookie(&http.Cookie{Name: LocaleCookieName, Value: LocaleZhHant})
	if got := ResolveRequestLocale(req); got != LocaleEn {
		t.Fatalf("request locale = %q, want global default %q", got, LocaleEn)
	}

	if got := ResolveRequestLocale(nil); got != LocaleEn {
		t.Fatalf("nil request locale = %q, want global default %q", got, LocaleEn)
	}
}

func TestLocaleMessageKeysComplete(t *testing.T) {
	base := messages[DefaultLocale]
	if len(base) == 0 {
		t.Fatal("default locale messages are empty")
	}

	for _, locale := range []string{LocaleZhCN, LocaleZhHant, LocaleEn, LocaleKoKR} {
		values := messages[locale]
		if len(values) == 0 {
			t.Fatalf("locale %s messages are empty", locale)
		}
		for key := range base {
			if values[key] == "" {
				t.Fatalf("locale %s missing key %s", locale, key)
			}
		}
		for key := range values {
			if base[key] == "" {
				t.Fatalf("locale %s has extra key %s", locale, key)
			}
		}
	}
}
