package i18n

import (
	"embed"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"

	"golang.org/x/text/language"
)

const (
	LocaleZhCN   = "zh-CN"
	LocaleZhHant = "zh-Hant"
	LocaleEn     = "en"

	DefaultLocale    = LocaleZhCN
	LocaleCookieName = "fn_knock_locale"
	LocaleHeaderName = "X-Fn-Knock-Locale"
)

type LocaleConfig struct {
	DefaultLocale string `json:"default_locale"`
}

//go:embed locales/*.json
var localeFS embed.FS

var (
	messages      = loadMessages()
	defaultLocale atomic.Value
	matcher       = language.NewMatcher([]language.Tag{
		language.MustParse(LocaleZhCN),
		language.MustParse(LocaleZhHant),
		language.MustParse(LocaleEn),
	})
)

func init() {
	defaultLocale.Store(DefaultLocale)
}

func loadMessages() map[string]map[string]string {
	out := map[string]map[string]string{}
	for _, locale := range []string{LocaleZhCN, LocaleZhHant, LocaleEn} {
		data, err := localeFS.ReadFile("locales/" + locale + ".json")
		if err != nil {
			continue
		}
		var values map[string]string
		if err := json.Unmarshal(data, &values); err != nil {
			continue
		}
		out[locale] = values
	}
	return out
}

func NormalizeLocale(value string) string {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return ""
	}
	switch raw {
	case LocaleZhCN, LocaleZhHant, LocaleEn:
		return raw
	}

	lower := strings.ToLower(strings.ReplaceAll(raw, "_", "-"))
	switch lower {
	case "zh", "zh-cn", "zh-hans", "zh-hans-cn", "zh-sg", "zh-my":
		return LocaleZhCN
	case "zh-tw", "zh-hk", "zh-mo", "zh-hant", "zh-hant-tw":
		return LocaleZhHant
	case "en", "en-us", "en-gb":
		return LocaleEn
	}
	if strings.HasPrefix(lower, "en-") {
		return LocaleEn
	}
	if strings.HasPrefix(lower, "zh-hant") {
		return LocaleZhHant
	}
	if strings.HasPrefix(lower, "zh-") {
		return LocaleZhCN
	}
	return ""
}

func NormalizeConfig(cfg LocaleConfig) LocaleConfig {
	locale := NormalizeLocale(cfg.DefaultLocale)
	if locale == "" {
		locale = DefaultLocale
	}
	return LocaleConfig{DefaultLocale: locale}
}

func SetDefaultLocale(locale string) {
	normalized := NormalizeLocale(locale)
	if normalized == "" {
		normalized = DefaultLocale
	}
	defaultLocale.Store(normalized)
}

func DefaultLocaleValue() string {
	value, _ := defaultLocale.Load().(string)
	if value == "" {
		return DefaultLocale
	}
	return value
}

func ResolveAcceptLanguage(header string) string {
	tags, _, err := language.ParseAcceptLanguage(header)
	if err != nil || len(tags) == 0 {
		return ""
	}
	tag, _, _ := matcher.Match(tags...)
	return NormalizeLocale(tag.String())
}

func ResolveRequestLocale(r *http.Request) string {
	if locale := DefaultLocaleValue(); locale != "" {
		return locale
	}
	return DefaultLocale
}

func T(locale string, key string) string {
	normalized := NormalizeLocale(locale)
	if normalized == "" {
		normalized = DefaultLocale
	}
	if value := messages[normalized][key]; value != "" {
		return value
	}
	if value := messages[DefaultLocale][key]; value != "" {
		return value
	}
	return key
}

func RequestT(r *http.Request, key string) string {
	return T(ResolveRequestLocale(r), key)
}
