package waf

import (
	"net/url"
	"strings"
)

func redactRequestURI(u *url.URL) string {
	if u == nil {
		return ""
	}
	clone := *u
	clone.RawQuery = redactRawQuery(u.RawQuery)
	return clone.RequestURI()
}

func redactRawQuery(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return ""
	}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return raw
	}
	for key := range values {
		if isSensitiveName(key) {
			values[key] = []string{"[redacted]"}
		}
	}
	return values.Encode()
}

func isSensitiveName(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return false
	}
	sensitiveParts := []string{
		"authorization",
		"cookie",
		"password",
		"passwd",
		"secret",
		"token",
		"session",
		"credential",
		"apikey",
		"api_key",
	}
	for _, part := range sensitiveParts {
		if strings.Contains(name, part) {
			return true
		}
	}
	return false
}
