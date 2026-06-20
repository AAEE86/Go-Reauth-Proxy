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
	if redacted, ok := redactRawQueryFast(raw); ok {
		return redacted
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

func redactRawQueryFast(raw string) (string, bool) {
	if strings.ContainsAny(raw, "%+;") {
		return "", false
	}

	var builder strings.Builder
	changed := false
	start := 0
	for start <= len(raw) {
		end := len(raw)
		if idx := strings.IndexByte(raw[start:], '&'); idx >= 0 {
			end = start + idx
		}
		part := raw[start:end]
		name := part
		if idx := strings.IndexByte(part, '='); idx >= 0 {
			name = part[:idx]
		}
		if isSensitiveName(name) {
			if !changed {
				builder.Grow(len(raw) + len("%5Bredacted%5D"))
				builder.WriteString(raw[:start])
				changed = true
			}
			builder.WriteString(name)
			builder.WriteString("=%5Bredacted%5D")
		} else if changed {
			builder.WriteString(part)
		}
		if end == len(raw) {
			break
		}
		if changed {
			builder.WriteByte('&')
		}
		start = end + 1
	}
	if !changed {
		return raw, true
	}
	return builder.String(), true
}

func isSensitiveName(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" {
		return false
	}
	for _, part := range sensitiveParts {
		if containsFoldASCIIString(name, part) {
			return true
		}
	}
	return false
}

var sensitiveParts = [...]string{
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

func containsFoldASCIIString(value string, search string) bool {
	if search == "" {
		return true
	}
	if len(search) > len(value) {
		return false
	}
	first := lowerASCIIByte(search[0])
	last := len(value) - len(search)
	for i := 0; i <= last; i++ {
		if lowerASCIIByte(value[i]) != first {
			continue
		}
		if hasFoldASCIIPrefix(value[i:], search) {
			return true
		}
	}
	return false
}

func hasFoldASCIIPrefix(value string, prefix string) bool {
	if len(prefix) > len(value) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		if lowerASCIIByte(value[i]) != lowerASCIIByte(prefix[i]) {
			return false
		}
	}
	return true
}

func lowerASCIIByte(value byte) byte {
	if value >= 'A' && value <= 'Z' {
		return value + ('a' - 'A')
	}
	return value
}
