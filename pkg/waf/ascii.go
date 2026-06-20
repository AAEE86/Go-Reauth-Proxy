package waf

import "strings"

func lowerASCIIString(value string) string {
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c >= 0x80 || (c >= 'A' && c <= 'Z') {
			return strings.ToLower(value)
		}
	}
	return value
}
