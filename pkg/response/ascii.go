package response

import "strings"

func equalFoldASCIIString(a string, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if lowerASCIIByte(a[i]) != lowerASCIIByte(b[i]) {
			return false
		}
	}
	return true
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

func lowerASCIIString(value string) string {
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c >= 0x80 || (c >= 'A' && c <= 'Z') {
			return strings.ToLower(value)
		}
	}
	return value
}
