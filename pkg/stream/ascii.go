package stream

func containsFoldASCIIString(value string, search string) bool {
	if search == "" {
		return true
	}
	if len(search) > len(value) {
		return false
	}
	first := lowerASCII(search[0])
	last := len(value) - len(search)
	for i := 0; i <= last; i++ {
		if lowerASCII(value[i]) != first {
			continue
		}
		if hasFoldASCIIPrefixString(value[i:], search) {
			return true
		}
	}
	return false
}

func hasFoldASCIIPrefixString(value string, prefix string) bool {
	if len(prefix) > len(value) {
		return false
	}
	for i := 1; i < len(prefix); i++ {
		if lowerASCII(value[i]) != lowerASCII(prefix[i]) {
			return false
		}
	}
	return true
}

func lowerASCII(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}
