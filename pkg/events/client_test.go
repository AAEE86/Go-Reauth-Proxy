package events

import (
	"fmt"
	"testing"
)

var eventsBenchmarkStringSink string

func TestLocalSystemEventsURLMatchesLegacyFormat(t *testing.T) {
	for _, port := range []int{1, defaultSystemEventsPort, 65535} {
		if got, want := localSystemEventsURL(port), fmt.Sprintf("http://127.0.0.1:%d%s", port, internalSystemEventsPath); got != want {
			t.Fatalf("localSystemEventsURL(%d) = %q, want %q", port, got, want)
		}
	}
}

func BenchmarkLocalSystemEventsURL(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		eventsBenchmarkStringSink = localSystemEventsURL(defaultSystemEventsPort)
	}
}

func BenchmarkLocalSystemEventsURLOld(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		eventsBenchmarkStringSink = fmt.Sprintf("http://127.0.0.1:%d%s", defaultSystemEventsPort, internalSystemEventsPath)
	}
}
