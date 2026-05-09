package logger

import "testing"

func TestBoolEnv(t *testing.T) {
	for _, value := range []string{"1", "true", "TRUE", "t", "yes", "y", "on", " On "} {
		t.Setenv("GO_REPROXY_TEST_BOOL", value)
		if !BoolEnv("GO_REPROXY_TEST_BOOL") {
			t.Fatalf("expected %q to enable bool env", value)
		}
	}

	for _, value := range []string{"", "0", "false", "no", "off", "anything"} {
		t.Setenv("GO_REPROXY_TEST_BOOL", value)
		if BoolEnv("GO_REPROXY_TEST_BOOL") {
			t.Fatalf("expected %q to disable bool env", value)
		}
	}
}
