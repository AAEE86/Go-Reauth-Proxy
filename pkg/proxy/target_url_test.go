package proxy

import "testing"

func TestCheckSafeTargetAllowsWebSocketSchemes(t *testing.T) {
	handler := &Handler{AdminPort: 7997}

	for _, target := range []string{
		"ws://127.0.0.1:8080/socket",
		"wss://example.com/socket",
		"http://127.0.0.1:8080",
		"https://example.com",
	} {
		t.Run(target, func(t *testing.T) {
			if err := handler.checkSafeTarget(target); err != nil {
				t.Fatalf("checkSafeTarget(%q) returned error: %v", target, err)
			}
		})
	}
}

func TestCheckSafeTargetRejectsUnsupportedScheme(t *testing.T) {
	handler := &Handler{AdminPort: 7997}

	if err := handler.checkSafeTarget("ftp://example.com/resource"); err == nil {
		t.Fatal("checkSafeTarget accepted ftp target, want error")
	}
}

func TestCheckSafeTargetRejectsLocalAdminPortForWebSocket(t *testing.T) {
	handler := &Handler{AdminPort: 7997}

	for _, target := range []string{
		"ws://localhost:7997/socket",
		"wss://127.0.0.1:7997/socket",
		"ws://[::1]:7997/socket",
	} {
		t.Run(target, func(t *testing.T) {
			if err := handler.checkSafeTarget(target); err == nil {
				t.Fatalf("checkSafeTarget(%q) returned nil error, want admin port rejection", target)
			}
		})
	}
}

func TestReverseProxyTransportURLMapsWebSocketSchemes(t *testing.T) {
	tests := []struct {
		target        string
		wantTransport string
	}{
		{target: "ws://example.com/socket", wantTransport: "http://example.com/socket"},
		{target: "wss://example.com/socket", wantTransport: "https://example.com/socket"},
		{target: "http://example.com", wantTransport: "http://example.com"},
		{target: "https://example.com", wantTransport: "https://example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.target, func(t *testing.T) {
			targetURL, transportURL, err := parseReverseProxyTargetURLs(tt.target)
			if err != nil {
				t.Fatalf("parseReverseProxyTargetURLs(%q) returned error: %v", tt.target, err)
			}
			if targetURL.String() != tt.target {
				t.Fatalf("targetURL = %q, want %q", targetURL.String(), tt.target)
			}
			if transportURL.String() != tt.wantTransport {
				t.Fatalf("transportURL = %q, want %q", transportURL.String(), tt.wantTransport)
			}
		})
	}
}
