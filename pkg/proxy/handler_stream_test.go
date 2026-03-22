package proxy

import (
	"strings"
	"testing"

	"go-reauth-proxy/pkg/config"
	"go-reauth-proxy/pkg/models"
)

func newTestHandler(t *testing.T, adminPort int, proxyPort int) *Handler {
	t.Helper()

	return NewHandler(adminPort, proxyPort, nil, &config.AppConfig{
		Rules:        []models.Rule{},
		HostRules:    []models.HostRule{},
		StreamRules:  []models.StreamRule{},
		DefaultRoute: "/__select__",
		AuthConfig: models.AuthConfig{
			AuthPort:     7997,
			AuthURL:      "/api/auth/verify",
			LoginURL:     "/login",
			LogoutURL:    "/api/auth/logout",
			PreflightURL: "/api/auth/preflight",
		},
	}, t.TempDir())
}

func TestValidateStreamRulesRejectsReservedPorts(t *testing.T) {
	handler := newTestHandler(t, 7996, 7999)

	testCases := []struct {
		name       string
		listenPort int
	}{
		{name: "admin", listenPort: 7996},
		{name: "proxy", listenPort: 7999},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := handler.ValidateStreamRules([]models.StreamRule{{
				ListenPort: tc.listenPort,
				Target:     "192.0.2.10:3306",
				UseAuth:    true,
			}})
			if err == nil {
				t.Fatalf("expected validation error for reserved port %d", tc.listenPort)
			}
			if !strings.Contains(err.Error(), "reserved") {
				t.Fatalf("expected reserved port error, got %v", err)
			}
		})
	}
}

func TestValidateStreamRulesRejectsLocalSelfTargets(t *testing.T) {
	handler := newTestHandler(t, 7996, 7999)

	testCases := []string{
		"127.0.0.1:3306",
		"localhost:3306",
		"[::1]:3306",
		"0.0.0.0:3306",
		"[::]:3306",
	}

	for _, target := range testCases {
		t.Run(target, func(t *testing.T) {
			_, err := handler.ValidateStreamRules([]models.StreamRule{{
				ListenPort: 3306,
				Target:     target,
				UseAuth:    true,
			}})
			if err == nil {
				t.Fatalf("expected validation error for self-target %s", target)
			}
			if !strings.Contains(err.Error(), "same local listen_port") {
				t.Fatalf("expected self-target error, got %v", err)
			}
		})
	}
}

func TestValidateStreamRulesAllowsRemoteSamePort(t *testing.T) {
	handler := newTestHandler(t, 7996, 7999)

	rules, err := handler.ValidateStreamRules([]models.StreamRule{{
		ListenPort: 3306,
		Target:     "192.0.2.10:3306",
		UseAuth:    true,
	}})
	if err != nil {
		t.Fatalf("expected remote same-port target to be allowed, got %v", err)
	}
	if len(rules) != 1 || rules[0].Target != "192.0.2.10:3306" {
		t.Fatalf("unexpected normalized rules: %+v", rules)
	}
}
