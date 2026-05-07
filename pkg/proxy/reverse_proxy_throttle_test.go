package proxy

import (
	"go-reauth-proxy/pkg/models"
	"testing"
	"time"
)

func TestReverseProxyThrottleTracksIdentitiesIndependently(t *testing.T) {
	throttle := newReverseProxyThrottle(models.ReverseProxyThrottleConfig{
		Enabled:           true,
		RequestsPerSecond: 1,
		Burst:             1,
		BlockSeconds:      5,
	})
	now := time.Unix(100, 0)

	if decision := throttle.evaluate("192.0.2.1", now); !decision.Allowed {
		t.Fatal("first request for first identity should be allowed")
	}
	if decision := throttle.evaluate("192.0.2.1", now); decision.Allowed || !decision.NewlyBlocked {
		t.Fatalf("second request for first identity = %#v, want newly blocked", decision)
	}
	if decision := throttle.evaluate("192.0.2.2", now); !decision.Allowed {
		t.Fatalf("first request for second identity = %#v, want allowed", decision)
	}
}

func TestReverseProxyThrottleDisableClearsEntries(t *testing.T) {
	throttle := newReverseProxyThrottle(models.ReverseProxyThrottleConfig{
		Enabled:           true,
		RequestsPerSecond: 1,
		Burst:             1,
		BlockSeconds:      5,
	})
	now := time.Unix(100, 0)

	_ = throttle.evaluate("192.0.2.1", now)
	if decision := throttle.evaluate("192.0.2.1", now); decision.Allowed {
		t.Fatal("identity should be blocked before disabling throttle")
	}

	throttle.updateConfig(models.ReverseProxyThrottleConfig{Enabled: false})
	if decision := throttle.evaluate("192.0.2.1", now); !decision.Allowed {
		t.Fatalf("disabled throttle decision = %#v, want allowed", decision)
	}

	throttle.updateConfig(models.ReverseProxyThrottleConfig{
		Enabled:           true,
		RequestsPerSecond: 1,
		Burst:             1,
		BlockSeconds:      5,
	})
	if decision := throttle.evaluate("192.0.2.1", now); !decision.Allowed {
		t.Fatalf("re-enabled throttle decision = %#v, want allowed after clearing entries", decision)
	}
}
