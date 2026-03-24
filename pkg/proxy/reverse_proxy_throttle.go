package proxy

import (
	"go-reauth-proxy/pkg/models"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	defaultReverseProxyThrottleRPS       = 20
	defaultReverseProxyThrottleBurst     = 50
	defaultReverseProxyThrottleBlockSecs = 30
	reverseProxyThrottleCleanupInterval  = 1 * time.Minute
	reverseProxyThrottleMinimumEntryTTL  = 2 * time.Minute
)

type reverseProxyThrottle struct {
	mu          sync.Mutex
	config      models.ReverseProxyThrottleConfig
	entries     map[string]*reverseProxyThrottleEntry
	nextCleanup time.Time
}

type reverseProxyThrottleEntry struct {
	tokens       float64
	lastSeen     time.Time
	blockedUntil time.Time
}

func newReverseProxyThrottle(cfg models.ReverseProxyThrottleConfig) *reverseProxyThrottle {
	return &reverseProxyThrottle{
		config:  normalizeReverseProxyThrottleConfig(cfg),
		entries: make(map[string]*reverseProxyThrottleEntry),
	}
}

func normalizeReverseProxyThrottleConfig(cfg models.ReverseProxyThrottleConfig) models.ReverseProxyThrottleConfig {
	if !cfg.Enabled {
		return cfg
	}

	if cfg.RequestsPerSecond <= 0 {
		cfg.RequestsPerSecond = defaultReverseProxyThrottleRPS
	}
	if cfg.Burst <= 0 {
		cfg.Burst = defaultReverseProxyThrottleBurst
	}
	if cfg.BlockSeconds <= 0 {
		cfg.BlockSeconds = defaultReverseProxyThrottleBlockSecs
	}
	return cfg
}

func (t *reverseProxyThrottle) updateConfig(cfg models.ReverseProxyThrottleConfig) {
	t.mu.Lock()
	t.config = normalizeReverseProxyThrottleConfig(cfg)
	if !t.config.Enabled {
		t.entries = make(map[string]*reverseProxyThrottleEntry)
	}
	t.mu.Unlock()
}

func (t *reverseProxyThrottle) allow(clientIP string, now time.Time) bool {
	if t == nil {
		return true
	}

	identity := normalizeClientIP(clientIP)
	if identity == "" {
		return true
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	cfg := normalizeReverseProxyThrottleConfig(t.config)
	if !cfg.Enabled {
		return true
	}

	if t.entries == nil {
		t.entries = make(map[string]*reverseProxyThrottleEntry)
	}
	t.cleanupLocked(now, cfg)

	entry := t.entries[identity]
	if entry == nil {
		entry = &reverseProxyThrottleEntry{
			tokens: float64(cfg.Burst),
		}
		t.entries[identity] = entry
	}

	if entry.blockedUntil.After(now) {
		entry.lastSeen = now
		return false
	}
	if !entry.blockedUntil.IsZero() && !entry.blockedUntil.After(now) {
		entry.blockedUntil = time.Time{}
		if entry.tokens < 1 {
			entry.tokens = float64(cfg.Burst)
		}
	}

	if !entry.lastSeen.IsZero() {
		elapsed := now.Sub(entry.lastSeen).Seconds()
		if elapsed > 0 {
			entry.tokens += elapsed * float64(cfg.RequestsPerSecond)
			if entry.tokens > float64(cfg.Burst) {
				entry.tokens = float64(cfg.Burst)
			}
		}
	}

	entry.lastSeen = now
	if entry.tokens < 1 {
		entry.blockedUntil = now.Add(time.Duration(cfg.BlockSeconds) * time.Second)
		return false
	}

	entry.tokens -= 1
	return true
}

func (t *reverseProxyThrottle) cleanupLocked(now time.Time, cfg models.ReverseProxyThrottleConfig) {
	if now.Before(t.nextCleanup) {
		return
	}

	entryTTL := reverseProxyThrottleEntryTTL(cfg)
	for identity, entry := range t.entries {
		if entry == nil {
			delete(t.entries, identity)
			continue
		}
		if entry.blockedUntil.After(now) {
			continue
		}
		if entry.lastSeen.IsZero() || now.Sub(entry.lastSeen) > entryTTL {
			delete(t.entries, identity)
		}
	}
	t.nextCleanup = now.Add(reverseProxyThrottleCleanupInterval)
}

func reverseProxyThrottleEntryTTL(cfg models.ReverseProxyThrottleConfig) time.Duration {
	ttl := time.Duration(cfg.BlockSeconds*2) * time.Second
	if ttl < reverseProxyThrottleMinimumEntryTTL {
		ttl = reverseProxyThrottleMinimumEntryTTL
	}
	return ttl
}

func normalizeClientIP(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	if ip := normalizeIPAddress(value); ip != "" {
		return ip
	}

	if host, _, err := net.SplitHostPort(value); err == nil {
		host = strings.TrimSpace(host)
		if ip := normalizeIPAddress(host); ip != "" {
			return ip
		}
		return strings.Trim(host, "[]")
	}

	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		trimmed := strings.Trim(value, "[]")
		if ip := normalizeIPAddress(trimmed); ip != "" {
			return ip
		}
		return trimmed
	}

	return value
}

func firstForwardedClientIP(value string) string {
	for _, part := range strings.Split(value, ",") {
		if ip := normalizeIPAddress(part); ip != "" {
			return ip
		}
	}
	return ""
}

func normalizeIPAddress(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	if ip := net.ParseIP(value); ip != nil {
		return ip.String()
	}

	if host, _, err := net.SplitHostPort(value); err == nil {
		host = strings.TrimSpace(host)
		if ip := net.ParseIP(host); ip != nil {
			return ip.String()
		}
		trimmed := strings.Trim(host, "[]")
		if ip := net.ParseIP(trimmed); ip != nil {
			return ip.String()
		}
	}

	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		trimmed := strings.Trim(value, "[]")
		if ip := net.ParseIP(trimmed); ip != nil {
			return ip.String()
		}
	}

	return ""
}
