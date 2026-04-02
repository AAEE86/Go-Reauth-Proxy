package proxy

import (
	"go-reauth-proxy/pkg/models"
	"net/netip"
	"strings"
	"sync"
	"time"
)

type reverseProxyThrottleExemptIPsRuntime struct {
	mu     sync.RWMutex
	config models.ReverseProxyThrottleExemptIPsRuntime
	ips    map[string]struct{}
}

func newReverseProxyThrottleExemptIPsRuntime(cfg models.ReverseProxyThrottleExemptIPsRuntime) *reverseProxyThrottleExemptIPsRuntime {
	runtime := &reverseProxyThrottleExemptIPsRuntime{
		ips: make(map[string]struct{}),
	}
	runtime.updateConfig(cfg)
	return runtime
}

func (r *reverseProxyThrottleExemptIPsRuntime) getConfig() models.ReverseProxyThrottleExemptIPsRuntime {
	if r == nil {
		return models.ReverseProxyThrottleExemptIPsRuntime{
			Enabled:   false,
			IPs:       []string{},
			UpdatedAt: "",
		}
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	ips := make([]string, len(r.config.IPs))
	copy(ips, r.config.IPs)

	return models.ReverseProxyThrottleExemptIPsRuntime{
		Enabled:   r.config.Enabled,
		IPs:       ips,
		UpdatedAt: r.config.UpdatedAt,
	}
}

func (r *reverseProxyThrottleExemptIPsRuntime) updateConfig(cfg models.ReverseProxyThrottleExemptIPsRuntime) bool {
	normalized, ipSet := normalizeReverseProxyThrottleExemptIPsRuntime(cfg)

	r.mu.Lock()
	defer r.mu.Unlock()

	if shouldIgnoreReverseProxyThrottleExemptIPsUpdate(r.config.UpdatedAt, normalized.UpdatedAt) {
		return false
	}

	r.config = normalized
	r.ips = ipSet
	return true
}

func (r *reverseProxyThrottleExemptIPsRuntime) shouldBypass(clientIP string) bool {
	normalizedIP, addr, ok := normalizeReverseProxyThrottleExemptIP(clientIP)
	if !ok {
		return false
	}

	if isVisibilityExemptAddr(addr) {
		return true
	}

	if r == nil {
		return false
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	if !r.config.Enabled {
		return false
	}

	_, exists := r.ips[normalizedIP]
	return exists
}

func normalizeReverseProxyThrottleExemptIPsRuntime(cfg models.ReverseProxyThrottleExemptIPsRuntime) (models.ReverseProxyThrottleExemptIPsRuntime, map[string]struct{}) {
	ips := make([]string, 0, len(cfg.IPs))
	ipSet := make(map[string]struct{}, len(cfg.IPs))

	for _, rawIP := range cfg.IPs {
		normalizedIP, addr, ok := normalizeReverseProxyThrottleExemptIP(rawIP)
		if !ok {
			continue
		}
		if isVisibilityExemptAddr(addr) {
			continue
		}
		if _, exists := ipSet[normalizedIP]; exists {
			continue
		}
		ipSet[normalizedIP] = struct{}{}
		ips = append(ips, normalizedIP)
	}

	return models.ReverseProxyThrottleExemptIPsRuntime{
		Enabled:   cfg.Enabled,
		IPs:       ips,
		UpdatedAt: strings.TrimSpace(cfg.UpdatedAt),
	}, ipSet
}

func normalizeReverseProxyThrottleExemptIP(value string) (string, netip.Addr, bool) {
	normalizedIP := normalizeIPAddress(value)
	if normalizedIP == "" {
		return "", netip.Addr{}, false
	}

	addr, err := netip.ParseAddr(normalizedIP)
	if err != nil {
		return "", netip.Addr{}, false
	}

	return normalizedIP, addr, true
}

func shouldIgnoreReverseProxyThrottleExemptIPsUpdate(currentUpdatedAt string, nextUpdatedAt string) bool {
	currentTime, okCurrent := parseReverseProxyThrottleExemptIPsUpdatedAt(currentUpdatedAt)
	nextTime, okNext := parseReverseProxyThrottleExemptIPsUpdatedAt(nextUpdatedAt)

	if !okCurrent || !okNext {
		return false
	}

	return nextTime.Before(currentTime)
}

func parseReverseProxyThrottleExemptIPsUpdatedAt(value string) (time.Time, bool) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return time.Time{}, false
	}

	parsed, err := time.Parse(time.RFC3339Nano, trimmed)
	if err == nil {
		return parsed, true
	}

	parsed, err = time.Parse(time.RFC3339, trimmed)
	if err == nil {
		return parsed, true
	}

	return time.Time{}, false
}
