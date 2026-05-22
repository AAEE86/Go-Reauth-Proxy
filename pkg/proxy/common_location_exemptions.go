package proxy

import (
	"go-reauth-proxy/pkg/models"
	"net/netip"
	"strings"
	"sync"
)

type commonLocationExemptionsRuntime struct {
	mu       sync.RWMutex
	config   models.CommonLocationExemptionsRuntime
	prefixes []netip.Prefix
}

func newCommonLocationExemptionsRuntime(cfg models.CommonLocationExemptionsRuntime) *commonLocationExemptionsRuntime {
	runtime := &commonLocationExemptionsRuntime{}
	runtime.updateConfig(cfg)
	return runtime
}

func (r *commonLocationExemptionsRuntime) getConfig() models.CommonLocationExemptionsRuntime {
	if r == nil {
		return models.CommonLocationExemptionsRuntime{
			Enabled:    false,
			WAFEnabled: false,
			CIDRs:      []string{},
			UpdatedAt:  "",
		}
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	cidrs := make([]string, len(r.config.CIDRs))
	copy(cidrs, r.config.CIDRs)

	return models.CommonLocationExemptionsRuntime{
		Enabled:    r.config.Enabled,
		WAFEnabled: r.config.WAFEnabled,
		CIDRs:      cidrs,
		UpdatedAt:  r.config.UpdatedAt,
	}
}

func (r *commonLocationExemptionsRuntime) updateConfig(cfg models.CommonLocationExemptionsRuntime) bool {
	normalized, prefixes := normalizeCommonLocationExemptionsRuntime(cfg)

	r.mu.Lock()
	defer r.mu.Unlock()

	if shouldIgnoreReverseProxyThrottleExemptIPsUpdate(r.config.UpdatedAt, normalized.UpdatedAt) {
		return false
	}

	r.config = normalized
	r.prefixes = prefixes
	return true
}

func (r *commonLocationExemptionsRuntime) shouldBypassWAF(clientIP string) bool {
	if r == nil {
		return false
	}

	normalizedIP := normalizeClientIP(clientIP)
	if normalizedIP == "" {
		return false
	}

	addr, err := netip.ParseAddr(normalizedIP)
	if err != nil {
		return false
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	if !r.config.Enabled || !r.config.WAFEnabled {
		return false
	}

	for _, prefix := range r.prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func normalizeCommonLocationExemptionsRuntime(cfg models.CommonLocationExemptionsRuntime) (models.CommonLocationExemptionsRuntime, []netip.Prefix) {
	cidrs := make([]string, 0, len(cfg.CIDRs))
	seen := make(map[string]struct{}, len(cfg.CIDRs))
	prefixes := make([]netip.Prefix, 0, len(cfg.CIDRs))

	for _, rawCIDR := range cfg.CIDRs {
		cidr := strings.TrimSpace(rawCIDR)
		if cidr == "" {
			continue
		}

		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			continue
		}

		prefix = prefix.Masked()
		text := prefix.String()
		if _, exists := seen[text]; exists {
			continue
		}
		seen[text] = struct{}{}
		cidrs = append(cidrs, text)
		prefixes = append(prefixes, prefix)
	}

	return models.CommonLocationExemptionsRuntime{
		Enabled:    cfg.Enabled,
		WAFEnabled: cfg.WAFEnabled,
		CIDRs:      cidrs,
		UpdatedAt:  strings.TrimSpace(cfg.UpdatedAt),
	}, prefixes
}
