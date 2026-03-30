package proxy

import (
	"fmt"
	"go-reauth-proxy/pkg/models"
	"net/netip"
	"strings"
	"sync"
)

var visibilityExemptPrefixes = []netip.Prefix{
	mustParseVisibilityPrefix("100.64.0.0/10"),
}

func mustParseVisibilityPrefix(value string) netip.Prefix {
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		panic(err)
	}
	return prefix.Masked()
}

type gatewayVisibility struct {
	mu       sync.RWMutex
	config   models.GatewayVisibilityConfig
	prefixes []netip.Prefix
}

func normalizeGatewayVisibilityConfig(cfg models.GatewayVisibilityConfig) (models.GatewayVisibilityConfig, []netip.Prefix, error) {
	normalized := models.GatewayVisibilityConfig{
		Enabled:   cfg.Enabled,
		CIDRs:     make([]string, 0, len(cfg.CIDRs)),
		UpdatedAt: strings.TrimSpace(cfg.UpdatedAt),
	}

	seen := make(map[string]struct{}, len(cfg.CIDRs))
	prefixes := make([]netip.Prefix, 0, len(cfg.CIDRs))

	for _, rawCIDR := range cfg.CIDRs {
		cidr := strings.TrimSpace(rawCIDR)
		if cidr == "" {
			continue
		}

		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return models.GatewayVisibilityConfig{}, nil, fmt.Errorf("invalid visibility cidr %q: %w", cidr, err)
		}

		prefix = prefix.Masked()
		text := prefix.String()
		if _, exists := seen[text]; exists {
			continue
		}
		seen[text] = struct{}{}
		normalized.CIDRs = append(normalized.CIDRs, text)
		prefixes = append(prefixes, prefix)
	}

	return normalized, prefixes, nil
}

func newGatewayVisibility(cfg models.GatewayVisibilityConfig) (*gatewayVisibility, error) {
	normalized, prefixes, err := normalizeGatewayVisibilityConfig(cfg)
	if err != nil {
		return nil, err
	}

	return &gatewayVisibility{
		config:   normalized,
		prefixes: prefixes,
	}, nil
}

func (v *gatewayVisibility) updateConfig(cfg models.GatewayVisibilityConfig) error {
	if v == nil {
		return nil
	}

	normalized, prefixes, err := normalizeGatewayVisibilityConfig(cfg)
	if err != nil {
		return err
	}

	v.mu.Lock()
	v.config = normalized
	v.prefixes = prefixes
	v.mu.Unlock()
	return nil
}

func (v *gatewayVisibility) getConfig() models.GatewayVisibilityConfig {
	if v == nil {
		return models.GatewayVisibilityConfig{
			Enabled:   false,
			CIDRs:     []string{},
			UpdatedAt: "",
		}
	}

	v.mu.RLock()
	defer v.mu.RUnlock()

	cidrs := make([]string, len(v.config.CIDRs))
	copy(cidrs, v.config.CIDRs)

	return models.GatewayVisibilityConfig{
		Enabled:   v.config.Enabled,
		CIDRs:     cidrs,
		UpdatedAt: v.config.UpdatedAt,
	}
}

func (v *gatewayVisibility) contains(clientIP string) bool {
	if v == nil {
		return true
	}

	v.mu.RLock()
	enabled := v.config.Enabled
	v.mu.RUnlock()

	if !enabled {
		return true
	}

	normalizedIP := normalizeClientIP(clientIP)
	if normalizedIP == "" {
		return false
	}

	addr, err := netip.ParseAddr(normalizedIP)
	if err != nil {
		return false
	}
	if isVisibilityExemptAddr(addr) {
		return true
	}

	v.mu.RLock()
	defer v.mu.RUnlock()

	for _, prefix := range v.prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}

	return false
}

func isVisibilityExemptAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}

	if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() {
		return true
	}

	for _, prefix := range visibilityExemptPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}

	return false
}
