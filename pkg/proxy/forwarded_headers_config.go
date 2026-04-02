package proxy

import (
	"go-reauth-proxy/pkg/models"
	"net/url"
	"path"
	"strings"
	"sync"
)

type forwardedHeadersConfig struct {
	mu          sync.RWMutex
	config      models.ForwardedHeadersConfig
	omitTargets map[string]struct{}
}

func newForwardedHeadersConfig(cfg models.ForwardedHeadersConfig) *forwardedHeadersConfig {
	runtime := &forwardedHeadersConfig{
		omitTargets: make(map[string]struct{}),
	}
	runtime.updateConfig(cfg)
	return runtime
}

func (c *forwardedHeadersConfig) updateConfig(cfg models.ForwardedHeadersConfig) {
	normalized, omitTargets := normalizeForwardedHeadersConfig(cfg)

	c.mu.Lock()
	c.config = normalized
	c.omitTargets = omitTargets
	c.mu.Unlock()
}

func (c *forwardedHeadersConfig) shouldOmit(target *url.URL) bool {
	if c == nil {
		return false
	}

	_, key, ok := normalizeForwardedHeadersTargetURL(target)
	if !ok {
		return false
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.config.Enabled {
		return false
	}

	_, exists := c.omitTargets[key]
	return exists
}

func (c *forwardedHeadersConfig) getConfig() models.ForwardedHeadersConfig {
	if c == nil {
		return models.ForwardedHeadersConfig{
			Enabled:     false,
			OmitTargets: []string{},
			UpdatedAt:   "",
		}
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	omitTargets := make([]string, len(c.config.OmitTargets))
	copy(omitTargets, c.config.OmitTargets)

	return models.ForwardedHeadersConfig{
		Enabled:     c.config.Enabled,
		OmitTargets: omitTargets,
		UpdatedAt:   c.config.UpdatedAt,
	}
}

func normalizeForwardedHeadersConfig(cfg models.ForwardedHeadersConfig) (models.ForwardedHeadersConfig, map[string]struct{}) {
	omitTargets := make([]string, 0, len(cfg.OmitTargets))
	omitTargetSet := make(map[string]struct{}, len(cfg.OmitTargets))

	for _, rawTarget := range cfg.OmitTargets {
		normalized, ok := normalizeForwardedHeadersTarget(rawTarget)
		if !ok {
			continue
		}
		if _, exists := omitTargetSet[normalized]; exists {
			continue
		}
		omitTargetSet[normalized] = struct{}{}
		omitTargets = append(omitTargets, normalized)
	}

	return models.ForwardedHeadersConfig{
		Enabled:     cfg.Enabled,
		OmitTargets: omitTargets,
		UpdatedAt:   strings.TrimSpace(cfg.UpdatedAt),
	}, omitTargetSet
}

func normalizeForwardedHeadersTarget(rawTarget string) (string, bool) {
	parsed, err := url.Parse(strings.TrimSpace(rawTarget))
	if err != nil {
		return "", false
	}

	_, normalized, ok := normalizeForwardedHeadersTargetURL(parsed)
	return normalized, ok
}

func normalizeForwardedHeadersTargetURL(target *url.URL) (*url.URL, string, bool) {
	if target == nil {
		return nil, "", false
	}

	normalized := *target
	normalized.Scheme = strings.ToLower(strings.TrimSpace(normalized.Scheme))
	switch normalized.Scheme {
	case "ws":
		normalized.Scheme = "http"
	case "wss":
		normalized.Scheme = "https"
	case "http", "https":
	default:
		return nil, "", false
	}

	if strings.TrimSpace(normalized.Host) == "" {
		return nil, "", false
	}

	normalized.User = nil
	normalized.RawQuery = ""
	normalized.Fragment = ""
	normalized.RawPath = ""
	normalized.Path = canonicalForwardedHeadersBasePath(normalized.Path)

	return &normalized, normalized.String(), true
}

func canonicalForwardedHeadersBasePath(rawPath string) string {
	rawPath = strings.TrimSpace(rawPath)
	if rawPath == "" || rawPath == "/" {
		return ""
	}

	cleaned := path.Clean(ensureLeadingSlash(rawPath))
	if cleaned == "." || cleaned == "/" {
		return ""
	}

	return cleaned
}
