package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

const (
	forwardedHeaderPolicyCacheTTL      = 30 * time.Second
	forwardedHeaderPolicyProbeTimeout  = 1500 * time.Millisecond
	forwardedHeaderPolicyProbeMaxBytes = 64 << 10
)

type forwardedHeaderPolicy int

const (
	forwardedHeaderPolicyAdd forwardedHeaderPolicy = iota
	forwardedHeaderPolicyOmit
)

type forwardedHeaderPolicyRule interface {
	Resolve(ctx context.Context, target *url.URL, client *http.Client) (forwardedHeaderPolicy, bool)
}

type forwardedHeaderPolicyCacheEntry struct {
	policy    forwardedHeaderPolicy
	expiresAt time.Time
}

type forwardedHeaderPolicyResolver struct {
	client       *http.Client
	ttl          time.Duration
	probeTimeout time.Duration
	rules        []forwardedHeaderPolicyRule

	mu          sync.RWMutex
	entries     map[string]forwardedHeaderPolicyCacheEntry
	lastCleanup time.Time
	group       singleflight.Group
}

type homeAssistantManifestForwardedHeaderRule struct{}

type manifestMetadata struct {
	ShortName string `json:"short_name"`
}

func newForwardedHeaderPolicyResolver(transport http.RoundTripper) *forwardedHeaderPolicyResolver {
	return newForwardedHeaderPolicyResolverWithConfig(transport, forwardedHeaderPolicyCacheTTL, forwardedHeaderPolicyProbeTimeout)
}

func newForwardedHeaderPolicyResolverWithConfig(transport http.RoundTripper, ttl time.Duration, timeout time.Duration) *forwardedHeaderPolicyResolver {
	if ttl <= 0 {
		ttl = forwardedHeaderPolicyCacheTTL
	}
	if timeout <= 0 {
		timeout = forwardedHeaderPolicyProbeTimeout
	}
	if transport == nil {
		transport = newProxyTransport()
	}

	return &forwardedHeaderPolicyResolver{
		client: &http.Client{
			Timeout:   timeout,
			Transport: transport,
		},
		ttl:          ttl,
		probeTimeout: timeout,
		rules: []forwardedHeaderPolicyRule{
			homeAssistantManifestForwardedHeaderRule{},
		},
		entries: make(map[string]forwardedHeaderPolicyCacheEntry),
	}
}

func (r *forwardedHeaderPolicyResolver) Policy(ctx context.Context, target *url.URL) forwardedHeaderPolicy {
	if r == nil {
		return forwardedHeaderPolicyAdd
	}
	if ctx == nil {
		ctx = context.Background()
	}

	normalizedTarget, cacheKey, ok := normalizeForwardedHeaderPolicyTarget(target)
	if !ok {
		return forwardedHeaderPolicyAdd
	}

	now := time.Now()
	if policy, ok := r.cachedPolicy(cacheKey, now); ok {
		return policy
	}

	resultAny, _, _ := r.group.Do(cacheKey, func() (any, error) {
		now := time.Now()
		if policy, ok := r.cachedPolicy(cacheKey, now); ok {
			return policy, nil
		}

		policy := r.resolvePolicy(ctx, normalizedTarget)
		r.storePolicy(cacheKey, policy, time.Now())
		return policy, nil
	})

	policy, ok := resultAny.(forwardedHeaderPolicy)
	if !ok {
		return forwardedHeaderPolicyAdd
	}
	return policy
}

func (r *forwardedHeaderPolicyResolver) resolvePolicy(ctx context.Context, target *url.URL) forwardedHeaderPolicy {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx = context.WithoutCancel(ctx)
	if r.probeTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.probeTimeout)
		defer cancel()
	}

	for _, rule := range r.rules {
		if policy, matched := rule.Resolve(ctx, target, r.client); matched {
			return policy
		}
	}
	return forwardedHeaderPolicyAdd
}

func (r *forwardedHeaderPolicyResolver) cachedPolicy(cacheKey string, now time.Time) (forwardedHeaderPolicy, bool) {
	r.mu.RLock()
	entry, ok := r.entries[cacheKey]
	r.mu.RUnlock()
	if !ok {
		return forwardedHeaderPolicyAdd, false
	}
	if !entry.expiresAt.After(now) {
		r.mu.Lock()
		delete(r.entries, cacheKey)
		r.mu.Unlock()
		return forwardedHeaderPolicyAdd, false
	}
	return entry.policy, true
}

func (r *forwardedHeaderPolicyResolver) storePolicy(cacheKey string, policy forwardedHeaderPolicy, now time.Time) {
	r.mu.Lock()
	r.entries[cacheKey] = forwardedHeaderPolicyCacheEntry{
		policy:    policy,
		expiresAt: now.Add(r.ttl),
	}
	r.cleanupExpiredLocked(now)
	r.mu.Unlock()
}

func (r *forwardedHeaderPolicyResolver) cleanupExpiredLocked(now time.Time) {
	if !r.lastCleanup.IsZero() && now.Sub(r.lastCleanup) < r.ttl {
		return
	}
	for key, entry := range r.entries {
		if !entry.expiresAt.After(now) {
			delete(r.entries, key)
		}
	}
	r.lastCleanup = now
}

func normalizeForwardedHeaderPolicyTarget(target *url.URL) (*url.URL, string, bool) {
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
	normalized.Path = canonicalForwardedHeaderPolicyBasePath(normalized.Path)

	return &normalized, normalized.String(), true
}

func canonicalForwardedHeaderPolicyBasePath(rawPath string) string {
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

func buildManifestProbeURL(target *url.URL) *url.URL {
	if target == nil {
		return nil
	}

	probe := *target
	probe.RawQuery = ""
	probe.Fragment = ""
	probe.RawPath = ""
	probe.Path = singleJoiningSlash(probe.Path, "/manifest.json")
	return &probe
}

func (homeAssistantManifestForwardedHeaderRule) Resolve(ctx context.Context, target *url.URL, client *http.Client) (forwardedHeaderPolicy, bool) {
	if target == nil || client == nil {
		return forwardedHeaderPolicyAdd, false
	}

	probeURL := buildManifestProbeURL(target)
	if probeURL == nil {
		return forwardedHeaderPolicyAdd, false
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL.String(), nil)
	if err != nil {
		return forwardedHeaderPolicyAdd, false
	}

	resp, err := client.Do(req)
	if err != nil {
		return forwardedHeaderPolicyAdd, false
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return forwardedHeaderPolicyAdd, false
	}

	var manifest manifestMetadata
	decoder := json.NewDecoder(io.LimitReader(resp.Body, forwardedHeaderPolicyProbeMaxBytes))
	if err := decoder.Decode(&manifest); err != nil {
		return forwardedHeaderPolicyAdd, false
	}

	if strings.EqualFold(strings.TrimSpace(manifest.ShortName), "Home Assistant") {
		return forwardedHeaderPolicyOmit, true
	}
	return forwardedHeaderPolicyAdd, false
}
