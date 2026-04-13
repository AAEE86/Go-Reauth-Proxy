package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go-reauth-proxy/pkg/config"
	"go-reauth-proxy/pkg/errors"
	"go-reauth-proxy/pkg/events"
	"go-reauth-proxy/pkg/gatewaylog"

	"go-reauth-proxy/pkg/models"
	"go-reauth-proxy/pkg/response"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Handler struct {
	mu                    sync.RWMutex
	Rules                 []models.Rule
	HostRules             []models.HostRule
	StreamRules           []models.StreamRule
	DefaultRoute          string
	AuthConfig            models.AuthConfig
	LoggingConfig         models.LoggingConfig
	AdminPort             int
	ProxyPort             int
	ProxyProtocolForce    bool
	ReverseProxyThrottle  models.ReverseProxyThrottleConfig
	GatewayVisibility     models.GatewayVisibilityConfig
	ForwardedHeaders      models.ForwardedHeadersConfig
	PreserveHost          models.PreserveHostConfig
	sslBundle             atomic.Value
	sslOnChange           atomic.Value
	proxyProtocolOnChange atomic.Value

	configManager     *config.Manager
	sslConfig         models.SSLConfig
	gatewayLogManager *gatewaylog.Manager

	trafficTotalIn  uint64
	trafficTotalOut uint64
	trafficActive   int64
	trafficError5xx uint64

	fnAppMockService           *fnAppMockService
	loggedInActive             sync.Map
	preflightClient            *http.Client
	authClient                 *http.Client
	proxyTransport             *http.Transport
	preflightSkipUntilUnixNano int64
	authCache                  authStateCache
	preflightCache             preflightStateCache
	reverseProxyThrottle       *reverseProxyThrottle
	reverseProxyThrottleExempt *reverseProxyThrottleExemptIPsRuntime
	gatewayVisibility          *gatewayVisibility
	forwardedHeaders           *forwardedHeadersConfig
	preserveHost               *preserveHostConfig
	systemEventClient          *events.Client
}

type requestSnapshot struct {
	rules              []models.Rule
	hostRules          []models.HostRule
	defaultRoute       string
	authConfig         models.AuthConfig
	proxyProtocolForce bool
}

type preflightDecision struct {
	deny             bool
	redirectLocation string
}

type authCheckResult struct {
	allowed         bool
	authenticated   bool
	suppressToolbar bool
	decision        string
}

func (h *Handler) snapshotForRequest() requestSnapshot {
	h.mu.RLock()
	rules := make([]models.Rule, len(h.Rules))
	copy(rules, h.Rules)
	hostRules := make([]models.HostRule, len(h.HostRules))
	copy(hostRules, h.HostRules)
	s := requestSnapshot{
		rules:              rules,
		hostRules:          hostRules,
		defaultRoute:       h.DefaultRoute,
		authConfig:         h.AuthConfig,
		proxyProtocolForce: h.ProxyProtocolForce,
	}
	h.mu.RUnlock()
	return s
}

func resolveClientIP(r *http.Request, authConfig models.AuthConfig, proxyProtocolForce bool) string {
	if authConfig.AliyunESAEnabled {
		if ip := normalizeIPAddress(r.Header.Get("Ali-Real-Client-IP")); ip != "" {
			return ip
		}
		if ip := firstForwardedClientIP(r.Header.Get("X-Forwarded-For")); ip != "" {
			return ip
		}
	}

	if proxyProtocolForce {
		if !authConfig.AliyunESAEnabled {
			if ip := firstForwardedClientIP(r.Header.Get("X-Forwarded-For")); ip != "" {
				return ip
			}
		}
		if ip := normalizeIPAddress(r.Header.Get("X-Real-IP")); ip != "" {
			return ip
		}
	}
	return normalizeClientIP(r.RemoteAddr)
}

func copyRule(rule models.Rule) *models.Rule {
	r := rule
	return &r
}

func copyHostRule(rule models.HostRule) *models.HostRule {
	r := rule
	return &r
}

func copyStreamRule(rule models.StreamRule) *models.StreamRule {
	r := rule
	return &r
}

func normalizeRequestHost(host string) string {
	value := strings.TrimSpace(strings.ToLower(host))
	if value == "" {
		return ""
	}

	if strings.HasPrefix(value, "[") {
		if idx := strings.LastIndex(value, "]"); idx != -1 {
			return value[:idx+1]
		}
	}

	if parsedHost, _, err := net.SplitHostPort(value); err == nil {
		return strings.TrimSpace(strings.ToLower(parsedHost))
	}

	return value
}

func newInternalTransport() *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConns = 100
	transport.MaxIdleConnsPerHost = 100
	transport.IdleConnTimeout = 90 * time.Second
	transport.ForceAttemptHTTP2 = true
	return transport
}

func newProxyTransport() *http.Transport {
	transport := newInternalTransport()
	transport.DialContext = (&net.Dialer{
		Timeout:   6 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext
	// Hardcode skipping upstream TLS verification for reverse-proxy targets.
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	transport.TLSHandshakeTimeout = 10 * time.Second
	transport.ResponseHeaderTimeout = 10 * time.Second
	return transport
}

func ensureLeadingSlash(p string) string {
	if p == "" {
		return "/"
	}
	if strings.HasPrefix(p, "/") {
		return p
	}
	return "/" + p
}

func firstForwardedValue(v string) string {
	if v == "" {
		return ""
	}
	parts := strings.Split(v, ",")
	if len(parts) == 0 {
		return ""
	}
	return strings.TrimSpace(parts[0])
}

func requestScheme(r *http.Request) string {
	if proto := firstForwardedValue(r.Header.Get("X-Forwarded-Proto")); proto != "" {
		return proto
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

const (
	internalPreflightHeader  = "X-Reauth-Internal-Preflight"
	preflightTimeout         = 1200 * time.Millisecond
	preflightFailureCooldown = 3 * time.Second
)

func localServiceURL(port int, urlPath string) string {
	return fmt.Sprintf("http://127.0.0.1:%d%s", port, ensureLeadingSlash(urlPath))
}

func copyUserAgentHeader(dst, src *http.Request) {
	if ua := src.Header.Get("User-Agent"); ua != "" {
		dst.Header.Set("User-Agent", ua)
		return
	}

	// Prevent Go's default client UA from leaking into upstream requests
	// when the original client did not send one.
	dst.Header.Set("User-Agent", "")
}

func applyNoStoreCacheHeaders(headers http.Header) {
	if headers == nil {
		return
	}

	headers.Set("Cache-Control", "private, no-store, no-cache, max-age=0, must-revalidate")
	headers.Set("Pragma", "no-cache")
	headers.Set("Expires", "0")
	headers.Set("CDN-Cache-Control", "private, no-store")
	headers.Set("Surrogate-Control", "no-store")
}

func shouldDisableAuthResponseCaching(requestPath string) bool {
	cleanPath := path.Clean(ensureLeadingSlash(strings.TrimSpace(requestPath)))
	return cleanPath == "/api/auth" || strings.HasPrefix(cleanPath, "/api/auth/")
}

func applyInternalAuthProxyHeaders(req *http.Request, source *http.Request, targetURL *url.URL, clientIP string, authConfig models.AuthConfig) {
	if req == nil {
		return
	}

	if targetURL != nil {
		req.Host = targetURL.Host
		req.URL.Path = targetURL.Path
	}

	req.Header.Set("X-Real-IP", clientIP)
	req.Header.Set("X-Forwarded-For", clientIP)
	if source != nil {
		req.Header.Set("X-Forwarded-Host", source.Host)
		req.Header.Set("X-Forwarded-Proto", requestScheme(source))
	}
	if authConfig.AliyunESAEnabled && clientIP != "" {
		req.Header.Set("Ali-Real-Client-IP", clientIP)
	} else {
		req.Header.Del("Ali-Real-Client-IP")
	}

	// Strip internal routing hints and any client-supplied real-IP header.
	req.Header.Del("X-Forwarded-Path")
	req.Header.Del("X-Match")
	copyUserAgentHeader(req, source)
}

func applyForwardedHeaderPolicy(out *http.Request, in *http.Request, clientIP string, omitForwardedHeaders bool) {
	if out == nil {
		return
	}

	out.Header.Set("X-Real-IP", clientIP)
	if omitForwardedHeaders {
		out.Header.Del("X-Forwarded-For")
		out.Header.Del("X-Forwarded-Host")
		out.Header.Del("X-Forwarded-Proto")
		return
	}

	if in == nil {
		return
	}

	out.Header.Set("X-Forwarded-For", clientIP)
	out.Header.Set("X-Forwarded-Host", in.Host)
	out.Header.Set("X-Forwarded-Proto", requestScheme(in))
}

func applyPreserveHostPolicy(out *http.Request, in *http.Request, targetURL *url.URL, preserveHost bool) {
	if out == nil {
		return
	}

	if preserveHost && in != nil {
		out.Host = in.Host
		return
	}

	if targetURL != nil {
		out.Host = targetURL.Host
	}
}

func (h *Handler) shouldOmitForwardedHeaders(target *url.URL) bool {
	if h == nil || h.forwardedHeaders == nil {
		return false
	}
	return h.forwardedHeaders.shouldOmit(target)
}

func (h *Handler) shouldOmitPreserveHost(target *url.URL) bool {
	if h == nil || h.preserveHost == nil {
		return false
	}
	return h.preserveHost.shouldOmit(target)
}

func (h *Handler) runPreflight(r *http.Request, authConfig models.AuthConfig, clientIP string, isMatch bool, accessMode string) preflightDecision {
	if r.Header.Get(internalPreflightHeader) == "1" {
		return preflightDecision{}
	}

	if authConfig.AuthPort <= 0 {
		return preflightDecision{}
	}
	now := time.Now()
	lookup, canLookup := buildPreflightCacheLookup(r, clientIP, accessMode, isMatch)
	ttl := preflightCacheTTL(authConfig)

	if canLookup && ttl > 0 {
		if entry, ok := h.preflightCacheGet(lookup.cacheKey, now); ok {
			if shouldBypassFNAppNegativePreflightCache(r, entry.decision) {
				h.preflightCache.mu.Lock()
				h.preflightCache.deleteEntryLocked(lookup.cacheKey)
				h.preflightCache.mu.Unlock()
			} else {
				return entry.decision
			}
		}
	}
	if skipUntil := atomic.LoadInt64(&h.preflightSkipUntilUnixNano); skipUntil > now.UnixNano() {
		return preflightDecision{}
	}

	if canLookup && ttl > 0 {
		executionAny, _, _ := h.preflightCache.group.Do(lookup.cacheKey, func() (any, error) {
			if entry, ok := h.preflightCacheGet(lookup.cacheKey, time.Now()); ok {
				if shouldBypassFNAppNegativePreflightCache(r, entry.decision) {
					h.preflightCache.mu.Lock()
					h.preflightCache.deleteEntryLocked(lookup.cacheKey)
					h.preflightCache.mu.Unlock()
				} else {
					return preflightCacheExecution{entry: &entry}, nil
				}
			}

			decision, err := h.performPreflight(r, authConfig, clientIP, isMatch, accessMode)
			if err != nil {
				cooldownUntil := time.Now().Add(preflightFailureCooldown).UnixNano()
				atomic.StoreInt64(&h.preflightSkipUntilUnixNano, cooldownUntil)
				log.Printf("Preflight request failed, skipping checks for %s: %v", preflightFailureCooldown, err)
				return preflightCacheExecution{}, nil
			}
			atomic.StoreInt64(&h.preflightSkipUntilUnixNano, 0)

			entry := preflightCacheEntry{
				decision:    decision,
				expiresAt:   time.Now().Add(ttl),
				identityKey: lookup.identityKey,
			}
			if !shouldBypassFNAppNegativePreflightCache(r, decision) {
				h.preflightCacheStore(lookup.cacheKey, entry, time.Now())
			}
			return preflightCacheExecution{entry: &entry}, nil
		})

		execution, _ := executionAny.(preflightCacheExecution)
		if execution.entry != nil {
			return execution.entry.decision
		}
		return execution.decision
	}

	decision, err := h.performPreflight(r, authConfig, clientIP, isMatch, accessMode)
	if err != nil {
		cooldownUntil := time.Now().Add(preflightFailureCooldown).UnixNano()
		atomic.StoreInt64(&h.preflightSkipUntilUnixNano, cooldownUntil)
		log.Printf("Preflight request failed, skipping checks for %s: %v", preflightFailureCooldown, err)
		return preflightDecision{}
	}
	atomic.StoreInt64(&h.preflightSkipUntilUnixNano, 0)
	return decision
}

func (h *Handler) performPreflight(r *http.Request, authConfig models.AuthConfig, clientIP string, isMatch bool, accessMode string) (preflightDecision, error) {
	preflightURLPath := authConfig.PreflightURL
	if preflightURLPath == "" {
		preflightURLPath = "/api/auth/preflight"
	}
	preflightURL := localServiceURL(authConfig.AuthPort, preflightURLPath)

	preflightReq, err := http.NewRequest(http.MethodHead, preflightURL, nil)
	if err != nil {
		log.Printf("Failed to create preflight request: %v", err)
		return preflightDecision{}, err
	}

	preflightReq.Header.Set("X-Real-IP", clientIP)
	preflightReq.Header.Set("X-Forwarded-For", clientIP)
	preflightReq.Header.Set("X-Forwarded-Path", r.URL.RequestURI())
	preflightReq.Header.Set("X-Forwarded-Host", r.Host)
	preflightReq.Header.Set("X-Forwarded-Proto", requestScheme(r))
	preflightReq.Header.Set("X-Match", strconv.FormatBool(isMatch))
	preflightReq.Header.Set(internalPreflightHeader, "1")
	if accessMode != "" {
		preflightReq.Header.Set("X-Reauth-Access-Mode", accessMode)
	}

	if cookie := r.Header.Get("Cookie"); cookie != "" {
		preflightReq.Header.Set("Cookie", cookie)
	}
	if auth := r.Header.Get("Authorization"); auth != "" {
		preflightReq.Header.Set("Authorization", auth)
	}
	copyUserAgentHeader(preflightReq, r)

	client := h.preflightClient
	if client == nil {
		client = &http.Client{
			Timeout:   preflightTimeout,
			Transport: newInternalTransport(),
		}
	}

	resp, err := client.Do(preflightReq)
	if err != nil {
		return preflightDecision{}, err
	}
	defer resp.Body.Close()

	decision := preflightDecision{
		deny: strings.EqualFold(resp.Header.Get("X-Option"), "deny"),
	}
	if location := strings.TrimSpace(resp.Header.Get("X-Reauth-Redirect-Location")); location != "" {
		if strings.HasPrefix(location, "/") || strings.HasPrefix(location, "http://") || strings.HasPrefix(location, "https://") {
			decision.redirectLocation = location
		}
	}
	return decision, nil
}

func (h *Handler) abortConnection(w http.ResponseWriter) {
	rc := http.NewResponseController(w)
	conn, _, err := rc.Hijack()
	if err == nil && conn != nil {
		conn.Close()
		return
	}
	panic(http.ErrAbortHandler)
}

func NewHandler(adminPort int, proxyPort int, cfgManager *config.Manager, initialCfg *config.AppConfig, logsDir string, systemEventClient *events.Client) *Handler {
	logConfig := gatewaylog.NormalizeConfig(initialCfg.Logging)
	normalizedForwardedHeaders, _ := normalizeForwardedHeadersConfig(initialCfg.ForwardedHeaders)
	normalizedPreserveHost, _ := normalizePreserveHostConfig(initialCfg.PreserveHost)
	if strings.TrimSpace(logsDir) == "" {
		logsDir = gatewaylog.DefaultLogsDir(".")
	}

	h := &Handler{
		Rules:                initialCfg.Rules,
		HostRules:            initialCfg.HostRules,
		StreamRules:          initialCfg.StreamRules,
		DefaultRoute:         initialCfg.DefaultRoute,
		AuthConfig:           initialCfg.AuthConfig,
		LoggingConfig:        logConfig,
		AdminPort:            adminPort,
		ProxyPort:            proxyPort,
		ProxyProtocolForce:   initialCfg.ProxyProtocolForce,
		ReverseProxyThrottle: normalizeReverseProxyThrottleConfig(initialCfg.ReverseProxyThrottle),
		GatewayVisibility:    initialCfg.Visibility,
		ForwardedHeaders:     normalizedForwardedHeaders,
		PreserveHost:         normalizedPreserveHost,
		configManager:        cfgManager,
		sslConfig:            copySSLConfig(initialCfg.SSL),
		gatewayLogManager:    gatewaylog.NewManager(logsDir, logConfig),
		fnAppMockService:     newFNAppMockServiceFromEnv(),
		preflightClient: &http.Client{
			Timeout:   preflightTimeout,
			Transport: newInternalTransport(),
		},
		authClient: &http.Client{
			Timeout:   5 * time.Second,
			Transport: newInternalTransport(),
		},
		proxyTransport:    newProxyTransport(),
		authCache:         newAuthStateCache(),
		preflightCache:    newPreflightStateCache(),
		forwardedHeaders:  newForwardedHeadersConfig(normalizedForwardedHeaders),
		preserveHost:      newPreserveHostConfig(normalizedPreserveHost),
		systemEventClient: systemEventClient,
	}
	h.reverseProxyThrottle = newReverseProxyThrottle(h.ReverseProxyThrottle)
	h.reverseProxyThrottleExempt = newReverseProxyThrottleExemptIPsRuntime(
		models.ReverseProxyThrottleExemptIPsRuntime{
			Enabled:   false,
			IPs:       []string{},
			UpdatedAt: "",
		},
	)
	visibility, err := newGatewayVisibility(initialCfg.Visibility)
	if err != nil {
		log.Printf("Failed to normalize initial gateway visibility: %v", err)
		visibility, _ = newGatewayVisibility(models.GatewayVisibilityConfig{
			Enabled:   false,
			CIDRs:     []string{},
			UpdatedAt: "",
		})
	}
	h.gatewayVisibility = visibility

	var emptyHook func()
	h.sslOnChange.Store(emptyHook)
	h.proxyProtocolOnChange.Store(emptyHook)

	if len(h.sslConfig.Certificates) == 0 && initialCfg.SSLCert != "" && initialCfg.SSLKey != "" {
		h.sslConfig = buildLegacySSLConfig(initialCfg.SSLCert, initialCfg.SSLKey)
	}
	normalizedSSL, err := normalizeSSLConfig(h.sslConfig)
	if err != nil {
		log.Printf("Failed to normalize initial SSL deployment: %v", err)
		normalizedSSL = models.SSLConfig{
			DeploymentMode: models.SSLDeploymentModeSingleActive,
			Certificates:   []models.SSLDeployedCertificate{},
		}
	}
	h.sslConfig = normalizedSSL
	bundle, err := newSSLRuntimeBundle(h.sslConfig)
	if err != nil {
		log.Printf("Failed to load initial SSL deployment: %v", err)
		bundle = newEmptySSLRuntimeBundle(h.sslConfig.DeploymentMode)
	}
	h.sslBundle.Store(bundle)
	return h
}

func (h *Handler) SetSSLChangeHook(hook func()) {
	h.sslOnChange.Store(hook)
}

func (h *Handler) getSSLChangeHook() func() {
	val := h.sslOnChange.Load()
	if val == nil {
		return nil
	}
	hook, _ := val.(func())
	return hook
}

func (h *Handler) SetProxyProtocolForceChangeHook(hook func()) {
	h.proxyProtocolOnChange.Store(hook)
}

func (h *Handler) getProxyProtocolForceChangeHook() func() {
	val := h.proxyProtocolOnChange.Load()
	if val == nil {
		return nil
	}
	hook, _ := val.(func())
	return hook
}

func (h *Handler) saveConfigLocked() {
	if h.configManager == nil {
		return
	}

	rulesCopy := make([]models.Rule, len(h.Rules))
	copy(rulesCopy, h.Rules)
	hostRulesCopy := make([]models.HostRule, len(h.HostRules))
	copy(hostRulesCopy, h.HostRules)
	streamRulesCopy := make([]models.StreamRule, len(h.StreamRules))
	copy(streamRulesCopy, h.StreamRules)

	if err := h.configManager.Update(func(conf *config.AppConfig) error {
		conf.Rules = rulesCopy
		conf.HostRules = hostRulesCopy
		conf.StreamRules = streamRulesCopy
		conf.DefaultRoute = h.DefaultRoute
		conf.AuthConfig = h.AuthConfig
		conf.Logging = h.LoggingConfig
		conf.ProxyProtocolForce = h.ProxyProtocolForce
		conf.ReverseProxyThrottle = h.ReverseProxyThrottle
		conf.Visibility = h.GatewayVisibility
		conf.ForwardedHeaders = h.ForwardedHeaders
		conf.PreserveHost = h.PreserveHost
		conf.SSL = copySSLConfig(h.sslConfig)
		conf.SSLCert, conf.SSLKey = legacySSLPEMFromConfig(h.sslConfig)
		return nil
	}); err != nil {
		log.Printf("Failed to save config: %v", err)
	}
}

func (h *Handler) GetProxyProtocolForce() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.ProxyProtocolForce
}

func (h *Handler) SetProxyProtocolForce(force bool) {
	h.mu.Lock()
	changed := h.ProxyProtocolForce != force
	h.ProxyProtocolForce = force
	h.saveConfigLocked()
	hook := h.getProxyProtocolForceChangeHook()
	h.mu.Unlock()
	if changed && hook != nil {
		hook()
	}
}

func (h *Handler) evaluateReverseProxyThrottleRequest(isAuthRoute bool, matchedHostRule *models.HostRule, matchedRule *models.Rule, clientIP string, now time.Time) reverseProxyThrottleDecision {
	if !isAuthRoute && matchedHostRule == nil && matchedRule == nil {
		return reverseProxyThrottleDecision{Allowed: true}
	}
	if h.reverseProxyThrottle == nil {
		return reverseProxyThrottleDecision{Allowed: true}
	}
	h.mu.RLock()
	exemptRuntime := h.reverseProxyThrottleExempt
	h.mu.RUnlock()
	if exemptRuntime != nil && exemptRuntime.shouldBypass(clientIP) {
		return reverseProxyThrottleDecision{Allowed: true}
	}
	return h.reverseProxyThrottle.evaluate(clientIP, now)
}

func classifyReverseProxyRouteType(requestPath string, isAuthRoute bool, matchedHostRule *models.HostRule, matchedRule *models.Rule) string {
	switch {
	case isAuthRoute:
		return "auth_proxy"
	case requestPath == "/__select__":
		return "select"
	case matchedHostRule != nil:
		return "host_rule"
	case matchedRule != nil:
		return "path_rule"
	default:
		return "not_found"
	}
}

func gatewayThrottleDedupeTTL(now time.Time, blockedUntil time.Time, fallback int) int {
	if blockedUntil.After(now) {
		ttlSeconds := int(time.Until(blockedUntil).Seconds()) + 60
		if ttlSeconds > 0 {
			return ttlSeconds
		}
	}
	if fallback > 0 {
		return fallback + 60
	}
	return 60
}

func (h *Handler) emitGatewayThrottleBlockedEvent(args struct {
	ClientIP     string
	BlockedUntil time.Time
	Config       models.ReverseProxyThrottleConfig
	RouteType    string
	Host         string
	RequestPath  string
	IsAuthRoute  bool
	HappenedAt   time.Time
}) {
	client := h.systemEventClient
	if client == nil {
		return
	}

	normalizedIP := normalizeClientIP(args.ClientIP)
	if normalizedIP == "" {
		normalizedIP = strings.TrimSpace(args.ClientIP)
	}
	if normalizedIP == "" {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := client.Publish(ctx, 0, events.SystemEventPublishInput{
		Type:             events.FnEventGatewayThrottleBlocked,
		Source:           events.SystemEventSourceGoReauthProxy,
		Level:            events.FnEventLevelWarn,
		HappenedAt:       args.HappenedAt.UTC().Format(time.RFC3339Nano),
		DedupeKey:        fmt.Sprintf("gateway-throttle:%s:%d", normalizedIP, args.BlockedUntil.Unix()),
		DedupeTTLSeconds: gatewayThrottleDedupeTTL(args.HappenedAt, args.BlockedUntil, args.Config.BlockSeconds),
		Subject: &events.SystemEventSubject{
			Kind: events.SystemEventSubjectKindIP,
			ID:   normalizedIP,
		},
		Payload: events.GatewayThrottleBlockedPayload{
			IP:                normalizedIP,
			BlockedUntil:      args.BlockedUntil.UTC().Format(time.RFC3339Nano),
			BlockSeconds:      args.Config.BlockSeconds,
			RequestsPerSecond: args.Config.RequestsPerSecond,
			Burst:             args.Config.Burst,
			RouteType:         args.RouteType,
			Host:              args.Host,
			Path:              args.RequestPath,
			IsAuthRoute:       args.IsAuthRoute,
		},
	})
	if err != nil {
		log.Printf("Failed to publish gateway throttle event for %s: %v", normalizedIP, err)
	}
}

func (h *Handler) SetSSLDeployment(config models.SSLConfig) error {
	normalized, err := normalizeSSLConfig(config)
	if err != nil {
		return err
	}
	bundle, err := newSSLRuntimeBundle(normalized)
	if err != nil {
		return err
	}

	h.mu.Lock()
	h.sslBundle.Store(bundle)
	h.sslConfig = normalized
	h.saveConfigLocked()
	hook := h.getSSLChangeHook()
	h.mu.Unlock()
	if hook != nil {
		hook()
	}
	return nil
}

func (h *Handler) SetSSLCertificate(cert *tls.Certificate, certPEM, keyPEM string) {
	if cert == nil {
		_ = h.SetSSLDeployment(models.SSLConfig{})
		return
	}
	normalizedCertPEM, normalizedKeyPEM, err := validateLegacySSLPair(certPEM, keyPEM)
	if err != nil {
		log.Printf("Failed to set legacy SSL certificate: %v", err)
		return
	}
	if err := h.SetSSLDeployment(buildLegacySSLConfig(normalizedCertPEM, normalizedKeyPEM)); err != nil {
		log.Printf("Failed to set legacy SSL certificate: %v", err)
	}
}

func (h *Handler) SetSSLCertificatePEM(certPEM, keyPEM string) error {
	normalizedCertPEM, normalizedKeyPEM, err := validateLegacySSLPair(certPEM, keyPEM)
	if err != nil {
		return err
	}
	return h.SetSSLDeployment(buildLegacySSLConfig(normalizedCertPEM, normalizedKeyPEM))
}

func (h *Handler) getSSLBundle() *sslRuntimeBundle {
	val := h.sslBundle.Load()
	if val == nil {
		return newEmptySSLRuntimeBundle(models.SSLDeploymentModeSingleActive)
	}
	bundle, _ := val.(*sslRuntimeBundle)
	if bundle == nil {
		return newEmptySSLRuntimeBundle(models.SSLDeploymentModeSingleActive)
	}
	return bundle
}

func (h *Handler) GetSSLCertificate() *tls.Certificate {
	return h.getSSLBundle().certificateForServerName("")
}

func (h *Handler) GetCertificate(info *tls.ClientHelloInfo) *tls.Certificate {
	if info == nil {
		return h.GetSSLCertificate()
	}
	return h.getSSLBundle().certificateForServerName(info.ServerName)
}

func (h *Handler) HasSSLCertificates() bool {
	return h.getSSLBundle().hasCertificates()
}

func (h *Handler) GetSSLDeployment() models.SSLConfig {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return copySSLConfig(h.sslConfig)
}

func (h *Handler) GetSSLInfo() models.SSLInfo {
	bundle := h.getSSLBundle()
	return copySSLInfo(models.SSLInfo{
		Enabled:        bundle.hasCertificates(),
		DeploymentMode: bundle.mode,
		Certificates:   bundle.certificates,
	})
}

func (h *Handler) ClearSSLCertificate() {
	_ = h.SetSSLDeployment(models.SSLConfig{})
}

func (h *Handler) AddRule(newRule models.Rule) error {
	if newRule.Path == "/" || newRule.Path == "" {
		return fmt.Errorf("cannot add rule for root path '/' or empty path")
	}
	if newRule.Target == "" {
		return fmt.Errorf("cannot add rule with empty target")
	}
	if newRule.Path == "/s" || newRule.Path == "/s/" {
		return fmt.Errorf("cannot add rule for reserved share path '/s' or '/s/'")
	}
	if strings.HasPrefix(newRule.Path, "/__") || strings.HasPrefix(newRule.Path, "__") {
		return fmt.Errorf("cannot add rule for reserved path starting with '__'")
	}
	if strings.HasSuffix(newRule.Path, "/") {
		return fmt.Errorf("path cannot end with a slash '/'")
	}
	if err := h.checkSafeTarget(newRule.Target); err != nil {
		return fmt.Errorf("invalid target: %v", err)
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	updated := false
	for i, rule := range h.Rules {
		if rule.Path == newRule.Path {
			h.Rules[i] = newRule
			updated = true
			break
		}
	}
	if !updated {
		h.Rules = append(h.Rules, newRule)
	}
	h.saveConfigLocked()
	return nil
}

func (h *Handler) checkSafeTarget(target string) error {
	u, err := url.Parse(target)
	if err != nil {
		return err
	}
	hostname := u.Hostname()
	port := u.Port()

	if hostname == "" {
		return fmt.Errorf("target must include a valid hostname")
	}

	if hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1" {
		if port == strconv.Itoa(h.AdminPort) {
			return fmt.Errorf("cannot target local admin port %d", h.AdminPort)
		}
	}
	return nil
}

func parseStreamTarget(target string) (string, int, error) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(target))
	if err != nil {
		return "", 0, fmt.Errorf("target must be in host:port format")
	}

	if strings.TrimSpace(host) == "" {
		return "", 0, fmt.Errorf("target must include a valid hostname")
	}

	portNum, err := strconv.Atoi(port)
	if err != nil || portNum <= 0 || portNum > 65535 {
		return "", 0, fmt.Errorf("target must include a valid port")
	}

	return host, portNum, nil
}

func normalizeStreamProtocol(protocol string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "", models.StreamProtocolTCP:
		return models.StreamProtocolTCP, nil
	case models.StreamProtocolUDP:
		return models.StreamProtocolUDP, nil
	default:
		return "", fmt.Errorf("protocol must be tcp or udp")
	}
}

func streamRuleMapKey(rule models.StreamRule) string {
	return rule.Protocol + "/" + strconv.Itoa(rule.ListenPort)
}

func isLoopbackOrUnspecifiedHost(host string) bool {
	normalizedHost := strings.TrimSpace(strings.Trim(host, "[]"))
	if normalizedHost == "" {
		return false
	}
	if strings.EqualFold(normalizedHost, "localhost") {
		return true
	}

	parsedIP := net.ParseIP(normalizedHost)
	return parsedIP != nil && (parsedIP.IsLoopback() || parsedIP.IsUnspecified())
}

func (h *Handler) reservedStreamPortName(rule models.StreamRule) string {
	if rule.Protocol != models.StreamProtocolTCP {
		return ""
	}

	switch {
	case h.AdminPort > 0 && rule.ListenPort == h.AdminPort:
		return "admin API"
	case h.ProxyPort > 0 && rule.ListenPort == h.ProxyPort:
		return "reverse proxy"
	default:
		return ""
	}
}

func (h *Handler) checkSafeStreamTarget(protocol string, target string) (string, int, error) {
	host, portNum, err := parseStreamTarget(target)
	if err != nil {
		return "", 0, err
	}

	if protocol == models.StreamProtocolTCP && isLoopbackOrUnspecifiedHost(host) {
		if portNum == h.AdminPort {
			return "", 0, fmt.Errorf("cannot target local admin port %d", h.AdminPort)
		}
	}

	return host, portNum, nil
}

func (h *Handler) normalizeStreamRule(newRule models.StreamRule) (models.StreamRule, error) {
	newRule.Target = strings.TrimSpace(newRule.Target)
	var err error
	newRule.Protocol, err = normalizeStreamProtocol(newRule.Protocol)
	if err != nil {
		return models.StreamRule{}, err
	}

	if newRule.ListenPort <= 0 || newRule.ListenPort > 65535 {
		return models.StreamRule{}, fmt.Errorf("listen_port must be between 1 and 65535")
	}
	if reservedName := h.reservedStreamPortName(newRule); reservedName != "" {
		return models.StreamRule{}, fmt.Errorf("listen_port %d is reserved for the %s", newRule.ListenPort, reservedName)
	}
	if newRule.Target == "" {
		return models.StreamRule{}, fmt.Errorf("cannot add stream rule with empty target")
	}
	targetHost, targetPort, err := h.checkSafeStreamTarget(newRule.Protocol, newRule.Target)
	if err != nil {
		return models.StreamRule{}, fmt.Errorf("invalid target: %v", err)
	}
	if newRule.ListenPort == targetPort && isLoopbackOrUnspecifiedHost(targetHost) {
		return models.StreamRule{}, fmt.Errorf("cannot target the same local listen_port %d", newRule.ListenPort)
	}

	return newRule, nil
}

func (h *Handler) RemoveRule(path string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	newRules := make([]models.Rule, 0, len(h.Rules))
	for _, rule := range h.Rules {
		if rule.Path != path {
			newRules = append(newRules, rule)
		}
	}
	h.Rules = newRules
	h.saveConfigLocked()
}

func (h *Handler) FlushRules() {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.Rules = make([]models.Rule, 0)
	h.saveConfigLocked()
}

func (h *Handler) GetRules() []models.Rule {
	h.mu.RLock()
	defer h.mu.RUnlock()

	rules := make([]models.Rule, len(h.Rules))
	copy(rules, h.Rules)
	return rules
}

func (h *Handler) normalizeHostRule(newRule models.HostRule) (models.HostRule, error) {
	newRule.Host = normalizeRequestHost(newRule.Host)
	if newRule.Host == "" {
		return models.HostRule{}, fmt.Errorf("cannot add host rule with empty host")
	}
	if strings.Contains(newRule.Host, "/") || strings.Contains(newRule.Host, "*") {
		return models.HostRule{}, fmt.Errorf("host rule must be an exact host without path or wildcard")
	}
	if newRule.Target == "" {
		return models.HostRule{}, fmt.Errorf("cannot add host rule with empty target")
	}
	if err := h.checkSafeTarget(newRule.Target); err != nil {
		return models.HostRule{}, fmt.Errorf("invalid target: %v", err)
	}
	if newRule.AccessMode == "" {
		newRule.AccessMode = "login_first"
	}

	return newRule, nil
}

func (h *Handler) AddHostRule(newRule models.HostRule) error {
	newRule, err := h.normalizeHostRule(newRule)
	if err != nil {
		return err
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	updated := false
	for i, rule := range h.HostRules {
		if normalizeRequestHost(rule.Host) == newRule.Host {
			h.HostRules[i] = newRule
			updated = true
			break
		}
	}
	if !updated {
		h.HostRules = append(h.HostRules, newRule)
	}
	h.saveConfigLocked()
	return nil
}

func (h *Handler) SetHostRules(rules []models.HostRule) error {
	normalizedRules := make([]models.HostRule, 0, len(rules))
	indexByHost := make(map[string]int, len(rules))

	for _, rule := range rules {
		normalizedRule, err := h.normalizeHostRule(rule)
		if err != nil {
			return err
		}

		if idx, exists := indexByHost[normalizedRule.Host]; exists {
			normalizedRules[idx] = normalizedRule
			continue
		}

		indexByHost[normalizedRule.Host] = len(normalizedRules)
		normalizedRules = append(normalizedRules, normalizedRule)
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	h.HostRules = normalizedRules
	h.saveConfigLocked()
	return nil
}

func (h *Handler) FlushHostRules() {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.HostRules = make([]models.HostRule, 0)
	h.saveConfigLocked()
}

func (h *Handler) GetHostRules() []models.HostRule {
	h.mu.RLock()
	defer h.mu.RUnlock()

	rules := make([]models.HostRule, len(h.HostRules))
	copy(rules, h.HostRules)
	return rules
}

func (h *Handler) ValidateStreamRules(rules []models.StreamRule) ([]models.StreamRule, error) {
	normalized := make([]models.StreamRule, 0, len(rules))
	seenRules := make(map[string]struct{}, len(rules))

	for _, rule := range rules {
		nextRule, err := h.normalizeStreamRule(rule)
		if err != nil {
			return nil, err
		}
		key := streamRuleMapKey(nextRule)
		if _, exists := seenRules[key]; exists {
			return nil, fmt.Errorf("duplicate stream rule for %s", key)
		}
		seenRules[key] = struct{}{}
		normalized = append(normalized, nextRule)
	}

	return normalized, nil
}

func (h *Handler) SetStreamRules(rules []models.StreamRule) error {
	normalized, err := h.ValidateStreamRules(rules)
	if err != nil {
		return err
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	h.StreamRules = normalized
	h.saveConfigLocked()
	return nil
}

func (h *Handler) FlushStreamRules() {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.StreamRules = make([]models.StreamRule, 0)
	h.saveConfigLocked()
}

func (h *Handler) GetStreamRules() []models.StreamRule {
	h.mu.RLock()
	defer h.mu.RUnlock()

	rules := make([]models.StreamRule, len(h.StreamRules))
	copy(rules, h.StreamRules)
	return rules
}

func (h *Handler) GetDefaultRoute() string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.DefaultRoute
}

func (h *Handler) SetDefaultRoute(route string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if route == "" {
		h.DefaultRoute = "/__select__"
	} else {
		h.DefaultRoute = route
	}
	h.saveConfigLocked()
}

func (h *Handler) GetAuthConfig() models.AuthConfig {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.AuthConfig
}

func (h *Handler) GetLoggingConfig() gatewaylog.ConfigInfo {
	if h.gatewayLogManager == nil {
		return gatewaylog.ConfigInfo{
			Enabled: false,
			MaxDays: gatewaylog.DefaultMaxDays,
		}
	}
	return h.gatewayLogManager.GetConfigInfo()
}

func (h *Handler) SetLoggingConfig(cfg models.LoggingConfig) gatewaylog.ConfigInfo {
	normalized := gatewaylog.NormalizeConfig(cfg)

	h.mu.Lock()
	h.LoggingConfig = normalized
	h.saveConfigLocked()
	h.mu.Unlock()

	if h.gatewayLogManager == nil {
		return gatewaylog.ConfigInfo{
			Enabled: normalized.Enabled,
			MaxDays: normalized.MaxDays,
		}
	}
	return h.gatewayLogManager.UpdateConfig(normalized)
}

func (h *Handler) GetLoggingDirectory() gatewaylog.DirectoryInfo {
	if h.gatewayLogManager == nil {
		return gatewaylog.DirectoryInfo{}
	}
	return gatewaylog.DirectoryInfo{LogsDir: h.gatewayLogManager.LogsDir()}
}

func (h *Handler) GetLogDates() (gatewaylog.DatesResult, error) {
	if h.gatewayLogManager == nil {
		return gatewaylog.DatesResult{}, nil
	}
	return h.gatewayLogManager.GetDates()
}

func (h *Handler) QueryLogEntries(date string, page int, limit int, search string, status string, loggedIn string, cursor string, pagination string) (gatewaylog.QueryResult, error) {
	if h.gatewayLogManager == nil {
		return gatewaylog.QueryResult{}, nil
	}
	return h.gatewayLogManager.Query(date, page, limit, search, status, loggedIn, cursor, pagination)
}

func (h *Handler) DeleteLogDate(date string) (gatewaylog.DeleteResult, error) {
	if h.gatewayLogManager == nil {
		return gatewaylog.DeleteResult{}, nil
	}
	return h.gatewayLogManager.DeleteDate(date)
}

func (h *Handler) SetAuthConfig(config models.AuthConfig) error {
	if config.AuthPort <= 0 {
		config.AuthPort = 7997
	}
	if config.AuthURL == "" {
		config.AuthURL = "/api/auth/verify"
	}
	if config.LoginURL == "" {
		config.LoginURL = "/login"
	}
	if config.LogoutURL == "" {
		config.LogoutURL = "/api/auth/logout"
	}
	if config.PreflightURL == "" {
		config.PreflightURL = "/api/auth/preflight"
	}
	if config.AuthCacheTTL < 0 {
		config.AuthCacheTTL = 0
	}
	if config.AuthCacheFailTTL < 0 {
		config.AuthCacheFailTTL = 0
	}
	if config.PublicHTTPPort < 0 {
		config.PublicHTTPPort = 0
	}
	if config.PublicHTTPSPort < 0 {
		config.PublicHTTPSPort = 0
	}
	config.PublicAuthBaseURL = strings.TrimSpace(strings.TrimRight(config.PublicAuthBaseURL, "/"))
	config.AuthHost = normalizeRequestHost(config.AuthHost)

	h.mu.Lock()
	defer h.mu.Unlock()
	h.AuthConfig = config
	h.saveConfigLocked()
	h.clearAuthCache()
	return nil
}

func (h *Handler) GetReverseProxyThrottle() models.ReverseProxyThrottleConfig {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.ReverseProxyThrottle
}

func (h *Handler) GetGatewayVisibility() models.GatewayVisibilityConfig {
	h.mu.RLock()
	defer h.mu.RUnlock()

	cidrs := make([]string, len(h.GatewayVisibility.CIDRs))
	copy(cidrs, h.GatewayVisibility.CIDRs)

	return models.GatewayVisibilityConfig{
		Enabled:   h.GatewayVisibility.Enabled,
		CIDRs:     cidrs,
		UpdatedAt: h.GatewayVisibility.UpdatedAt,
	}
}

func (h *Handler) GetForwardedHeadersConfig() models.ForwardedHeadersConfig {
	h.mu.RLock()
	defer h.mu.RUnlock()

	omitTargets := make([]string, len(h.ForwardedHeaders.OmitTargets))
	copy(omitTargets, h.ForwardedHeaders.OmitTargets)

	return models.ForwardedHeadersConfig{
		Enabled:     h.ForwardedHeaders.Enabled,
		OmitTargets: omitTargets,
		UpdatedAt:   h.ForwardedHeaders.UpdatedAt,
	}
}

func (h *Handler) GetPreserveHostConfig() models.PreserveHostConfig {
	h.mu.RLock()
	defer h.mu.RUnlock()

	omitTargets := make([]string, len(h.PreserveHost.OmitTargets))
	copy(omitTargets, h.PreserveHost.OmitTargets)

	return models.PreserveHostConfig{
		Enabled:     h.PreserveHost.Enabled,
		OmitTargets: omitTargets,
		UpdatedAt:   h.PreserveHost.UpdatedAt,
	}
}

func (h *Handler) GetReverseProxyThrottleExemptIPs() models.ReverseProxyThrottleExemptIPsRuntime {
	h.mu.RLock()
	runtime := h.reverseProxyThrottleExempt
	h.mu.RUnlock()

	if runtime == nil {
		return models.ReverseProxyThrottleExemptIPsRuntime{
			Enabled:   false,
			IPs:       []string{},
			UpdatedAt: "",
		}
	}

	return runtime.getConfig()
}

func (h *Handler) IsClientIPVisible(clientIP string) bool {
	h.mu.RLock()
	visibility := h.gatewayVisibility
	h.mu.RUnlock()

	if visibility == nil {
		return true
	}
	return visibility.contains(clientIP)
}

func (h *Handler) SetReverseProxyThrottle(cfg models.ReverseProxyThrottleConfig) {
	normalized := normalizeReverseProxyThrottleConfig(cfg)

	h.mu.Lock()
	h.ReverseProxyThrottle = normalized
	h.saveConfigLocked()
	throttle := h.reverseProxyThrottle
	h.mu.Unlock()

	if throttle == nil {
		h.mu.Lock()
		if h.reverseProxyThrottle == nil {
			h.reverseProxyThrottle = newReverseProxyThrottle(normalized)
			throttle = h.reverseProxyThrottle
		} else {
			throttle = h.reverseProxyThrottle
		}
		h.mu.Unlock()
	}
	if throttle != nil {
		throttle.updateConfig(normalized)
	}
}

func (h *Handler) SetGatewayVisibility(cfg models.GatewayVisibilityConfig) error {
	normalized, prefixes, err := normalizeGatewayVisibilityConfig(cfg)
	if err != nil {
		return err
	}

	h.mu.Lock()
	h.GatewayVisibility = normalized
	h.saveConfigLocked()
	visibility := h.gatewayVisibility
	if visibility == nil {
		visibility = &gatewayVisibility{}
		h.gatewayVisibility = visibility
	}
	h.mu.Unlock()

	visibility.mu.Lock()
	visibility.config = normalized
	visibility.prefixes = prefixes
	visibility.mu.Unlock()

	return nil
}

func (h *Handler) SetForwardedHeadersConfig(cfg models.ForwardedHeadersConfig) {
	normalized, _ := normalizeForwardedHeadersConfig(cfg)

	h.mu.Lock()
	h.ForwardedHeaders = normalized
	h.saveConfigLocked()
	forwardedHeaders := h.forwardedHeaders
	if forwardedHeaders == nil {
		forwardedHeaders = newForwardedHeadersConfig(normalized)
		h.forwardedHeaders = forwardedHeaders
	}
	h.mu.Unlock()

	forwardedHeaders.updateConfig(normalized)
}

func (h *Handler) SetPreserveHostConfig(cfg models.PreserveHostConfig) {
	normalized, _ := normalizePreserveHostConfig(cfg)

	h.mu.Lock()
	h.PreserveHost = normalized
	h.saveConfigLocked()
	preserveHost := h.preserveHost
	if preserveHost == nil {
		preserveHost = newPreserveHostConfig(normalized)
		h.preserveHost = preserveHost
	}
	h.mu.Unlock()

	preserveHost.updateConfig(normalized)
}

func (h *Handler) SetReverseProxyThrottleExemptIPs(cfg models.ReverseProxyThrottleExemptIPsRuntime) {
	h.mu.Lock()
	runtime := h.reverseProxyThrottleExempt
	if runtime == nil {
		runtime = newReverseProxyThrottleExemptIPsRuntime(
			models.ReverseProxyThrottleExemptIPsRuntime{},
		)
		h.reverseProxyThrottleExempt = runtime
	}
	h.mu.Unlock()

	runtime.updateConfig(cfg)
}

type TrafficStats struct {
	TotalIn     uint64 `json:"total_in"`
	TotalOut    uint64 `json:"total_out"`
	ActiveConns int64  `json:"active_conns"`
	Error5xx    uint64 `json:"error_5xx"`
}

func (h *Handler) GetTrafficStats(timestamp time.Time) TrafficStats {
	return TrafficStats{
		TotalIn:     atomic.LoadUint64(&h.trafficTotalIn),
		TotalOut:    atomic.LoadUint64(&h.trafficTotalOut),
		ActiveConns: h.activeLoggedInCount(timestamp),
		Error5xx:    atomic.LoadUint64(&h.trafficError5xx),
	}
}

func (h *Handler) AddStreamTraffic(bytesIn, bytesOut uint64, status int) {
	if bytesIn > 0 {
		atomic.AddUint64(&h.trafficTotalIn, bytesIn)
	}
	if bytesOut > 0 {
		atomic.AddUint64(&h.trafficTotalOut, bytesOut)
	}
	if status >= 500 {
		atomic.AddUint64(&h.trafficError5xx, 1)
	}
}

func (h *Handler) LogGatewayEntry(entry gatewaylog.Entry) {
	if h.gatewayLogManager != nil {
		h.gatewayLogManager.Log(entry)
	}
}

const loggedInActiveWindow = 2 * time.Minute

func canonicalCookieIdentity(r *http.Request) string {
	cookies := r.Cookies()
	if len(cookies) == 0 {
		return ""
	}

	filtered := make([]*http.Cookie, 0, len(cookies))
	for _, c := range cookies {
		if c == nil {
			continue
		}
		if c.Name == "__proxy_path" {
			continue
		}
		if c.Name == "" || c.Value == "" {
			continue
		}
		filtered = append(filtered, c)
	}
	if len(filtered) == 0 {
		return ""
	}

	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].Name == filtered[j].Name {
			return filtered[i].Value < filtered[j].Value
		}
		return filtered[i].Name < filtered[j].Name
	})

	var b strings.Builder
	for i, c := range filtered {
		if i > 0 {
			b.WriteByte(';')
		}
		b.WriteString(c.Name)
		b.WriteByte('=')
		b.WriteString(c.Value)
	}
	return b.String()
}

func activeIdentityKey(r *http.Request, clientIP string) string {
	var src string
	if cookieID := canonicalCookieIdentity(r); cookieID != "" {
		src = "cookie:" + cookieID
	} else if auth := r.Header.Get("Authorization"); auth != "" {
		src = "auth:" + auth
	} else if clientIP != "" {
		src = "ip:" + clientIP
	} else {
		return ""
	}

	return activeIdentityKeyFromSource(src)
}

func activeIdentityKeyFromSource(src string) string {
	if strings.TrimSpace(src) == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(src))
	return hex.EncodeToString(sum[:])
}

func activeIdentityKeyFromClientIP(clientIP string) string {
	clientIP = strings.TrimSpace(clientIP)
	if clientIP == "" {
		return ""
	}
	return activeIdentityKeyFromSource("ip:" + clientIP)
}

func (h *Handler) storeLoggedInActive(key string, now time.Time) {
	if key == "" {
		return
	}
	h.loggedInActive.Store(key, now.UnixNano())
}

func (h *Handler) markLoggedInActive(r *http.Request, clientIP string, now time.Time) {
	h.storeLoggedInActive(activeIdentityKey(r, clientIP), now)
}

func (h *Handler) MarkLoggedInActiveByClientIP(clientIP string, now time.Time) {
	h.storeLoggedInActive(activeIdentityKeyFromClientIP(clientIP), now)
}

func (h *Handler) activeLoggedInCount(now time.Time) int64 {
	cutoff := now.Add(-loggedInActiveWindow).UnixNano()
	var count int64

	h.loggedInActive.Range(func(key, value any) bool {
		ts, ok := value.(int64)
		if !ok || ts < cutoff {
			h.loggedInActive.Delete(key)
			return true
		}
		count++
		return true
	})

	return count
}

type requestTrafficMetrics struct {
	inBytes     uint64
	outBytes    uint64
	statusCode  int
	wroteHeader bool
}

type trafficReadCloser struct {
	io.ReadCloser
	handler *Handler
	metrics *requestTrafficMetrics
}

func (trc *trafficReadCloser) Read(p []byte) (int, error) {
	n, err := trc.ReadCloser.Read(p)
	if n > 0 {
		trc.metrics.inBytes += uint64(n)
		atomic.AddUint64(&trc.handler.trafficTotalIn, uint64(n))
	}
	return n, err
}

type trafficResponseWriter struct {
	http.ResponseWriter
	handler       *Handler
	metrics       *requestTrafficMetrics
	skipAccessLog bool
}

func (tw *trafficResponseWriter) WriteHeader(statusCode int) {
	if !tw.metrics.wroteHeader {
		tw.metrics.wroteHeader = true
		tw.metrics.statusCode = statusCode
	}
	tw.ResponseWriter.WriteHeader(statusCode)
}

func (tw *trafficResponseWriter) Write(p []byte) (int, error) {
	if !tw.metrics.wroteHeader {
		tw.WriteHeader(http.StatusOK)
	}
	n, err := tw.ResponseWriter.Write(p)
	if n > 0 {
		tw.metrics.outBytes += uint64(n)
		atomic.AddUint64(&tw.handler.trafficTotalOut, uint64(n))
	}
	return n, err
}

func (tw *trafficResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := tw.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	return hj.Hijack()
}

func (tw *trafficResponseWriter) Flush() {
	if fl, ok := tw.ResponseWriter.(http.Flusher); ok {
		fl.Flush()
	}
}

func (tw *trafficResponseWriter) Push(target string, opts *http.PushOptions) error {
	ps, ok := tw.ResponseWriter.(http.Pusher)
	if !ok {
		return http.ErrNotSupported
	}
	return ps.Push(target, opts)
}

func (tw *trafficResponseWriter) SuppressAccessLog() {
	tw.skipAccessLog = true
}

type accessLogSuppressor interface {
	SuppressAccessLog()
}

func suppressAccessLog(w http.ResponseWriter) {
	if suppressor, ok := w.(accessLogSuppressor); ok {
		suppressor.SuppressAccessLog()
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	atomic.AddInt64(&h.trafficActive, 1)
	metrics := &requestTrafficMetrics{statusCode: http.StatusOK}
	accessEntry := gatewaylog.Entry{
		Method:          r.Method,
		Scheme:          requestScheme(r),
		Host:            r.Host,
		Path:            r.URL.Path,
		Query:           r.URL.RawQuery,
		RequestURI:      r.URL.RequestURI(),
		Protocol:        r.Proto,
		Status:          http.StatusOK,
		RemoteAddr:      r.RemoteAddr,
		UserAgent:       r.UserAgent(),
		Referer:         r.Referer(),
		TLS:             r.TLS != nil,
		WebSocket:       strings.EqualFold(r.Header.Get("Upgrade"), "websocket"),
		AliRealClientIP: strings.TrimSpace(r.Header.Get("Ali-Real-Client-IP")),
		XForwardedFor:   firstForwardedValue(r.Header.Get("X-Forwarded-For")),
		XRealIP:         strings.TrimSpace(r.Header.Get("X-Real-IP")),
	}
	var clientIP string
	loggedStatusCode := 0

	if r.Body != nil {
		r.Body = &trafficReadCloser{ReadCloser: r.Body, handler: h, metrics: metrics}
	}
	tw := &trafficResponseWriter{ResponseWriter: w, handler: h, metrics: metrics}
	w = tw

	defer func() {
		atomic.AddInt64(&h.trafficActive, -1)
		if metrics.statusCode >= 500 {
			atomic.AddUint64(&h.trafficError5xx, 1)
		}
		accessEntry.Path = r.URL.Path
		accessEntry.Query = r.URL.RawQuery
		accessEntry.RequestURI = r.URL.RequestURI()
		accessEntry.BytesIn = metrics.inBytes
		accessEntry.BytesOut = metrics.outBytes
		accessEntry.DurationMs = time.Since(start).Milliseconds()
		if loggedStatusCode > 0 {
			accessEntry.Status = loggedStatusCode
		} else {
			accessEntry.Status = metrics.statusCode
		}
		if clientIP != "" {
			accessEntry.RemoteIP = clientIP
		}
		if !tw.skipAccessLog && h.gatewayLogManager != nil {
			h.gatewayLogManager.Log(accessEntry)
		}
		if rec := recover(); rec != nil {
			panic(rec)
		}
	}()

	snapshot := h.snapshotForRequest()
	cleanedPath := path.Clean(r.URL.Path)
	if strings.HasSuffix(r.URL.Path, "/") && cleanedPath != "/" {
		cleanedPath += "/"
	}
	r.URL.Path = cleanedPath

	clientIP = resolveClientIP(r, snapshot.authConfig, snapshot.proxyProtocolForce)
	accessEntry.RemoteIP = clientIP

	if !h.IsClientIPVisible(clientIP) {
		accessEntry.RouteType = "visibility"
		accessEntry.RouteKey = "cidr"
		accessEntry.AuthDecision = "visibility_denied"
		loggedStatusCode = 499
		h.abortConnection(w)
		return
	}

	if response.IsFaviconPath(r.URL.Path) {
		accessEntry.RouteType = "favicon"
		accessEntry.RouteKey = r.URL.Path
		accessEntry.Matched = true
		response.ServeFavicon(w, r)
		return
	}

	isSelectRoute := r.URL.Path == "/__select__"
	isAuthRoute := strings.HasPrefix(r.URL.Path, "/__auth__/")
	matchedHostRule := matchHostRule(r, snapshot.hostRules)
	accessMode := ""
	if matchedHostRule != nil {
		accessMode = matchedHostRule.AccessMode
	}

	matchedRule, needsSlashRedirect := matchRule(r, snapshot.rules)
	if matchedHostRule != nil {
		matchedRule = nil
		needsSlashRedirect = ""
	}

	if matchedRule == nil && snapshot.defaultRoute != "" && snapshot.defaultRoute != "/__select__" {
		for _, rule := range snapshot.rules {
			if rule.Path == snapshot.defaultRoute {
				matchedRule = copyRule(rule)
				break
			}
		}
	}
	throttleCheckedAt := time.Now()
	throttleDecision := h.evaluateReverseProxyThrottleRequest(
		isAuthRoute,
		matchedHostRule,
		matchedRule,
		clientIP,
		throttleCheckedAt,
	)
	if !throttleDecision.Allowed {
		if throttleDecision.NewlyBlocked {
			go h.emitGatewayThrottleBlockedEvent(struct {
				ClientIP     string
				BlockedUntil time.Time
				Config       models.ReverseProxyThrottleConfig
				RouteType    string
				Host         string
				RequestPath  string
				IsAuthRoute  bool
				HappenedAt   time.Time
			}{
				ClientIP:     clientIP,
				BlockedUntil: throttleDecision.BlockedUntil,
				Config:       throttleDecision.Config,
				RouteType:    classifyReverseProxyRouteType(r.URL.Path, isAuthRoute, matchedHostRule, matchedRule),
				Host:         r.Host,
				RequestPath:  r.URL.Path,
				IsAuthRoute:  isAuthRoute,
				HappenedAt:   throttleCheckedAt,
			})
		}
		suppressAccessLog(w)
		h.abortConnection(w)
		return
	}
	isMatch := isSelectRoute || isAuthRoute || matchedHostRule != nil || matchedRule != nil || r.URL.Path == "/"
	accessEntry.Matched = isMatch
	accessEntry.AccessMode = accessMode
	preflight := h.runPreflight(r, snapshot.authConfig, clientIP, isMatch, accessMode)
	if preflight.deny {
		accessEntry.RouteType = "preflight"
		accessEntry.AuthDecision = "denied"
		loggedStatusCode = 499
		suppressAccessLog(w)
		h.abortConnection(w)
		return
	}
	if preflight.redirectLocation != "" {
		accessEntry.RouteType = "preflight"
		accessEntry.AuthDecision = "redirected"
		http.Redirect(w, r, preflight.redirectLocation, http.StatusFound)
		return
	}
	if needsSlashRedirect != "" {
		accessEntry.RouteType = "slash_redirect"
		accessEntry.RouteKey = needsSlashRedirect
		newPath := needsSlashRedirect
		if r.URL.RawQuery != "" {
			newPath += "?" + r.URL.RawQuery
		}
		http.Redirect(w, r, newPath, http.StatusMovedPermanently)
		return
	}
	if isSelectRoute {
		accessEntry.RouteType = "select"
		accessEntry.RouteKey = r.URL.Path
		accessEntry.AuthRequired = snapshot.authConfig.AuthURL != ""
		authResult := h.handleSelectRoute(w, r, snapshot, clientIP)
		accessEntry.LoggedIn = authResult.authenticated
		accessEntry.AuthDecision = authResult.decision
		return
	}
	if isAuthRoute {
		accessEntry.RouteType = "auth_proxy"
		accessEntry.RouteKey = r.URL.Path
		if snapshot.authConfig.AuthPort > 0 {
			accessEntry.Upstream = fmt.Sprintf("http://127.0.0.1:%d", snapshot.authConfig.AuthPort)
		}
		accessEntry.AuthDecision = "proxy"
		h.handleAuthProxyRoute(w, r, snapshot, clientIP)
		return
	}
	if matchedHostRule != nil {
		accessEntry.RouteType = "host_rule"
		accessEntry.RouteKey = matchedHostRule.Host
		accessEntry.Upstream = matchedHostRule.Target
		accessEntry.AuthRequired = matchedHostRule.UseAuth && snapshot.authConfig.AuthURL != ""
		authResult := authCheckResult{allowed: true, decision: "not_required"}
		if accessEntry.AuthRequired {
			authResult = h.checkAuth(w, r, snapshot.authConfig, clientIP, matchedHostRule.AccessMode, matchedHostRule.Target)
			accessEntry.LoggedIn = authResult.authenticated
			accessEntry.AuthDecision = authResult.decision
			if !authResult.allowed {
				if authResult.decision == "denied" {
					loggedStatusCode = 499
				}
				return
			}
		} else {
			accessEntry.AuthDecision = authResult.decision
		}
		accessEntry.LoggedIn = authResult.authenticated
		h.proxyToHostTarget(w, r, snapshot, *matchedHostRule, clientIP, authResult)
		return
	}
	if matchedRule == nil {
		accessEntry.RouteType = "not_found"
		accessEntry.RouteKey = r.URL.Path
		accessEntry.AuthDecision = "not_required"
		h.handleNoMatchRoute(w, r, snapshot, clientIP)
		return
	}
	accessEntry.RouteType = "path_rule"
	accessEntry.RouteKey = matchedRule.Path
	accessEntry.Upstream = matchedRule.Target
	accessEntry.AuthRequired = matchedRule.UseAuth && snapshot.authConfig.AuthURL != ""
	if matchedRule.UseRootMode && matchedRule.Path != "/" && strings.HasPrefix(r.URL.Path, matchedRule.Path) {
		accessEntry.AuthDecision = "root_mode_redirect"
		http.SetCookie(w, &http.Cookie{
			Name:  "__proxy_path",
			Value: matchedRule.Path,
			Path:  "/",
		})
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	authResult := authCheckResult{allowed: true, decision: "not_required"}
	if accessEntry.AuthRequired {
		authResult = h.checkAuth(w, r, snapshot.authConfig, clientIP, "", matchedRule.Target)
		accessEntry.LoggedIn = authResult.authenticated
		accessEntry.AuthDecision = authResult.decision
		if !authResult.allowed {
			if authResult.decision == "denied" {
				loggedStatusCode = 499
			}
			return
		}
	} else {
		accessEntry.AuthDecision = authResult.decision
	}
	accessEntry.LoggedIn = authResult.authenticated
	h.proxyToRuleTarget(w, r, snapshot, *matchedRule, clientIP, authResult)
}

func (h *Handler) handleSelectRoute(w http.ResponseWriter, r *http.Request, snapshot requestSnapshot, clientIP string) authCheckResult {
	if snapshot.authConfig.AuthURL != "" {
		authResult := h.checkAuth(w, r, snapshot.authConfig, clientIP, "", "")
		if !authResult.allowed {
			return authResult
		}
		response.SelectPage(w, r, snapshot.rules, snapshot.hostRules)
		return authResult
	}
	response.SelectPage(w, r, snapshot.rules, snapshot.hostRules)
	return authCheckResult{allowed: true, decision: "not_required"}
}

func (h *Handler) handleAuthProxyRoute(w http.ResponseWriter, r *http.Request, snapshot requestSnapshot, clientIP string) bool {
	if !strings.HasPrefix(r.URL.Path, "/__auth__/") {
		return false
	}

	if snapshot.authConfig.AuthPort <= 0 {
		response.HTML(w, r, errors.CodeInternal, "Authentication service is not configured", nil)
		return true
	}
	targetURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", snapshot.authConfig.AuthPort))

	proxyPath := r.URL.Path
	switch r.URL.Path {
	case "/__auth__/login":
		proxyPath = snapshot.authConfig.LoginURL
		if proxyPath == "" {
			proxyPath = "/login"
		}
		if redirectTarget := buildInternalAuthLoginRedirect(proxyPath, r.URL.RawQuery); redirectTarget != "" {
			http.Redirect(w, r, redirectTarget, http.StatusFound)
			return true
		}
	case "/__auth__/api/auth/logout":
		proxyPath = snapshot.authConfig.LogoutURL
		if proxyPath == "" {
			proxyPath = "/api/auth/logout"
		}
	default:
		rawProxyPath := strings.TrimPrefix(r.URL.Path, "/__auth__")
		proxyPath = path.Clean(ensureLeadingSlash(rawProxyPath))
	}

	targetURL.Path = singleJoiningSlash(targetURL.Path, proxyPath)

	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	if h.proxyTransport != nil {
		proxy.Transport = h.proxyTransport
	} else {
		proxy.Transport = newProxyTransport()
	}

	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		applyInternalAuthProxyHeaders(req, r, targetURL, clientIP, snapshot.authConfig)
	}
	proxy.ModifyResponse = func(resp *http.Response) error {
		if shouldDisableAuthResponseCaching(proxyPath) {
			applyNoStoreCacheHeaders(resp.Header)
		}
		h.authCacheInvalidateForSetCookieMutation(r, clientIP, resp.Header.Values("Set-Cookie"))
		return nil
	}

	proxy.ServeHTTP(w, r)
	return true
}

func matchRuleFromProxyPathCookie(r *http.Request, rules []models.Rule) *models.Rule {
	cookie, err := r.Cookie("__proxy_path")
	if err != nil || cookie.Value == "" {
		return nil
	}

	for _, rule := range rules {
		if cookie.Value == rule.Path {
			return copyRule(rule)
		}
	}

	return nil
}

func matchHostRule(r *http.Request, rules []models.HostRule) *models.HostRule {
	if len(rules) == 0 {
		return nil
	}

	host := normalizeRequestHost(r.Host)
	if forwardedHost := normalizeRequestHost(r.Header.Get("X-Forwarded-Host")); forwardedHost != "" {
		host = forwardedHost
	}
	if host == "" {
		return nil
	}

	for _, rule := range rules {
		if normalizeRequestHost(rule.Host) == host {
			return copyHostRule(rule)
		}
	}

	return nil
}

func matchRule(r *http.Request, rules []models.Rule) (*models.Rule, string) {
	var matchedRule *models.Rule
	var longestMatch int
	var needsSlashRedirect string
	var rootPathCookieRule *models.Rule

	// When the user returns to "/", prefer the last root-mode selection
	// before falling back to a catch-all "/" rule or the configured default route.
	if r.URL.Path == "/" {
		rootPathCookieRule = matchRuleFromProxyPathCookie(r, rules)
	}

	for _, rule := range rules {
		if strings.HasPrefix(r.URL.Path, rule.Path) && len(rule.Path) > longestMatch {
			matchedRule = copyRule(rule)
			longestMatch = len(rule.Path)
		}
		if r.URL.Path+"/" == rule.Path {
			needsSlashRedirect = rule.Path
		}
	}

	if matchedRule != nil && matchedRule.Path != "/" && r.URL.Path == matchedRule.Path && !strings.HasSuffix(matchedRule.Path, "/") {
		if r.Method == http.MethodGet {
			needsSlashRedirect = matchedRule.Path + "/"
			matchedRule = nil
		}
	} else if longestMatch == len(r.URL.Path) {
		needsSlashRedirect = ""
	} else if needsSlashRedirect != "" {
		matchedRule = nil
	}

	if rootPathCookieRule != nil && needsSlashRedirect == "" {
		matchedRule = rootPathCookieRule
	}

	if matchedRule == nil && needsSlashRedirect == "" {
		isWebSocket := strings.ToLower(r.Header.Get("Upgrade")) == "websocket"
		canUseCookie := r.URL.Path == "/" || r.Header.Get("Referer") != "" || r.Header.Get("Origin") != "" || isWebSocket
		if canUseCookie {
			matchedRule = matchRuleFromProxyPathCookie(r, rules)
		}

		if matchedRule == nil {
			referer := r.Header.Get("Referer")
			if referer != "" {
				refURL, err := url.Parse(referer)
				if err == nil {
					var longestRefMatch int
					for _, rule := range rules {
						if strings.HasPrefix(refURL.Path, rule.Path) && len(rule.Path) > longestRefMatch {
							matchedRule = copyRule(rule)
							longestRefMatch = len(rule.Path)
						}
					}
				}
			}
		}
	}

	return matchedRule, needsSlashRedirect
}

func (h *Handler) handleNoMatchRoute(w http.ResponseWriter, r *http.Request, snapshot requestSnapshot, clientIP string) {
	if r.URL.Path == "/" {
		if len(snapshot.rules) == 0 && len(snapshot.hostRules) == 0 {
			response.Welcome(w, r, nil)
			return
		}
		if len(snapshot.rules) > 0 {
			http.Redirect(w, r, "/__select__", http.StatusFound)
			return
		}
	}
	response.RouteNotFound(w, r, snapshot.rules)
}

func (h *Handler) proxyToHostTarget(w http.ResponseWriter, r *http.Request, snapshot requestSnapshot, matchedRule models.HostRule, clientIP string, authResult authCheckResult) {
	targetURL, err := url.Parse(matchedRule.Target)
	if err != nil {
		response.HTML(w, r, errors.CodeProxyTargetInvalid, "Invalid target URL configuration", snapshot.rules)
		return
	}

	switch targetURL.Scheme {
	case "ws":
		targetURL.Scheme = "http"
	case "wss":
		targetURL.Scheme = "https"
	}

	transport := h.proxyTransport
	if transport == nil {
		transport = newProxyTransport()
	}
	omitForwardedHeaders := h.shouldOmitForwardedHeaders(targetURL)
	preserveHost := matchedRule.PreserveHost && !h.shouldOmitPreserveHost(targetURL)
	suppressToolbarForUA := response.ShouldSuppressToolbarForUserAgent(r.UserAgent())
	isAuthHostProxy := snapshot.authConfig.AuthHost != "" && normalizeRequestHost(matchedRule.Host) == snapshot.authConfig.AuthHost

	proxy := &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			applyForwardedHeaderPolicy(pr.Out, pr.In, clientIP, omitForwardedHeaders)
			copyUserAgentHeader(pr.Out, pr.In)
			pr.SetURL(targetURL)
			applyUpstreamPrivateIPv4HintHeader(pr.Out, targetURL)
			applyPreserveHostPolicy(pr.Out, pr.In, targetURL, preserveHost)

			if !preserveHost {
				if origin := pr.In.Header.Get("Origin"); origin != "" {
					pr.Out.Header.Set("Origin", targetURL.Scheme+"://"+targetURL.Host)
				}
				if referer := pr.In.Header.Get("Referer"); referer != "" {
					ref, err := url.Parse(referer)
					if err == nil {
						ref.Scheme = targetURL.Scheme
						ref.Host = targetURL.Host
						pr.Out.Header.Set("Referer", ref.String())
					}
				}
			}

			if matchedRule.UseAuth && !matchedRule.SuppressToolbar && !authResult.suppressToolbar && !suppressToolbarForUA {
				pr.Out.Header.Del("Accept-Encoding")
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("Host proxy error: %v", err)
			response.HTML(w, r, errors.CodeProxyTimeout, "Upstream unavailable: "+err.Error(), h.GetRules())
		},
	}

	proxy.ModifyResponse = func(resp *http.Response) error {
		if isAuthHostProxy && shouldDisableAuthResponseCaching(r.URL.Path) {
			applyNoStoreCacheHeaders(resp.Header)
		}
		if isAuthHostProxy {
			h.authCacheInvalidateForSetCookieMutation(r, clientIP, resp.Header.Values("Set-Cookie"))
		}

		needsToolbar := matchedRule.UseAuth && !matchedRule.SuppressToolbar && !authResult.suppressToolbar && !suppressToolbarForUA
		if !needsToolbar {
			return nil
		}

		contentType := strings.ToLower(resp.Header.Get("Content-Type"))
		if !strings.Contains(contentType, "text/html") {
			return nil
		}

		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		resp.Body.Close()

		bodyStr := injectToolbarIntoHTML(
			string(bodyBytes),
			response.GenerateToolbarWithHosts(
				snapshot.rules,
				snapshot.hostRules,
				r.URL.Path,
				matchedRule.Host,
				snapshot.authConfig.AuthHost,
			),
		)

		newBody := []byte(bodyStr)
		resp.Body = io.NopCloser(bytes.NewReader(newBody))
		resp.ContentLength = int64(len(newBody))
		resp.Header.Set("Content-Length", strconv.Itoa(len(newBody)))
		return nil
	}

	proxy.ServeHTTP(w, r)
}

func (h *Handler) proxyToRuleTarget(w http.ResponseWriter, r *http.Request, snapshot requestSnapshot, matchedRule models.Rule, clientIP string, authResult authCheckResult) {
	targetURL, err := url.Parse(matchedRule.Target)
	if err != nil {
		response.HTML(w, r, errors.CodeProxyTargetInvalid, "Invalid target URL configuration", snapshot.rules)
		return
	}

	switch targetURL.Scheme {
	case "ws":
		targetURL.Scheme = "http"
	case "wss":
		targetURL.Scheme = "https"
	}

	transport := h.proxyTransport
	if transport == nil {
		transport = newProxyTransport()
	}
	preserveHost := !h.shouldOmitPreserveHost(targetURL)
	suppressToolbarForUA := response.ShouldSuppressToolbarForUserAgent(r.UserAgent())
	proxy := &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			applyForwardedHeaderPolicy(pr.Out, pr.In, clientIP, false)
			copyUserAgentHeader(pr.Out, pr.In)
			pr.SetURL(targetURL)
			applyUpstreamPrivateIPv4HintHeader(pr.Out, targetURL)
			applyPreserveHostPolicy(pr.Out, pr.In, targetURL, preserveHost)

			if matchedRule.StripPath {
				pr.Out.URL.Path = strings.TrimPrefix(pr.Out.URL.Path, matchedRule.Path)
				if !strings.HasPrefix(pr.Out.URL.Path, "/") {
					pr.Out.URL.Path = "/" + pr.Out.URL.Path
				}
				pr.Out.URL.RawPath = ""
			}

			if !preserveHost {
				if origin := pr.In.Header.Get("Origin"); origin != "" {
					pr.Out.Header.Set("Origin", targetURL.Scheme+"://"+targetURL.Host)
				}
				if referer := pr.In.Header.Get("Referer"); referer != "" {
					ref, err := url.Parse(referer)
					if err == nil {
						ref.Scheme = targetURL.Scheme
						ref.Host = targetURL.Host
						ref.Path = path.Clean(ref.Path)

						if matchedRule.StripPath {
							ref.Path = strings.TrimPrefix(ref.Path, matchedRule.Path)
							if !strings.HasPrefix(ref.Path, "/") {
								ref.Path = "/" + ref.Path
							}
						}
						ref.RawPath = ""

						pr.Out.Header.Set("Referer", ref.String())
					}
				}
			}

			if matchedRule.RewriteHTML || (matchedRule.UseAuth && !authResult.suppressToolbar && !suppressToolbarForUA) {
				pr.Out.Header.Del("Accept-Encoding")
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("Proxy error: %v", err)
			response.HTML(w, r, errors.CodeProxyTimeout, "Upstream unavailable: "+err.Error(), h.GetRules())
		},
	}

	proxy.ModifyResponse = func(resp *http.Response) error {
		cookie := &http.Cookie{
			Name:  "__proxy_path",
			Value: matchedRule.Path,
			Path:  "/",
		}
		resp.Header.Add("Set-Cookie", cookie.String())

		needsRewrite := matchedRule.RewriteHTML && !matchedRule.UseRootMode
		needsToolbar := matchedRule.UseAuth && !authResult.suppressToolbar && !suppressToolbarForUA
		if !needsRewrite && !needsToolbar {
			return nil
		}

		if needsRewrite {
			if location := resp.Header.Get("Location"); location != "" {
				if strings.HasPrefix(location, "/") {
					resp.Header.Set("Location", matchedRule.Path+location)
				}
			}
		}

		contentType := resp.Header.Get("Content-Type")
		if !strings.Contains(strings.ToLower(contentType), "text/html") {
			return nil
		}

		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		resp.Body.Close()

		bodyStr := string(bodyBytes)

		if needsRewrite {
			prefix := strings.TrimSuffix(matchedRule.Path, "/")
			replacements := []struct {
				old string
				new string
			}{
				{`href="/`, `href="` + prefix + `/`},
				{`src="/`, `src="` + prefix + `/`},
				{`action="/`, `action="` + prefix + `/`},
				{`<base href="/">`, `<base href="` + prefix + `/">`},
			}

			for _, rep := range replacements {
				bodyStr = strings.ReplaceAll(bodyStr, rep.old, rep.new)
			}
		}

		if needsToolbar {
			bodyStr = injectToolbarIntoHTML(
				bodyStr,
				response.GenerateToolbar(snapshot.rules, matchedRule.Path),
			)
		}

		newBody := []byte(bodyStr)
		resp.Body = io.NopCloser(bytes.NewReader(newBody))
		resp.ContentLength = int64(len(newBody))
		resp.Header.Set("Content-Length", strconv.Itoa(len(newBody)))
		return nil
	}

	proxy.ServeHTTP(w, r)
}

func injectToolbarIntoHTML(bodyStr string, toolbarHTML string) string {
	if toolbarHTML == "" || bodyStr == "" {
		return bodyStr
	}

	lowerBody := strings.ToLower(bodyStr)
	if idx := strings.LastIndex(lowerBody, "</body>"); idx != -1 {
		return bodyStr[:idx] + toolbarHTML + bodyStr[idx:]
	}

	if strings.Contains(lowerBody, "<html") ||
		strings.Contains(lowerBody, "<head") ||
		strings.Contains(lowerBody, "<body") ||
		strings.Contains(lowerBody, "<!doctype") {
		return bodyStr + toolbarHTML
	}

	return bodyStr
}

type authCheckErrorPage struct {
	code    int
	title   string
	message string
}

type authCheckPlan struct {
	result           authCheckResult
	setCookies       []string
	redirectLocation string
	abortConnection  bool
	errorPage        *authCheckErrorPage
}

type authCheckExecution struct {
	entry *authCacheEntry
	plan  authCheckPlan
}

func (h *Handler) performAuthCheck(r *http.Request, authConfig models.AuthConfig, clientIP string, accessMode string) authCheckPlan {
	client := h.authClient
	if client == nil {
		client = &http.Client{
			Timeout:   5 * time.Second,
			Transport: newInternalTransport(),
		}
	}

	if authConfig.AuthPort <= 0 {
		log.Printf("Auth check requested but AuthPort is not configured")
		return authCheckPlan{
			result: authCheckResult{decision: "error"},
			errorPage: &authCheckErrorPage{
				code:    errors.CodeInternal,
				title:   "Authentication Service Not Configured",
				message: "Authentication Service Not Configured",
			},
		}
	}

	authURLPath := authConfig.AuthURL
	if authURLPath == "" {
		authURLPath = "/api/auth/verify"
	}
	authURL := localServiceURL(authConfig.AuthPort, authURLPath)

	authReq, err := http.NewRequest("GET", authURL, nil)
	if err != nil {
		log.Printf("Failed to create auth request: %v", err)
		return authCheckPlan{
			result: authCheckResult{decision: "error"},
			errorPage: &authCheckErrorPage{
				code:    errors.CodeInternal,
				title:   "Internal Server Error during Auth",
				message: "Internal Server Error during Auth",
			},
		}
	}

	authReq.Header.Set("X-Real-IP", clientIP)
	authReq.Header.Set("X-Forwarded-For", clientIP)
	authReq.Header.Set("X-Forwarded-Host", r.Host)
	authReq.Header.Set("X-Forwarded-Proto", requestScheme(r))
	if accessMode != "" {
		authReq.Header.Set("X-Reauth-Access-Mode", accessMode)
	}

	if cookie := r.Header.Get("Cookie"); cookie != "" {
		authReq.Header.Set("Cookie", cookie)
	}
	if auth := r.Header.Get("Authorization"); auth != "" {
		authReq.Header.Set("Authorization", auth)
	}

	authReq.Header.Set("X-Forwarded-Path", r.URL.RequestURI())
	copyUserAgentHeader(authReq, r)

	resp, err := client.Do(authReq)
	if err != nil {
		log.Printf("Auth request failed: %v", err)
		return authCheckPlan{
			result: authCheckResult{decision: "error"},
			errorPage: &authCheckErrorPage{
				code:    errors.CodeProxyAuthFailed,
				title:   "Authentication Service Unavailable",
				message: "Authentication Service Unavailable",
			},
		}
	}
	defer resp.Body.Close()
	setCookies := copySetCookieHeaders(resp.Header.Values("Set-Cookie"))

	var authResponse struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&authResponse); err != nil {
		log.Printf("Failed to decode auth response: %v", err)
		return authCheckPlan{
			result: authCheckResult{decision: "error"},
			errorPage: &authCheckErrorPage{
				code:    errors.CodeInternal,
				title:   "Invalid Auth Response Format",
				message: "Invalid Auth Response Format",
			},
		}
	}
	if authResponse.Success {
		return authCheckPlan{
			result: authCheckResult{
				allowed:         true,
				authenticated:   true,
				suppressToolbar: strings.EqualFold(resp.Header.Get("X-Reauth-Access-Mode"), "fnos-share"),
				decision:        "passed",
			},
			setCookies: setCookies,
		}
	}
	log.Printf("Auth failed: %s", authResponse.Message)
	if accessMode == "strict_whitelist" {
		return authCheckPlan{
			result:          authCheckResult{decision: "denied"},
			setCookies:      setCookies,
			abortConnection: true,
		}
	}
	if redirectLocation := strings.TrimSpace(resp.Header.Get("X-Reauth-Redirect-Location")); redirectLocation != "" {
		if strings.HasPrefix(redirectLocation, "/") || strings.HasPrefix(redirectLocation, "http://") || strings.HasPrefix(redirectLocation, "https://") {
			return authCheckPlan{
				result:           authCheckResult{decision: "redirected"},
				setCookies:       setCookies,
				redirectLocation: redirectLocation,
			}
		}
	}

	originalURL := buildPublicRequestURL(r, authConfig, "")
	if originalURL == nil {
		originalURL = &url.URL{
			Scheme:   requestScheme(r),
			Host:     r.Host,
			Path:     r.URL.Path,
			RawQuery: r.URL.RawQuery,
		}
	}

	loginURL := buildPublicAuthLoginURL(authConfig, r, originalURL)
	if loginURL == nil {
		loginURL, _ = url.Parse("/__auth__/login")
		q := loginURL.Query()
		q.Set("redirect_uri", originalURL.String())
		loginURL.RawQuery = q.Encode()
	}

	return authCheckPlan{
		result:           authCheckResult{decision: "redirected"},
		setCookies:       setCookies,
		redirectLocation: loginURL.String(),
	}
}

func (h *Handler) applyAuthCheckPlan(w http.ResponseWriter, r *http.Request, plan authCheckPlan, clientIP string, upstreamTarget string) authCheckResult {
	for _, setCookie := range plan.setCookies {
		w.Header().Add("Set-Cookie", setCookie)
	}
	if len(plan.setCookies) > 0 {
		h.authCacheInvalidateForSetCookieMutation(r, clientIP, plan.setCookies)
	}

	if plan.errorPage != nil {
		response.HTML(w, r, plan.errorPage.code, plan.errorPage.message, nil)
		return plan.result
	}

	if plan.result.allowed {
		h.markLoggedInActive(r, clientIP, time.Now())
		return plan.result
	}

	if h.fnAppMockService != nil {
		handled, err := h.fnAppMockService.handleUnauthorizedRequest(w, r, upstreamTarget)
		if err != nil {
			log.Printf("Failed to serve unauthorized FN App mock response: %v", err)
			return authCheckResult{decision: "error"}
		}
		if handled {
			return authCheckResult{decision: "fn_app_prompt"}
		}
	}

	if plan.abortConnection {
		suppressAccessLog(w)
		h.abortConnection(w)
		return plan.result
	}
	if plan.redirectLocation != "" {
		http.Redirect(w, r, plan.redirectLocation, http.StatusFound)
		return plan.result
	}
	return plan.result
}

func (h *Handler) checkAuth(w http.ResponseWriter, r *http.Request, authConfig models.AuthConfig, clientIP string, accessMode string, upstreamTarget string) authCheckResult {
	now := time.Now()
	useCache := authCacheEnabled(authConfig)
	lookup, canLookup := buildAuthCacheLookup(r, clientIP, accessMode)

	if useCache && canLookup {
		if entry, ok := h.authCacheGet(lookup.cacheKey, now); ok {
			if shouldBypassFNAppUnauthorizedAuthCache(r, entry.result) {
				h.authCache.mu.Lock()
				h.authCache.deleteEntryLocked(lookup.cacheKey)
				h.authCache.mu.Unlock()
			} else {
				return h.applyAuthCacheEntry(w, r, entry, clientIP, upstreamTarget)
			}
		}

		executionAny, _, _ := h.authCache.group.Do(lookup.cacheKey, func() (any, error) {
			if entry, ok := h.authCacheGet(lookup.cacheKey, time.Now()); ok {
				if shouldBypassFNAppUnauthorizedAuthCache(r, entry.result) {
					h.authCache.mu.Lock()
					h.authCache.deleteEntryLocked(lookup.cacheKey)
					h.authCache.mu.Unlock()
				} else {
					return authCheckExecution{entry: &entry}, nil
				}
			}

			plan := h.performAuthCheck(r, authConfig, clientIP, accessMode)
			if plan.errorPage == nil && len(plan.setCookies) == 0 {
				if ttl := authCacheTTL(authConfig, plan.result); ttl > 0 {
					entry := authCacheEntry{
						result:           plan.result,
						setCookies:       copySetCookieHeaders(plan.setCookies),
						redirectLocation: plan.redirectLocation,
						abortConnection:  plan.abortConnection,
						expiresAt:        time.Now().Add(ttl),
						identityKey:      lookup.identityKey,
					}
					if !shouldBypassFNAppUnauthorizedAuthCache(r, plan.result) {
						h.authCacheStore(lookup.cacheKey, entry, time.Now())
					}
					return authCheckExecution{entry: &entry}, nil
				}
			}

			return authCheckExecution{plan: plan}, nil
		})

		execution, _ := executionAny.(authCheckExecution)
		if execution.entry != nil {
			return h.applyAuthCacheEntry(w, r, *execution.entry, clientIP, upstreamTarget)
		}
		return h.applyAuthCheckPlan(w, r, execution.plan, clientIP, upstreamTarget)
	}

	plan := h.performAuthCheck(r, authConfig, clientIP, accessMode)
	return h.applyAuthCheckPlan(w, r, plan, clientIP, upstreamTarget)
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

func mergeQueryValues(dst url.Values, src url.Values) {
	for key, values := range src {
		dst.Del(key)
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func applyRequestPortToPublicAuthBase(baseURL *url.URL, r *http.Request, authConfig models.AuthConfig) {
	if authConfig.AliyunESAEnabled || baseURL == nil || baseURL.Host == "" || baseURL.Port() != "" {
		return
	}

	requestPort := resolvedPublicPort(r, authConfig, baseURL.Scheme, "")
	if requestPort == "" || requestPort == defaultPortForScheme(baseURL.Scheme) {
		return
	}

	hostname := baseURL.Hostname()
	if hostname == "" {
		return
	}

	baseURL.Host = net.JoinHostPort(hostname, requestPort)
}

func buildPublicAuthLoginURL(authConfig models.AuthConfig, r *http.Request, originalURL *url.URL) *url.URL {
	if strings.TrimSpace(authConfig.PublicAuthBaseURL) == "" {
		return nil
	}

	baseURL, err := url.Parse(authConfig.PublicAuthBaseURL)
	if err != nil {
		return nil
	}
	applyRequestPortToPublicAuthBase(baseURL, r, authConfig)

	loginPath := strings.TrimSpace(authConfig.LoginURL)
	if loginPath == "" {
		loginPath = "/login"
	}

	var loginURL *url.URL
	if strings.HasPrefix(loginPath, "/#") || strings.HasPrefix(loginPath, "#") {
		loginURL = baseURL.ResolveReference(&url.URL{})
		if loginURL.Path == "" {
			loginURL.Path = "/"
		}
		loginURL.Fragment = strings.TrimPrefix(strings.TrimPrefix(loginPath, "/"), "#")
	} else {
		loginURL, err = baseURL.Parse(loginPath)
		if err != nil {
			return nil
		}
	}

	q := loginURL.Query()
	q.Set("redirect_uri", originalURL.String())
	loginURL.RawQuery = q.Encode()
	return loginURL
}

func buildInternalAuthLoginRedirect(loginPath string, rawQuery string) string {
	parsedLoginPath, err := url.Parse(strings.TrimSpace(loginPath))
	if err != nil {
		return ""
	}
	if parsedLoginPath.Fragment == "" && parsedLoginPath.RawQuery == "" {
		return ""
	}

	redirectPath := parsedLoginPath.Path
	if redirectPath == "" {
		redirectPath = "/"
	}

	redirectURL := &url.URL{
		Path: singleJoiningSlash("/__auth__", ensureLeadingSlash(redirectPath)),
	}
	query := redirectURL.Query()
	mergeQueryValues(query, parsedLoginPath.Query())
	if requestQuery, err := url.ParseQuery(rawQuery); err == nil {
		mergeQueryValues(query, requestQuery)
	}
	redirectURL.RawQuery = query.Encode()
	redirectURL.Fragment = parsedLoginPath.Fragment
	return redirectURL.String()
}
