package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"go-reauth-proxy/pkg/models"

	"golang.org/x/sync/singleflight"
)

const (
	authSessionCookieName      = "x-go-reauth-proxy-session-id"
	authShareSessionCookieName = "fn-knock-fnos-share-session"
	authCacheCleanupInterval   = 30 * time.Second
)

type authStateCache struct {
	mu             sync.RWMutex
	entries        map[string]authCacheEntry
	keysByIdentity map[string]map[string]struct{}
	group          singleflight.Group
	lastCleanup    time.Time
}

type preflightStateCache struct {
	mu             sync.RWMutex
	entries        map[string]preflightCacheEntry
	keysByIdentity map[string]map[string]struct{}
	group          singleflight.Group
	lastCleanup    time.Time
}

type authCacheLookup struct {
	cacheKey    string
	identityKey string
}

type preflightCacheLookup struct {
	cacheKey    string
	identityKey string
}

type authCacheEntry struct {
	result           authCheckResult
	setCookies       []string
	redirectLocation string
	abortConnection  bool
	expiresAt        time.Time
	identityKey      string
}

type preflightCacheEntry struct {
	decision    preflightDecision
	expiresAt   time.Time
	identityKey string
}

type preflightCacheExecution struct {
	entry    *preflightCacheEntry
	decision preflightDecision
}

func newAuthStateCache() authStateCache {
	return authStateCache{
		entries:        make(map[string]authCacheEntry),
		keysByIdentity: make(map[string]map[string]struct{}),
	}
}

func newPreflightStateCache() preflightStateCache {
	return preflightStateCache{
		entries:        make(map[string]preflightCacheEntry),
		keysByIdentity: make(map[string]map[string]struct{}),
	}
}

func authCacheEnabled(authConfig models.AuthConfig) bool {
	return authConfig.AuthCacheTTL > 0 || authConfig.AuthCacheFailTTL > 0
}

func authCacheTTL(authConfig models.AuthConfig, result authCheckResult) time.Duration {
	switch {
	case result.allowed && result.authenticated && authConfig.AuthCacheTTL > 0:
		return time.Duration(authConfig.AuthCacheTTL) * time.Second
	case !result.allowed && result.decision != "error" && result.decision != "fn_app_prompt" && authConfig.AuthCacheFailTTL > 0:
		return time.Duration(authConfig.AuthCacheFailTTL) * time.Second
	default:
		return 0
	}
}

func shouldBypassFNAppUnauthorizedAuthCache(r *http.Request, result authCheckResult) bool {
	return isFNAppRequest(r) && (!result.allowed || !result.authenticated)
}

func shouldBypassFNAppNegativePreflightCache(r *http.Request, decision preflightDecision) bool {
	return isFNAppRequest(r) && (decision.deny || strings.TrimSpace(decision.redirectLocation) != "")
}

func preflightCacheTTL(authConfig models.AuthConfig) time.Duration {
	successTTL := authConfig.AuthCacheTTL
	failTTL := authConfig.AuthCacheFailTTL

	switch {
	case successTTL > 0 && failTTL > 0:
		if successTTL < failTTL {
			return time.Duration(successTTL) * time.Second
		}
		return time.Duration(failTTL) * time.Second
	case successTTL > 0:
		return time.Duration(successTTL) * time.Second
	case failTTL > 0:
		return time.Duration(failTTL) * time.Second
	default:
		return 0
	}
}

func requestIdentitySource(r *http.Request, clientIP string) string {
	if cookieID := canonicalCookieIdentity(r); cookieID != "" {
		return "cookie:" + cookieID
	}
	if auth := strings.TrimSpace(r.Header.Get("Authorization")); auth != "" {
		return "auth:" + auth
	}
	clientIP = strings.TrimSpace(clientIP)
	if clientIP != "" {
		return "ip:" + clientIP
	}
	return ""
}

func requestIdentityKey(r *http.Request, clientIP string) string {
	return activeIdentityKeyFromSource(requestIdentitySource(r, clientIP))
}

func authCacheClientIPDimension(identitySource string, clientIP string) string {
	identitySource = strings.TrimSpace(identitySource)
	if !(strings.HasPrefix(identitySource, "cookie:") || strings.HasPrefix(identitySource, "auth:")) {
		return ""
	}
	return strings.TrimSpace(clientIP)
}

func buildAuthCacheLookup(r *http.Request, clientIP string, accessMode string) (authCacheLookup, bool) {
	identitySource := requestIdentitySource(r, clientIP)
	identityKey := activeIdentityKeyFromSource(identitySource)
	if identityKey == "" {
		return authCacheLookup{}, false
	}
	clientIPDimension := authCacheClientIPDimension(identitySource, clientIP)

	host := normalizeRequestHost(r.Host)
	if host == "" {
		host = normalizeRequestHost(r.Header.Get("X-Forwarded-Host"))
	}

	raw := strings.Join([]string{
		identityKey,
		clientIPDimension,
		strings.TrimSpace(strings.ToLower(accessMode)),
		strings.TrimSpace(strings.ToLower(requestScheme(r))),
		strings.TrimSpace(strings.ToUpper(r.Method)),
		host,
		r.URL.RequestURI(),
	}, "\n")
	sum := sha256.Sum256([]byte(raw))

	return authCacheLookup{
		cacheKey:    hex.EncodeToString(sum[:]),
		identityKey: identityKey,
	}, true
}

func buildPreflightCacheLookup(r *http.Request, clientIP string, accessMode string, isMatch bool) (preflightCacheLookup, bool) {
	identitySource := requestIdentitySource(r, clientIP)
	identityKey := activeIdentityKeyFromSource(identitySource)
	if identityKey == "" {
		return preflightCacheLookup{}, false
	}
	clientIPDimension := authCacheClientIPDimension(identitySource, clientIP)

	host := normalizeRequestHost(r.Host)
	if host == "" {
		host = normalizeRequestHost(r.Header.Get("X-Forwarded-Host"))
	}

	raw := strings.Join([]string{
		identityKey,
		clientIPDimension,
		strings.TrimSpace(strings.ToLower(accessMode)),
		strings.TrimSpace(strings.ToLower(requestScheme(r))),
		host,
		strconv.FormatBool(isMatch),
		r.URL.RequestURI(),
	}, "\n")
	sum := sha256.Sum256([]byte(raw))

	return preflightCacheLookup{
		cacheKey:    hex.EncodeToString(sum[:]),
		identityKey: identityKey,
	}, true
}

func copySetCookieHeaders(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	cloned := make([]string, len(values))
	copy(cloned, values)
	return cloned
}

func (h *Handler) authCacheGet(cacheKey string, now time.Time) (authCacheEntry, bool) {
	cache := &h.authCache

	cache.mu.RLock()
	entry, ok := cache.entries[cacheKey]
	cache.mu.RUnlock()
	if !ok {
		return authCacheEntry{}, false
	}
	if !entry.expiresAt.After(now) {
		cache.mu.Lock()
		cache.deleteEntryLocked(cacheKey)
		cache.mu.Unlock()
		return authCacheEntry{}, false
	}
	return entry, true
}

func (h *Handler) preflightCacheGet(cacheKey string, now time.Time) (preflightCacheEntry, bool) {
	cache := &h.preflightCache

	cache.mu.RLock()
	entry, ok := cache.entries[cacheKey]
	cache.mu.RUnlock()
	if !ok {
		return preflightCacheEntry{}, false
	}
	if !entry.expiresAt.After(now) {
		cache.mu.Lock()
		cache.deleteEntryLocked(cacheKey)
		cache.mu.Unlock()
		return preflightCacheEntry{}, false
	}
	return entry, true
}

func (h *Handler) authCacheStore(cacheKey string, entry authCacheEntry, now time.Time) {
	cache := &h.authCache

	cache.mu.Lock()
	cache.entries[cacheKey] = entry
	if entry.identityKey != "" {
		keys := cache.keysByIdentity[entry.identityKey]
		if keys == nil {
			keys = make(map[string]struct{})
			cache.keysByIdentity[entry.identityKey] = keys
		}
		keys[cacheKey] = struct{}{}
	}
	cache.cleanupExpiredLocked(now)
	cache.mu.Unlock()
}

func (h *Handler) preflightCacheStore(cacheKey string, entry preflightCacheEntry, now time.Time) {
	cache := &h.preflightCache

	cache.mu.Lock()
	cache.entries[cacheKey] = entry
	if entry.identityKey != "" {
		keys := cache.keysByIdentity[entry.identityKey]
		if keys == nil {
			keys = make(map[string]struct{})
			cache.keysByIdentity[entry.identityKey] = keys
		}
		keys[cacheKey] = struct{}{}
	}
	cache.cleanupExpiredLocked(now)
	cache.mu.Unlock()
}

func (h *Handler) authCacheInvalidateByIdentityKeys(identityKeys ...string) {
	authCache := &h.authCache
	preflightCache := &h.preflightCache

	authCache.mu.Lock()
	for _, identityKey := range identityKeys {
		if identityKey == "" {
			continue
		}
		keys := authCache.keysByIdentity[identityKey]
		for cacheKey := range keys {
			authCache.deleteEntryLocked(cacheKey)
		}
	}
	authCache.mu.Unlock()

	preflightCache.mu.Lock()
	for _, identityKey := range identityKeys {
		if identityKey == "" {
			continue
		}
		keys := preflightCache.keysByIdentity[identityKey]
		for cacheKey := range keys {
			preflightCache.deleteEntryLocked(cacheKey)
		}
	}
	preflightCache.mu.Unlock()
}

func (h *Handler) clearAuthCache() {
	authCache := &h.authCache
	preflightCache := &h.preflightCache

	authCache.mu.Lock()
	authCache.entries = make(map[string]authCacheEntry)
	authCache.keysByIdentity = make(map[string]map[string]struct{})
	authCache.lastCleanup = time.Time{}
	authCache.mu.Unlock()

	preflightCache.mu.Lock()
	preflightCache.entries = make(map[string]preflightCacheEntry)
	preflightCache.keysByIdentity = make(map[string]map[string]struct{})
	preflightCache.lastCleanup = time.Time{}
	preflightCache.mu.Unlock()
}

func (c *authStateCache) deleteEntryLocked(cacheKey string) {
	entry, ok := c.entries[cacheKey]
	if !ok {
		return
	}
	delete(c.entries, cacheKey)
	if entry.identityKey == "" {
		return
	}
	keys := c.keysByIdentity[entry.identityKey]
	delete(keys, cacheKey)
	if len(keys) == 0 {
		delete(c.keysByIdentity, entry.identityKey)
	}
}

func (c *authStateCache) cleanupExpiredLocked(now time.Time) {
	if !c.lastCleanup.IsZero() && now.Sub(c.lastCleanup) < authCacheCleanupInterval {
		return
	}
	for cacheKey, entry := range c.entries {
		if !entry.expiresAt.After(now) {
			c.deleteEntryLocked(cacheKey)
		}
	}
	c.lastCleanup = now
}

func (c *preflightStateCache) deleteEntryLocked(cacheKey string) {
	entry, ok := c.entries[cacheKey]
	if !ok {
		return
	}
	delete(c.entries, cacheKey)
	if entry.identityKey == "" {
		return
	}
	keys := c.keysByIdentity[entry.identityKey]
	delete(keys, cacheKey)
	if len(keys) == 0 {
		delete(c.keysByIdentity, entry.identityKey)
	}
}

func (c *preflightStateCache) cleanupExpiredLocked(now time.Time) {
	if !c.lastCleanup.IsZero() && now.Sub(c.lastCleanup) < authCacheCleanupInterval {
		return
	}
	for cacheKey, entry := range c.entries {
		if !entry.expiresAt.After(now) {
			c.deleteEntryLocked(cacheKey)
		}
	}
	c.lastCleanup = now
}

func requestCookieMap(r *http.Request) map[string]string {
	cookies := r.Cookies()
	if len(cookies) == 0 {
		return nil
	}

	values := make(map[string]string, len(cookies))
	for _, cookie := range cookies {
		if cookie == nil || cookie.Name == "" || cookie.Name == proxyPathCookieName {
			continue
		}
		if cookie.Value == "" {
			delete(values, cookie.Name)
			continue
		}
		values[cookie.Name] = cookie.Value
	}
	if len(values) == 0 {
		return nil
	}
	return values
}

func canonicalCookieIdentityFromMap(values map[string]string) string {
	if len(values) == 0 {
		return ""
	}

	names := make([]string, 0, len(values))
	for name, value := range values {
		if name == "" || value == "" || name == proxyPathCookieName {
			continue
		}
		names = append(names, name)
	}
	if len(names) == 0 {
		return ""
	}

	sort.Strings(names)
	var b strings.Builder
	for i, name := range names {
		if i > 0 {
			b.WriteByte(';')
		}
		b.WriteString(name)
		b.WriteByte('=')
		b.WriteString(values[name])
	}
	return b.String()
}

func identityKeyFromState(cookieValues map[string]string, authHeader string, clientIP string) string {
	if cookieID := canonicalCookieIdentityFromMap(cookieValues); cookieID != "" {
		return activeIdentityKeyFromSource("cookie:" + cookieID)
	}
	if auth := strings.TrimSpace(authHeader); auth != "" {
		return activeIdentityKeyFromSource("auth:" + auth)
	}
	if clientIP := strings.TrimSpace(clientIP); clientIP != "" {
		return activeIdentityKeyFromSource("ip:" + clientIP)
	}
	return ""
}

func parseRelevantAuthSetCookies(setCookieHeaders []string) []*http.Cookie {
	if len(setCookieHeaders) == 0 {
		return nil
	}

	header := http.Header{}
	for _, value := range setCookieHeaders {
		header.Add("Set-Cookie", value)
	}
	resp := &http.Response{Header: header}
	all := resp.Cookies()
	if len(all) == 0 {
		return nil
	}

	relevant := make([]*http.Cookie, 0, len(all))
	for _, cookie := range all {
		if cookie == nil {
			continue
		}
		switch cookie.Name {
		case authSessionCookieName, authShareSessionCookieName:
			relevant = append(relevant, cookie)
		}
	}
	return relevant
}

func applySetCookieMutations(base map[string]string, cookies []*http.Cookie) map[string]string {
	if len(cookies) == 0 {
		return base
	}

	updated := make(map[string]string, len(base)+len(cookies))
	for name, value := range base {
		updated[name] = value
	}

	for _, cookie := range cookies {
		if cookie == nil || cookie.Name == "" {
			continue
		}
		if cookie.Value == "" || cookie.MaxAge < 0 || cookie.MaxAge == 0 {
			delete(updated, cookie.Name)
			continue
		}
		updated[cookie.Name] = cookie.Value
	}
	if len(updated) == 0 {
		return nil
	}
	return updated
}

func (h *Handler) authCacheInvalidateForSetCookieMutation(r *http.Request, clientIP string, setCookieHeaders []string) {
	relevantCookies := parseRelevantAuthSetCookies(setCookieHeaders)
	if len(relevantCookies) == 0 {
		return
	}

	identityKeySet := make(map[string]struct{}, 3)
	if key := requestIdentityKey(r, clientIP); key != "" {
		identityKeySet[key] = struct{}{}
	}
	if key := activeIdentityKeyFromClientIP(clientIP); key != "" {
		identityKeySet[key] = struct{}{}
	}

	nextCookies := applySetCookieMutations(requestCookieMap(r), relevantCookies)
	if key := identityKeyFromState(nextCookies, r.Header.Get("Authorization"), clientIP); key != "" {
		identityKeySet[key] = struct{}{}
	}

	identityKeys := make([]string, 0, len(identityKeySet))
	for key := range identityKeySet {
		identityKeys = append(identityKeys, key)
	}
	h.authCacheInvalidateByIdentityKeys(identityKeys...)
}

func (h *Handler) applyAuthCacheEntry(w http.ResponseWriter, r *http.Request, entry authCacheEntry, clientIP string, upstreamTarget string) authCheckResult {
	for _, setCookie := range entry.setCookies {
		w.Header().Add("Set-Cookie", setCookie)
	}

	if entry.result.allowed && entry.result.authenticated {
		h.markLoggedInActive(r, clientIP, time.Now())
		return entry.result
	}

	if h.fnAppMockService != nil {
		handled, err := h.fnAppMockService.handleUnauthorizedRequest(w, r, upstreamTarget)
		if err != nil {
			log.Printf("Failed to serve unauthorized FN App mock response from auth cache: %v", err)
			return authCheckResult{decision: "error"}
		}
		if handled {
			return authCheckResult{decision: "fn_app_prompt"}
		}
	}

	if entry.abortConnection {
		h.abortConnection(w)
		return entry.result
	}
	if entry.redirectLocation != "" {
		http.Redirect(w, r, entry.redirectLocation, http.StatusFound)
		return entry.result
	}
	return entry.result
}
