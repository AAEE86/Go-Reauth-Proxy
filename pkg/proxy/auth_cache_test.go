package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAuthCacheLookupSeparatesCookieIdentityByClientIP(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/path?q=1", nil)
	req.AddCookie(&http.Cookie{Name: authSessionCookieName, Value: "session-a"})

	first, ok := buildAuthCacheLookup(req, "198.51.100.10", "login_first")
	if !ok {
		t.Fatal("first auth cache lookup was not buildable")
	}
	second, ok := buildAuthCacheLookup(req, "198.51.100.11", "login_first")
	if !ok {
		t.Fatal("second auth cache lookup was not buildable")
	}
	if first.identityKey != second.identityKey {
		t.Fatalf("identity keys differ for the same cookie: %q != %q", first.identityKey, second.identityKey)
	}
	if first.cacheKey == second.cacheKey {
		t.Fatal("auth cache keys should differ when the same cookie is seen from different client IPs")
	}

	firstPreflight, ok := buildPreflightCacheLookup(req, "198.51.100.10", "login_first", true)
	if !ok {
		t.Fatal("first preflight cache lookup was not buildable")
	}
	secondPreflight, ok := buildPreflightCacheLookup(req, "198.51.100.11", "login_first", true)
	if !ok {
		t.Fatal("second preflight cache lookup was not buildable")
	}
	if firstPreflight.identityKey != secondPreflight.identityKey {
		t.Fatalf("preflight identity keys differ for the same cookie: %q != %q", firstPreflight.identityKey, secondPreflight.identityKey)
	}
	if firstPreflight.cacheKey == secondPreflight.cacheKey {
		t.Fatal("preflight cache keys should differ when the same cookie is seen from different client IPs")
	}
}

func TestAuthCacheLookupSeparatesAuthorizationIdentityByClientIP(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/path", nil)
	req.Header.Set("Authorization", "Bearer token-a")

	first, ok := buildAuthCacheLookup(req, "2001:db8::10", "login_first")
	if !ok {
		t.Fatal("first auth cache lookup was not buildable")
	}
	second, ok := buildAuthCacheLookup(req, "2001:db8::11", "login_first")
	if !ok {
		t.Fatal("second auth cache lookup was not buildable")
	}
	if first.identityKey != second.identityKey {
		t.Fatalf("identity keys differ for the same auth header: %q != %q", first.identityKey, second.identityKey)
	}
	if first.cacheKey == second.cacheKey {
		t.Fatal("auth cache keys should differ when the same auth header is seen from different client IPs")
	}
}

func TestAuthCacheInvalidationClearsAllClientIPVariantsForIdentity(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/path", nil)
	req.AddCookie(&http.Cookie{Name: authSessionCookieName, Value: "session-a"})

	first, ok := buildAuthCacheLookup(req, "198.51.100.10", "login_first")
	if !ok {
		t.Fatal("first auth cache lookup was not buildable")
	}
	second, ok := buildAuthCacheLookup(req, "198.51.100.11", "login_first")
	if !ok {
		t.Fatal("second auth cache lookup was not buildable")
	}
	firstPreflight, ok := buildPreflightCacheLookup(req, "198.51.100.10", "login_first", true)
	if !ok {
		t.Fatal("first preflight cache lookup was not buildable")
	}
	secondPreflight, ok := buildPreflightCacheLookup(req, "198.51.100.11", "login_first", true)
	if !ok {
		t.Fatal("second preflight cache lookup was not buildable")
	}

	handler := &Handler{
		authCache:      newAuthStateCache(),
		preflightCache: newPreflightStateCache(),
	}
	now := time.Now()
	handler.authCacheStore(first.cacheKey, authCacheEntry{
		result:      authCheckResult{allowed: true, authenticated: true},
		expiresAt:   now.Add(time.Minute),
		identityKey: first.identityKey,
	}, now)
	handler.authCacheStore(second.cacheKey, authCacheEntry{
		result:      authCheckResult{allowed: true, authenticated: true},
		expiresAt:   now.Add(time.Minute),
		identityKey: second.identityKey,
	}, now)
	handler.preflightCacheStore(firstPreflight.cacheKey, preflightCacheEntry{
		decision:    preflightDecision{},
		expiresAt:   now.Add(time.Minute),
		identityKey: firstPreflight.identityKey,
	}, now)
	handler.preflightCacheStore(secondPreflight.cacheKey, preflightCacheEntry{
		decision:    preflightDecision{},
		expiresAt:   now.Add(time.Minute),
		identityKey: secondPreflight.identityKey,
	}, now)

	handler.authCacheInvalidateByIdentityKeys(first.identityKey)

	if _, ok := handler.authCacheGet(first.cacheKey, now); ok {
		t.Fatal("first auth cache entry was not invalidated")
	}
	if _, ok := handler.authCacheGet(second.cacheKey, now); ok {
		t.Fatal("second auth cache entry was not invalidated")
	}
	if _, ok := handler.preflightCacheGet(firstPreflight.cacheKey, now); ok {
		t.Fatal("first preflight cache entry was not invalidated")
	}
	if _, ok := handler.preflightCacheGet(secondPreflight.cacheKey, now); ok {
		t.Fatal("second preflight cache entry was not invalidated")
	}
}
