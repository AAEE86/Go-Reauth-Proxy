package proxy

import (
	"go-reauth-proxy/pkg/models"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

func BuildHTTPSRedirectURL(r *http.Request, authConfig models.AuthConfig) string {
	target := buildPublicRequestURL(r, authConfig, "https")
	if target == nil {
		return ""
	}
	return target.String()
}

func buildPublicRequestURL(r *http.Request, authConfig models.AuthConfig, schemeOverride string) *url.URL {
	if r == nil {
		return nil
	}

	scheme := normalizedPublicScheme(r, schemeOverride)
	host := publicRequestHost(r, authConfig, scheme)
	if host == "" {
		host = strings.TrimSpace(r.Host)
	}

	return &url.URL{
		Scheme:   scheme,
		Host:     host,
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
	}
}

func normalizedPublicScheme(r *http.Request, schemeOverride string) string {
	if scheme := strings.ToLower(strings.TrimSpace(schemeOverride)); scheme != "" {
		return scheme
	}

	if scheme := strings.ToLower(strings.TrimSpace(requestScheme(r))); scheme != "" {
		return scheme
	}

	return "http"
}

func publicRequestHost(r *http.Request, authConfig models.AuthConfig, scheme string) string {
	requestHost := publicRequestHostHeader(r)
	hostname, hostPort := splitRequestHostPort(requestHost)
	if hostname == "" {
		return strings.TrimSpace(requestHost)
	}

	port := resolvedPublicPort(r, authConfig, scheme, hostPort)
	return formatURLHost(hostname, port, scheme)
}

func publicRequestHostHeader(r *http.Request) string {
	if r == nil {
		return ""
	}

	if forwardedHost := firstForwardedValue(r.Header.Get("X-Forwarded-Host")); forwardedHost != "" {
		return strings.TrimSpace(forwardedHost)
	}

	return strings.TrimSpace(r.Host)
}

func splitRequestHostPort(host string) (string, string) {
	host = strings.TrimSpace(host)
	if host == "" {
		return "", ""
	}

	parsed, err := url.Parse("//" + host)
	if err != nil {
		return host, ""
	}

	hostname := parsed.Hostname()
	if hostname == "" {
		return host, ""
	}

	return hostname, parsed.Port()
}

func resolvedPublicPort(r *http.Request, authConfig models.AuthConfig, scheme string, requestHostPort string) string {
	if configuredPort := configuredPublicPort(authConfig, scheme); configuredPort != "" {
		return configuredPort
	}

	if forwardedPort := forwardedRequestPort(r); forwardedPort != "" {
		return forwardedPort
	}

	if isValidPort(requestHostPort) {
		return requestHostPort
	}

	if authConfig.AliyunESAEnabled {
		return ""
	}

	return localRequestPort(r)
}

func configuredPublicPort(authConfig models.AuthConfig, scheme string) string {
	switch strings.ToLower(strings.TrimSpace(scheme)) {
	case "http":
		if authConfig.PublicHTTPPort > 0 {
			return strconv.Itoa(authConfig.PublicHTTPPort)
		}
	case "https":
		if authConfig.PublicHTTPSPort > 0 {
			return strconv.Itoa(authConfig.PublicHTTPSPort)
		}
	}

	if derivedPort := publicPortFromAuthBaseURL(authConfig.PublicAuthBaseURL, scheme); derivedPort != "" {
		return derivedPort
	}

	return ""
}

func publicPortFromAuthBaseURL(rawBaseURL string, scheme string) string {
	baseURL, err := url.Parse(strings.TrimSpace(rawBaseURL))
	if err != nil || baseURL == nil {
		return ""
	}

	if !strings.EqualFold(baseURL.Scheme, strings.TrimSpace(scheme)) {
		return ""
	}

	port := strings.TrimSpace(baseURL.Port())
	if !isValidPort(port) {
		return ""
	}

	return port
}

func forwardedRequestPort(r *http.Request) string {
	if r == nil {
		return ""
	}

	value := firstForwardedValue(r.Header.Get("X-Forwarded-Port"))
	if !isValidPort(value) {
		return ""
	}

	return value
}

func localRequestPort(r *http.Request) string {
	if r == nil {
		return ""
	}

	localAddr := r.Context().Value(http.LocalAddrContextKey)
	addr, ok := localAddr.(net.Addr)
	if !ok || addr == nil {
		return ""
	}

	switch value := addr.(type) {
	case *net.TCPAddr:
		if value.Port <= 0 {
			return ""
		}
		return strconv.Itoa(value.Port)
	case *net.UDPAddr:
		if value.Port <= 0 {
			return ""
		}
		return strconv.Itoa(value.Port)
	default:
		_, port, err := net.SplitHostPort(addr.String())
		if err != nil || !isValidPort(port) {
			return ""
		}
		return port
	}
}

func formatURLHost(hostname string, port string, scheme string) string {
	if hostname == "" {
		return ""
	}

	if port == "" || port == defaultPortForScheme(scheme) {
		if strings.Contains(hostname, ":") {
			return "[" + hostname + "]"
		}
		return hostname
	}

	return net.JoinHostPort(hostname, port)
}

func defaultPortForScheme(scheme string) string {
	switch strings.ToLower(strings.TrimSpace(scheme)) {
	case "http":
		return "80"
	case "https":
		return "443"
	default:
		return ""
	}
}

func isValidPort(value string) bool {
	port, err := strconv.Atoi(strings.TrimSpace(value))
	return err == nil && port > 0 && port <= 65535
}
