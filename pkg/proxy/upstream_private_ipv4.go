package proxy

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	upstreamPrivateIPv4HeaderName    = "X-Reauth-Upstream-Private-IPv4"
	upstreamPrivateIPv4CacheTTL      = 30 * time.Second
	upstreamPrivateIPv4LookupTimeout = 300 * time.Millisecond
)

var (
	privateIPv4Detector         = newPreferredPrivateIPv4Detector(upstreamPrivateIPv4CacheTTL, detectPreferredPrivateIPv4)
	hostnamePrivateIPv4Resolver = newCachedPrivateIPv4Resolver(upstreamPrivateIPv4CacheTTL, lookupHostnamePrivateIPv4)
)

type preferredPrivateIPv4Detector struct {
	mu        sync.Mutex
	value     string
	expiresAt time.Time
	ttl       time.Duration
	detect    func() string
}

type cachedPrivateIPv4Resolver struct {
	mu       sync.Mutex
	ttl      time.Duration
	resolve  func(string) string
	entries  map[string]cachedPrivateIPv4Entry
	inflight map[string]*cachedPrivateIPv4Call
}

type cachedPrivateIPv4Entry struct {
	value     string
	expiresAt time.Time
}

type cachedPrivateIPv4Call struct {
	done  chan struct{}
	value string
}

func newPreferredPrivateIPv4Detector(ttl time.Duration, detect func() string) *preferredPrivateIPv4Detector {
	if ttl <= 0 {
		ttl = upstreamPrivateIPv4CacheTTL
	}
	if detect == nil {
		detect = detectPreferredPrivateIPv4
	}
	return &preferredPrivateIPv4Detector{
		ttl:    ttl,
		detect: detect,
	}
}

func (d *preferredPrivateIPv4Detector) get() string {
	now := time.Now()

	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.expiresAt.IsZero() && now.Before(d.expiresAt) {
		return d.value
	}

	d.value = d.detect()
	d.expiresAt = time.Now().Add(d.ttl)
	return d.value
}

func newCachedPrivateIPv4Resolver(ttl time.Duration, resolve func(string) string) *cachedPrivateIPv4Resolver {
	if ttl <= 0 {
		ttl = upstreamPrivateIPv4CacheTTL
	}
	if resolve == nil {
		resolve = func(string) string { return "" }
	}
	return &cachedPrivateIPv4Resolver{
		ttl:      ttl,
		resolve:  resolve,
		entries:  make(map[string]cachedPrivateIPv4Entry),
		inflight: make(map[string]*cachedPrivateIPv4Call),
	}
}

func (r *cachedPrivateIPv4Resolver) get(hostname string) string {
	key := normalizeUpstreamHostname(hostname)
	if key == "" {
		return ""
	}

	now := time.Now()

	r.mu.Lock()
	if entry, ok := r.entries[key]; ok && entry.expiresAt.After(now) {
		value := entry.value
		r.mu.Unlock()
		return value
	}
	if call, ok := r.inflight[key]; ok {
		r.mu.Unlock()
		<-call.done
		return call.value
	}
	if r.entries == nil {
		r.entries = make(map[string]cachedPrivateIPv4Entry)
	}
	if r.inflight == nil {
		r.inflight = make(map[string]*cachedPrivateIPv4Call)
	}
	call := &cachedPrivateIPv4Call{done: make(chan struct{})}
	r.inflight[key] = call
	r.mu.Unlock()

	value := r.resolve(key)
	expiresAt := time.Now().Add(r.ttl)

	r.mu.Lock()
	r.entries[key] = cachedPrivateIPv4Entry{
		value:     value,
		expiresAt: expiresAt,
	}
	delete(r.inflight, key)
	call.value = value
	close(call.done)
	r.mu.Unlock()

	return value
}

func applyUpstreamPrivateIPv4HintHeader(out *http.Request, targetURL *url.URL) {
	if out == nil {
		return
	}

	if hint := resolveUpstreamPrivateIPv4Hint(targetURL); hint != "" {
		out.Header.Set(upstreamPrivateIPv4HeaderName, hint)
		return
	}

	out.Header.Del(upstreamPrivateIPv4HeaderName)
}

func resolveUpstreamPrivateIPv4Hint(targetURL *url.URL) string {
	if targetURL == nil {
		return ""
	}

	hostname := normalizeUpstreamHostname(targetURL.Hostname())
	if hostname == "" {
		return ""
	}

	if isUsablePrivateIPv4(hostname) {
		return hostname
	}

	if isLoopbackOrLocalHostname(hostname) {
		return privateIPv4Detector.get()
	}

	return hostnamePrivateIPv4Resolver.get(hostname)
}

func lookupHostnamePrivateIPv4(hostname string) string {
	ctx, cancel := context.WithTimeout(context.Background(), upstreamPrivateIPv4LookupTimeout)
	defer cancel()

	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, hostname)
	if err != nil {
		return ""
	}

	for _, item := range addresses {
		if ip := normalizeIPv4(item.IP); ip != "" && isUsablePrivateIPv4(ip) {
			return ip
		}
	}

	return ""
}

func normalizeUpstreamHostname(value string) string {
	normalized := strings.TrimSpace(strings.ToLower(value))
	return strings.TrimSuffix(normalized, ".")
}

func detectPreferredPrivateIPv4() string {
	for _, remoteAddr := range []string{"1.1.1.1:53", "8.8.8.8:53"} {
		if ip := detectOutboundPrivateIPv4(remoteAddr); ip != "" {
			return ip
		}
	}

	return detectInterfacePrivateIPv4()
}

func detectOutboundPrivateIPv4(remoteAddr string) string {
	conn, err := net.Dial("udp4", remoteAddr)
	if err != nil {
		return ""
	}
	defer conn.Close()

	udpAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || udpAddr == nil {
		return ""
	}

	ip := normalizeIPv4(udpAddr.IP)
	if !isUsablePrivateIPv4(ip) {
		return ""
	}

	return ip
}

func detectInterfacePrivateIPv4() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}

	sort.Slice(interfaces, func(i, j int) bool {
		return interfaces[i].Name < interfaces[j].Name
	})

	for _, iface := range interfaces {
		if shouldSkipPrivateIPv4Interface(iface.Name) {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch value := addr.(type) {
			case *net.IPNet:
				ip = value.IP
			case *net.IPAddr:
				ip = value.IP
			default:
				continue
			}

			normalized := normalizeIPv4(ip)
			if isUsablePrivateIPv4(normalized) {
				return normalized
			}
		}
	}

	return ""
}

func shouldSkipPrivateIPv4Interface(name string) bool {
	normalized := strings.TrimSpace(strings.ToLower(name))
	if normalized == "" {
		return true
	}

	for _, prefix := range []string{
		"lo",
		"docker",
		"br-",
		"veth",
		"tailscale",
		"zt",
		"tun",
		"tap",
		"wg",
		"vmnet",
	} {
		if strings.HasPrefix(normalized, prefix) {
			return true
		}
	}

	return false
}

func isLoopbackOrLocalHostname(value string) bool {
	normalized := strings.TrimSpace(strings.ToLower(value))
	if normalized == "" {
		return false
	}

	if normalized == "localhost" {
		return true
	}

	ip := net.ParseIP(normalized)
	return ip != nil && ip.IsLoopback()
}

func normalizeIPv4(value net.IP) string {
	if value == nil {
		return ""
	}

	ipv4 := value.To4()
	if ipv4 == nil {
		return ""
	}

	return ipv4.String()
}

func isUsablePrivateIPv4(value string) bool {
	ip := net.ParseIP(strings.TrimSpace(value))
	if ip == nil {
		return false
	}

	ipv4 := ip.To4()
	if ipv4 == nil {
		return false
	}

	if ipv4[0] == 10 {
		return true
	}
	if ipv4[0] == 172 && ipv4[1] >= 16 && ipv4[1] <= 31 {
		return true
	}
	if ipv4[0] == 192 && ipv4[1] == 168 {
		return true
	}

	return false
}
