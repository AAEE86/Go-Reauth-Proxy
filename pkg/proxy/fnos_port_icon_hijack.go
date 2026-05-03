package proxy

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"go-reauth-proxy/pkg/models"
	"io"
	"log"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

const defaultFnosPortIconHijackGatewayPort = 7999

type fnosPortIconHijackWebSocketOptions struct {
	targetURL            *url.URL
	hostRules            []models.HostRule
	clientIP             string
	omitForwardedHeaders bool
	preserveHost         bool
	rewriteOriginReferer bool
	stripPath            bool
	pathPrefix           string
}

func (h *Handler) maybeProxyFnosPortIconHijackWebSocket(w http.ResponseWriter, r *http.Request, options fnosPortIconHijackWebSocketOptions) bool {
	if !h.shouldProxyFnosPortIconHijackWebSocket(r) {
		return false
	}

	targets := buildFnosPortIconHijackTargets(options.hostRules)
	if len(targets) == 0 {
		return false
	}

	if err := h.proxyFnosPortIconHijackWebSocket(w, r, options, targets); err != nil {
		if !isFNAppConnectionTermination(err) {
			log.Printf("FNOS port icon hijack websocket proxy failed: %v", err)
		}
	}
	return true
}

func (h *Handler) shouldProxyFnosPortIconHijackWebSocket(r *http.Request) bool {
	if r == nil || r.URL == nil || !isFNAppWebSocketRequest(r) {
		return false
	}
	if path.Clean(r.URL.Path) != "/websocket" {
		return false
	}
	if r.URL.Query().Get("type") != "main" {
		return false
	}
	return h.GetFnosPortIconHijackConfig().Enabled
}

func (h *Handler) proxyFnosPortIconHijackWebSocket(w http.ResponseWriter, r *http.Request, options fnosPortIconHijackWebSocketOptions, targets map[int]string) error {
	if options.targetURL == nil {
		http.Error(w, "missing upstream target", http.StatusBadGateway)
		return fmt.Errorf("missing websocket upstream target")
	}

	upstreamURL := buildFnosPortIconHijackWebSocketURL(options.targetURL, r.URL, options.stripPath, options.pathPrefix)
	requestHeader := buildFnosPortIconHijackWebSocketHeader(r, options, upstreamURL)
	dialer := websocket.Dialer{
		Proxy:             http.ProxyFromEnvironment,
		HandshakeTimeout:  10 * time.Second,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		EnableCompression: false,
		Subprotocols:      websocket.Subprotocols(r),
	}

	upstreamConn, resp, err := dialer.DialContext(r.Context(), upstreamURL.String(), requestHeader)
	if resp != nil && resp.Body != nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	if err != nil {
		http.Error(w, "websocket upstream unavailable", http.StatusBadGateway)
		return err
	}
	defer upstreamConn.Close()

	upgrader := websocket.Upgrader{
		CheckOrigin: func(_ *http.Request) bool {
			return true
		},
		EnableCompression: false,
	}
	if subprotocol := upstreamConn.Subprotocol(); subprotocol != "" {
		upgrader.Subprotocols = []string{subprotocol}
	}

	clientConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return err
	}
	defer clientConn.Close()

	responsePort := h.fnosPortIconHijackResponsePort()

	errCh := make(chan error, 2)
	go func() {
		errCh <- relayWebSocketMessages(clientConn, upstreamConn, func(messageType int, payload []byte) (int, []byte, error) {
			if messageType != websocket.TextMessage {
				return messageType, payload, nil
			}

			rewritten, changed, err := rewriteFnosPortIconHijackMessage(payload, targets, responsePort)
			if err != nil {
				log.Printf("Failed to rewrite FNOS port icon payload: %v", err)
				return messageType, payload, nil
			}
			if !changed {
				return messageType, payload, nil
			}
			return messageType, rewritten, nil
		})
	}()
	go func() {
		errCh <- relayWebSocketMessages(upstreamConn, clientConn, nil)
	}()

	err = <-errCh
	_ = clientConn.Close()
	_ = upstreamConn.Close()
	return err
}

func (h *Handler) fnosPortIconHijackResponsePort() int {
	h.mu.RLock()
	edgeClientIPEnabled := h.AuthConfig.EdgeClientIPEnabled
	proxyPort := h.ProxyPort
	h.mu.RUnlock()

	if edgeClientIPEnabled {
		return 80
	}
	if proxyPort > 0 {
		return proxyPort
	}
	return defaultFnosPortIconHijackGatewayPort
}

func buildFnosPortIconHijackWebSocketURL(targetURL *url.URL, incomingURL *url.URL, stripPath bool, pathPrefix string) *url.URL {
	upstreamURL := *targetURL
	switch strings.ToLower(upstreamURL.Scheme) {
	case "https", "wss":
		upstreamURL.Scheme = "wss"
	default:
		upstreamURL.Scheme = "ws"
	}

	upstreamPath := "/"
	if incomingURL != nil {
		upstreamPath = incomingURL.Path
		if stripPath {
			upstreamPath = strings.TrimPrefix(upstreamPath, pathPrefix)
			if !strings.HasPrefix(upstreamPath, "/") {
				upstreamPath = "/" + upstreamPath
			}
		}
		upstreamURL.RawQuery = incomingURL.RawQuery
	} else {
		upstreamURL.RawQuery = ""
	}
	upstreamURL.Path = singleJoiningSlash(targetURL.Path, upstreamPath)
	upstreamURL.RawPath = ""
	upstreamURL.Fragment = ""
	return &upstreamURL
}

func buildFnosPortIconHijackWebSocketHeader(r *http.Request, options fnosPortIconHijackWebSocketOptions, upstreamURL *url.URL) http.Header {
	headers := r.Header.Clone()
	for _, name := range []string{
		"Connection",
		"Upgrade",
		"Sec-WebSocket-Accept",
		"Sec-WebSocket-Extensions",
		"Sec-WebSocket-Key",
		"Sec-WebSocket-Protocol",
		"Sec-WebSocket-Version",
	} {
		headers.Del(name)
	}

	out := r.Clone(r.Context())
	out.Header = headers
	out.URL = upstreamURL
	out.Host = upstreamURL.Host
	applyForwardedHeaderPolicy(out, r, options.clientIP, options.omitForwardedHeaders)
	copyUserAgentHeader(out, r)
	applyUpstreamPrivateIPv4HintHeader(out, options.targetURL)
	applyPreserveHostPolicy(out, r, options.targetURL, options.preserveHost)

	if options.rewriteOriginReferer {
		if origin := r.Header.Get("Origin"); origin != "" {
			headers.Set("Origin", options.targetURL.Scheme+"://"+options.targetURL.Host)
		}
		if referer := r.Header.Get("Referer"); referer != "" {
			if ref, err := url.Parse(referer); err == nil {
				ref.Scheme = options.targetURL.Scheme
				ref.Host = options.targetURL.Host
				ref.Path = path.Clean(ref.Path)
				if options.stripPath {
					ref.Path = strings.TrimPrefix(ref.Path, options.pathPrefix)
					if !strings.HasPrefix(ref.Path, "/") {
						ref.Path = "/" + ref.Path
					}
				}
				ref.RawPath = ""
				headers.Set("Referer", ref.String())
			}
		}
	}

	if out.Host != "" && out.Host != upstreamURL.Host {
		headers.Set("Host", out.Host)
	}
	return headers
}

func relayWebSocketMessages(dst *websocket.Conn, src *websocket.Conn, transform func(int, []byte) (int, []byte, error)) error {
	for {
		messageType, payload, err := src.ReadMessage()
		if err != nil {
			return err
		}
		if transform != nil {
			messageType, payload, err = transform(messageType, payload)
			if err != nil {
				return err
			}
		}
		if err := dst.WriteMessage(messageType, payload); err != nil {
			return err
		}
	}
}

func buildFnosPortIconHijackTargets(hostRules []models.HostRule) map[int]string {
	targets := make(map[int]string)
	for _, rule := range hostRules {
		host := normalizeRequestHost(rule.Host)
		if host == "" {
			continue
		}

		port, ok := hostRuleTargetPort(rule.Target)
		if !ok {
			continue
		}
		if _, exists := targets[port]; exists {
			continue
		}
		targets[port] = host
	}
	return targets
}

func hostRuleTargetPort(rawTarget string) (int, bool) {
	parsed, err := url.Parse(strings.TrimSpace(rawTarget))
	if err != nil || parsed.Host == "" {
		return 0, false
	}
	if port := parsed.Port(); port != "" {
		parsedPort, err := strconv.Atoi(port)
		if err == nil && parsedPort > 0 && parsedPort <= 65535 {
			return parsedPort, true
		}
		return 0, false
	}

	switch strings.ToLower(parsed.Scheme) {
	case "http", "ws":
		return 80, true
	case "https", "wss":
		return 443, true
	default:
		return 0, false
	}
}

func rewriteFnosPortIconHijackMessage(payload []byte, hostByPort map[int]string, gatewayPort int) ([]byte, bool, error) {
	if len(hostByPort) == 0 || gatewayPort <= 0 {
		return payload, false, nil
	}

	var value any
	if err := json.Unmarshal(payload, &value); err != nil {
		return payload, false, nil
	}

	if !rewriteFnosPortIconHijackValue(value, hostByPort, gatewayPort) {
		return payload, false, nil
	}

	rewritten, err := json.Marshal(value)
	if err != nil {
		return payload, false, err
	}
	return rewritten, true, nil
}

func rewriteFnosPortIconHijackValue(value any, hostByPort map[int]string, gatewayPort int) bool {
	switch typed := value.(type) {
	case map[string]any:
		changed := rewriteFnosPortIconHijackObject(typed, hostByPort, gatewayPort)
		for _, child := range typed {
			if rewriteFnosPortIconHijackValue(child, hostByPort, gatewayPort) {
				changed = true
			}
		}
		return changed
	case []any:
		changed := false
		for _, child := range typed {
			if rewriteFnosPortIconHijackValue(child, hostByPort, gatewayPort) {
				changed = true
			}
		}
		return changed
	default:
		return false
	}
}

func rewriteFnosPortIconHijackObject(object map[string]any, hostByPort map[int]string, gatewayPort int) bool {
	rawHost, hasHost := object["host"]
	if !hasHost {
		return false
	}
	host, ok := rawHost.(string)
	if !ok || strings.TrimSpace(host) != "" {
		return false
	}

	port, ok := jsonPortNumber(object["port"])
	if !ok {
		return false
	}

	nextHost := hostByPort[port]
	if nextHost == "" {
		return false
	}

	object["host"] = nextHost
	object["port"] = strconv.Itoa(gatewayPort)
	object["path"] = ""
	return true
}

func jsonPortNumber(value any) (int, bool) {
	switch typed := value.(type) {
	case string:
		port, err := strconv.Atoi(strings.TrimSpace(typed))
		if err != nil || port <= 0 || port > 65535 {
			return 0, false
		}
		return port, true
	case float64:
		port := int(typed)
		if typed != float64(port) || port <= 0 || port > 65535 {
			return 0, false
		}
		return port, true
	case json.Number:
		port, err := strconv.Atoi(typed.String())
		if err != nil || port <= 0 || port > 65535 {
			return 0, false
		}
		return port, true
	default:
		return 0, false
	}
}
