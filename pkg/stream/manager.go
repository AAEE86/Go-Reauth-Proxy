package stream

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go-reauth-proxy/pkg/gatewaylog"
	"go-reauth-proxy/pkg/models"
	"go-reauth-proxy/pkg/proxy"
	"io"
	"log"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	streamAuthTimeout   = 2 * time.Second
	streamDialTimeout   = 5 * time.Second
	streamAcceptBackoff = 150 * time.Millisecond
	maxAuthBodyBytes    = 1 << 20
)

type Manager struct {
	mu         sync.RWMutex
	handler    *proxy.Handler
	listeners  map[int]*listenerState
	rules      map[int]models.StreamRule
	authClient *http.Client
	closed     bool
}

type listenerState struct {
	port      int
	listeners []net.Listener
	stop      chan struct{}
	wg        sync.WaitGroup
	mu        sync.Mutex
	conns     map[net.Conn]struct{}
	closing   bool
}

type authVerifyPayload struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type relayResult struct {
	direction string
	bytes     uint64
	err       error
}

func NewManager(handler *proxy.Handler) *Manager {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConns = 32
	transport.MaxIdleConnsPerHost = 32
	transport.IdleConnTimeout = 30 * time.Second
	transport.ForceAttemptHTTP2 = false

	return &Manager{
		handler:   handler,
		listeners: make(map[int]*listenerState),
		rules:     make(map[int]models.StreamRule),
		authClient: &http.Client{
			Timeout:   streamAuthTimeout,
			Transport: transport,
		},
	}
}

func (m *Manager) Reconcile(rules []models.StreamRule) error {
	nextRules := make(map[int]models.StreamRule, len(rules))
	nextPorts := make([]int, 0, len(rules))
	for _, rule := range rules {
		if _, exists := nextRules[rule.ListenPort]; exists {
			return fmt.Errorf("duplicate listen_port: %d", rule.ListenPort)
		}
		nextRules[rule.ListenPort] = rule
		nextPorts = append(nextPorts, rule.ListenPort)
	}
	slices.Sort(nextPorts)

	m.mu.RLock()
	if m.closed {
		m.mu.RUnlock()
		return fmt.Errorf("stream manager is closed")
	}
	currentPorts := make([]int, 0, len(m.listeners))
	for port := range m.listeners {
		currentPorts = append(currentPorts, port)
	}
	m.mu.RUnlock()
	slices.Sort(currentPorts)

	currentSet := make(map[int]struct{}, len(currentPorts))
	for _, port := range currentPorts {
		currentSet[port] = struct{}{}
	}

	toAdd := make([]int, 0)
	for _, port := range nextPorts {
		if _, exists := currentSet[port]; !exists {
			toAdd = append(toAdd, port)
		}
		delete(currentSet, port)
	}

	toRemove := make([]int, 0, len(currentSet))
	for port := range currentSet {
		toRemove = append(toRemove, port)
	}
	slices.Sort(toRemove)

	created := make(map[int]*listenerState, len(toAdd))
	for _, port := range toAdd {
		state, err := newListenerState(port, m.handleConn)
		if err != nil {
			for _, candidate := range created {
				candidate.close()
			}
			return err
		}
		created[port] = state
	}

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		for _, candidate := range created {
			candidate.close()
		}
		return fmt.Errorf("stream manager is closed")
	}

	for port, state := range created {
		m.listeners[port] = state
	}
	m.rules = nextRules

	removed := make([]*listenerState, 0, len(toRemove))
	for _, port := range toRemove {
		if state, exists := m.listeners[port]; exists {
			removed = append(removed, state)
			delete(m.listeners, port)
		}
	}
	m.mu.Unlock()

	for _, state := range removed {
		state.close()
	}

	return nil
}

func (m *Manager) Stop() {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true

	states := make([]*listenerState, 0, len(m.listeners))
	for port, state := range m.listeners {
		states = append(states, state)
		delete(m.listeners, port)
	}
	m.rules = map[int]models.StreamRule{}
	m.mu.Unlock()

	for _, state := range states {
		state.close()
	}
}

func (m *Manager) currentRule(port int) (models.StreamRule, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	rule, ok := m.rules[port]
	return rule, ok
}

func newListenerState(port int, handler func(net.Conn, int)) (*listenerState, error) {
	hosts := []string{"0.0.0.0", "::"}
	listeners := make([]net.Listener, 0, len(hosts))
	listenAddrs := make([]string, 0, len(hosts))

	for _, host := range hosts {
		network := "tcp4"
		if strings.Contains(host, ":") {
			network = "tcp6"
		}

		addr := net.JoinHostPort(host, strconv.Itoa(port))
		ln, err := net.Listen(network, addr)
		if err != nil {
			if network == "tcp6" {
				log.Printf("Stream IPv6 listener unavailable on %s: %v", addr, err)
				continue
			}
			for _, existing := range listeners {
				_ = existing.Close()
			}
			return nil, fmt.Errorf("failed to listen on %s: %w", addr, err)
		}
		listeners = append(listeners, ln)
		listenAddrs = append(listenAddrs, ln.Addr().String())
	}

	if len(listeners) == 0 {
		return nil, fmt.Errorf("no stream listeners started for port %d", port)
	}

	state := &listenerState{
		port:      port,
		listeners: listeners,
		stop:      make(chan struct{}),
		conns:     make(map[net.Conn]struct{}),
	}

	for _, ln := range listeners {
		state.wg.Add(1)
		go state.acceptLoop(ln, handler)
	}

	log.Printf("Stream listener started on %s", strings.Join(listenAddrs, ", "))
	return state, nil
}

func (s *listenerState) acceptLoop(ln net.Listener, handler func(net.Conn, int)) {
	defer s.wg.Done()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.stop:
				return
			default:
			}

			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				log.Printf("Temporary stream accept error on %d: %v", s.port, err)
				time.Sleep(streamAcceptBackoff)
				continue
			}
			if isClosedConnErr(err) {
				return
			}
			log.Printf("Stream accept error on %d: %v", s.port, err)
			return
		}

		if !s.beginConn(conn) {
			_ = conn.Close()
			return
		}
		go func() {
			defer s.endConn(conn)
			handler(conn, s.port)
		}()
	}
}

func (s *listenerState) beginConn(conn net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closing {
		return false
	}

	s.wg.Add(1)
	s.conns[conn] = struct{}{}
	return true
}

func (s *listenerState) endConn(conn net.Conn) {
	s.mu.Lock()
	delete(s.conns, conn)
	s.mu.Unlock()
	s.wg.Done()
}

func (s *listenerState) close() {
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return
	}
	s.closing = true
	conns := make([]net.Conn, 0, len(s.conns))
	for conn := range s.conns {
		conns = append(conns, conn)
	}
	s.mu.Unlock()

	select {
	case <-s.stop:
	default:
		close(s.stop)
	}

	for _, ln := range s.listeners {
		_ = ln.Close()
	}
	for _, conn := range conns {
		_ = conn.Close()
	}
	s.wg.Wait()
}

func (m *Manager) handleConn(client net.Conn, listenPort int) {
	start := time.Now()
	remoteAddr := ""
	clientIP := ""
	if client != nil {
		remoteAddr = client.RemoteAddr().String()
		clientIP = extractRemoteIP(client.RemoteAddr())
	}

	entry := gatewaylog.Entry{
		Method:       "STREAM",
		Protocol:     "tcp",
		Status:       http.StatusOK,
		RemoteAddr:   remoteAddr,
		RemoteIP:     clientIP,
		RouteType:    "stream_rule",
		RouteKey:     strconv.Itoa(listenPort),
		Matched:      true,
		AuthDecision: "bypassed",
	}

	defer func() {
		entry.DurationMs = time.Since(start).Milliseconds()
		m.handler.AddStreamTraffic(entry.BytesIn, entry.BytesOut, entry.Status)
		m.handler.LogGatewayEntry(entry)
		if client != nil {
			_ = client.Close()
		}
	}()

	rule, ok := m.currentRule(listenPort)
	if !ok {
		entry.Matched = false
		entry.Status = http.StatusNotFound
		entry.AuthDecision = "rule_missing"
		return
	}

	entry.AuthRequired = rule.UseAuth
	entry.Upstream = rule.Target

	if rule.UseAuth {
		allowed, status, decision, err := m.verify(rule, clientIP)
		entry.AuthDecision = decision
		entry.LoggedIn = allowed
		if !allowed {
			entry.Status = status
			if err != nil {
				log.Printf("Stream auth rejected on port %d for %s: %v", listenPort, clientIP, err)
			}
			return
		}
		m.handler.MarkLoggedInActiveByClientIP(clientIP, time.Now())
	} else {
		entry.AuthDecision = "public"
	}

	dialer := &net.Dialer{
		Timeout:   streamDialTimeout,
		KeepAlive: 30 * time.Second,
	}
	upstream, err := dialer.Dial("tcp", rule.Target)
	if err != nil {
		entry.Status = http.StatusBadGateway
		log.Printf("Stream upstream dial failed on port %d to %s: %v", listenPort, rule.Target, err)
		return
	}
	defer upstream.Close()

	bytesIn, bytesOut, relayErr := relayBidirectional(client, upstream)
	entry.BytesIn = bytesIn
	entry.BytesOut = bytesOut
	if relayErr != nil {
		entry.Status = http.StatusBadGateway
		log.Printf("Stream relay failed on port %d to %s: %v", listenPort, rule.Target, relayErr)
	}
}

func (m *Manager) verify(rule models.StreamRule, clientIP string) (bool, int, string, error) {
	authConfig := m.handler.GetAuthConfig()
	if authConfig.AuthPort <= 0 {
		return false, http.StatusBadGateway, "auth_unconfigured", fmt.Errorf("auth_port is not configured")
	}

	authPath := ensureLeadingSlash(strings.TrimSpace(authConfig.AuthURL))
	if authPath == "/" {
		authPath = "/api/auth/verify"
	}
	verifyURL := fmt.Sprintf("http://127.0.0.1:%d%s", authConfig.AuthPort, authPath)

	ctx, cancel := context.WithTimeout(context.Background(), streamAuthTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, verifyURL, nil)
	if err != nil {
		return false, http.StatusBadGateway, "auth_error", err
	}

	req.Header.Set("User-Agent", "")
	req.Header.Set("X-Real-IP", clientIP)
	req.Header.Set("X-Forwarded-For", clientIP)
	req.Header.Set("X-Reauth-Protocol", "tcp")
	req.Header.Set("X-Reauth-Listen-Port", strconv.Itoa(rule.ListenPort))
	req.Header.Set("X-Reauth-Target", rule.Target)

	resp, err := m.authClient.Do(req)
	if err != nil {
		if isTimeoutErr(err) {
			return false, http.StatusGatewayTimeout, "timeout", err
		}
		return false, http.StatusBadGateway, "auth_error", err
	}
	defer resp.Body.Close()

	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxAuthBodyBytes))
	if readErr != nil {
		return false, http.StatusBadGateway, "auth_error", readErr
	}

	var payload authVerifyPayload
	if len(body) > 0 {
		if err := json.Unmarshal(body, &payload); err != nil {
			if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
				return false, http.StatusForbidden, "denied", nil
			}
			return false, http.StatusBadGateway, "invalid_response", err
		}
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 && payload.Success {
		return true, http.StatusOK, "passed", nil
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return false, http.StatusForbidden, "denied", nil
	}
	if resp.StatusCode >= 500 {
		return false, http.StatusBadGateway, "auth_error", fmt.Errorf("auth service returned %d", resp.StatusCode)
	}
	if !payload.Success {
		message := strings.TrimSpace(payload.Message)
		if message == "" {
			message = fmt.Sprintf("auth service denied access with status %d", resp.StatusCode)
		}
		return false, http.StatusForbidden, "denied", errors.New(message)
	}

	return false, http.StatusBadGateway, "auth_error", fmt.Errorf("unexpected auth response status %d", resp.StatusCode)
}

func relayBidirectional(client net.Conn, upstream net.Conn) (uint64, uint64, error) {
	results := make(chan relayResult, 2)

	go func() {
		bytes, err := copyStream(upstream, client)
		closeWrite(upstream)
		results <- relayResult{direction: "in", bytes: bytes, err: err}
	}()

	go func() {
		bytes, err := copyStream(client, upstream)
		closeWrite(client)
		results <- relayResult{direction: "out", bytes: bytes, err: err}
	}()

	var bytesIn uint64
	var bytesOut uint64
	var firstErr error

	for i := 0; i < 2; i++ {
		result := <-results
		if result.direction == "in" {
			bytesIn = result.bytes
		} else {
			bytesOut = result.bytes
		}
		if err := normalizeRelayError(result.err); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	return bytesIn, bytesOut, firstErr
}

func copyStream(dst net.Conn, src net.Conn) (uint64, error) {
	buffer := make([]byte, 32*1024)
	written, err := io.CopyBuffer(dst, src, buffer)
	if written < 0 {
		written = 0
	}
	return uint64(written), err
}

func closeWrite(conn net.Conn) {
	type closeWriter interface {
		CloseWrite() error
	}

	if conn == nil {
		return
	}
	if cw, ok := conn.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
}

func normalizeRelayError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return nil
	}

	errText := strings.ToLower(err.Error())
	if strings.Contains(errText, "use of closed network connection") ||
		strings.Contains(errText, "connection reset by peer") ||
		strings.Contains(errText, "broken pipe") {
		return nil
	}

	return err
}

func extractRemoteIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}

	host, _, err := net.SplitHostPort(addr.String())
	if err == nil {
		return strings.TrimSpace(host)
	}
	return strings.TrimSpace(addr.String())
}

func ensureLeadingSlash(path string) string {
	if path == "" {
		return "/"
	}
	if strings.HasPrefix(path, "/") {
		return path
	}
	return "/" + path
}

func isClosedConnErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "use of closed network connection")
}

func isTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
