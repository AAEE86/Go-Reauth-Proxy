package waf

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/corazawaf/coraza/v3/types"

	"go-reauth-proxy/pkg/models"
)

var traceFallbackCounter uint64

type Runtime struct {
	current         atomic.Value
	config          atomic.Value
	lastError       atomic.Value
	events          *EventStore
	defaultRulesDir string
}

func NewRuntime(cfg models.WAFConfig, runtimeDir string) *Runtime {
	defaultRulesDir := DefaultRulesDir(runtimeDir)
	rt := &Runtime{
		events:          NewEventStore(DefaultMaxEvents, DefaultEventTTL),
		defaultRulesDir: defaultRulesDir,
	}
	rt.config.Store(NormalizeConfig(cfg, defaultRulesDir))
	rt.lastError.Store("")
	return rt
}

func (rt *Runtime) Config() models.WAFConfig {
	if rt == nil {
		return NormalizeConfig(models.WAFConfig{}, DefaultRulesDir("."))
	}
	cfg, _ := rt.config.Load().(models.WAFConfig)
	return cfg
}

func (rt *Runtime) Status() Status {
	if rt == nil {
		return Status{}
	}
	cfg := rt.Config()
	status := Status{
		Enabled:       cfg.Enabled,
		Mode:          cfg.Mode,
		RulesDir:      cfg.RulesDir,
		PendingEvents: rt.events.Pending(),
	}
	if lastError, _ := rt.lastError.Load().(string); lastError != "" {
		status.LastError = lastError
	}
	if current := rt.compiled(); current != nil {
		status.Loaded = true
		status.BundleID = current.BundleID
		status.BundleHash = current.BundleHash
		status.LoadedAt = current.LoadedAt.Format(time.RFC3339Nano)
	}
	return status
}

func (rt *Runtime) SetConfig(cfg models.WAFConfig) (models.WAFConfig, error) {
	if rt == nil {
		return cfg, nil
	}
	cfg = NormalizeConfig(cfg, rt.defaultRulesDir)
	if !IsActive(cfg) {
		rt.current.Store((*CompiledRuntime)(nil))
		rt.config.Store(cfg)
		rt.lastError.Store("")
		return cfg, nil
	}
	current := rt.compiled()
	if current != nil {
		compiled, err := buildCompiledRuntime(cfg, rt.defaultRulesDir, "", "")
		if err != nil {
			rt.lastError.Store(err.Error())
			return cfg, err
		}
		rt.current.Store(compiled)
	}
	rt.config.Store(cfg)
	rt.lastError.Store("")
	return cfg, nil
}

func (rt *Runtime) Validate(cfg models.WAFConfig, bundleID string, bundlePath string) (ValidationResult, error) {
	if rt == nil {
		return ValidationResult{OK: false, Error: "WAF runtime is not initialized"}, fmt.Errorf("WAF runtime is not initialized")
	}
	compiled, err := buildCompiledRuntime(cfg, rt.defaultRulesDir, bundleID, bundlePath)
	if err != nil {
		result := ValidationResult{
			OK:         false,
			BundleID:   strings.TrimSpace(bundleID),
			BundlePath: strings.TrimSpace(bundlePath),
			Error:      err.Error(),
		}
		return result, err
	}
	return ValidationResult{
		OK:         true,
		BundleID:   compiled.BundleID,
		BundlePath: compiled.BundlePath,
		BundleHash: compiled.BundleHash,
	}, nil
}

func (rt *Runtime) Reload(cfg models.WAFConfig, bundleID string, bundlePath string) (Status, error) {
	if rt == nil {
		return Status{}, fmt.Errorf("WAF runtime is not initialized")
	}
	cfg = NormalizeConfig(cfg, rt.defaultRulesDir)
	if !IsActive(cfg) {
		rt.current.Store((*CompiledRuntime)(nil))
		rt.config.Store(cfg)
		rt.lastError.Store("")
		return rt.Status(), nil
	}
	compiled, err := buildCompiledRuntime(cfg, rt.defaultRulesDir, bundleID, bundlePath)
	if err != nil {
		rt.lastError.Store(err.Error())
		return rt.Status(), err
	}
	rt.current.Store(compiled)
	rt.config.Store(compiled.Config)
	rt.lastError.Store("")
	return rt.Status(), nil
}

func (rt *Runtime) Drain(limit int) DrainResult {
	if rt == nil || rt.events == nil {
		return DrainResult{Events: []Event{}}
	}
	return rt.events.Drain(limit)
}

func (rt *Runtime) Evaluate(r *http.Request, ctx EvaluateContext) Decision {
	decision := Decision{Allowed: true}
	if rt == nil || r == nil {
		return decision
	}
	cfg := rt.Config()
	decision.Enabled = IsActive(cfg)
	decision.Mode = cfg.Mode
	decision.DetectionOnly = cfg.Mode == ModeDetection
	if !decision.Enabled || rt.isExcluded(r) {
		return decision
	}
	compiled := rt.compiled()
	if compiled == nil || compiled.WAF == nil {
		return decision
	}

	tx := compiled.WAF.NewTransaction()
	defer func() {
		tx.ProcessLogging()
		_ = tx.Close()
	}()
	clientIP, clientPort := splitAddress(ctx.ClientIP, r.RemoteAddr)
	tx.ProcessConnection(clientIP, clientPort, "", 0)
	tx.ProcessURI(r.URL.RequestURI(), r.Method, r.Proto)
	if r.Host != "" {
		tx.AddRequestHeader("Host", r.Host)
		tx.SetServerName(r.Host)
	}
	for key, values := range r.Header {
		for _, value := range values {
			tx.AddRequestHeader(key, value)
		}
	}
	for _, te := range r.TransferEncoding {
		tx.AddRequestHeader("Transfer-Encoding", te)
	}
	addInternalHeader(tx, "X-Fn-Knock-Route-Type", ctx.RouteType)
	addInternalHeader(tx, "X-Fn-Knock-Route-Key", ctx.RouteKey)
	addInternalHeader(tx, "X-Fn-Knock-Upstream", ctx.Upstream)

	var interruption *types.Interruption
	if it := tx.ProcessRequestHeaders(); it != nil {
		interruption = it
	} else if tx.IsRequestBodyAccessible() && r.Body != nil && r.Body != http.NoBody {
		if it, err := readAndRestoreRequestBody(tx, r); err != nil {
			decision.Err = err
		} else if it != nil {
			interruption = it
		}
		if interruption == nil {
			if it, err := tx.ProcessRequestBody(); err != nil {
				decision.Err = err
			} else if it != nil {
				interruption = it
			}
		}
	} else if it, err := tx.ProcessRequestBody(); err != nil {
		decision.Err = err
	} else if it != nil {
		interruption = it
	}
	if interruption == nil && decision.DetectionOnly {
		interruption = detectionOnlyInterruption(tx)
	}

	rules := collectRuleMatches(tx.MatchedRules(), interruption)
	ruleIDs := uniqueRuleIDs(rules, interruption)
	if len(rules) == 0 && interruption == nil && decision.Err == nil {
		return decision
	}

	traceID := newTraceID()
	decision.TraceID = traceID
	decision.BundleID = compiled.BundleID

	action := "log"
	status := 0
	if interruption != nil {
		status = normalizeStatus(interruption.Status)
		if decision.DetectionOnly {
			action = "detect"
		} else {
			action = strings.TrimSpace(interruption.Action)
			if action == "" {
				action = "deny"
			}
			decision.Allowed = false
			decision.Status = status
		}
	} else if decision.DetectionOnly {
		action = "detect"
	}
	decision.Action = action
	decision.RuleIDs = ruleIDs

	event := buildEvent(r, ctx, compiled, traceID, cfg.Mode, action, status, ruleIDs, rules, interruption, decision.Err)
	rt.events.Add(event)
	decision.Event = &event
	return decision
}

func (rt *Runtime) compiled() *CompiledRuntime {
	if rt == nil {
		return nil
	}
	value := rt.current.Load()
	if value == nil {
		return nil
	}
	compiled, _ := value.(*CompiledRuntime)
	return compiled
}

func (rt *Runtime) isExcluded(r *http.Request) bool {
	cfg := rt.Config()
	host := normalizeHost(r.Host)
	for _, disabledHost := range cfg.DisabledHosts {
		if normalizeHost(disabledHost) == host {
			return true
		}
	}
	requestPath := filepath.ToSlash(filepath.Clean(r.URL.Path))
	if !strings.HasPrefix(requestPath, "/") {
		requestPath = "/" + requestPath
	}
	for _, prefix := range cfg.DisabledPathPrefixes {
		if prefix == "/" || requestPath == prefix || strings.HasPrefix(requestPath, strings.TrimRight(prefix, "/")+"/") {
			return true
		}
	}
	return false
}

type requestBodyReadCloser struct {
	io.Reader
	closer io.Closer
}

func (r requestBodyReadCloser) Close() error {
	if r.closer == nil {
		return nil
	}
	return r.closer.Close()
}

func readAndRestoreRequestBody(tx interface {
	ReadRequestBodyFrom(io.Reader) (*types.Interruption, int, error)
}, r *http.Request) (*types.Interruption, error) {
	originalBody := r.Body
	var buffered bytes.Buffer
	tee := io.TeeReader(originalBody, &buffered)
	it, _, err := tx.ReadRequestBodyFrom(tee)
	r.Body = requestBodyReadCloser{
		Reader: io.MultiReader(bytes.NewReader(buffered.Bytes()), originalBody),
		closer: originalBody,
	}
	if err != nil {
		return nil, fmt.Errorf("failed to append request body: %w", err)
	}
	return it, nil
}

func addInternalHeader(tx interface{ AddRequestHeader(string, string) }, key string, value string) {
	value = strings.TrimSpace(value)
	if value != "" {
		tx.AddRequestHeader(key, value)
	}
}

func detectionOnlyInterruption(tx any) *types.Interruption {
	withDetectionOnly, ok := tx.(interface {
		DetectionOnlyInterruption() *types.Interruption
	})
	if !ok {
		return nil
	}
	return withDetectionOnly.DetectionOnlyInterruption()
}

func buildEvent(r *http.Request, ctx EvaluateContext, compiled *CompiledRuntime, traceID string, mode string, action string, status int, ruleIDs []int, rules []RuleMatch, interruption *types.Interruption, evalErr error) Event {
	event := Event{
		TraceID:       traceID,
		TransactionID: traceID,
		Time:          time.Now().UTC().Format(time.RFC3339Nano),
		Mode:          mode,
		Action:        action,
		Status:        status,
		ClientIP:      ctx.ClientIP,
		RemoteAddr:    r.RemoteAddr,
		Method:        r.Method,
		Scheme:        ctx.Scheme,
		Host:          r.Host,
		Path:          r.URL.Path,
		Query:         redactRawQuery(r.URL.RawQuery),
		RequestURI:    redactRequestURI(r.URL),
		UserAgent:     r.UserAgent(),
		Referer:       r.Referer(),
		RouteType:     ctx.RouteType,
		RouteKey:      ctx.RouteKey,
		Upstream:      ctx.Upstream,
		BundleID:      compiled.BundleID,
		BundleHash:    compiled.BundleHash,
		RuleIDs:       ruleIDs,
		Rules:         rules,
	}
	if event.Scheme == "" {
		event.Scheme = "http"
		if r.TLS != nil {
			event.Scheme = "https"
		}
	}
	if interruption != nil {
		event.Interruption = &InterruptionInfo{
			RuleID: interruption.RuleID,
			Action: interruption.Action,
			Status: normalizeStatus(interruption.Status),
		}
	}
	if evalErr != nil {
		event.Error = evalErr.Error()
	}
	return event
}

func collectRuleMatches(matches []types.MatchedRule, interruption *types.Interruption) []RuleMatch {
	out := make([]RuleMatch, 0, len(matches))
	for _, match := range matches {
		if match == nil || match.Rule() == nil {
			continue
		}
		rule := match.Rule()
		if isInternalRule(rule) {
			continue
		}
		if !shouldRecordRuleMatch(match, interruption) {
			continue
		}
		out = append(out, RuleMatch{
			ID:               rule.ID(),
			Message:          truncate(match.Message(), 512),
			Data:             truncate(match.Data(), 512),
			Severity:         fmt.Sprint(rule.Severity()),
			Phase:            int(rule.Phase()),
			File:             rule.File(),
			Line:             rule.Line(),
			Tags:             append([]string{}, rule.Tags()...),
			Disruptive:       match.Disruptive(),
			MatchedVariables: collectMatchedVariables(match.MatchedDatas()),
		})
	}
	return out
}

func isInternalRule(rule types.RuleMetadata) bool {
	if rule == nil {
		return true
	}
	return rule.ID() == internalSetupRuleID ||
		strings.EqualFold(filepath.Base(rule.File()), initializationRuleFilename)
}

func shouldRecordRuleMatch(match types.MatchedRule, interruption *types.Interruption) bool {
	if match == nil || match.Rule() == nil {
		return false
	}
	if interruption != nil && match.Rule().ID() == interruption.RuleID {
		return true
	}
	if strings.TrimSpace(match.Message()) != "" || strings.TrimSpace(match.Data()) != "" {
		return true
	}
	for _, data := range match.MatchedDatas() {
		if data == nil {
			continue
		}
		if strings.TrimSpace(data.Message()) != "" || strings.TrimSpace(data.Data()) != "" {
			return true
		}
	}
	if withLog, ok := match.(interface{ Log() bool }); ok && withLog.Log() {
		return true
	}
	if withAudit, ok := match.(interface{ Audit() bool }); ok && withAudit.Audit() {
		return true
	}
	return false
}

func collectMatchedVariables(matches []types.MatchData) []MatchedVariable {
	out := make([]MatchedVariable, 0, len(matches))
	for _, match := range matches {
		if match == nil {
			continue
		}
		key := match.Key()
		value := match.Value()
		if isSensitiveName(key) || isSensitiveName(fmt.Sprint(match.Variable())) {
			value = "[redacted]"
		}
		out = append(out, MatchedVariable{
			Variable:     fmt.Sprint(match.Variable()),
			Key:          key,
			ValuePreview: truncate(value, 256),
		})
	}
	return out
}

func uniqueRuleIDs(rules []RuleMatch, interruption *types.Interruption) []int {
	seen := make(map[int]struct{}, len(rules)+1)
	out := make([]int, 0, len(rules)+1)
	for _, rule := range rules {
		if rule.ID <= 0 {
			continue
		}
		if _, ok := seen[rule.ID]; ok {
			continue
		}
		seen[rule.ID] = struct{}{}
		out = append(out, rule.ID)
	}
	if interruption != nil && interruption.RuleID > 0 {
		if _, ok := seen[interruption.RuleID]; !ok {
			out = append(out, interruption.RuleID)
		}
	}
	return out
}

func splitAddress(clientIP string, remoteAddr string) (string, int) {
	clientIP = strings.TrimSpace(clientIP)
	if clientIP != "" {
		return clientIP, 0
	}
	host, port, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return strings.TrimSpace(remoteAddr), 0
	}
	portNum, _ := strconv.Atoi(port)
	return host, portNum
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return ""
	}
	if strings.HasPrefix(host, "[") {
		if idx := strings.LastIndex(host, "]"); idx >= 0 {
			return host[:idx+1]
		}
	}
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		return strings.TrimSpace(strings.ToLower(parsedHost))
	}
	return host
}

func normalizeStatus(status int) int {
	if status < 400 || status > 599 {
		return http.StatusForbidden
	}
	return status
}

func newTraceID() string {
	var uuid [16]byte
	if _, err := rand.Read(uuid[:]); err != nil {
		binary.BigEndian.PutUint64(uuid[0:8], uint64(time.Now().UnixNano()))
		binary.BigEndian.PutUint64(uuid[8:16], atomic.AddUint64(&traceFallbackCounter, 1))
	}
	uuid[6] = (uuid[6] & 0x0f) | 0x40
	uuid[8] = (uuid[8] & 0x3f) | 0x80
	return fmt.Sprintf("waf_%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16])
}

func truncate(value string, limit int) string {
	if limit <= 0 || len(value) <= limit {
		return value
	}
	return value[:limit]
}
