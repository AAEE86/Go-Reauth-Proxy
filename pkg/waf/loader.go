package waf

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/corazawaf/coraza/v3"

	"go-reauth-proxy/pkg/models"
)

const (
	localRuleSetID             = "local"
	internalSetupRuleID        = 1000000
	initializationRuleFilename = "REQUEST-901-INITIALIZATION.conf"
	crsSetupVersion            = 4250
	rulesStateFilename         = "rules-state.json"
	systemRulesDirName         = "system"
	customRulesDirName         = "custom"
)

var (
	defaultDisabledSystemRuleFilenames = map[string]struct{}{
		"REQUEST-920-PROTOCOL-ENFORCEMENT.conf":    {},
		"REQUEST-930-APPLICATION-ATTACK-LFI.conf":  {},
		"REQUEST-932-APPLICATION-ATTACK-RCE.conf":  {},
		"REQUEST-941-APPLICATION-ATTACK-XSS.conf":  {},
		"REQUEST-942-APPLICATION-ATTACK-SQLI.conf": {},
	}
	ruleIDActionRe            = regexp.MustCompile(`(?i)\bid\s*:\s*(\d+)\b`)
	secRuleUpdateTargetByIDRe = regexp.MustCompile(`(?i)^SecRuleUpdateTargetById\s+(\d+)\b`)
)

type CompiledRuntime struct {
	Config     models.WAFConfig
	BundleID   string
	BundlePath string
	BundleHash string
	LoadedAt   time.Time
	WAF        coraza.WAF
}

type rulesState struct {
	SystemEnabled map[string]bool `json:"system_enabled"`
	CustomEnabled map[string]bool `json:"custom_enabled"`
}

func buildCompiledRuntime(cfg models.WAFConfig, defaultRulesDir string, bundleID string, bundlePath string) (*CompiledRuntime, error) {
	cfg = NormalizeConfig(cfg, defaultRulesDir)
	rulesDir, err := resolveRulesDir(cfg.RulesDir)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(bundlePath) != "" {
		return nil, fmt.Errorf("bundle_path is no longer supported; WAF loads rules_dir directly")
	}
	if err := ensureRulesDirectories(rulesDir); err != nil {
		return nil, err
	}
	state, err := readRulesState(rulesDir)
	if err != nil {
		return nil, err
	}
	targets := loadOrder(rulesDir, state)
	ruleSetHash, err := hashRuleSet(rulesDir, targets)
	if err != nil {
		return nil, err
	}
	definedRuleIDs, err := collectDefinedRuleIDs(targets)
	if err != nil {
		return nil, err
	}

	wafConfig := coraza.NewWAFConfig().
		WithRootFS(updateTargetFilteringFS{
			root:           os.DirFS(rulesDir),
			definedRuleIDs: definedRuleIDs,
		}).
		WithRequestBodyLimit(cfg.RequestBodyLimitBytes).
		WithRequestBodyInMemoryLimit(cfg.RequestBodyInMemoryLimitBytes).
		WithDirectives(dynamicDirectives(cfg))
	if cfg.RequestBodyAccess {
		wafConfig = wafConfig.WithRequestBodyAccess()
	}
	if cfg.ResponseBodyAccess {
		wafConfig = wafConfig.WithResponseBodyAccess()
	}

	for _, file := range targets {
		if file.path == "" {
			continue
		}
		rel, err := filepath.Rel(rulesDir, file.path)
		if err != nil {
			return nil, err
		}
		wafConfig = wafConfig.WithDirectivesFromFile(filepath.ToSlash(rel))
	}

	compiledWAF, err := coraza.NewWAF(wafConfig)
	if err != nil {
		return nil, err
	}
	cfg.ActiveBundleID = localRuleSetID
	return &CompiledRuntime{
		Config:     cfg,
		BundleID:   localRuleSetID,
		BundlePath: rulesDir,
		BundleHash: ruleSetHash,
		LoadedAt:   time.Now().UTC(),
		WAF:        compiledWAF,
	}, nil
}

type loadKind int

const (
	loadFile loadKind = iota
)

type loadTarget struct {
	kind loadKind
	path string
}

func loadOrder(rulesDir string, state rulesState) []loadTarget {
	targets := globEnabledTargets(filepath.Join(rulesDir, systemRulesDirName), state.SystemEnabled, isSystemRuleEnabledByDefault)
	targets = append(targets, globEnabledTargets(filepath.Join(rulesDir, customRulesDirName), state.CustomEnabled, func(string) bool {
		return true
	})...)
	return targets
}

func globEnabledTargets(dir string, enabled map[string]bool, enabledByDefault func(string) bool) []loadTarget {
	matches, _ := filepath.Glob(filepath.Join(dir, "*.conf"))
	sort.Strings(matches)
	targets := make([]loadTarget, 0, len(matches))
	for _, match := range matches {
		filename := filepath.Base(match)
		if filename == initializationRuleFilename {
			targets = append(targets, loadTarget{kind: loadFile, path: match})
			continue
		}
		if value, ok := enabled[filename]; ok {
			if !value {
				continue
			}
		} else if enabledByDefault != nil && !enabledByDefault(filename) {
			continue
		}
		targets = append(targets, loadTarget{kind: loadFile, path: match})
	}
	return targets
}

func isSystemRuleEnabledByDefault(filename string) bool {
	if filename == initializationRuleFilename {
		return true
	}
	_, disabled := defaultDisabledSystemRuleFilenames[filename]
	return !disabled
}

func dynamicDirectives(cfg models.WAFConfig) string {
	engine := "DetectionOnly"
	switch cfg.Mode {
	case ModeBlocking:
		engine = "On"
	case ModeOff:
		engine = "Off"
	}
	requestBodyAccess := "Off"
	if cfg.RequestBodyAccess {
		requestBodyAccess = "On"
	}
	responseBodyAccess := "Off"
	if cfg.ResponseBodyAccess {
		responseBodyAccess = "On"
	}

	return fmt.Sprintf(`
SecRuleEngine %s
SecRequestBodyAccess %s
SecRequestBodyLimit %d
SecRequestBodyInMemoryLimit %d
SecRequestBodyLimitAction ProcessPartial
SecResponseBodyAccess %s
SecAction "id:%d,phase:1,pass,nolog,t:none,setvar:tx.crs_setup_version=%d,setvar:tx.blocking_paranoia_level=%d,setvar:tx.detection_paranoia_level=%d,setvar:tx.paranoia_level=%d,setvar:tx.executing_paranoia_level=%d,setvar:tx.inbound_anomaly_score_threshold=%d,setvar:tx.outbound_anomaly_score_threshold=%d"
`,
		engine,
		requestBodyAccess,
		cfg.RequestBodyLimitBytes,
		cfg.RequestBodyInMemoryLimitBytes,
		responseBodyAccess,
		internalSetupRuleID,
		crsSetupVersion,
		cfg.ParanoiaLevel,
		cfg.ExecutingParanoiaLevel,
		cfg.ParanoiaLevel,
		cfg.ExecutingParanoiaLevel,
		cfg.InboundAnomalyThreshold,
		cfg.OutboundAnomalyThreshold,
	)
}

func resolveRulesDir(rulesDir string) (string, error) {
	rulesDir = strings.TrimSpace(rulesDir)
	if rulesDir == "" {
		return "", fmt.Errorf("rules_dir is required")
	}
	return filepath.Abs(filepath.Clean(rulesDir))
}

func ensureRulesDirectories(root string) error {
	if err := os.MkdirAll(filepath.Join(root, systemRulesDirName), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(root, customRulesDirName), 0o755); err != nil {
		return err
	}
	return requireDirectory(root)
}

func ensureWithin(root string, target string) error {
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return err
	}
	if rel == "." {
		return nil
	}
	if strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || rel == ".." {
		return fmt.Errorf("path escapes rules_dir")
	}
	return nil
}

func requireDirectory(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", path)
	}
	return nil
}

func readRulesState(rulesDir string) (rulesState, error) {
	state := rulesState{
		SystemEnabled: map[string]bool{},
		CustomEnabled: map[string]bool{},
	}
	raw, err := os.ReadFile(filepath.Join(rulesDir, rulesStateFilename))
	if err != nil {
		if os.IsNotExist(err) {
			return state, nil
		}
		return state, err
	}
	if err := json.Unmarshal(raw, &state); err != nil {
		return state, err
	}
	if state.SystemEnabled == nil {
		state.SystemEnabled = map[string]bool{}
	}
	if state.CustomEnabled == nil {
		state.CustomEnabled = map[string]bool{}
	}
	return state, nil
}

func collectDefinedRuleIDs(targets []loadTarget) (map[int]struct{}, error) {
	ids := map[int]struct{}{}
	for _, target := range targets {
		if target.path == "" || !strings.EqualFold(filepath.Ext(target.path), ".conf") {
			continue
		}
		raw, err := os.ReadFile(target.path)
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			for _, match := range ruleIDActionRe.FindAllStringSubmatch(line, -1) {
				id, err := strconv.Atoi(match[1])
				if err == nil {
					ids[id] = struct{}{}
				}
			}
		}
	}
	return ids, nil
}

type updateTargetFilteringFS struct {
	root           fs.FS
	definedRuleIDs map[int]struct{}
}

func (f updateTargetFilteringFS) Open(name string) (fs.File, error) {
	if !strings.EqualFold(filepath.Ext(name), ".conf") {
		return f.root.Open(name)
	}

	file, err := f.root.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	raw, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}

	filtered, changed := filterMissingUpdateTargetDirectives(raw, f.definedRuleIDs)
	if !changed {
		return f.root.Open(name)
	}
	return &filteredRuleFile{
		Reader: bytes.NewReader(filtered),
		info: filteredRuleFileInfo{
			name:    info.Name(),
			size:    int64(len(filtered)),
			mode:    info.Mode(),
			modTime: info.ModTime(),
			sys:     info.Sys(),
		},
	}, nil
}

func filterMissingUpdateTargetDirectives(raw []byte, definedRuleIDs map[int]struct{}) ([]byte, bool) {
	var out strings.Builder
	changed := false
	for _, line := range strings.SplitAfter(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			out.WriteString(line)
			continue
		}
		match := secRuleUpdateTargetByIDRe.FindStringSubmatch(trimmed)
		if len(match) == 2 {
			id, err := strconv.Atoi(match[1])
			if err == nil {
				if _, ok := definedRuleIDs[id]; !ok {
					changed = true
					out.WriteString("# fn-knock skipped SecRuleUpdateTargetById ")
					out.WriteString(match[1])
					out.WriteString(" because the target rule is not enabled")
					if strings.HasSuffix(line, "\n") {
						out.WriteString("\n")
					}
					continue
				}
			}
		}
		out.WriteString(line)
	}
	return []byte(out.String()), changed
}

type filteredRuleFile struct {
	*bytes.Reader
	info filteredRuleFileInfo
}

func (f *filteredRuleFile) Stat() (fs.FileInfo, error) {
	return f.info, nil
}

func (f *filteredRuleFile) Close() error {
	return nil
}

type filteredRuleFileInfo struct {
	name    string
	size    int64
	mode    fs.FileMode
	modTime time.Time
	sys     any
}

func (i filteredRuleFileInfo) Name() string {
	return i.name
}

func (i filteredRuleFileInfo) Size() int64 {
	return i.size
}

func (i filteredRuleFileInfo) Mode() fs.FileMode {
	return i.mode
}

func (i filteredRuleFileInfo) ModTime() time.Time {
	return i.modTime
}

func (i filteredRuleFileInfo) IsDir() bool {
	return false
}

func (i filteredRuleFileInfo) Sys() any {
	return i.sys
}

func hashRuleSet(rulesDir string, targets []loadTarget) (string, error) {
	h := sha256.New()
	for _, target := range targets {
		if err := ensureWithin(rulesDir, target.path); err != nil {
			return "", err
		}
		rel, err := filepath.Rel(rulesDir, target.path)
		if err != nil {
			return "", err
		}
		rel = filepath.ToSlash(rel)
		_, _ = h.Write([]byte(rel))
		_, _ = h.Write([]byte{0})
		f, err := os.Open(target.path)
		if err != nil {
			return "", err
		}
		if _, err := io.Copy(h, f); err != nil {
			_ = f.Close()
			return "", err
		}
		if err := f.Close(); err != nil {
			return "", err
		}
		_, _ = h.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}
