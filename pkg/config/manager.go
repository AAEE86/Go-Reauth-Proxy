package config

import (
	"encoding/json"
	"go-reauth-proxy/pkg/gatewaylog"
	"go-reauth-proxy/pkg/models"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	defaultAuthCacheTTLSeconds             = 1
	defaultAuthCacheUnauthorizedTTLSeconds = 1
	defaultReverseProxyThrottleRPS         = 100
	defaultReverseProxyThrottleBurst       = 200
	defaultReverseProxyThrottleBlockSecs   = 30
)

type AppConfig struct {
	Rules                []models.Rule                     `json:"rules"`
	HostRules            []models.HostRule                 `json:"host_rules,omitempty"`
	StreamRules          []models.StreamRule               `json:"stream_rules,omitempty"`
	DefaultRoute         string                            `json:"default_route"`
	AuthConfig           models.AuthConfig                 `json:"auth_config"`
	AdminPort            int                               `json:"admin_port,omitempty"`
	ProxyProtocolForce   bool                              `json:"proxy_protocol_force,omitempty"`
	ReverseProxyThrottle models.ReverseProxyThrottleConfig `json:"reverse_proxy_throttle,omitempty"`
	Visibility           models.GatewayVisibilityConfig    `json:"visibility,omitempty"`
	ForwardedHeaders     models.ForwardedHeadersConfig     `json:"forwarded_headers,omitempty"`
	PreserveHost         models.PreserveHostConfig         `json:"preserve_host,omitempty"`
	IptablesChainName    string                            `json:"iptables_chain_name,omitempty"`
	Logging              models.LoggingConfig              `json:"logging,omitempty"`
	SSL                  models.SSLConfig                  `json:"ssl,omitempty"`
	SSLCert              string                            `json:"ssl_cert,omitempty"`
	SSLKey               string                            `json:"ssl_key,omitempty"`
}

type Manager struct {
	filePath string
	mu       sync.RWMutex
}

func NewManager(filePath string) *Manager {
	return &Manager{
		filePath: filePath,
	}
}

func defaultConfig() *AppConfig {
	return &AppConfig{
		Rules:        []models.Rule{},
		HostRules:    []models.HostRule{},
		StreamRules:  []models.StreamRule{},
		DefaultRoute: "/__select__",
		AuthConfig: models.AuthConfig{
			AuthPort:          7997,
			AuthURL:           "/api/auth/verify",
			LoginURL:          "/login",
			LogoutURL:         "/api/auth/logout",
			PreflightURL:      "/api/auth/preflight",
			AuthCacheTTL:      defaultAuthCacheTTLSeconds,
			AuthCacheFailTTL:  defaultAuthCacheUnauthorizedTTLSeconds,
			AliyunESAEnabled:  false,
			PublicAuthBaseURL: "",
			PublicHTTPPort:    0,
			PublicHTTPSPort:   0,
			AuthHost:          "",
		},
		AdminPort:          7996,
		ProxyProtocolForce: false,
		ReverseProxyThrottle: models.ReverseProxyThrottleConfig{
			Enabled:           true,
			RequestsPerSecond: defaultReverseProxyThrottleRPS,
			Burst:             defaultReverseProxyThrottleBurst,
			BlockSeconds:      defaultReverseProxyThrottleBlockSecs,
		},
		Visibility: models.GatewayVisibilityConfig{
			Enabled:   false,
			CIDRs:     []string{},
			UpdatedAt: "",
		},
		ForwardedHeaders: models.ForwardedHeadersConfig{
			Enabled:     false,
			OmitTargets: []string{},
			UpdatedAt:   "",
		},
		PreserveHost: models.PreserveHostConfig{
			Enabled:     true,
			OmitTargets: []string{},
			UpdatedAt:   "",
		},
		Logging: models.LoggingConfig{
			Enabled: false,
			MaxDays: gatewaylog.DefaultMaxDays,
		},
		SSL: models.SSLConfig{
			DeploymentMode: models.SSLDeploymentModeSingleActive,
			Certificates:   []models.SSLDeployedCertificate{},
		},
	}
}

func applyDefaults(cfg *AppConfig) {
	if cfg.Rules == nil {
		cfg.Rules = []models.Rule{}
	}
	if cfg.HostRules == nil {
		cfg.HostRules = []models.HostRule{}
	}
	if cfg.StreamRules == nil {
		cfg.StreamRules = []models.StreamRule{}
	}
	if cfg.SSL.Certificates == nil {
		cfg.SSL.Certificates = []models.SSLDeployedCertificate{}
	}
	if cfg.SSL.DeploymentMode != models.SSLDeploymentModeMultiSNI {
		cfg.SSL.DeploymentMode = models.SSLDeploymentModeSingleActive
	}
	if len(cfg.SSL.Certificates) == 0 {
		legacyCert := strings.TrimSpace(cfg.SSLCert)
		legacyKey := strings.TrimSpace(cfg.SSLKey)
		if legacyCert != "" && legacyKey != "" {
			cfg.SSL = models.SSLConfig{
				DeploymentMode: models.SSLDeploymentModeSingleActive,
				Certificates: []models.SSLDeployedCertificate{
					{
						ID:        "legacy-default",
						Label:     "Legacy SSL",
						Cert:      legacyCert,
						Key:       legacyKey,
						IsDefault: true,
					},
				},
			}
		}
	}

	if cfg.DefaultRoute == "" {
		cfg.DefaultRoute = "/__select__"
	}
	if cfg.AuthConfig.AuthPort <= 0 {
		cfg.AuthConfig.AuthPort = 7997
	}
	if cfg.AuthConfig.AuthURL == "" {
		cfg.AuthConfig.AuthURL = "/api/auth/verify"
	}
	if cfg.AuthConfig.LoginURL == "" {
		cfg.AuthConfig.LoginURL = "/login"
	}
	if cfg.AuthConfig.LogoutURL == "" {
		cfg.AuthConfig.LogoutURL = "/api/auth/logout"
	}
	if cfg.AuthConfig.PreflightURL == "" {
		cfg.AuthConfig.PreflightURL = "/api/auth/preflight"
	}
	if cfg.AuthConfig.AuthCacheTTL < 0 {
		cfg.AuthConfig.AuthCacheTTL = 0
	}
	if cfg.AuthConfig.AuthCacheFailTTL < 0 {
		cfg.AuthConfig.AuthCacheFailTTL = 0
	}
	if cfg.AuthConfig.PublicAuthBaseURL == "" {
		cfg.AuthConfig.PublicAuthBaseURL = ""
	}
	if cfg.AuthConfig.PublicHTTPPort < 0 {
		cfg.AuthConfig.PublicHTTPPort = 0
	}
	if cfg.AuthConfig.PublicHTTPSPort < 0 {
		cfg.AuthConfig.PublicHTTPSPort = 0
	}
	if cfg.AuthConfig.AuthHost == "" {
		cfg.AuthConfig.AuthHost = ""
	}

	if cfg.AdminPort <= 0 {
		cfg.AdminPort = 7996
	}
	if cfg.ReverseProxyThrottle.Enabled {
		if cfg.ReverseProxyThrottle.RequestsPerSecond <= 0 {
			cfg.ReverseProxyThrottle.RequestsPerSecond = defaultReverseProxyThrottleRPS
		}
		if cfg.ReverseProxyThrottle.Burst <= 0 {
			cfg.ReverseProxyThrottle.Burst = defaultReverseProxyThrottleBurst
		}
		if cfg.ReverseProxyThrottle.BlockSeconds <= 0 {
			cfg.ReverseProxyThrottle.BlockSeconds = defaultReverseProxyThrottleBlockSecs
		}
	}
	if cfg.Visibility.CIDRs == nil {
		cfg.Visibility.CIDRs = []string{}
	}
	if cfg.Visibility.UpdatedAt == "" {
		cfg.Visibility.UpdatedAt = ""
	}
	if cfg.ForwardedHeaders.OmitTargets == nil {
		cfg.ForwardedHeaders.OmitTargets = []string{}
	}
	if cfg.ForwardedHeaders.UpdatedAt == "" {
		cfg.ForwardedHeaders.UpdatedAt = ""
	}
	if cfg.PreserveHost.OmitTargets == nil {
		cfg.PreserveHost.OmitTargets = []string{}
	}
	if cfg.PreserveHost.UpdatedAt == "" {
		cfg.PreserveHost.UpdatedAt = ""
	}
	if cfg.Logging.MaxDays <= 0 {
		cfg.Logging.MaxDays = gatewaylog.DefaultMaxDays
	}
}

func detectAuthCacheFieldPresence(data []byte) (hasAuthCacheTTL bool, hasAuthCacheFailTTL bool) {
	var raw struct {
		AuthConfig map[string]json.RawMessage `json:"auth_config"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return false, false
	}
	if raw.AuthConfig == nil {
		return false, false
	}

	_, hasAuthCacheTTL = raw.AuthConfig["auth_cache_ttl_seconds"]
	_, hasAuthCacheFailTTL = raw.AuthConfig["auth_cache_unauthorized_ttl_seconds"]
	return hasAuthCacheTTL, hasAuthCacheFailTTL
}

func detectReverseProxyThrottleFieldPresence(data []byte) bool {
	var raw struct {
		ReverseProxyThrottle json.RawMessage `json:"reverse_proxy_throttle"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return false
	}
	return len(raw.ReverseProxyThrottle) > 0
}

func applyMissingAuthCacheDefaults(cfg *AppConfig, hasAuthCacheTTL bool, hasAuthCacheFailTTL bool) bool {
	changed := false

	if !hasAuthCacheTTL && cfg.AuthConfig.AuthCacheTTL == 0 {
		cfg.AuthConfig.AuthCacheTTL = defaultAuthCacheTTLSeconds
		changed = true
	}
	if !hasAuthCacheFailTTL && cfg.AuthConfig.AuthCacheFailTTL == 0 {
		cfg.AuthConfig.AuthCacheFailTTL = defaultAuthCacheUnauthorizedTTLSeconds
		changed = true
	}

	return changed
}

func applyMissingReverseProxyThrottleDefaults(cfg *AppConfig, hasReverseProxyThrottle bool) bool {
	if hasReverseProxyThrottle {
		return false
	}

	cfg.ReverseProxyThrottle = models.ReverseProxyThrottleConfig{
		Enabled:           true,
		RequestsPerSecond: defaultReverseProxyThrottleRPS,
		Burst:             defaultReverseProxyThrottleBurst,
		BlockSeconds:      defaultReverseProxyThrottleBlockSecs,
	}
	return true
}

func (m *Manager) loadUnlocked() (*AppConfig, bool, bool, error) {
	data, err := os.ReadFile(m.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return defaultConfig(), false, true, nil
		}
		return nil, false, false, err
	}

	var cfg AppConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, true, false, err
	}
	applyDefaults(&cfg)
	hasAuthCacheTTL, hasAuthCacheFailTTL := detectAuthCacheFieldPresence(data)
	hasReverseProxyThrottle := detectReverseProxyThrottleFieldPresence(data)
	migrated := applyMissingAuthCacheDefaults(&cfg, hasAuthCacheTTL, hasAuthCacheFailTTL)
	if applyMissingReverseProxyThrottleDefaults(&cfg, hasReverseProxyThrottle) {
		migrated = true
	}
	return &cfg, true, migrated, nil
}

func (m *Manager) saveUnlocked(cfg *AppConfig) error {
	dir := filepath.Dir(m.filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(m.filePath, data, 0644)
}

func (m *Manager) Load() (*AppConfig, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	cfg, existed, migrated, err := m.loadUnlocked()
	if err != nil {
		return nil, err
	}
	if !existed || migrated {
		if err := m.saveUnlocked(cfg); err != nil {
			return nil, err
		}
	}
	return cfg, nil
}

func (m *Manager) Save(config *AppConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	applyDefaults(config)
	return m.saveUnlocked(config)
}

func (m *Manager) Update(updateFn func(*AppConfig) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cfg, _, _, err := m.loadUnlocked()
	if err != nil {
		return err
	}

	if err := updateFn(cfg); err != nil {
		return err
	}

	applyDefaults(cfg)
	return m.saveUnlocked(cfg)
}
