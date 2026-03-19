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

type AppConfig struct {
	Rules              []models.Rule        `json:"rules"`
	HostRules          []models.HostRule    `json:"host_rules,omitempty"`
	DefaultRoute       string               `json:"default_route"`
	AuthConfig         models.AuthConfig    `json:"auth_config"`
	AdminPort          int                  `json:"admin_port,omitempty"`
	ProxyProtocolForce bool                 `json:"proxy_protocol_force,omitempty"`
	IptablesChainName  string               `json:"iptables_chain_name,omitempty"`
	Logging            models.LoggingConfig `json:"logging,omitempty"`
	SSL                models.SSLConfig     `json:"ssl,omitempty"`
	SSLCert            string               `json:"ssl_cert,omitempty"`
	SSLKey             string               `json:"ssl_key,omitempty"`
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
		DefaultRoute: "/__select__",
		AuthConfig: models.AuthConfig{
			AuthPort:          7997,
			AuthURL:           "/api/auth/verify",
			LoginURL:          "/login",
			LogoutURL:         "/api/auth/logout",
			PreflightURL:      "/api/auth/preflight",
			PublicAuthBaseURL: "",
			AuthHost:          "",
		},
		AdminPort:          7996,
		ProxyProtocolForce: false,
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
	if cfg.AuthConfig.PublicAuthBaseURL == "" {
		cfg.AuthConfig.PublicAuthBaseURL = ""
	}
	if cfg.AuthConfig.AuthHost == "" {
		cfg.AuthConfig.AuthHost = ""
	}

	if cfg.AdminPort <= 0 {
		cfg.AdminPort = 7996
	}
	if cfg.Logging.MaxDays <= 0 {
		cfg.Logging.MaxDays = gatewaylog.DefaultMaxDays
	}
}

func (m *Manager) loadUnlocked() (*AppConfig, bool, error) {
	data, err := os.ReadFile(m.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return defaultConfig(), false, nil
		}
		return nil, false, err
	}

	var cfg AppConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, true, err
	}
	applyDefaults(&cfg)
	return &cfg, true, nil
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

	cfg, existed, err := m.loadUnlocked()
	if err != nil {
		return nil, err
	}
	if !existed {
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

	cfg, _, err := m.loadUnlocked()
	if err != nil {
		return err
	}

	if err := updateFn(cfg); err != nil {
		return err
	}

	applyDefaults(cfg)
	return m.saveUnlocked(cfg)
}
