package models

type Rule struct {
	Path        string `json:"path" example:"/api"`                    // Path prefix to match (e.g., "/api")
	Target      string `json:"target" example:"http://localhost:8080"` // Target URL (e.g., "http://localhost:7996")
	UseAuth     bool   `json:"use_auth" example:"false"`               // If true, invokes global authentication check before proxying.
	StripPath   bool   `json:"strip_path" example:"true"`              // If true, strips the Path prefix from the request before forwarding.
	RewriteHTML bool   `json:"rewrite_html" example:"true"`            // If true, rewrites absolute paths in HTML response to include Path prefix.
	UseRootMode bool   `json:"use_root_mode" example:"false"`          // If true, sets cookie and redirects matched path to /.
}

type HostRule struct {
	Host            string          `json:"host" example:"redis.example.com"`
	Target          string          `json:"target" example:"http://127.0.0.1:5173"`
	UseAuth         bool            `json:"use_auth" example:"true"`
	AccessMode      string          `json:"access_mode,omitempty" example:"login_first"`
	SuppressToolbar bool            `json:"suppress_toolbar,omitempty" example:"false"`
	PreserveHost    bool            `json:"preserve_host,omitempty" example:"true"`
	Title           string          `json:"title,omitempty" example:"Redis"`
	BasicAuth       BasicAuthConfig `json:"basic_auth,omitempty"`
	Locations       []HostLocation  `json:"locations,omitempty"`
}

const (
	HostLocationMatchExact  = "exact"
	HostLocationMatchPrefix = "prefix"

	HostLocationActionProxy    = "proxy"
	HostLocationActionResponse = "response"
)

type HostLocation struct {
	Path        string               `json:"path" example:"/api"`
	Match       string               `json:"match,omitempty" example:"prefix"`
	Action      string               `json:"action,omitempty" example:"proxy"`
	Target      string               `json:"target,omitempty" example:"http://127.0.0.1:8080"`
	StripPath   bool                 `json:"strip_path" example:"true"`
	RewriteHTML bool                 `json:"rewrite_html" example:"true"`
	Response    HostLocationResponse `json:"response,omitempty"`
}

type HostLocationResponse struct {
	Status      int               `json:"status,omitempty" example:"200"`
	ContentType string            `json:"content_type,omitempty" example:"text/plain; charset=utf-8"`
	Headers     map[string]string `json:"headers,omitempty"`
	Body        string            `json:"body,omitempty" example:"ok"`
}

type BasicAuthConfig struct {
	Enabled  bool   `json:"enabled" example:"true"`
	Username string `json:"username" example:"admin"`
	Password string `json:"password" example:"password"`
}

const (
	StreamProtocolTCP = "tcp"
	StreamProtocolUDP = "udp"
)

type StreamRule struct {
	Protocol   string `json:"protocol" example:"tcp"`
	ListenPort int    `json:"listen_port" example:"3306"`
	Target     string `json:"target" example:"127.0.0.1:3306"`
	UseAuth    bool   `json:"use_auth" example:"true"`
}

type AuthConfig struct {
	AuthPort              int    `json:"auth_port" example:"3000"`                                  // Local Auth Service Port
	AuthURL               string `json:"auth_url" example:"/api/auth/verify"`                       // Relative Verify URL (default /api/auth/verify)
	LoginURL              string `json:"login_url" example:"/login"`                                // Relative Login URL (default /login)
	LogoutURL             string `json:"logout_url" example:"/api/auth/logout"`                     // Relative Logout URL (default /api/auth/logout)
	PreflightURL          string `json:"preflight_url" example:"/api/auth/preflight"`               // Relative Preflight URL (default /api/auth/preflight)
	AuthCacheTTL          int    `json:"auth_cache_ttl_seconds,omitempty" example:"1"`              // Successful auth-result cache TTL in seconds. 0 disables the cache.
	AuthCacheFailTTL      int    `json:"auth_cache_unauthorized_ttl_seconds,omitempty" example:"1"` // Unauthorized auth-result cache TTL in seconds. 0 disables the cache.
	EdgeClientIPEnabled   bool   `json:"edge_client_ip_enabled,omitempty" example:"false"`          // Master switch for edge vendor client IP/header handling.
	AliyunESAEnabled      bool   `json:"aliyun_esa_enabled,omitempty" example:"false"`              // Enables Alibaba Cloud ESA client IP/header handling.
	TencentEdgeOneEnabled bool   `json:"tencent_edgeone_enabled,omitempty" example:"false"`         // Enables Tencent EdgeOne client IP/header handling.
	PublicAuthBaseURL     string `json:"public_auth_base_url,omitempty" example:"https://auth.example.com"`
	PublicHTTPPort        int    `json:"public_http_port,omitempty" example:"80"`
	PublicHTTPSPort       int    `json:"public_https_port,omitempty" example:"443"`
	AuthHost              string `json:"auth_host,omitempty" example:"auth.example.com"`
	TrustForwardedProto   bool   `json:"trust_forwarded_proto,omitempty" example:"false"`
}

func (c *AuthConfig) NormalizeEdgeClientIPSelection() bool {
	if c == nil {
		return false
	}

	changed := false
	if !c.EdgeClientIPEnabled {
		if c.AliyunESAEnabled {
			c.AliyunESAEnabled = false
			changed = true
		}
		if c.TencentEdgeOneEnabled {
			c.TencentEdgeOneEnabled = false
			changed = true
		}
		return changed
	}

	// Keep vendor selection mutually exclusive. When both are set, Tencent wins.
	if c.TencentEdgeOneEnabled && c.AliyunESAEnabled {
		c.AliyunESAEnabled = false
		changed = true
	}

	return changed
}

func (c AuthConfig) EdgeClientIPActive() bool {
	return c.EdgeClientIPEnabled && (c.AliyunESAEnabled || c.TencentEdgeOneEnabled)
}

func (c AuthConfig) AliyunESAActive() bool {
	return c.EdgeClientIPEnabled && c.AliyunESAEnabled && !c.TencentEdgeOneEnabled
}

func (c AuthConfig) TencentEdgeOneActive() bool {
	return c.EdgeClientIPEnabled && c.TencentEdgeOneEnabled
}

type LoggingConfig struct {
	Enabled bool `json:"enabled"`
	MaxDays int  `json:"max_days,omitempty"`
}

type WAFConfig struct {
	Enabled                       bool     `json:"enabled,omitempty"`
	Mode                          string   `json:"mode,omitempty"`
	RulesDir                      string   `json:"rules_dir,omitempty"`
	ActiveBundleID                string   `json:"active_bundle_id,omitempty"`
	ParanoiaLevel                 int      `json:"paranoia_level,omitempty"`
	ExecutingParanoiaLevel        int      `json:"executing_paranoia_level,omitempty"`
	InboundAnomalyThreshold       int      `json:"inbound_anomaly_threshold,omitempty"`
	OutboundAnomalyThreshold      int      `json:"outbound_anomaly_threshold,omitempty"`
	RequestBodyAccess             bool     `json:"request_body_access,omitempty"`
	RequestBodyLimitBytes         int      `json:"request_body_limit_bytes,omitempty"`
	RequestBodyInMemoryLimitBytes int      `json:"request_body_in_memory_limit_bytes,omitempty"`
	ResponseBodyAccess            bool     `json:"response_body_access,omitempty"`
	DisabledHosts                 []string `json:"disabled_hosts,omitempty"`
	DisabledPathPrefixes          []string `json:"disabled_path_prefixes,omitempty"`
	UpdatedAt                     string   `json:"updated_at,omitempty"`
}

type ReverseProxyThrottleConfig struct {
	Enabled           bool `json:"enabled,omitempty"`
	RequestsPerSecond int  `json:"requests_per_second,omitempty" example:"100"`
	Burst             int  `json:"burst,omitempty" example:"200"`
	BlockSeconds      int  `json:"block_seconds,omitempty" example:"30"`
}

type GatewayVisibilityConfig struct {
	Enabled   bool     `json:"enabled,omitempty"`
	CIDRs     []string `json:"cidrs,omitempty"`
	UpdatedAt string   `json:"updated_at,omitempty"`
}

type ForwardedHeadersConfig struct {
	Enabled     bool     `json:"enabled,omitempty"`
	OmitTargets []string `json:"omit_targets,omitempty"`
	UpdatedAt   string   `json:"updated_at,omitempty"`
}

type PreserveHostConfig struct {
	Enabled     bool     `json:"enabled,omitempty"`
	OmitTargets []string `json:"omit_targets,omitempty"`
	UpdatedAt   string   `json:"updated_at,omitempty"`
}

const (
	GatewayPortalDisplayStyleDomain = "domain"
	GatewayPortalDisplayStyleTitle  = "title"
)

type GatewayPortalConfig struct {
	DisplayStyle string `json:"display_style,omitempty" example:"domain"`
}

func NormalizeGatewayPortalConfig(cfg GatewayPortalConfig) GatewayPortalConfig {
	if cfg.DisplayStyle == GatewayPortalDisplayStyleTitle {
		return GatewayPortalConfig{DisplayStyle: GatewayPortalDisplayStyleTitle}
	}
	return GatewayPortalConfig{DisplayStyle: GatewayPortalDisplayStyleDomain}
}

type FnosPortIconHijackConfig struct {
	Enabled   bool   `json:"enabled,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

type ReverseProxyThrottleExemptIPsRuntime struct {
	Enabled   bool     `json:"enabled,omitempty"`
	IPs       []string `json:"ips,omitempty"`
	CIDRs     []string `json:"cidrs,omitempty"`
	UpdatedAt string   `json:"updated_at,omitempty"`
}

type CommonLocationExemptionsRuntime struct {
	Enabled    bool     `json:"enabled,omitempty"`
	WAFEnabled bool     `json:"waf_enabled,omitempty"`
	CIDRs      []string `json:"cidrs,omitempty"`
	UpdatedAt  string   `json:"updated_at,omitempty"`
}

type PortConfig struct {
	Port  int    `json:"port"`
	Rules []Rule `json:"rules"`
}

type SSLDeploymentMode string

const (
	SSLDeploymentModeSingleActive SSLDeploymentMode = "single_active"
	SSLDeploymentModeMultiSNI     SSLDeploymentMode = "multi_sni"
)

type SSLDeployedCertificate struct {
	ID        string `json:"id,omitempty"`
	Label     string `json:"label,omitempty"`
	Cert      string `json:"cert" example:"-----BEGIN CERTIFICATE-----\n..."`
	Key       string `json:"key" example:"-----BEGIN RSA PRIVATE KEY-----\n..."`
	IsDefault bool   `json:"is_default,omitempty"`
}

type SSLDeployedCertificateInfo struct {
	ID        string   `json:"id,omitempty"`
	Label     string   `json:"label,omitempty"`
	Domains   []string `json:"domains,omitempty"`
	IsDefault bool     `json:"is_default,omitempty"`
}

type SSLConfig struct {
	DeploymentMode SSLDeploymentMode        `json:"deployment_mode,omitempty" example:"single_active"`
	Certificates   []SSLDeployedCertificate `json:"certificates,omitempty"`
}

type SSLInfo struct {
	Enabled        bool                         `json:"enabled"`
	DeploymentMode SSLDeploymentMode            `json:"deployment_mode,omitempty"`
	Certificates   []SSLDeployedCertificateInfo `json:"certificates,omitempty"`
}

type SSLRequest struct {
	Cert string `json:"cert" example:"-----BEGIN CERTIFICATE-----\n..."`
	Key  string `json:"key" example:"-----BEGIN RSA PRIVATE KEY-----\n..."`
}

type SSLDeploymentRequest struct {
	DeploymentMode SSLDeploymentMode        `json:"deployment_mode,omitempty" example:"single_active"`
	Certificates   []SSLDeployedCertificate `json:"certificates,omitempty"`
	Cert           string                   `json:"cert,omitempty" example:"-----BEGIN CERTIFICATE-----\n..."`
	Key            string                   `json:"key,omitempty" example:"-----BEGIN RSA PRIVATE KEY-----\n..."`
}
