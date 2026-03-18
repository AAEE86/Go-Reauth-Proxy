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
	Host         string `json:"host" example:"redis.example.com"`
	Target       string `json:"target" example:"http://127.0.0.1:5173"`
	UseAuth      bool   `json:"use_auth" example:"true"`
	AccessMode   string `json:"access_mode,omitempty" example:"login_first"`
	PreserveHost bool   `json:"preserve_host,omitempty" example:"true"`
}

type AuthConfig struct {
	AuthPort          int    `json:"auth_port" example:"3000"`                    // Local Auth Service Port
	AuthURL           string `json:"auth_url" example:"/api/auth/verify"`         // Relative Verify URL (default /api/auth/verify)
	LoginURL          string `json:"login_url" example:"/login"`                  // Relative Login URL (default /login)
	LogoutURL         string `json:"logout_url" example:"/api/auth/logout"`       // Relative Logout URL (default /api/auth/logout)
	PreflightURL      string `json:"preflight_url" example:"/api/auth/preflight"` // Relative Preflight URL (default /api/auth/preflight)
	PublicAuthBaseURL string `json:"public_auth_base_url,omitempty" example:"https://auth.example.com"`
	AuthHost          string `json:"auth_host,omitempty" example:"auth.example.com"`
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
