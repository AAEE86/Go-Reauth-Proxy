package events

const (
	FnEventGatewayThrottleBlocked  = "FN_EVENT_GATEWAY_THROTTLE_BLOCKED"
	FnEventLevelWarn               = "WARN"
	SystemEventSourceGoReauthProxy = "GO_REAUTH_PROXY"
	SystemEventSubjectKindIP       = "IP"
)

type SystemEventSubject struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

type SystemEventPublishInput struct {
	Type             string              `json:"type"`
	Source           string              `json:"source"`
	Level            string              `json:"level,omitempty"`
	HappenedAt       string              `json:"happened_at,omitempty"`
	DedupeKey        string              `json:"dedupe_key,omitempty"`
	DedupeTTLSeconds int                 `json:"dedupe_ttl_seconds,omitempty"`
	Subject          *SystemEventSubject `json:"subject,omitempty"`
	Tags             []string            `json:"tags,omitempty"`
	Payload          any                 `json:"payload"`
}

type GatewayThrottleBlockedPayload struct {
	IP                string `json:"ip"`
	BlockedUntil      string `json:"blocked_until"`
	BlockSeconds      int    `json:"block_seconds"`
	RequestsPerSecond int    `json:"requests_per_second"`
	Burst             int    `json:"burst"`
	RouteType         string `json:"route_type,omitempty"`
	Host              string `json:"host,omitempty"`
	Path              string `json:"path,omitempty"`
	IsAuthRoute       bool   `json:"is_auth_route"`
}
