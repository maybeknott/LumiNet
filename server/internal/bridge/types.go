// Package bridge provides the types for the FFI bridge.
package bridge

// ScanConfig holds configuration for scan operations sent to the Rust core.
type ScanConfig struct {
	Timeout      uint32 `json:"timeout_ms"`
	Concurrency  uint32 `json:"max_concurrent"`
	RateLimitPPS uint32 `json:"rate_limit_pps"`
	RetryCount   uint8  `json:"retry_count"`
	AdaptiveRate bool   `json:"adaptive_rate"`
	IPv6         bool   `json:"ipv6"`
	Shuffle      bool   `json:"shuffle"`
	ShuffleSeed  uint64 `json:"shuffle_seed"`
}

// ProbeResult represents the result of a single network probe from the Rust core.
type ProbeResult struct {
	Target    string            `json:"target"`
	IP        string            `json:"ip,omitempty"`
	Port      uint16            `json:"port,omitempty"`
	Alive     bool              `json:"success"`
	LatencyMs float64           `json:"latency_ms"`
	Error     string            `json:"error,omitempty"`
	ErrorCode string            `json:"error_code,omitempty"`
	Timestamp uint64            `json:"timestamp"`
	Metadata  map[string]string `json:"metadata"`
}

// PortResult represents the result of a single port probe.
type PortResult struct {
	IP        string  `json:"ip"`
	Port      uint16  `json:"port"`
	Open      bool    `json:"open"`
	Protocol  string  `json:"protocol"`
	Service   string  `json:"service,omitempty"`
	LatencyMs float64 `json:"latency_ms"`
	Banner    string  `json:"banner,omitempty"`
}

// DnsRecord represents a single DNS record returned by the Rust core.
type DnsRecord struct {
	Name  string `json:"name"`
	Type  string `json:"record_type"`
	Value string `json:"value"`
	TTL   uint32 `json:"ttl"`
	Class string `json:"class"`
}

// DnsServerResult represents the result of a DNS scan returned by the Rust core.
type DnsServerResult struct {
	Server    string      `json:"server"`
	Protocol  string      `json:"protocol"`
	LatencyMs float64     `json:"latency_ms"`
	Success   bool        `json:"success"`
	Records   []DnsRecord `json:"records"`
	Error     string      `json:"error,omitempty"`
}

// TlsInfo contains TLS handshake information from the Rust core.
type TlsInfo struct {
	Version           string   `json:"version"`
	CipherSuite       string   `json:"cipher_suite"`
	CertIssuer        string   `json:"issuer"`
	CertSubject       string   `json:"subject"`
	NotBefore         string   `json:"not_before"`
	NotAfter          string   `json:"not_after"`
	SerialNumber      string   `json:"serial_number"`
	ALPN              []string `json:"alpn"`
	SanDomains        []string `json:"san_domains"`
	FingerprintSha256 string   `json:"fingerprint_sha256"`
	ChainLength       int      `json:"chain_length"`
	OcspStapled       bool     `json:"ocsp_stapled"`
}

// SniResult represents the result of an SNI blocking detection test.
type SniResult struct {
	Domain     string   `json:"domain"`
	Blocked    bool     `json:"blocked"`
	TlsSuccess bool     `json:"tls_success"`
	TlsInfo    *TlsInfo `json:"tls_info,omitempty"`
	Error      string   `json:"error,omitempty"`
	Evidence   string   `json:"evidence"`
	Confidence float32  `json:"confidence"`
}

// SpeedResult contains the results of a speed test.
type SpeedResult struct {
	DownloadMbps     float64 `json:"download_mbps"`
	UploadMbps       float64 `json:"upload_mbps"`
	LatencyMs        float64 `json:"latency_ms"`
	JitterMs         float64 `json:"jitter_ms"`
	BytesTransferred uint64  `json:"bytes_transferred"`
	DurationMs       uint64  `json:"duration_ms"`
	Server           string  `json:"server"`
}

// HttpResponse represents an HTTP response from the Rust core.
type HttpResponse struct {
	StatusCode    int               `json:"status_code"`
	Headers       map[string]string `json:"headers"`
	Body          string            `json:"body_preview"`
	LatencyMs     float64           `json:"latency_ms"`
	ContentLength uint64            `json:"content_length"`
	Redirected    bool              `json:"redirected"`
	FinalURL      string            `json:"final_url"`
}
