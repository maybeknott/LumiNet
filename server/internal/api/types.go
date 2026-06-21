package api

import (
	"time"
)

// ─── Scan Request/Response Types ──────────────────────────────────────────

// CreateScanRequest is the request body for creating a new ICMP scan.
type CreateScanRequest struct {
	Targets     []string `json:"targets" binding:"required"`
	Timeout     int      `json:"timeout,omitempty"`
	Concurrency int      `json:"concurrency,omitempty"`
	Count       int      `json:"count,omitempty"`
	TTL         int      `json:"ttl,omitempty"`
	IPv6        bool     `json:"ipv6,omitempty"`
}

// ScanResponse is the top-level response for a scan status query.
type ScanResponse struct {
	ID           string     `json:"id"`
	Status       string     `json:"status"`
	Progress     int        `json:"progress"`
	CreatedAt    time.Time  `json:"created_at"`
	StartedAt    *time.Time `json:"started_at,omitempty"`
	CompletedAt  *time.Time `json:"completed_at,omitempty"`
	TotalTargets int        `json:"total_targets"`
	AliveCount   int        `json:"alive_count"`
	Error        string     `json:"error,omitempty"`
}

// ScanAliveResponse contains only the alive hosts from a scan.
type ScanAliveResponse struct {
	ID    string      `json:"id"`
	Alive []AliveHost `json:"alive"`
}

// AliveHost represents a single responsive host.
type AliveHost struct {
	IP         string  `json:"ip"`
	Hostname   string  `json:"hostname,omitempty"`
	LatencyMs  float64 `json:"latency_ms"`
	TTL        int     `json:"ttl"`
	PacketLoss float64 `json:"packet_loss"`
}

// ScanResultsResponse contains the full results from a scan.
type ScanResultsResponse struct {
	ID      string                `json:"id"`
	Results []ProbeResultResponse `json:"results"`
	Summary ScanSummary           `json:"summary"`
}

// ProbeResultResponse represents the result of probing a single target.
type ProbeResultResponse struct {
	Target     string  `json:"target"`
	IP         string  `json:"ip"`
	Alive      bool    `json:"alive"`
	LatencyMs  float64 `json:"latency_ms"`
	TTL        int     `json:"ttl"`
	PacketLoss float64 `json:"packet_loss"`
	Error      string  `json:"error,omitempty"`
	MacAddress string  `json:"mac_address,omitempty"`
	Vendor     string  `json:"vendor,omitempty"`
}

// ScanSummary contains aggregate scan statistics.
type ScanSummary struct {
	TotalTargets int     `json:"total_targets"`
	AliveCount   int     `json:"alive_count"`
	DeadCount    int     `json:"dead_count"`
	AvgLatencyMs float64 `json:"avg_latency_ms"`
	MinLatencyMs float64 `json:"min_latency_ms"`
	MaxLatencyMs float64 `json:"max_latency_ms"`
	Duration     float64 `json:"duration_seconds"`
}

// ─── Port Scan Types ──────────────────────────────────────────────────────

// CreatePortScanRequest is the request body for a port scan.
type CreatePortScanRequest struct {
	Target      string   `json:"target" binding:"required"`
	Ports       []uint16 `json:"ports" binding:"required"`
	Timeout     int      `json:"timeout,omitempty"`
	Concurrency int      `json:"concurrency,omitempty"`
}

// ─── DNS Scan Types ───────────────────────────────────────────────────────

// CreateDnsScanRequest is the request body for a DNS scan.
type CreateDnsScanRequest struct {
	Domain     string `json:"domain" binding:"required"`
	Server     string `json:"server,omitempty"`
	RecordType string `json:"record_type,omitempty"`
	TimeoutMs  uint32 `json:"timeout_ms,omitempty"`
}

// ─── TLS/SNI Scan Types ───────────────────────────────────────────────────

// CreateTlsScanRequest is the request body for a TLS scan.
type CreateTlsScanRequest struct {
	Target      string   `json:"target,omitempty"`
	Targets     []string `json:"targets,omitempty"`
	Port        uint16   `json:"port,omitempty"`
	TimeoutMs   uint32   `json:"timeout_ms,omitempty"`
	Sni         string   `json:"sni,omitempty"`
	Concurrency int      `json:"concurrency,omitempty"`
	SampleRate  int      `json:"sample_rate,omitempty"`
	Mode        string   `json:"mode,omitempty"`
}

// CreateSniScanRequest is the request body for an SNI scan.
type CreateSniScanRequest struct {
	Domain    string `json:"domain" binding:"required"`
	TimeoutMs uint32 `json:"timeout_ms,omitempty"`
}

// ─── Proxy Request/Response Types ──────────────────────────────────────────

// CreateProxyScanRequest is the request body for creating a proxy scan.
type CreateProxyScanRequest struct {
	Proxies     []string `json:"proxies" binding:"required"`
	URLs        []string `json:"urls,omitempty"`
	Timeout     int      `json:"timeout,omitempty"`
	Concurrency int      `json:"concurrency,omitempty"`
	SpeedTest   bool     `json:"speed_test,omitempty"`
	GeoIP       bool     `json:"geoip,omitempty"`
	CoreType    string   `json:"core_type,omitempty"`
	DnsResolver string   `json:"dns_resolver,omitempty"`
}

// ProxyScanResponse is the response for a proxy scan status query.
type ProxyScanResponse struct {
	ID           string    `json:"id"`
	Status       string    `json:"status"`
	Progress     int       `json:"progress"`
	CreatedAt    time.Time `json:"created_at"`
	TotalProxies int       `json:"total_proxies"`
	WorkingCount int       `json:"working_count"`
	FailedCount  int       `json:"failed_count"`
	Error        string    `json:"error,omitempty"`
}

// ProxyScanRowResponse represents a single proxy test result row.
type ProxyScanRowResponse struct {
	Index     int        `json:"index"`
	ProxyURI  string     `json:"proxy_uri"`
	Protocol  string     `json:"protocol"`
	Address   string     `json:"address"`
	Port      int        `json:"port"`
	Status    string     `json:"status"`
	LatencyMs float64    `json:"latency_ms"`
	SpeedMbps float64    `json:"speed_mbps,omitempty"`
	GeoIP     *GeoIPInfo `json:"geoip,omitempty"`
	Error     string     `json:"error,omitempty"`
}

// GeoIPInfo contains geolocation data for an IP address.
type GeoIPInfo struct {
	Country string `json:"country"`
	City    string `json:"city,omitempty"`
	ISP     string `json:"isp,omitempty"`
	ASN     string `json:"asn,omitempty"`
}

// CreateProxyTestRequest is the request body for creating a single proxy test.
type CreateProxyTestRequest struct {
	ProxyURI      string   `json:"proxy_uri" binding:"required"`
	URLs          []string `json:"urls,omitempty"`
	Timeout       int      `json:"timeout,omitempty"`
	SpeedTest     bool     `json:"speed_test,omitempty"`
	StabilityRuns int      `json:"stability_runs,omitempty"`
	DnsResolver   string   `json:"dns_resolver,omitempty"`
}

// ProxyTestResponse is the response for a single proxy test status.
type ProxyTestResponse struct {
	ID     string                `json:"id"`
	Status string                `json:"status"`
	Result *ProxyScanRowResponse `json:"result,omitempty"`
	Error  string                `json:"error,omitempty"`
}

// ParseProxyRequest is the request body for parsing pasted proxy content.
type ParseProxyRequest struct {
	Content string `json:"content" binding:"required"`
	Dedupe  bool   `json:"dedupe,omitempty"`
}

// ParsedProxyResponse is a credential-safe parsed proxy preview.
type ParsedProxyResponse struct {
	Index     int    `json:"index"`
	Protocol  string `json:"protocol"`
	Name      string `json:"name,omitempty"`
	Address   string `json:"address"`
	Port      int    `json:"port"`
	TLS       bool   `json:"tls"`
	SNI       string `json:"sni,omitempty"`
	Transport string `json:"transport,omitempty"`
	Preview   string `json:"preview"`
}

// ParseProxyResponse summarizes a pasted proxy parse operation.
type ParseProxyResponse struct {
	Count   int                   `json:"count"`
	Results []ParsedProxyResponse `json:"results"`
}

// RewriteProxyRequest is the request body for mapping clean IPs onto proxy subscription lists.
type RewriteProxyRequest struct {
	Content  string   `json:"content" binding:"required"`
	CleanIPs []string `json:"clean_ips" binding:"required"`
	NewPort  int      `json:"new_port,omitempty"`
	NewName  string   `json:"new_name,omitempty"`
}

// RewriteProxyResponse returns the rewritten proxy configurations.
type RewriteProxyResponse struct {
	Count   int      `json:"count"`
	Results []string `json:"results"`
}


// ─── System Types ──────────────────────────────────────────────────────────

// SystemStatusResponse contains real-time system metrics and status.
type SystemStatusResponse struct {
	ApiConnected  bool                       `json:"api_connected"`
	PublicIPv4    string                     `json:"public_ipv4"`
	PublicIPv6    string                     `json:"public_ipv6,omitempty"`
	DNSServers    []string                   `json:"dns_servers"`
	ProxyActive   bool                       `json:"proxy_active"`
	EvasionActive bool                       `json:"evasion_active"`
	TunActive     bool                       `json:"tun_active"`
	Interfaces    []NetworkInterfaceResponse `json:"interfaces"`
	UptimeSeconds int64                      `json:"uptime_seconds"`
	ActiveJobs    int                        `json:"active_jobs"`
	CpuUsage      int                        `json:"cpu_usage"`
	RamUsage      int                        `json:"ram_usage"`
	TotalRamGb    float64                    `json:"total_ram_gb"`
	UsedRamGb     float64                    `json:"used_ram_gb"`
	DiskUsage     int                        `json:"disk_usage"`
	DiskFreeGb    int                        `json:"disk_free_gb"`
	UploadBytes   uint64                     `json:"upload_bytes"`
	DownloadBytes uint64                     `json:"download_bytes"`
}

// NetworkInterfaceResponse is a frontend-safe view of an active network interface.
type NetworkInterfaceResponse struct {
	Name       string   `json:"name"`
	MAC        string   `json:"mac"`
	IPs        []string `json:"ips"`
	Gateway    string   `json:"gateway"`
	IsWireless bool     `json:"is_wireless"`
	SSID       string   `json:"ssid,omitempty"`
}

// DNSStatusResponse contains the current DNS configuration.
type DNSStatusResponse struct {
	Interface string   `json:"interface"`
	Servers   []string `json:"servers"`
	Source    string   `json:"source"`
}

// SetDNSRequest is the request body for setting DNS servers.
type SetDNSRequest struct {
	Servers   []string `json:"servers" binding:"required"`
	Interface string   `json:"interface,omitempty"`
}

// ProxySettingsResponse contains the current system proxy settings.
type ProxySettingsResponse struct {
	Enabled bool   `json:"enabled"`
	Server  string `json:"server,omitempty"`
	PacURL  string `json:"pac_url,omitempty"`
	Bypass  string `json:"bypass,omitempty"`
	Socks5  string `json:"socks5,omitempty"`
}

// SetProxyRequest is the request body for setting proxy settings.
type SetProxyRequest struct {
	Enabled bool   `json:"enabled"`
	Server  string `json:"server,omitempty"`
	Bypass  string `json:"bypass,omitempty"`
	PacURL  string `json:"pac_url,omitempty"`
}

// StartupStatusResponse contains the current system startup status.
type StartupStatusResponse struct {
	Enabled bool `json:"enabled"`
}

// SetStartupRequest is the request body for setting startup status.
type SetStartupRequest struct {
	Enabled bool `json:"enabled"`
}

// ProfileResponse describes a single network profile.
type ProfileResponse struct {
	Name   string `json:"name"`
	SSID   string `json:"ssid,omitempty"`
	BSSID  string `json:"bssid,omitempty"`
	Active bool   `json:"active"`
}

// ─── WebSocket Types ──────────────────────────────────────────────────────

// WSMessage represents a WebSocket message envelope.
type WSMessage struct {
	Type      string      `json:"type"`
	JobID     string      `json:"job_id,omitempty"`
	Data      interface{} `json:"data"`
	Timestamp time.Time   `json:"timestamp"`
}

// WSCommand represents a client-to-server WS command.
type WSCommand struct {
	Action string `json:"action"` // e.g. "subscribe", "unsubscribe"
	JobID  string `json:"job_id"`
}
