package relay

import (
	"fmt"
	"net/netip"
	"strings"
)

var (
	// CanonicalCloudflareIPv4 lists the Cloudflare IPv4 CIDR blocks.
	CanonicalCloudflareIPv4 = []string{
		"173.245.48.0/20",
		"103.21.244.0/22",
		"103.22.200.0/22",
		"103.31.4.0/22",
		"141.101.64.0/18",
		"108.162.192.0/18",
		"190.93.240.0/20",
		"188.114.96.0/20",
		"197.234.240.0/22",
		"198.41.128.0/17",
		"162.158.0.0/15",
		"104.16.0.0/13",
		"104.24.0.0/14",
		"172.64.0.0/13",
		"131.0.72.0/22",
	}

	// CanonicalCloudflareIPv6 lists the Cloudflare IPv6 CIDR blocks.
	CanonicalCloudflareIPv6 = []string{
		"2400:cb00::/32",
		"2606:4700::/32",
		"2803:f800::/32",
		"2405:b500::/32",
		"2405:8100::/32",
		"2a06:98c0::/29",
		"2c0f:f248::/32",
	}
)

// EdgeRelayConfig defines upstream relay cluster topology and DoH resolver configuration.
type EdgeRelayConfig struct {
	RelayHosts      []string
	RelayPort       int
	DnsHost         string
	CloudflareCIDRs []netip.Prefix
}

// DefaultEdgeRelayConfig returns the default serverless relay cluster configuration.
func DefaultEdgeRelayConfig() EdgeRelayConfig {
	var prefixes []netip.Prefix

	for _, cidr := range CanonicalCloudflareIPv4 {
		if p, err := netip.ParsePrefix(cidr); err == nil {
			prefixes = append(prefixes, p)
		}
	}
	for _, cidr := range CanonicalCloudflareIPv6 {
		if p, err := netip.ParsePrefix(cidr); err == nil {
			prefixes = append(prefixes, p)
		}
	}

	return EdgeRelayConfig{
		RelayHosts: []string{
			"relay1.bepass.org",
			"relay2.bepass.org",
			"relay3.bepass.org",
		},
		RelayPort:       6666,
		DnsHost:         "1.1.1.1",
		CloudflareCIDRs: prefixes,
	}
}

// RouteTarget encapsulates outbound connection parameters.
type RouteTarget struct {
	Network    string // "tcp" or "udp"
	Host       string
	Port       int
	ResolvedIP netip.Addr
}

// EdgeRoutingDecision specifies whether outbound traffic routes directly or via an edge relay tunnel.
type EdgeRoutingDecision struct {
	IsRelayChained  bool
	TargetHost      string
	TargetPort      int
	RelayHost       string
	RelayPort       int
	DelimiterHeader string
}

// EdgeRelayRouter decides between direct socket dialing and chained relay proxying.
type EdgeRelayRouter struct {
	config EdgeRelayConfig
}

// NewEdgeRelayRouter constructs a router with the provided relay configuration.
func NewEdgeRelayRouter(config EdgeRelayConfig) *EdgeRelayRouter {
	return &EdgeRelayRouter{config: config}
}

// SelectRelayEndpoint deterministically selects an upstream relay node based on session ID.
func (r *EdgeRelayRouter) SelectRelayEndpoint(sessionID *uint64) (string, int) {
	if len(r.config.RelayHosts) == 0 {
		return "127.0.0.1", r.config.RelayPort
	}
	idx := 0
	if sessionID != nil {
		idx = int(*sessionID % uint64(len(r.config.RelayHosts)))
	}
	return r.config.RelayHosts[idx], r.config.RelayPort
}

// IsCloudflareIP checks if the target IP belongs to Cloudflare's edge CDN blocks.
func (r *EdgeRelayRouter) IsCloudflareIP(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	for _, prefix := range r.config.CloudflareCIDRs {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// DecideRoute calculates whether to dial directly or route through the relay pool with a header.
func (r *EdgeRelayRouter) DecideRoute(target RouteTarget, sessionID *uint64) EdgeRoutingDecision {
	netLower := strings.ToLower(target.Network)
	requiresRelay := netLower == "udp" || r.IsCloudflareIP(target.ResolvedIP)

	if requiresRelay {
		relayHost, relayPort := r.SelectRelayEndpoint(sessionID)
		header := fmt.Sprintf("%s@%s$%d\r\n", netLower, target.Host, target.Port)
		return EdgeRoutingDecision{
			IsRelayChained:  true,
			TargetHost:      target.Host,
			TargetPort:      target.Port,
			RelayHost:       relayHost,
			RelayPort:       relayPort,
			DelimiterHeader: header,
		}
	}

	return EdgeRoutingDecision{
		IsRelayChained: false,
		TargetHost:     target.Host,
		TargetPort:     target.Port,
	}
}

// BuildFallbackRelayRoute produces a chained relay route for connection retries.
func (r *EdgeRelayRouter) BuildFallbackRelayRoute(target RouteTarget, sessionID *uint64) EdgeRoutingDecision {
	netLower := strings.ToLower(target.Network)
	relayHost, relayPort := r.SelectRelayEndpoint(sessionID)
	header := fmt.Sprintf("%s@%s$%d\r\n", netLower, target.Host, target.Port)

	return EdgeRoutingDecision{
		IsRelayChained:  true,
		TargetHost:      target.Host,
		TargetPort:      target.Port,
		RelayHost:       relayHost,
		RelayPort:       relayPort,
		DelimiterHeader: header,
	}
}

// BuildDohAQuery crafts an RFC 1035 / RFC 8484 wire DNS A-record query for DoH lookups.
func BuildDohAQuery(domain string) []byte {
	var buf []byte

	// Header
	buf = append(buf,
		0x12, 0x34, // Transaction ID
		0x01, 0x00, // Standard query, RD=1
		0x00, 0x01, // Questions: 1
		0x00, 0x00, // Answer RRs: 0
		0x00, 0x00, // Authority RRs: 0
		0x00, 0x00, // Additional RRs: 0
	)

	// QNAME labels
	parts := strings.Split(domain, ".")
	for _, part := range parts {
		if len(part) == 0 {
			continue
		}
		buf = append(buf, byte(len(part)))
		buf = append(buf, []byte(part)...)
	}
	buf = append(buf, 0x00) // End of QNAME

	// QTYPE (A = 1) and QCLASS (IN = 1)
	buf = append(buf, 0x00, 0x01, 0x00, 0x01)

	return buf
}
