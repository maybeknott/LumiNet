package relay

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
)

var (
	// DefaultEdgeCIDRs lists the authorized Cloudflare edge network CIDRs for relay ingress.
	DefaultEdgeCIDRs = []string{
		"103.21.244.0/22",
		"103.22.200.0/22",
		"103.31.4.0/22",
		"104.16.0.0/12",
		"108.162.192.0/18",
		"131.0.72.0/22",
		"141.101.64.0/18",
		"162.158.0.0/15",
		"172.64.0.0/13",
		"173.245.48.0/20",
		"188.114.96.0/20",
		"190.93.240.0/20",
		"197.234.240.0/22",
		"198.41.128.0/17",
		"2400:cb00::/32",
		"2405:8100::/32",
		"2405:b500::/32",
		"2606:4700::/32",
		"2803:f800::/32",
		"2c0f:f248::/32",
		"2a06:98c0::/29",
	}

	// DefaultBlockedCIDRs lists localhost and known abusive torrent tracker CIDRs prohibited from egress.
	DefaultBlockedCIDRs = []string{
		"127.0.0.0/8",
		"::1/128",
		"93.158.213.92/32",
		"102.223.180.235/32",
		"23.134.88.6/32",
		"185.243.218.213/32",
		"208.83.20.20/32",
		"91.216.110.52/32",
		"83.146.97.90/32",
		"23.157.120.14/32",
		"185.102.219.163/32",
		"163.172.29.130/32",
		"156.234.201.18/32",
		"209.141.59.16/32",
		"34.94.213.23/32",
		"192.3.165.191/32",
		"130.61.55.93/32",
		"109.201.134.183/32",
		"95.31.11.224/32",
		"83.102.180.21/32",
		"192.95.46.115/32",
		"198.100.149.66/32",
		"95.216.74.39/32",
		"51.68.174.87/32",
		"37.187.111.136/32",
		"51.15.79.209/32",
		"45.92.156.182/32",
		"49.12.76.8/32",
		"5.196.89.204/32",
		"62.233.57.13/32",
		"45.9.60.30/32",
		"35.227.12.84/32",
		"179.43.155.30/32",
		"94.243.222.100/32",
		"207.241.231.226/32",
		"207.241.226.111/32",
		"51.159.54.68/32",
		"82.65.115.10/32",
		"95.217.167.10/32",
		"86.57.161.157/32",
		"83.31.30.230/32",
		"94.103.87.87/32",
		"160.119.252.41/32",
		"193.42.111.57/32",
		"80.240.22.46/32",
		"107.189.31.134/32",
		"104.244.79.114/32",
		"85.239.33.28/32",
		"61.222.178.254/32",
		"38.7.201.142/32",
		"51.81.222.188/32",
		"103.196.36.31/32",
		"23.153.248.2/32",
		"73.170.204.100/32",
		"176.31.250.174/32",
		"149.56.179.233/32",
		"212.237.53.230/32",
		"185.68.21.244/32",
		"82.156.24.219/32",
		"216.201.9.155/32",
		"51.15.41.46/32",
		"85.206.172.159/32",
		"104.244.77.87/32",
		"37.27.4.53/32",
		"192.3.165.198/32",
		"15.204.205.14/32",
		"103.122.21.50/32",
		"104.131.98.232/32",
		"173.249.201.201/32",
		"23.254.228.89/32",
		"5.102.159.190/32",
		"65.130.205.148/32",
		"119.28.71.45/32",
		"159.69.65.157/32",
		"160.251.78.190/32",
		"107.189.7.143/32",
		"159.65.224.91/32",
		"185.217.199.21/32",
		"91.224.92.110/32",
		"161.97.67.210/32",
		"51.15.3.74/32",
		"209.126.11.233/32",
		"37.187.95.112/32",
		"167.99.185.219/32",
		"144.91.88.22/32",
		"88.99.2.212/32",
		"37.59.48.81/32",
		"95.179.130.187/32",
		"51.15.26.25/32",
		"192.9.228.30/32",
	}
)

// RelayAclFilter evaluates connection permissions based on source whitelist and destination blacklist.
type RelayAclFilter struct {
	sourceWhitelist      []netip.Prefix
	destinationBlacklist []netip.Prefix
}

// NewRelayAclFilter constructs a filter populated with default edge whitelist and tracker blacklist prefixes.
func NewRelayAclFilter() *RelayAclFilter {
	f := &RelayAclFilter{
		sourceWhitelist:      make([]netip.Prefix, 0, len(DefaultEdgeCIDRs)),
		destinationBlacklist: make([]netip.Prefix, 0, len(DefaultBlockedCIDRs)),
	}

	for _, cidr := range DefaultEdgeCIDRs {
		if prefix, err := netip.ParsePrefix(cidr); err == nil {
			f.sourceWhitelist = append(f.sourceWhitelist, prefix)
		}
	}

	for _, cidr := range DefaultBlockedCIDRs {
		if prefix, err := netip.ParsePrefix(cidr); err == nil {
			f.destinationBlacklist = append(f.destinationBlacklist, prefix)
		}
	}

	return f
}

// AddSourceWhitelist adds an authorized source prefix.
func (f *RelayAclFilter) AddSourceWhitelist(prefix netip.Prefix) {
	f.sourceWhitelist = append(f.sourceWhitelist, prefix)
}

// AddDestinationBlacklist adds a blocked destination prefix.
func (f *RelayAclFilter) AddDestinationBlacklist(prefix netip.Prefix) {
	f.destinationBlacklist = append(f.destinationBlacklist, prefix)
}

// IsSourceAllowed tests whether a remote connection origin belongs to the authorized edge IP pool.
func (f *RelayAclFilter) IsSourceAllowed(addr netip.Addr) bool {
	for _, prefix := range f.sourceWhitelist {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// IsDestinationAllowed tests whether a destination target is clear of abusive tracker or loopback ranges.
func (f *RelayAclFilter) IsDestinationAllowed(addr netip.Addr) bool {
	for _, prefix := range f.destinationBlacklist {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

// Evaluate performs joint source and destination policy inspection.
func (f *RelayAclFilter) Evaluate(src, dst netip.Addr) error {
	if !f.IsSourceAllowed(src) {
		return fmt.Errorf("source ip %s is not in authorized edge whitelist", src)
	}
	if !f.IsDestinationAllowed(dst) {
		return fmt.Errorf("destination ip %s is blocked by relay security policy", dst)
	}
	return nil
}

// UdpOverTcpFrame represents an 8-byte framed UDP packet transmitted over a streaming relay TCP tunnel.
type UdpOverTcpFrame struct {
	SessionID [6]byte
	StreamTag [2]byte
	Payload   []byte
}

// Encode wraps a session ID, stream tag, and datagram payload into an 8-byte framed byte slice.
func EncodeUdpOverTcpFrame(sessionID [6]byte, streamTag [2]byte, payload []byte) []byte {
	out := make([]byte, 8+len(payload))
	copy(out[0:6], sessionID[:])
	copy(out[6:8], streamTag[:])
	copy(out[8:], payload)
	return out
}

// DecodeUdpOverTcpFrame unmarshals an 8-byte framed packet from a stream buffer.
func DecodeUdpOverTcpFrame(src []byte) (*UdpOverTcpFrame, error) {
	if len(src) < 8 {
		return nil, errors.New("buffer too short for UDP-over-TCP header (minimum 8 bytes required)")
	}
	var sessionID [6]byte
	var streamTag [2]byte
	copy(sessionID[:], src[0:6])
	copy(streamTag[:], src[6:8])

	payload := make([]byte, len(src)-8)
	copy(payload, src[8:])

	return &UdpOverTcpFrame{
		SessionID: sessionID,
		StreamTag: streamTag,
		Payload:   payload,
	}, nil
}

// BuildUdpResponsePacket frames a remote UDP response datagram with its 2-byte return tag.
func BuildUdpResponsePacket(streamTag [2]byte, datagram []byte) []byte {
	out := make([]byte, 2+len(datagram))
	copy(out[0:2], streamTag[:])
	copy(out[2:], datagram)
	return out
}

// DecodeUdpResponsePacket extracts the 2-byte return tag and datagram payload.
func DecodeUdpResponsePacket(src []byte) ([2]byte, []byte, error) {
	var tag [2]byte
	if len(src) < 2 {
		return tag, nil, errors.New("buffer too short for UDP response tag (minimum 2 bytes required)")
	}
	copy(tag[:], src[0:2])
	return tag, src[2:], nil
}

// ChannelKey formats the session multiplexing map key for active tunnel routing.
func ChannelKey(destination string, sessionID [6]byte, streamTag [2]byte) string {
	headerHex := hex.EncodeToString(sessionID[:]) + hex.EncodeToString(streamTag[:])
	return fmt.Sprintf("%s:%s", destination, headerHex)
}
