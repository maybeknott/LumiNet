// Package proxy implements proxy URI parsing, testing, subscription management,
// and core instance lifecycle for various proxy protocols.
package proxy

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// ProxyProtocol identifies the proxy protocol type.
type ProxyProtocol string

const (
	// ProtocolVMess is the VMess protocol.
	ProtocolVMess ProxyProtocol = "vmess"
	// ProtocolVLESS is the VLESS protocol.
	ProtocolVLESS ProxyProtocol = "vless"
	// ProtocolTrojan is the Trojan protocol.
	ProtocolTrojan ProxyProtocol = "trojan"
	// ProtocolShadowsocks is the Shadowsocks protocol.
	ProtocolShadowsocks ProxyProtocol = "shadowsocks"
	// ProtocolShadowsocksR is the ShadowsocksR protocol.
	ProtocolShadowsocksR ProxyProtocol = "shadowsocksr"
	// ProtocolSOCKS5 is the SOCKS5 protocol.
	ProtocolSOCKS5 ProxyProtocol = "socks5"
	// ProtocolHTTP is the HTTP/HTTPS proxy protocol.
	ProtocolHTTP ProxyProtocol = "http"
	// ProtocolHysteria2 is the Hysteria2 protocol.
	ProtocolHysteria2 ProxyProtocol = "hysteria2"
	// ProtocolTUIC is the TUIC protocol.
	ProtocolTUIC ProxyProtocol = "tuic"
	// ProtocolNaive is the NaiveProxy protocol.
	ProtocolNaive ProxyProtocol = "naive"
	// ProtocolWireGuard is the WireGuard protocol.
	ProtocolWireGuard ProxyProtocol = "wireguard"
	// ProtocolAmneziaWG is the AmneziaWG protocol.
	ProtocolAmneziaWG ProxyProtocol = "amneziawg"
	// ProtocolSingBox is the SingBox outbound format.
	ProtocolSingBox ProxyProtocol = "singbox"
	// ProtocolKCP is the KCP protocol.
	ProtocolKCP ProxyProtocol = "kcp"
	// ProtocolAnyTLS is the AnyTLS protocol.
	ProtocolAnyTLS ProxyProtocol = "anytls"
	// ProtocolJuicity is the Juicity protocol.
	ProtocolJuicity ProxyProtocol = "juicity"
	// ProtocolNipo is the NipoVPN protocol.
	ProtocolNipo ProxyProtocol = "nipo"
	// ProtocolDNSTT is the DNSTT protocol.
	ProtocolDNSTT ProxyProtocol = "dnstt"
)

// ProxyConfig represents a fully parsed proxy configuration.
type ProxyConfig struct {
	// KCP specific parameters
	KCPProfile         string `json:"kcp_profile,omitempty"`
	KCPNoDelay         int    `json:"kcp_nodelay,omitempty"`
	KCPInterval        int    `json:"kcp_interval,omitempty"`
	KCPResend          int    `json:"kcp_resend,omitempty"`
	KCPNoCongestion    int    `json:"kcp_nocongestion,omitempty"`
	KCPSendWindow      int    `json:"kcp_sndwnd,omitempty"`
	KCPReceiveWindow   int    `json:"kcp_rcvwnd,omitempty"`
	KCPMTU             int    `json:"kcp_mtu,omitempty"`
	KCPCompression     string `json:"kcp_compression,omitempty"`
	KCPJitter          bool   `json:"kcp_jitter,omitempty"`
	KCPJitterMin       int    `json:"kcp_jitter_min,omitempty"`
	KCPJitterMax       int    `json:"kcp_jitter_max,omitempty"`

	// Protocol is the proxy protocol type.
	Protocol ProxyProtocol `json:"protocol"`
	// Name is the optional display name / remark.
	Name string `json:"name,omitempty"`
	// Address is the proxy server address (hostname or IP).
	Address string `json:"address"`
	// Port is the proxy server port.
	Port int `json:"port"`
	// UUID is the user ID (VMess/VLESS).
	UUID string `json:"uuid,omitempty"`
	// Password is the authentication password (Trojan/SS/SSR/Naive).
	Password string `json:"password,omitempty"`
	// Method is the encryption method (SS/SSR).
	Method string `json:"method,omitempty"`
	// Security is the encryption security level (VMess: auto/aes-128-gcm/chacha20-poly1305/none).
	Security string `json:"security,omitempty"`
	// AlterID is the VMess alter ID.
	AlterID int `json:"alter_id,omitempty"`
	// Transport is the transport protocol (tcp/ws/grpc/h2/quic/httpupgrade).
	Transport string `json:"transport,omitempty"`
	// TLS indicates whether TLS is enabled.
	TLS bool `json:"tls,omitempty"`
	// SNI is the TLS Server Name Indication.
	SNI string `json:"sni,omitempty"`
	// Path is the WebSocket/HTTP path.
	Path string `json:"path,omitempty"`
	// Host is the HTTP host header.
	Host string `json:"host,omitempty"`
	// ServiceName is the gRPC service name.
	ServiceName string `json:"service_name,omitempty"`
	// Authority is the gRPC authority host.
	Authority string `json:"authority,omitempty"`
	// MultiMode enables gRPC multiMode.
	MultiMode bool `json:"multi_mode,omitempty"`
	// Flow is the VLESS flow control (xtls-rprx-vision, etc.).
	Flow string `json:"flow,omitempty"`
	// Fingerprint is the TLS client fingerprint to impersonate.
	Fingerprint string `json:"fingerprint,omitempty"`
	// ALPN is the list of Application-Layer Protocol Negotiation values.
	ALPN []string `json:"alpn,omitempty"`
	// SkipCertVerify disables TLS certificate verification.
	SkipCertVerify bool `json:"skip_cert_verify,omitempty"`
	// Plugin is the SIP003 plugin name (SS).
	Plugin string `json:"plugin,omitempty"`
	// PluginOpts is the SIP003 plugin options.
	PluginOpts string `json:"plugin_opts,omitempty"`
	// Prefix is the Shadowsocks custom packet prefix (from Outline).
	Prefix string `json:"prefix,omitempty"`
	// Protocol_ is the SSR protocol.
	Protocol_ string `json:"protocol_,omitempty"`
	// ProtocolParam is the SSR protocol parameter.
	ProtocolParam string `json:"protocol_param,omitempty"`
	// Obfs is the SSR obfuscation method.
	Obfs string `json:"obfs,omitempty"`
	// ObfsParam is the SSR obfuscation parameter.
	ObfsParam string `json:"obfs_param,omitempty"`
	// PrivateKey is the WireGuard private key.
	PrivateKey string `json:"private_key,omitempty"`
	// PublicKey is the WireGuard or Reality peer public key.
	PublicKey string `json:"public_key,omitempty"`
	// ShortID is the Reality short ID.
	ShortID string `json:"short_id,omitempty"`
	// PreSharedKey is the WireGuard pre-shared key.
	PreSharedKey string `json:"pre_shared_key,omitempty"`
	// LocalAddress is the WireGuard local address.
	LocalAddress []string `json:"local_address,omitempty"`
	// MTU is the WireGuard MTU.
	MTU int `json:"mtu,omitempty"`
	// Reserved is the WireGuard reserved bytes.
	Reserved []int `json:"reserved,omitempty"`
	// WNoise is the WireGuard noise type.
	WNoise string `json:"wnoise,omitempty"`
	// WNoiseCount is the WireGuard noise count range.
	WNoiseCount string `json:"wnoisecount,omitempty"`
	// WPayloadSize is the WireGuard payload size range.
	WPayloadSize string `json:"wpayloadsize,omitempty"`
	// WNoiseDelay is the WireGuard noise delay.
	WNoiseDelay string `json:"wnoisedelay,omitempty"`
	// FakePackets is the sing-box fake packets setting.
	FakePackets string `json:"fake_packets,omitempty"`
	// FakePacketsSize is the sing-box fake packets size range.
	FakePacketsSize string `json:"fake_packets_size,omitempty"`
	// FakePacketsDelay is the sing-box fake packets delay range.
	FakePacketsDelay string `json:"fake_packets_delay,omitempty"`
	// FakePacketsMode is the sing-box fake packets mode.
	FakePacketsMode string `json:"fake_packets_mode,omitempty"`
	// Jc is the AmneziaWG junk packet count.
	Jc int `json:"jc,omitempty"`
	// Jmin is the AmneziaWG junk packet min size.
	Jmin int `json:"jmin,omitempty"`
	// Jmax is the AmneziaWG junk packet max size.
	Jmax int `json:"jmax,omitempty"`
	// S1 is the AmneziaWG handshake initiation padding size.
	S1 int `json:"s1,omitempty"`
	// S2 is the AmneziaWG handshake response padding size.
	S2 int `json:"s2,omitempty"`
	// S3 is the AmneziaWG cookie reply padding size.
	S3 int `json:"s3,omitempty"`
	// S4 is the AmneziaWG transport data padding size.
	S4 int `json:"s4,omitempty"`
	// H1 is the AmneziaWG handshake initiation header magic value.
	H1 string `json:"h1,omitempty"`
	// H2 is the AmneziaWG handshake response header magic value.
	H2 string `json:"h2,omitempty"`
	// H3 is the AmneziaWG cookie reply header magic value.
	H3 string `json:"h3,omitempty"`
	// H4 is the AmneziaWG transport data header magic value.
	H4 string `json:"h4,omitempty"`
	// I1 is the AmneziaWG 1.5 custom option I1.
	I1 string `json:"i1,omitempty"`
	// I2 is the AmneziaWG 1.5 custom option I2.
	I2 string `json:"i2,omitempty"`
	// I3 is the AmneziaWG 1.5 custom option I3.
	I3 string `json:"i3,omitempty"`
	// I4 is the AmneziaWG 1.5 custom option I4.
	I4 string `json:"i4,omitempty"`
	// I5 is the AmneziaWG 1.5 custom option I5.
	I5 string `json:"i5,omitempty"`
	// UpMbps is the Hysteria2 upload speed in Mbps.
	UpMbps int `json:"up_mbps,omitempty"`
	// DownMbps is the Hysteria2 download speed in Mbps.
	DownMbps int `json:"down_mbps,omitempty"`
	// Obfuscation is the Hysteria2 obfuscation password.
	Obfuscation string `json:"obfuscation,omitempty"`
	// CongestionControl is the TUIC congestion control algorithm.
	CongestionControl string `json:"congestion_control,omitempty"`
	// UDPRelayMode is the TUIC UDP relay mode.
	UDPRelayMode string `json:"udp_relay_mode,omitempty"`
	// MinIdleSessions is the minimum idle sessions (AnyTLS).
	MinIdleSessions int `json:"min_idle_sessions,omitempty"`
	// PinnedCertChainSHA256 is the pinned cert chain SHA-256 (Juicity).
	PinnedCertChainSHA256 string `json:"pinned_certchain_sha256,omitempty"`
	// RawURI is the original unparsed URI.
	RawURI string `json:"raw_uri,omitempty"`
	// SmuxEnabled enables multiplexing for Clash profiles.
	SmuxEnabled bool `json:"smux_enabled,omitempty"`
	// SmuxConcurrency sets the multiplexing concurrency limit.
	SmuxConcurrency int `json:"smux_concurrency,omitempty"`
	// ReservedIsBase64 stores if the reserved field was parsed from base64.
	ReservedIsBase64 bool `json:"reserved_is_base64,omitempty"`
	// FragmentPackets is the TLS hello fragmentation packets pattern (xray).
	FragmentPackets string `json:"fragment_packets,omitempty"`
	// FragmentLength is the TLS hello fragmentation length pattern (xray).
	FragmentLength string `json:"fragment_length,omitempty"`
	// FragmentInterval is the TLS hello fragmentation interval pattern (xray).
	FragmentInterval string `json:"fragment_interval,omitempty"`
	// Detour points to the next proxy configuration in a cascaded chain.
	Detour *ProxyConfig `json:"detour,omitempty"`
	// DialerProxy is the tag/name of the detour outbound.
	DialerProxy string `json:"dialer_proxy,omitempty"`
	// Resolvers is the list of DNS resolvers for DNSTT.
	Resolvers []string `json:"resolvers,omitempty"`
	// TunnelPerResolver is the number of concurrent tunnels for DNSTT.
	TunnelPerResolver int `json:"tunnel_per_resolver,omitempty"`
	// UDPOverTCP forces UDP over TCP encapsulation for DNSTT.
	UDPOverTCP bool `json:"udp_over_tcp,omitempty"`
}

// IsSuspicious checks if a configuration string looks suspicious or malformed.
// It filters out double encoded strings, excessively long lines, and test keywords.
func IsSuspicious(uri string) bool {
	// 1. Length check (>= 1500 chars)
	if len(uri) >= 1500 {
		return true
	}
	// 2. Keyword check
	if strings.Contains(strings.ToLower(uri), "i_love_") {
		return true
	}
	// 3. Double encoding sequences
	if strings.Contains(uri, "%2525") {
		return true
	}
	// 4. Excessive %25 sequence counts (>= 15)
	if strings.Count(uri, "%25") >= 15 {
		return true
	}
	return false
}

// ParseProxyURI parses a single proxy URI string into a ProxyConfig.
// It automatically detects the protocol from the URI scheme and dispatches
// to the appropriate protocol-specific parser.
func ParseProxyURI(uri string) (*ProxyConfig, error) {
	uri = strings.TrimSpace(uri)
	if uri == "" {
		return nil, fmt.Errorf("empty proxy URI")
	}

	if IsSuspicious(uri) {
		return nil, fmt.Errorf("suspicious configuration detected")
	}

	// Handle `->` splits for cascaded chains
	if strings.Contains(uri, "->") {
		parts := strings.Split(uri, "->")
		var first *ProxyConfig
		var prev *ProxyConfig

		for i, part := range parts {
			part = strings.TrimSpace(part)
			cfg, err := ParseProxyURI(part)
			if err != nil {
				return nil, fmt.Errorf("failed to parse chain part %d %q: %w", i, part, err)
			}
			if first == nil {
				first = cfg
			}
			if prev != nil {
				prev.Detour = cfg
				// Set default tag/name for detour
				name := cfg.Name
				if name == "" {
					name = fmt.Sprintf("chain-%d", i)
				}
				prev.DialerProxy = name
			}
			prev = cfg
		}
		return first, nil
	}

	lowered := strings.ToLower(uri)
	var config *ProxyConfig
	var err error

	if strings.HasPrefix(lowered, "vmess://") {
		config, err = parseVMess(uri)
	} else if strings.HasPrefix(lowered, "vless://") {
		config, err = parseVLESS(uri)
	} else if strings.HasPrefix(lowered, "trojan://") {
		config, err = parseTrojan(uri)
	} else if strings.HasPrefix(lowered, "ss://") {
		config, err = parseShadowsocks(uri)
	} else if strings.HasPrefix(lowered, "ssr://") {
		config, err = parseShadowsocksR(uri)
	} else if strings.HasPrefix(lowered, "socks5://") || strings.HasPrefix(lowered, "socks://") {
		config, err = parseSOCKS5(uri)
	} else if strings.HasPrefix(lowered, "http://") || strings.HasPrefix(lowered, "https://") {
		config, err = parseHTTP(uri)
	} else if strings.HasPrefix(lowered, "hysteria2://") || strings.HasPrefix(lowered, "hy2://") {
		config, err = parseHysteria2(uri)
	} else if strings.HasPrefix(lowered, "tuic://") {
		config, err = parseTUIC(uri)
	} else if strings.HasPrefix(lowered, "kcp://") {
		config, err = parseKCP(uri)
	} else if strings.HasPrefix(lowered, "naive://") || strings.HasPrefix(lowered, "naive+https://") {
		config, err = parseNaive(uri)
	} else if strings.HasPrefix(lowered, "anytls://") {
		config, err = parseAnyTLS(uri)
	} else if strings.HasPrefix(lowered, "juicity://") {
		config, err = parseJuicity(uri)
	} else if strings.HasPrefix(lowered, "nipovpn://") {
		config, err = parseNipo(uri)
	} else if strings.HasPrefix(lowered, "wireguard://") || strings.HasPrefix(lowered, "wg://") || strings.HasPrefix(lowered, "awg://") || strings.HasPrefix(lowered, "amneziawg://") || strings.HasPrefix(lowered, "warp://") {
		config, err = parseWireGuard(uri)
	} else if strings.HasPrefix(lowered, "dnstt://") {
		config, err = parseDNSTT(uri)
	} else {
		return nil, fmt.Errorf("unsupported proxy protocol scheme: %s", uri)
	}

	if err != nil {
		return nil, err
	}

	// Parse detour query parameter if present and we don't already have a detour from `->`
	if config.Detour == nil {
		u, err := url.Parse(uri)
		if err == nil {
			detourURI := u.Query().Get("detour")
			if detourURI != "" {
				detourCfg, err := ParseProxyURI(detourURI)
				if err == nil {
					config.Detour = detourCfg
					name := detourCfg.Name
					if name == "" {
						name = "detour-out"
					}
					config.DialerProxy = name
				}
			}
		}
	}

	config.RawURI = uri
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid proxy configuration: %w", err)
	}
	return config, nil
}

// ParseProxyList parses a multi-line string of proxy URIs into a list of ProxyConfigs.
// Each line is parsed independently; lines that fail to parse are collected as errors.
func ParseProxyList(input string) ([]*ProxyConfig, error) {
	lines := strings.Split(input, "\n")
	var configs []*ProxyConfig
	var errs []error

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		cfg, err := ParseProxyURI(line)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		configs = append(configs, cfg)
	}

	if len(configs) == 0 && len(errs) > 0 {
		return nil, fmt.Errorf("failed to parse any proxy URIs: %v", errs[0])
	}
	return configs, nil
}

// SanitizeAndDedupe removes invalid proxy configs and deduplicates by address:port+protocol.
// Returns a new slice with only unique, valid proxy configurations.
func SanitizeAndDedupe(proxies []*ProxyConfig) []*ProxyConfig {
	seen := make(map[string]bool)
	var unique []*ProxyConfig

	for _, p := range proxies {
		if p == nil {
			continue
		}
		if err := p.Validate(); err != nil {
			continue
		}
		// Create unique key: protocol + address + port
		key := fmt.Sprintf("%s://%s:%d", p.Protocol, strings.ToLower(p.Address), p.Port)
		if seen[key] {
			continue
		}
		seen[key] = true
		unique = append(unique, p)
	}
	return unique
}

// Validate checks whether a ProxyConfig has all required fields for its protocol.
func (p *ProxyConfig) Validate() error {
	if p.Address == "" {
		return fmt.Errorf("missing server address")
	}
	if p.Port <= 0 || p.Port > 65535 {
		return fmt.Errorf("invalid port: %d", p.Port)
	}

	switch p.Protocol {
	case ProtocolVMess:
		if p.UUID == "" {
			return fmt.Errorf("missing VMess UUID")
		}
	case ProtocolVLESS:
		if p.UUID == "" {
			return fmt.Errorf("missing VLESS UUID")
		}
	case ProtocolTrojan:
		if p.Password == "" {
			return fmt.Errorf("missing Trojan password")
		}
	case ProtocolShadowsocks:
		if p.Method == "" || p.Password == "" {
			return fmt.Errorf("missing Shadowsocks method or password")
		}
	case ProtocolHysteria2:
		if p.Password == "" {
			return fmt.Errorf("missing Hysteria2 password")
		}
	case ProtocolTUIC:
		if p.UUID == "" || p.Password == "" {
			return fmt.Errorf("missing TUIC UUID or password")
		}
	case ProtocolKCP:
		if p.Password == "" {
			return fmt.Errorf("missing KCP password")
		}
	case ProtocolNaive:
		if p.Password == "" {
			return fmt.Errorf("missing Naive password")
		}
	case ProtocolWireGuard, ProtocolAmneziaWG:
		if p.PrivateKey == "" || p.PublicKey == "" {
			return fmt.Errorf("missing WireGuard keys")
		}
	case ProtocolAnyTLS:
		if p.Password == "" {
			return fmt.Errorf("missing AnyTLS password")
		}
	case ProtocolJuicity:
		if p.UUID == "" && p.Password == "" {
			return fmt.Errorf("missing Juicity UUID or password")
		}
	}
	return nil
}

// ToURI converts a ProxyConfig back into a proxy URI string.
func (p *ProxyConfig) ToURI() string {
	var remark string
	if p.Name != "" {
		remark = "#" + url.PathEscape(p.Name)
	}

	switch p.Protocol {
	case ProtocolVMess:
		m := map[string]interface{}{
			"v":    "2",
			"ps":   p.Name,
			"add":  p.Address,
			"port": p.Port,
			"id":   p.UUID,
			"aid":  p.AlterID,
			"scy":  p.Security,
			"net":  p.Transport,
			"type": "none",
			"host": p.Host,
			"path": p.Path,
			"tls":  "",
		}
		if p.TLS {
			m["tls"] = "tls"
		}
		data, _ := json.Marshal(m)
		return "vmess://" + base64.StdEncoding.EncodeToString(data)

	case ProtocolVLESS:
		u := fmt.Sprintf("vless://%s@%s:%d", p.UUID, p.Address, p.Port)
		q := url.Values{}
		if p.Transport != "" {
			q.Set("type", p.Transport)
		}
		if p.TLS {
			q.Set("security", "tls")
		} else {
			q.Set("security", "none")
		}
		if p.SNI != "" {
			q.Set("sni", p.SNI)
		}
		if p.Flow != "" {
			q.Set("flow", p.Flow)
		}
		if p.Path != "" {
			q.Set("path", p.Path)
		}
		if p.Host != "" {
			q.Set("host", p.Host)
		}
		if len(q) > 0 {
			u += "?" + q.Encode()
		}
		return u + remark

	case ProtocolTrojan:
		u := fmt.Sprintf("trojan://%s@%s:%d", p.Password, p.Address, p.Port)
		q := url.Values{}
		if p.SNI != "" {
			q.Set("sni", p.SNI)
		}
		if p.Transport != "" {
			q.Set("type", p.Transport)
		}
		if len(q) > 0 {
			u += "?" + q.Encode()
		}
		return u + remark

	case ProtocolShadowsocks:
		userinfo := base64.URLEncoding.EncodeToString([]byte(p.Method + ":" + p.Password))
		return fmt.Sprintf("ss://%s@%s:%d%s", userinfo, p.Address, p.Port, remark)

	case ProtocolSOCKS5:
		if p.Password != "" {
			return fmt.Sprintf("socks5://%s:%s@%s:%d%s", p.UUID, p.Password, p.Address, p.Port, remark)
		}
		return fmt.Sprintf("socks5://%s:%d%s", p.Address, p.Port, remark)

	case ProtocolHTTP:
		if p.Password != "" {
			return fmt.Sprintf("http://%s:%s@%s:%d%s", p.UUID, p.Password, p.Address, p.Port, remark)
		}
		return fmt.Sprintf("http://%s:%d%s", p.Address, p.Port, remark)

	case ProtocolHysteria2:
		u := fmt.Sprintf("hysteria2://%s@%s:%d", p.Password, p.Address, p.Port)
		q := url.Values{}
		if p.SNI != "" {
			q.Set("sni", p.SNI)
		}
		if len(q) > 0 {
			u += "?" + q.Encode()
		}
		return u + remark

	case ProtocolTUIC:
		u := fmt.Sprintf("tuic://%s:%s@%s:%d", p.UUID, p.Password, p.Address, p.Port)
		q := url.Values{}
		if p.CongestionControl != "" {
			q.Set("congestion_control", p.CongestionControl)
		}
		if p.UDPRelayMode != "" {
			q.Set("udp_relay_mode", p.UDPRelayMode)
		}
		if p.SNI != "" {
			q.Set("sni", p.SNI)
		}
		if len(q) > 0 {
			u += "?" + q.Encode()
		}
		return u + remark

	case ProtocolKCP:
		u := fmt.Sprintf("kcp://%s@%s:%d", url.PathEscape(p.Password), p.Address, p.Port)
		q := url.Values{}
		if p.Method != "" {
			q.Set("crypt", p.Method)
		}
		if p.KCPProfile != "" {
			q.Set("profile", p.KCPProfile)
		}
		if p.KCPNoDelay != 0 {
			q.Set("nodelay", fmt.Sprintf("%d", p.KCPNoDelay))
		}
		if p.KCPInterval != 0 {
			q.Set("interval", fmt.Sprintf("%d", p.KCPInterval))
		}
		if p.KCPResend != 0 {
			q.Set("resend", fmt.Sprintf("%d", p.KCPResend))
		}
		if p.KCPNoCongestion != 0 {
			q.Set("nc", fmt.Sprintf("%d", p.KCPNoCongestion))
		}
		if p.KCPSendWindow != 0 {
			q.Set("sndwnd", fmt.Sprintf("%d", p.KCPSendWindow))
		}
		if p.KCPReceiveWindow != 0 {
			q.Set("rcvwnd", fmt.Sprintf("%d", p.KCPReceiveWindow))
		}
		if p.KCPMTU != 0 {
			q.Set("mtu", fmt.Sprintf("%d", p.KCPMTU))
		}
		if p.KCPCompression != "" {
			q.Set("compression", p.KCPCompression)
		}
		if p.KCPJitter {
			q.Set("jitter", "true")
		}
		if p.KCPJitterMin != 0 {
			q.Set("jitter_min", fmt.Sprintf("%d", p.KCPJitterMin))
		}
		if p.KCPJitterMax != 0 {
			q.Set("jitter_max", fmt.Sprintf("%d", p.KCPJitterMax))
		}
		if len(q) > 0 {
			u += "?" + q.Encode()
		}
		return u + remark

	case ProtocolNaive:
		return fmt.Sprintf("naive://%s:%s@%s:%d%s", p.UUID, p.Password, p.Address, p.Port, remark)

	case ProtocolWireGuard:
		u := fmt.Sprintf("wireguard://%s@%s:%d", p.PrivateKey, p.Address, p.Port)
		q := url.Values{}
		if p.PublicKey != "" {
			q.Set("publickey", p.PublicKey)
		}
		if len(p.LocalAddress) > 0 {
			q.Set("address", strings.Join(p.LocalAddress, ","))
		}
		if p.MTU > 0 {
			q.Set("mtu", fmt.Sprintf("%d", p.MTU))
		}
		if len(p.Reserved) > 0 {
			if p.ReservedIsBase64 {
				bytesVal := make([]byte, len(p.Reserved))
				for i, v := range p.Reserved {
					bytesVal[i] = byte(v)
				}
				q.Set("reserved", base64.StdEncoding.EncodeToString(bytesVal))
			} else {
				var strVals []string
				for _, v := range p.Reserved {
					strVals = append(strVals, fmt.Sprintf("%d", v))
				}
				q.Set("reserved", strings.Join(strVals, ","))
			}
		}
		if p.WNoise != "" {
			q.Set("wnoise", p.WNoise)
		}
		if p.WNoiseCount != "" {
			q.Set("wnoisecount", p.WNoiseCount)
		}
		if p.WPayloadSize != "" {
			q.Set("wpayloadsize", p.WPayloadSize)
		}
		if p.WNoiseDelay != "" {
			q.Set("wnoisedelay", p.WNoiseDelay)
		}
		if p.FakePackets != "" {
			q.Set("fake_packets", p.FakePackets)
		}
		if p.FakePacketsSize != "" {
			q.Set("fake_packets_size", p.FakePacketsSize)
		}
		if p.FakePacketsDelay != "" {
			q.Set("fake_packets_delay", p.FakePacketsDelay)
		}
		if p.FakePacketsMode != "" {
			q.Set("fake_packets_mode", p.FakePacketsMode)
		}
		if len(q) > 0 {
			u += "?" + q.Encode()
		}
		return u + remark

	case ProtocolAmneziaWG:
		u := fmt.Sprintf("awg://%s@%s:%d", p.PrivateKey, p.Address, p.Port)
		q := url.Values{}
		if p.PublicKey != "" {
			q.Set("publickey", p.PublicKey)
		}
		if len(p.LocalAddress) > 0 {
			q.Set("address", strings.Join(p.LocalAddress, ","))
		}
		if p.MTU > 0 {
			q.Set("mtu", fmt.Sprintf("%d", p.MTU))
		}
		if len(p.Reserved) > 0 {
			if p.ReservedIsBase64 {
				bytesVal := make([]byte, len(p.Reserved))
				for i, v := range p.Reserved {
					bytesVal[i] = byte(v)
				}
				q.Set("reserved", base64.StdEncoding.EncodeToString(bytesVal))
			} else {
				var strVals []string
				for _, v := range p.Reserved {
					strVals = append(strVals, fmt.Sprintf("%d", v))
				}
				q.Set("reserved", strings.Join(strVals, ","))
			}
		}
		if p.Jc > 0 {
			q.Set("jc", fmt.Sprintf("%d", p.Jc))
		}
		if p.Jmin > 0 {
			q.Set("jmin", fmt.Sprintf("%d", p.Jmin))
		}
		if p.Jmax > 0 {
			q.Set("jmax", fmt.Sprintf("%d", p.Jmax))
		}
		if p.S1 > 0 {
			q.Set("s1", fmt.Sprintf("%d", p.S1))
		}
		if p.S2 > 0 {
			q.Set("s2", fmt.Sprintf("%d", p.S2))
		}
		if p.S3 > 0 {
			q.Set("s3", fmt.Sprintf("%d", p.S3))
		}
		if p.S4 > 0 {
			q.Set("s4", fmt.Sprintf("%d", p.S4))
		}
		if p.H1 != "" {
			q.Set("h1", p.H1)
		}
		if p.H2 != "" {
			q.Set("h2", p.H2)
		}
		if p.H3 != "" {
			q.Set("h3", p.H3)
		}
		if p.H4 != "" {
			q.Set("h4", p.H4)
		}
		if p.I1 != "" {
			q.Set("i1", p.I1)
		}
		if p.I2 != "" {
			q.Set("i2", p.I2)
		}
		if p.I3 != "" {
			q.Set("i3", p.I3)
		}
		if p.I4 != "" {
			q.Set("i4", p.I4)
		}
		if p.I5 != "" {
			q.Set("i5", p.I5)
		}
		if p.WNoise != "" {
			q.Set("wnoise", p.WNoise)
		}
		if p.WNoiseCount != "" {
			q.Set("wnoisecount", p.WNoiseCount)
		}
		if p.WPayloadSize != "" {
			q.Set("wpayloadsize", p.WPayloadSize)
		}
		if p.WNoiseDelay != "" {
			q.Set("wnoisedelay", p.WNoiseDelay)
		}
		if p.FakePackets != "" {
			q.Set("fake_packets", p.FakePackets)
		}
		if p.FakePacketsSize != "" {
			q.Set("fake_packets_size", p.FakePacketsSize)
		}
		if p.FakePacketsDelay != "" {
			q.Set("fake_packets_delay", p.FakePacketsDelay)
		}
		if p.FakePacketsMode != "" {
			q.Set("fake_packets_mode", p.FakePacketsMode)
		}
		if len(q) > 0 {
			u += "?" + q.Encode()
		}
		return u + remark

	case ProtocolAnyTLS:
		u := fmt.Sprintf("anytls://%s@%s:%d", p.Password, p.Address, p.Port)
		q := url.Values{}
		if p.SNI != "" {
			q.Set("sni", p.SNI)
		}
		if p.SkipCertVerify {
			q.Set("allowInsecure", "true")
		}
		if p.MinIdleSessions > 0 {
			q.Set("minIdleSessions", fmt.Sprintf("%d", p.MinIdleSessions))
		}
		if len(q) > 0 {
			u += "?" + q.Encode()
		}
		return u + remark

	case ProtocolJuicity:
		var auth string
		if p.UUID != "" && p.Password != "" {
			auth = p.UUID + ":" + p.Password
		} else if p.UUID != "" {
			auth = p.UUID
		} else {
			auth = p.Password
		}
		u := fmt.Sprintf("juicity://%s@%s:%d", auth, p.Address, p.Port)
		q := url.Values{}
		if p.SNI != "" {
			q.Set("sni", p.SNI)
		}
		if p.SkipCertVerify {
			q.Set("allowInsecure", "true")
		}
		if p.CongestionControl != "" {
			q.Set("congestion", p.CongestionControl)
		}
		if p.PinnedCertChainSHA256 != "" {
			q.Set("pinnedCertchain", p.PinnedCertChainSHA256)
		}
		if len(q) > 0 {
			u += "?" + q.Encode()
		}
		return u + remark

	case ProtocolNipo:
		profile := nipoProfile{
			Name: p.Name,
			Config: nipoConfig{
				Token:           p.Password,
				Protocol:        p.Transport,
				TlsEnable:       p.TLS,
				ServerIp:        p.Address,
				ServerPort:      fmt.Sprintf("%d", p.Port),
				FakeUrls:        p.SNI,
				EndPoints:       strings.TrimPrefix(p.Path, "/"),
				LogLevel:        "INFO",
				Timeout:         "10",
				PullTimeout:     "50",
				ConnectionReuse: true,
			},
		}
		data, _ := json.Marshal(profile)
		return "nipovpn://" + base64.StdEncoding.EncodeToString(data)
	}

	return p.RawURI
}

func parseSOCKS5(uri string) (*ProxyConfig, error) {
	parsed, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}
	host := parsed.Hostname()
	if host == "" {
		return nil, fmt.Errorf("missing server address")
	}
	port := 1080
	if parsed.Port() != "" {
		fmt.Sscanf(parsed.Port(), "%d", &port)
	}
	var username, password string
	if parsed.User != nil {
		username = parsed.User.Username()
		password, _ = parsed.User.Password()
	}

	return &ProxyConfig{
		Protocol: ProtocolSOCKS5,
		Address:  host,
		Port:     port,
		UUID:     username,
		Password: password,
		Name:     parsed.Fragment,
	}, nil
}

func parseHTTP(uri string) (*ProxyConfig, error) {
	parsed, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}
	host := parsed.Hostname()
	if host == "" {
		return nil, fmt.Errorf("missing server address")
	}
	port := 8080
	if parsed.Port() != "" {
		fmt.Sscanf(parsed.Port(), "%d", &port)
	}
	var username, password string
	if parsed.User != nil {
		username = parsed.User.Username()
		password, _ = parsed.User.Password()
	}

	return &ProxyConfig{
		Protocol: ProtocolHTTP,
		Address:  host,
		Port:     port,
		UUID:     username,
		Password: password,
		Name:     parsed.Fragment,
	}, nil
}

// String returns a human-readable summary of the proxy configuration.
func (p *ProxyConfig) String() string {
	return fmt.Sprintf("%s://%s:%d [%s]", p.Protocol, p.Address, p.Port, p.Name)
}
