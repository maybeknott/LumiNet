package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

var errPluginConfig = errors.New("invalid routing plugin config")

type RoutingPluginDescriptor struct {
	SchemaVersion     int      `json:"schema_version"`
	PluginID          string   `json:"plugin_id"`
	PluginType        string   `json:"plugin_type"`
	DisplayName       string   `json:"display_name"`
	Version           string   `json:"version"`
	SourceURL         string   `json:"source_url"`
	License           string   `json:"license"`
	RouteType         string   `json:"route_type"`
	CredentialMode    string   `json:"credential_mode"`
	LocalAPIMode      string   `json:"local_api_mode"`
	LocalAPIRequired  bool     `json:"local_api_required"`
	SecretPolicy      string   `json:"secret_policy"`
	Enabled           bool     `json:"enabled"`
	EnabledByDefault  bool     `json:"enabled_by_default"`
	SupportsIPv4      bool     `json:"supports_ipv4"`
	SupportsIPv6      bool     `json:"supports_ipv6"`
	SupportsRemoteDNS bool     `json:"supports_remote_dns"`
	DiagnosticLabel   string   `json:"diagnostic_label"`
	RedactedFields    []string `json:"redacted_fields,omitempty"`
	Notes             []string `json:"notes,omitempty"`
}

type RoutingPluginConfig struct {
	SchemaVersion int               `json:"schema_version"`
	RouteID       string            `json:"route_id"`
	PluginID      string            `json:"plugin_id"`
	Enabled       bool              `json:"enabled"`
	RemoteDNS     bool              `json:"remote_dns"`
	Endpoint      string            `json:"endpoint,omitempty"`
	LocalAPIURL   string            `json:"local_api_url,omitempty"`
	CredentialRef string            `json:"credential_ref,omitempty"`
	ConfigRef     string            `json:"config_ref,omitempty"`
	ProfileRef    string            `json:"profile_ref,omitempty"`
	Fields        map[string]string `json:"fields,omitempty"`
}

type ProviderRouteReadiness struct {
	ProviderID           string            `json:"provider_id"`
	RouteID              string            `json:"route_id"`
	ProtocolMode         string            `json:"protocol_mode"`
	RouteBinding         string            `json:"route_binding"`
	RouteStrategy        string            `json:"route_strategy,omitempty"`
	ConduitMode          string            `json:"conduit_mode,omitempty"`
	ProviderChain        string            `json:"provider_chain,omitempty"`
	FrontingPolicy       string            `json:"fronting_policy,omitempty"`
	LANSharing           bool              `json:"lan_sharing,omitempty"`
	BeastMode            bool              `json:"beast_mode,omitempty"`
	ReadinessState       string            `json:"readiness_state"`
	Status               string            `json:"status"`
	SOCKSPort            int               `json:"socks_port,omitempty"`
	HTTPProxyPort        int               `json:"http_proxy_port,omitempty"`
	LANSOCKSPort         int               `json:"lan_socks_port,omitempty"`
	LANHTTPProxyPort     int               `json:"lan_http_proxy_port,omitempty"`
	ExternalVPNObserved  bool              `json:"external_vpn_observed,omitempty"`
	LocalProxyObserved   bool              `json:"local_proxy_observed,omitempty"`
	DNSPolicyObserved    string            `json:"dns_policy_observed,omitempty"`
	InterfaceHint        string            `json:"interface_hint,omitempty"`
	ErrorCode            string            `json:"error_code,omitempty"`
	Evidence             map[string]string `json:"evidence,omitempty"`
	LastTransitionUnixMS int64             `json:"last_transition_unix_ms"`
}

type ConnectivitySnapshotter interface {
	Snapshot(ctx context.Context) (ConnectivitySnapshot, error)
}

type ConnectivitySnapshot struct {
	ExternalIP       string
	DNSResolvers     []string
	Interfaces       []string
	DefaultInterface string
	HTTPProxy        string
	SOCKSProxy       string
}

type RoutingPluginConfigValidation struct {
	Valid          bool                    `json:"valid"`
	RouteID        string                  `json:"route_id"`
	PluginID       string                  `json:"plugin_id"`
	PluginType     string                  `json:"plugin_type"`
	RouteType      string                  `json:"route_type"`
	RemoteDNS      bool                    `json:"remote_dns"`
	AuthMode       string                  `json:"auth_mode,omitempty"`
	ProtocolMode   string                  `json:"protocol_mode,omitempty"`
	DNSPolicy      string                  `json:"dns_policy,omitempty"`
	SplitTunnel    string                  `json:"split_tunnel,omitempty"`
	UpstreamMode   string                  `json:"upstream_mode,omitempty"`
	DownstreamMode string                  `json:"downstream_mode,omitempty"`
	RouteBinding   string                  `json:"route_binding,omitempty"`
	RouteStrategy  string                  `json:"route_strategy,omitempty"`
	ConduitMode    string                  `json:"conduit_mode,omitempty"`
	ProviderChain  string                  `json:"provider_chain,omitempty"`
	FrontingPolicy string                  `json:"fronting_policy,omitempty"`
	LANSharing     bool                    `json:"lan_sharing"`
	BeastMode      bool                    `json:"beast_mode"`
	DryRunOnly     bool                    `json:"dry_run_only"`
	Attachable     bool                    `json:"attachable"`
	ReadinessProbe string                  `json:"readiness_probe,omitempty"`
	Capabilities   []string                `json:"capabilities,omitempty"`
	Components     []string                `json:"components,omitempty"`
	Observations   []string                `json:"observations,omitempty"`
	Observation    RouteObservationPreview `json:"observation_template"`
	RedactedConfig map[string]string       `json:"redacted_config"`
	Warnings       []string                `json:"warnings,omitempty"`
	Descriptor     RoutingPluginDescriptor `json:"descriptor"`
}

type RouteObservationPreview struct {
	SchemaVersion      int            `json:"schema_version"`
	ObservationID      string         `json:"observation_id"`
	RouteID            string         `json:"route_id"`
	RouteType          string         `json:"route_type"`
	RouteBinding       string         `json:"route_binding"`
	NetworkPath        string         `json:"network_path"`
	ProviderID         *string        `json:"provider_id"`
	ProtocolMode       *string        `json:"protocol_mode"`
	AuthMode           *string        `json:"auth_mode"`
	DNSPolicy          string         `json:"dns_policy"`
	RemoteDNSRequested bool           `json:"remote_dns_requested"`
	RemoteDNSObserved  *bool          `json:"remote_dns_observed"`
	SplitTunnel        *string        `json:"split_tunnel"`
	UpstreamMode       *string        `json:"upstream_mode"`
	DownstreamMode     *string        `json:"downstream_mode"`
	ProxyGatewayMode   *string        `json:"proxy_gateway_mode"`
	RouteStrategy      *string        `json:"route_strategy,omitempty"`
	ConduitMode        *string        `json:"conduit_mode,omitempty"`
	ProviderChain      *string        `json:"provider_chain,omitempty"`
	FrontingPolicy     *string        `json:"fronting_policy,omitempty"`
	LANSharing         bool           `json:"lan_sharing,omitempty"`
	BeastMode          bool           `json:"beast_mode,omitempty"`
	ReadinessState     string         `json:"readiness_state"`
	Status             string         `json:"status"`
	LatencyMS          float64        `json:"latency_ms"`
	ErrorCode          *string        `json:"error_code"`
	Evidence           map[string]any `json:"evidence"`
}

func containsCRLF(values ...string) bool {
	for _, value := range values {
		if strings.ContainsAny(value, "\r\n") {
			return true
		}
	}
	return false
}

func allowedValue(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func validateProxyEndpoint(endpoint string) error {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return fmt.Errorf("%w: generic proxy endpoint is required", errPluginConfig)
	}
	if containsCRLF(endpoint) {
		return fmt.Errorf("%w: endpoint must not contain CR/LF", errPluginConfig)
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("%w: invalid proxy endpoint: %v", errPluginConfig, err)
	}
	if parsed.User != nil {
		return fmt.Errorf("%w: endpoint must not contain inline credentials", errPluginConfig)
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return fmt.Errorf("%w: proxy endpoint must not contain path, query, or fragment", errPluginConfig)
	}
	if !allowedValue(parsed.Scheme, "socks5", "http", "http-connect") {
		return fmt.Errorf("%w: proxy endpoint scheme must be socks5, http, or http-connect", errPluginConfig)
	}
	if strings.TrimSpace(parsed.Hostname()) == "" || !validPort(parsed.Port()) {
		return fmt.Errorf("%w: proxy endpoint must include host and numeric port", errPluginConfig)
	}
	return nil
}

func isLoopbackHost(host string) bool {
	host = strings.Trim(strings.ToLower(host), "[]")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validPort(port string) bool {
	n, err := strconv.Atoi(port)
	return err == nil && n > 0 && n <= 65535
}

func normalizedProtocolMode(plugin RoutingPluginDescriptor, cfg RoutingPluginConfig) string {
	mode := strings.TrimSpace(strings.ToLower(cfg.Fields["mode"]))
	if mode != "" {
		if plugin.PluginType == "windscribe" && mode == "tcp" {
			return "openvpn_tcp"
		}
		return mode
	}
	switch plugin.PluginType {
	case "psiphon":
		return "tunnel_core_supervised"
	case "windscribe":
		return "external_vpn"
	default:
		return plugin.RouteType
	}
}

func routeBindingForPlugin(plugin RoutingPluginDescriptor, cfg RoutingPluginConfig) string {
	switch plugin.PluginType {
	case "psiphon":
		mode := normalizedProtocolMode(plugin, cfg)
		if mode == "external_vpn_apk" || mode == "external_vpn" {
			return "external_vpn_observation"
		}
		return "tunnel_core_local_proxy"
	case "windscribe":
		switch normalizedProtocolMode(plugin, cfg) {
		case "local_proxy":
			return "local_proxy_gateway"
		case "openvpn_udp", "openvpn_tcp", "stealth", "wstunnel", "wireguard", "ikev2":
			return "profile_backed_vpn_or_proxy"
		default:
			return "external_vpn_observation"
		}
	case "generic_proxy":
		return "generic_local_proxy"
	default:
		return "custom_route"
	}
}

func normalizedRouteStrategy(plugin RoutingPluginDescriptor, cfg RoutingPluginConfig) string {
	strategy := normalizedField(cfg, "route_strategy", "")
	if strategy == "" && plugin.PluginType == "psiphon" {
		strategy = normalizedField(cfg, "protocol_selection", "")
	}
	if strategy != "" {
		return strategy
	}
	switch plugin.PluginType {
	case "psiphon":
		return "auto"
	case "windscribe":
		return "provider_default"
	default:
		return "direct"
	}
}

func normalizedProviderChain(cfg RoutingPluginConfig) string {
	return normalizedField(cfg, "provider_chain", "none")
}

func lanSharingEnabled(cfg RoutingPluginConfig) bool {
	return normalizedField(cfg, "share_proxy_on_lan", "false") == "true" || normalizedField(cfg, "proxy_gateway_scope", "loopback_only") == "lan_shared"
}

func normalizedField(cfg RoutingPluginConfig, key, fallback string) string {
	if cfg.Fields == nil {
		return fallback
	}
	value := strings.TrimSpace(strings.ToLower(cfg.Fields[key]))
	if value == "" {
		return fallback
	}
	return value
}
