package proxy

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

// FormatDecoder defines the interface for parsing non-standard or custom encrypted mobile configs.
type FormatDecoder interface {
	Decode(data []byte) (*ProxyConfig, error)
	CanDecode(data []byte) bool
}

type FormatRegistry struct {
	mu       sync.RWMutex
	decoders map[string]FormatDecoder
}

var (
	globalRegistry *FormatRegistry
	onceRegistry   sync.Once
)

// GetFormatRegistry returns the singleton format registry.
func GetFormatRegistry() *FormatRegistry {
	onceRegistry.Do(func() {
		globalRegistry = &FormatRegistry{
			decoders: make(map[string]FormatDecoder),
		}
		// Register default decoders
		globalRegistry.Register("npvt", &NapsternetVDecoder{})
		globalRegistry.Register("hc", &HttpCustomDecoder{})
		globalRegistry.Register("ehi", &HttpInjectorDecoder{})
		globalRegistry.Register("opaque_bundle", &OpaqueBundleDecoder{})
		globalRegistry.Register("nipo", &NipoVPNDecoder{})
		globalRegistry.Register("nm", &NetModDecoder{})
		globalRegistry.Register("slipnet", &SlipNetDecoder{})
		globalRegistry.Register("hctools", &HCToolsDecoder{})
	})
	return globalRegistry
}

func (r *FormatRegistry) Register(name string, d FormatDecoder) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.decoders[strings.ToLower(name)] = d
}

func (r *FormatRegistry) Decode(formatName string, data []byte) (*ProxyConfig, error) {
	r.mu.RLock()
	decoder, ok := r.decoders[strings.ToLower(formatName)]
	r.mu.RUnlock()

	if !ok {
		// Fallback to auto-detect
		return r.AutoDecode(data)
	}

	return decoder.Decode(data)
}

func (r *FormatRegistry) AutoDecode(data []byte) (*ProxyConfig, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for name, decoder := range r.decoders {
		if decoder.CanDecode(data) {
			cfg, err := decoder.Decode(data)
			if err == nil {
				cfg.Name = fmt.Sprintf("%s-auto-decoded", name)
				return cfg, nil
			}
		}
	}
	return nil, fmt.Errorf("no suitable decoder found for config payload")
}

// --- Built-in Decoders ---

// NapsternetVDecoder parses .npvt JSON files.
type NapsternetVDecoder struct{}

type npvtSchema struct {
	V         string `json:"v"`
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Id        string `json:"id"`
	Aid       int    `json:"aid"`
	Net       string `json:"net"`
	Type      string `json:"type"`
	TLS       string `json:"tls"`
	Sni       string `json:"sni"`
	Path      string `json:"path"`
	Prot      string `json:"protocol"`
	Remarks   string `json:"remarks"`
}

func (d *NapsternetVDecoder) CanDecode(data []byte) bool {
	// Simple check: npvt configuration is typically a JSON structure containing a protocol/host/port
	var s npvtSchema
	if err := json.Unmarshal(data, &s); err == nil {
		return s.Host != "" && s.Port > 0 && (s.Prot == "vmess" || s.Prot == "vless" || s.V != "")
	}
	return false
}

func (d *NapsternetVDecoder) Decode(data []byte) (*ProxyConfig, error) {
	var s npvtSchema
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("invalid npvt json format: %w", err)
	}

	protocol := ProtocolVMess
	if s.Prot != "" {
		protocol = ProxyProtocol(strings.ToLower(s.Prot))
	}

	cfg := &ProxyConfig{
		Protocol:  protocol,
		Address:   s.Host,
		Port:      s.Port,
		UUID:      s.Id,
		AlterID:   s.Aid,
		Transport: s.Net,
		TLS:       s.TLS == "tls",
		SNI:       s.Sni,
		Path:      s.Path,
		Name:      s.Remarks,
	}

	return cfg, nil
}

// HttpCustomDecoder parses .hc configurations.
type HttpCustomDecoder struct{}

func (d *HttpCustomDecoder) CanDecode(data []byte) bool {
	s := string(data)
	return strings.HasPrefix(s, "hc://") || (strings.HasPrefix(s, "ey") && json.Valid(data))
}

func (d *HttpCustomDecoder) Decode(data []byte) (*ProxyConfig, error) {
	s := string(data)
	if strings.HasPrefix(s, "hc://") {
		// Parse URL format
		rawStr := strings.TrimPrefix(s, "hc://")
		decoded, err := base64.StdEncoding.DecodeString(rawStr)
		if err != nil {
			return nil, fmt.Errorf("failed to decode base64 payload: %w", err)
		}
		data = decoded
	}

	var rawMap map[string]any
	if err := json.Unmarshal(data, &rawMap); err != nil {
		return nil, fmt.Errorf("invalid hc json format: %w", err)
	}

	// Read fields
	host, _ := rawMap["server"].(string)
	portVal, _ := rawMap["port"]
	var port int
	switch v := portVal.(type) {
	case float64:
		port = int(v)
	case int:
		port = v
	}

	password, _ := rawMap["password"].(string)
	remarks, _ := rawMap["remarks"].(string)

	if host == "" || port <= 0 {
		return nil, fmt.Errorf("invalid host or port in hc configuration")
	}

	return &ProxyConfig{
		Protocol: ProtocolSOCKS5,
		Address:  host,
		Port:     port,
		Password: password,
		Name:     remarks,
	}, nil
}

// HttpInjectorDecoder parses .ehi configuration files.
type HttpInjectorDecoder struct{}

func (d *HttpInjectorDecoder) CanDecode(data []byte) bool {
	return strings.HasPrefix(string(data), "ehi://")
}

func (d *HttpInjectorDecoder) Decode(data []byte) (*ProxyConfig, error) {
	s := string(data)
	if !strings.HasPrefix(s, "ehi://") {
		return nil, fmt.Errorf("invalid ehi scheme")
	}
	raw := strings.TrimPrefix(s, "ehi://")
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ehi base64: %w", err)
	}

	parts := strings.Split(string(decoded), "|")
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid ehi payload parameters")
	}

	host := parts[0]
	var port int
	fmt.Sscanf(parts[1], "%d", &port)
	password := parts[2]

	var name string
	if len(parts) > 3 {
		name = parts[3]
	}

	return &ProxyConfig{
		Protocol: ProtocolShadowsocks,
		Address:  host,
		Port:     port,
		Password: password,
		Method:   "chacha20-ietf-poly1305",
		Name:     name,
	}, nil
}

// OpaqueBundleDecoder parses custom obfuscated bundles.
type OpaqueBundleDecoder struct{}

func (d *OpaqueBundleDecoder) CanDecode(data []byte) bool {
	return strings.HasPrefix(string(data), "opaque:")
}

func (d *OpaqueBundleDecoder) Decode(data []byte) (*ProxyConfig, error) {
	s := string(data)
	if !strings.HasPrefix(s, "opaque:") {
		return nil, fmt.Errorf("invalid opaque bundle scheme")
	}
	raw := strings.TrimPrefix(s, "opaque:")
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to decode opaque base64: %w", err)
	}

	// Simple XOR decryption for demonstration
	for i := range decoded {
		decoded[i] ^= 0x5A
	}

	// The payload is a standard URL scheme or JSON
	if strings.Contains(string(decoded), "://") {
		return ParseProxyURI(string(decoded))
	}

	var config ProxyConfig
	if err := json.Unmarshal(decoded, &config); err != nil {
		return nil, fmt.Errorf("failed to parse decrypted config JSON: %w", err)
	}
	return &config, nil
}

// NipoVPNDecoder parses nipovpn:// configurations.
type NipoVPNDecoder struct{}

func (d *NipoVPNDecoder) CanDecode(data []byte) bool {
	return strings.HasPrefix(string(data), "nipovpn://")
}

func (d *NipoVPNDecoder) Decode(data []byte) (*ProxyConfig, error) {
	return parseNipo(string(data))
}
