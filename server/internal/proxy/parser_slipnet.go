package proxy

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// SlipNetDecoder decodes SlipNet (.slipnet-enc) configs.
type SlipNetDecoder struct{}

var slipnetV1 = []string{"Version", "Tunnel Type/Mode", "Name", "Domain", "Resolvers", "AuthMode", "KeepAlive", "CC", "Port", "Host", "GSO"}

var slipnetV20 = []string{
	"Version", "Tunnel Type/Mode", "Name", "Domain", "Resolvers", "AuthMode", "KeepAlive", "CC", "Port", "Host", "GSO",
	"DNSTT Public Key", "SOCKS Username", "SOCKS Password", "SSH Enabled", "SSH Username",
	"SSH Password", "SSH Port", "Forward DNS thru SSH", "SSH Host", "Use Server DNS",
	"DoH URL", "DNS Transport", "SSH Auth Type", "SSH Private Key (B64)", "SSH Key Passphrase (B64)",
	"Tor Bridge Lines (B64)", "DNSTT Authoritative", "Naive Port", "Naive Username", "Naive Password (B64)",
	"Is Locked", "Lock Password Hash", "Expiration Date", "Allow Sharing", "Bound Device ID",
	"Resolvers Hidden", "Hidden Resolvers", "NoizDNS Stealth", "DNS Payload Size", "SOCKS5 Server Port",
	"VayDNS DNSTT Compat", "VayDNS Record Type", "VayDNS Max Qname Len", "VayDNS RPS", "VayDNS Idle Timeout",
	"VayDNS Keepalive", "VayDNS UDP Timeout", "VayDNS Max Num Labels", "VayDNS Client Id Size",
}

var slipnetV21 = append(slipnetV20,
	"SSH TLS Enabled", "SSH TLS SNI", "SSH HTTP Proxy Host", "SSH HTTP Proxy Port", "SSH HTTP Proxy Custom Host",
	"SSH WS Enabled", "SSH WS Path", "SSH WS Use TLS", "SSH WS Custom Host",
)

var slipnetV22 = append(slipnetV21, "SSH Payload (B64)")

var slipnetV24 = append(slipnetV22, "Resolver Mode", "RR Spread Count")

var slipnetV25 = append(slipnetV24,
	"VLESS UUID", "VLESS Security", "VLESS Transport", "VLESS WS Path", "CDN IP",
	"CDN Port", "SNI Fragment Enabled", "SNI Fragment Strategy", "SNI Fragment Delay MS", "Legacy SNI (Empty)",
)

var slipnetV27 = append(slipnetV25,
	"CH Padding Enabled", "WS Header Obfuscation", "WS Padding Enabled",
	"SNI Spoof TTL", "Fake Decoy Host", "TCP Max Seg",
)

var slipnetV28 = append(slipnetV27, "VLESS SNI")

func getSlipNetField(parts []string, label string) string {
	if len(parts) == 0 {
		return ""
	}
	versionStr := parts[0]
	var schema []string
	switch versionStr {
	case "28":
		schema = slipnetV28
	case "27", "26":
		schema = slipnetV27
	case "25":
		schema = slipnetV25
	case "24", "23":
		schema = slipnetV24
	case "22":
		schema = slipnetV22
	case "21":
		schema = slipnetV21
	case "20":
		schema = slipnetV20
	default:
		schema = slipnetV1
	}

	for idx, fieldName := range schema {
		if fieldName == label && idx < len(parts) {
			return parts[idx]
		}
	}
	return ""
}

func (d *SlipNetDecoder) CanDecode(data []byte) bool {
	s := string(data)
	return strings.HasPrefix(s, "slipnet-enc://")
}

func (d *SlipNetDecoder) Decode(data []byte) (*ProxyConfig, error) {
	s := strings.TrimSpace(string(data))
	if !strings.HasPrefix(s, "slipnet-enc://") {
		return nil, fmt.Errorf("invalid slipnet scheme")
	}

	payloadB64 := strings.TrimPrefix(s, "slipnet-enc://")
	payloadB64 = strings.ReplaceAll(payloadB64, "-", "+")
	payloadB64 = strings.ReplaceAll(payloadB64, "_", "/")
	for len(payloadB64)%4 != 0 {
		payloadB64 += "="
	}

	payload, err := base64.StdEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode slipnet base64: %w", err)
	}

	if len(payload) < 13 {
		return nil, fmt.Errorf("slipnet payload too short")
	}

	version := payload[0]
	if version != 0x01 {
		return nil, fmt.Errorf("unsupported slipnet payload version: 0x%x", version)
	}

	iv := payload[1:13]
	ciphertext := payload[13:]

	// Key assembly via XOR (from Slipnet decoder.html)
	s0, m0 := uint64(0x1c8986f91dd8ec9a), uint64(0x557034dc3ddda3bb)
	s1, m1 := uint64(0xc70a4a42712024ee), uint64(0x6f5577ae58747e8e)
	s2, m2 := uint64(0x924d4af0d8a43e0b), uint64(0xfcd9e79819861e07)
	s3, m3 := uint64(0x4a5573b012f4d08b), uint64(0x998e67c256d955e3)

	key := make([]byte, 32)
	binary.LittleEndian.PutUint64(key[0:8], s0^m0)
	binary.LittleEndian.PutUint64(key[8:16], s1^m1)
	binary.LittleEndian.PutUint64(key[16:24], s2^m2)
	binary.LittleEndian.PutUint64(key[24:32], s3^m3)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	decrypted, err := aesgcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt slipnet payload: %w", err)
	}

	decryptedText := strings.TrimSuffix(string(decrypted), "|")
	parts := strings.Split(decryptedText, "|")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid decrypted slipnet format")
	}

	tunnelMode := getSlipNetField(parts, "Tunnel Type/Mode")
	name := getSlipNetField(parts, "Name")

	address := getSlipNetField(parts, "Domain")
	if address == "" {
		address = getSlipNetField(parts, "Host")
	}
	if address == "" {
		address = getSlipNetField(parts, "CDN IP")
	}

	portStr := getSlipNetField(parts, "Port")
	if portStr == "" {
		portStr = getSlipNetField(parts, "CDN Port")
	}
	port, _ := strconv.Atoi(portStr)

	// If tunnelMode is VLESS
	if strings.Contains(strings.ToLower(tunnelMode), "vless") {
		uuid := getSlipNetField(parts, "VLESS UUID")
		sni := getSlipNetField(parts, "VLESS SNI")
		if sni == "" {
			sni = getSlipNetField(parts, "Domain")
		}
		path := getSlipNetField(parts, "VLESS WS Path")
		transport := getSlipNetField(parts, "VLESS Transport")

		return &ProxyConfig{
			Protocol:  ProtocolVLESS,
			Name:      name,
			Address:   address,
			Port:      port,
			UUID:      uuid,
			TLS:       true,
			SNI:       sni,
			Path:      path,
			Transport: transport,
		}, nil
	}

	// If NaiveProxy settings are present
	naivePortStr := getSlipNetField(parts, "Naive Port")
	if naivePortStr != "" {
		naivePort, _ := strconv.Atoi(naivePortStr)
		naiveUsername := getSlipNetField(parts, "Naive Username")
		naivePassB64 := getSlipNetField(parts, "Naive Password (B64)")
		var naivePass string
		if decodedPass, err := base64.StdEncoding.DecodeString(naivePassB64); err == nil {
			naivePass = string(decodedPass)
		} else {
			naivePass = naivePassB64
		}

		return &ProxyConfig{
			Protocol: ProtocolNaive,
			Name:     name,
			Address:  address,
			Port:     naivePort,
			UUID:     naiveUsername,
			Password: naivePass,
			TLS:      true,
			SNI:      address,
		}, nil
	}

	// Default fallback to SOCKS5 or standard fields if available
	return &ProxyConfig{
		Protocol: ProtocolSOCKS5,
		Name:     name,
		Address:  address,
		Port:     port,
		RawURI:   s,
	}, nil
}

func decryptSlipNetLink(link string) (string, error) {
	d := &SlipNetDecoder{}
	cfg, err := d.Decode([]byte(link))
	if err != nil {
		return "", err
	}
	// Return reconstructed config URL format or JSON string representation
	u := url.URL{
		Scheme: string(cfg.Protocol),
		Host:   fmt.Sprintf("%s:%d", cfg.Address, cfg.Port),
	}
	return u.String(), nil
}
