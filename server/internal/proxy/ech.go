package proxy

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

var (
	// ECHInsecureSkipVerify controls whether client skips verification of server certificates.
	ECHInsecureSkipVerify = true

	// ECHRootCAs defines the custom Root CA pool to use for certificate verification.
	ECHRootCAs *x509.CertPool
)

// ECHConfig represents a decrypted/parsed ECH configuration block.
type ECHConfig struct {
	Version    uint16
	PublicName string
	KEMID      uint16
	PublicKey  []byte
}

// ECHKeyCache represents a cached ECH key block with an expiration time to avoid handshake failures.
type ECHKeyCache struct {
	Base64Config string
	ExpiresAt    time.Time
}

// IsExpired returns true if the cached ECH key has passed its expiration time.
func (k *ECHKeyCache) IsExpired() bool {
	return time.Now().After(k.ExpiresAt)
}

// ParseECHConfigList parses a serialized ECHConfigList (either raw bytes or base64 encoded string).
func ParseECHConfigList(data string) ([]*ECHConfig, error) {
	var raw []byte
	var err error

	data = strings.TrimSpace(data)
	if strings.Contains(data, "=") || len(data) > 20 {
		raw, err = base64.RawStdEncoding.DecodeString(data)
		if err != nil {
			raw, err = base64.StdEncoding.DecodeString(data)
			if err != nil {
				raw = []byte(data)
			}
		}
	} else {
		raw = []byte(data)
	}

	if len(raw) < 4 {
		return nil, errors.New("ECH config list too short")
	}

	var configs []*ECHConfig
	offset := 0

	firstWord := uint16(raw[0])<<8 | uint16(raw[1])
	if firstWord != 0xfe0d {
		listLen := int(firstWord)
		if listLen+2 <= len(raw) {
			raw = raw[2 : listLen+2]
		}
	}

	for offset < len(raw) {
		if len(raw)-offset < 4 {
			break
		}
		version := uint16(raw[offset])<<8 | uint16(raw[offset+1])
		length := uint16(raw[offset+2])<<8 | uint16(raw[offset+3])
		offset += 4

		if offset+int(length) > len(raw) {
			return nil, fmt.Errorf("malformed ECH config: length field exceeds remaining bytes")
		}

		configBytes := raw[offset : offset+int(length)]
		offset += int(length)

		if version != 0xfe0d {
			continue
		}

		if len(configBytes) < 4 {
			continue
		}

		cfgOffset := 1 // skip config_id
		kemID := uint16(configBytes[cfgOffset])<<8 | uint16(configBytes[cfgOffset+1])
		cfgOffset += 2

		if len(configBytes)-cfgOffset < 2 {
			continue
		}
		pubKeyLen := uint16(configBytes[cfgOffset])<<8 | uint16(configBytes[cfgOffset+1])
		cfgOffset += 2

		if len(configBytes)-cfgOffset < int(pubKeyLen) {
			continue
		}
		pubKey := configBytes[cfgOffset : cfgOffset+int(pubKeyLen)]
		cfgOffset += int(pubKeyLen)

		if len(configBytes)-cfgOffset < 2 {
			continue
		}
		ciphersLen := uint16(configBytes[cfgOffset])<<8 | uint16(configBytes[cfgOffset+1])
		cfgOffset += 2 + int(ciphersLen)

		cfgOffset += 1 // maximum name length

		if len(configBytes)-cfgOffset < 1 {
			continue
		}
		publicNameLen := int(configBytes[cfgOffset])
		cfgOffset += 1

		if len(configBytes)-cfgOffset < publicNameLen {
			continue
		}
		publicName := string(configBytes[cfgOffset : cfgOffset+publicNameLen])

		configs = append(configs, &ECHConfig{
			Version:    version,
			PublicName: publicName,
			KEMID:      kemID,
			PublicKey:  pubKey,
		})
	}

	if len(configs) == 0 {
		return nil, errors.New("no valid ECH v5 configurations found")
	}

	return configs, nil
}

// DialECH establishes a TLS connection using ECH, falling back to Domain Fronting if ECH fails.
func DialECH(ctx context.Context, network, addr, hostname, echConfigB64 string, fallbackSNI string) (net.Conn, error) {
	echConf, err := base64.RawStdEncoding.DecodeString(echConfigB64)
	if err != nil {
		echConf, err = base64.StdEncoding.DecodeString(echConfigB64)
	}

	if err != nil {
		return dialFallbackFronting(ctx, network, addr, hostname, fallbackSNI)
	}

	configs, err := ParseECHConfigList(echConfigB64)
	outerSNI := fallbackSNI
	if err == nil && len(configs) > 0 {
		outerSNI = configs[0].PublicName
	}
	if outerSNI == "" {
		outerSNI = hostname
	}

	// Randomize outer SNI names to prevent endpoint mapping if using wildcard hostnames
	if strings.HasPrefix(outerSNI, "public.") {
		outerSNI = getRandomPrefix() + "." + strings.TrimPrefix(outerSNI, "public.")
	}

	var dialer net.Dialer
	tcpConn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial TCP: %w", err)
	}

	config := &utls.Config{
		ServerName:                     hostname,
		EncryptedClientHelloConfigList: echConf,
		InsecureSkipVerify:             ECHInsecureSkipVerify,
		RootCAs:                        ECHRootCAs,
	}

	uconn := utls.UClient(tcpConn, config, utls.HelloChrome_120)
	err = uconn.HandshakeContext(ctx)
	if err != nil {
		tcpConn.Close()
		// Handshake failed (e.g. key expired at target) -> fallback to Domain Fronting
		return dialFallbackFronting(ctx, network, addr, hostname, fallbackSNI)
	}

	return uconn, nil
}

func dialFallbackFronting(ctx context.Context, network, addr, hostname, frontingSNI string) (net.Conn, error) {
	var dialer net.Dialer
	tcpConn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, fmt.Errorf("fallback tcp dial failed: %w", err)
	}

	serverName := frontingSNI
	if serverName == "" {
		serverName = hostname
	}

	config := &utls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: ECHInsecureSkipVerify,
		RootCAs:            ECHRootCAs,
	}

	uconn := utls.UClient(tcpConn, config, utls.HelloChrome_Auto)
	err = uconn.HandshakeContext(ctx)
	if err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("fallback domain fronting handshake failed: %w", err)
	}

	return uconn, nil
}

func getRandomPrefix() string {
	chars := "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 8)
	for i := range b {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		b[i] = chars[n.Int64()]
	}
	return string(b)
}

// TinyTunClient represents a lightweight TLS tunnel config.
type TinyTunClient struct {
	ServerAddr string
	TLSConfig  *utls.Config
}

// NewTinyTunClient instantiates a new TinyTun Client.
func NewTinyTunClient(serverAddr string, sni string) *TinyTunClient {
	return &TinyTunClient{
		ServerAddr: serverAddr,
		TLSConfig: &utls.Config{
			ServerName:         sni,
			InsecureSkipVerify: ECHInsecureSkipVerify,
			RootCAs:            ECHRootCAs,
		},
	}
}

// Dial establishes a lightweight TLS tunnel connection.
func (t *TinyTunClient) Dial(ctx context.Context) (net.Conn, error) {
	var dialer net.Dialer
	tcpConn, err := dialer.DialContext(ctx, "tcp", t.ServerAddr)
	if err != nil {
		return nil, err
	}
	uconn := utls.UClient(tcpConn, t.TLSConfig, utls.HelloChrome_Auto)
	err = uconn.HandshakeContext(ctx)
	if err != nil {
		tcpConn.Close()
		return nil, err
	}
	return uconn, nil
}
