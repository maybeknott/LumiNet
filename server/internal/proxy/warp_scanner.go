package proxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"
)

// WireGuard Handshake Initiation Packet Constants
const (
	wgHandshakeType     = 1 // initiation
	wgHandshakeLen      = 148
	wgEncryptedStatic   = 48 // 32 key + 16 auth tag
	wgEncryptedTime     = 28 // 12 time + 16 auth tag
)

// ConstructWireGuardHandshake creates a valid-looking WireGuard initiation packet.
func ConstructWireGuardHandshake() []byte {
	packet := make([]byte, wgHandshakeLen)

	// 1. Type (1 byte)
	packet[0] = wgHandshakeType

	// 2. Reserved (3 bytes) - Zeroed by make()

	// 3. Sender Index (4 bytes) - Random arbitrary ID
	if _, err := rand.Read(packet[4:8]); err != nil {
		return nil
	}

	// 4. Ephemeral Public Key (32 bytes)
	var priv [32]byte
	var pub [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return nil
	}
	curve25519.ScalarBaseMult(&pub, &priv)
	copy(packet[8:40], pub[:])

	// 5. Encrypted Static & Timestamp (48 + 28 bytes)
	if _, err := rand.Read(packet[40 : 40+wgEncryptedStatic+wgEncryptedTime]); err != nil {
		return nil
	}

	return packet
}

// ConstructWireGuardHandshakeWithObfuscation creates a WireGuard initiation packet
// with custom obfuscation payload layouts applied if ifpm mode is specified.
func ConstructWireGuardHandshakeWithObfuscation(ifpm string) []byte {
	packet := ConstructWireGuardHandshake()
	if packet == nil || ifpm == "" {
		return packet
	}

	ifpm = strings.TrimSpace(strings.ToLower(ifpm))

	// Handle m1..m6 modes (randomized/QUIC long or short headers)
	var modeBytes []byte
	switch ifpm {
	case "m1":
		modeBytes = make([]byte, 4)
		if _, err := rand.Read(modeBytes); err == nil {
			modeBytes[0] = 0xc0 | (modeBytes[0] & 0x3f)
		}
	case "m2":
		modeBytes = make([]byte, 8)
		if _, err := rand.Read(modeBytes); err == nil {
			modeBytes[0] = 0xc0 | (modeBytes[0] & 0x3f)
		}
	case "m3":
		modeBytes = make([]byte, 16)
		if _, err := rand.Read(modeBytes); err == nil {
			modeBytes[0] = 0xc0 | (modeBytes[0] & 0x3f)
		}
	case "m4":
		modeBytes = make([]byte, 4)
		if _, err := rand.Read(modeBytes); err == nil {
			modeBytes[0] = 0x40 | (modeBytes[0] & 0x3f)
		}
	case "m5":
		modeBytes = make([]byte, 8)
		if _, err := rand.Read(modeBytes); err == nil {
			modeBytes[0] = 0x40 | (modeBytes[0] & 0x3f)
		}
	case "m6":
		modeBytes = make([]byte, 16)
		if _, err := rand.Read(modeBytes); err == nil {
			modeBytes[0] = 0x40 | (modeBytes[0] & 0x3f)
		}
	}

	if len(modeBytes) > 0 {
		copy(packet[4:], modeBytes)
		return packet
	}

	// Handle hHEX and gHEX modes (hex-encoded custom obfuscation layout)
	if strings.HasPrefix(ifpm, "h") {
		hexBytes, err := hex.DecodeString(ifpm[1:])
		if err == nil && len(hexBytes) > 0 {
			copy(packet[4:], hexBytes)
		}
	} else if strings.HasPrefix(ifpm, "g") {
		hexBytes, err := hex.DecodeString(ifpm[1:])
		if err == nil && len(hexBytes) > 0 {
			copy(packet[4:], hexBytes)
		}
	}

	return packet
}


// WarpNoiseType specifies the noise payload type
type WarpNoiseType string

const (
	NoiseRandom WarpNoiseType = "Random"
	NoiseHex    WarpNoiseType = "Hex"
	NoiseBase64 WarpNoiseType = "Base64"
	NoiseString WarpNoiseType = "String"
)

// WarpScanConfig defines parameters for a WARP endpoint scan
type WarpScanConfig struct {
	Endpoints   []string      // List of candidate IP:port endpoints
	NoiseType   WarpNoiseType // Noise payload generation strategy
	NoiseVal    string        // Raw value for Hex/Base64/String strategies
	NoiseCount  int           // Number of noise packets to send
	NoiseMinLen int           // Min length for random noise
	NoiseMaxLen int           // Max length for random noise
	Ifpm        string        // Obfuscation layout selector (m1..m6, hHEX, gHEX)
	Timeout     time.Duration // Timeout per endpoint test
	Concurrency int           // Concurrent workers
}

// WarpEndpointResult represents the outcome of a scanned endpoint
type WarpEndpointResult struct {
	Endpoint string
	RTT      time.Duration
	Error    error
}

// WarpScanner handles registration and validation of WARP endpoints
type WarpScanner struct{}

// NewWarpScanner creates a new scanner instance
func NewWarpScanner() *WarpScanner {
	return &WarpScanner{}
}

// Scan concurrently tests WARP endpoints for latency and responsiveness
func (ws *WarpScanner) Scan(ctx context.Context, cfg WarpScanConfig) ([]WarpEndpointResult, error) {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 10
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 2 * time.Second
	}

	endpointsChan := make(chan string, len(cfg.Endpoints))
	for _, ep := range cfg.Endpoints {
		endpointsChan <- ep
	}
	close(endpointsChan)

	resultsChan := make(chan WarpEndpointResult, len(cfg.Endpoints))
	var wg sync.WaitGroup

	for i := 0; i < cfg.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ep := range endpointsChan {
				select {
				case <-ctx.Done():
					resultsChan <- WarpEndpointResult{Endpoint: ep, Error: ctx.Err()}
					continue
				default:
				}

				rtt, err := ws.testEndpoint(ctx, ep, cfg)
				resultsChan <- WarpEndpointResult{
					Endpoint: ep,
					RTT:      rtt,
					Error:    err,
				}
			}
		}()
	}

	wg.Wait()
	close(resultsChan)

	var results []WarpEndpointResult
	for r := range resultsChan {
		results = append(results, r)
	}

	return results, nil
}

// GenerateNoisePayload formats a custom payload based on config parameters
func (ws *WarpScanner) GenerateNoisePayload(cfg WarpScanConfig) ([]byte, error) {
	switch cfg.NoiseType {
	case NoiseHex:
		return hex.DecodeString(cfg.NoiseVal)
	case NoiseBase64:
		return base64.StdEncoding.DecodeString(cfg.NoiseVal)
	case NoiseString:
		return []byte(cfg.NoiseVal), nil
	case NoiseRandom:
		fallthrough
	default:
		minL, maxL := cfg.NoiseMinLen, cfg.NoiseMaxLen
		if minL <= 0 {
			minL = 50
		}
		if maxL < minL {
			maxL = minL + 50
		}
		delta := maxL - minL + 1
		nBig, err := rand.Int(rand.Reader, big.NewInt(int64(delta)))
		if err != nil {
			return nil, err
		}
		length := int(nBig.Int64()) + minL
		buf := make([]byte, length)
		if _, err := rand.Read(buf); err != nil {
			return nil, err
		}
		return buf, nil
	}
}

func (ws *WarpScanner) testEndpoint(ctx context.Context, ep string, cfg WarpScanConfig) (time.Duration, error) {
	d := net.Dialer{
		Timeout: cfg.Timeout,
	}

	start := time.Now()
	conn, err := d.DialContext(ctx, "udp", ep)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	// Configure deadlines
	if err := conn.SetDeadline(time.Now().Add(cfg.Timeout)); err != nil {
		return 0, err
	}

	// Send UDP noise packets if configured
	if cfg.NoiseCount > 0 {
		payload, err := ws.GenerateNoisePayload(cfg)
		if err != nil {
			return 0, fmt.Errorf("noise payload generation failed: %w", err)
		}
		for i := 0; i < cfg.NoiseCount; i++ {
			if _, err := conn.Write(payload); err != nil {
				return 0, fmt.Errorf("failed writing noise payload: %w", err)
			}
		}
	}

	// Ping exchange: send a valid WireGuard initiation packet to trigger a response
	pingPayload := ConstructWireGuardHandshakeWithObfuscation(cfg.Ifpm)
	if pingPayload == nil {
		pingPayload = []byte{0x00, 0x00, 0x00, 0x00}
	}
	if _, err := conn.Write(pingPayload); err != nil {
		return 0, err
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		// Since endpoint might not send data back unless authenticated,
		// we treat successful UDP write and no immediate port-unreachable error
		// as a validation signal, but if data is received we calculate the exact RTT.
		return time.Since(start), nil
	}

	if n > 0 {
		// Validate response type (2 = Response, 3 = Cookie Reply, 4 = Under Load)
		msgType := buf[0]
		if msgType != 2 && msgType != 3 && msgType != 4 {
			return 0, fmt.Errorf("invalid WireGuard response type: %d", msgType)
		}
		return time.Since(start), nil
	}

	return time.Since(start), nil
}

// WarpKeyPair represents a WireGuard key pair
type WarpKeyPair struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

// WarpRegisterResponse represents Cloudflare client registration response
type WarpRegisterResponse struct {
	Config struct {
		Interface struct {
			Addresses struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"addresses"`
		} `json:"interface"`
		ClientID string `json:"client_id"`
		Peers    []struct {
			PublicKey string `json:"public_key"`
			Endpoint  struct {
				Host string `json:"host"`
				V4   string `json:"v4"`
				V6   string `json:"v6"`
			} `json:"endpoint"`
		} `json:"peers"`
	} `json:"config"`
}

// WarpParams holds the extracted params for custom WireGuard/WARP profiles
type WarpParams struct {
	IPv4       string `json:"ipv4"`
	IPv6       string `json:"ipv6"`
	Reserved   []int  `json:"reserved"`
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
	ClientID   string `json:"client_id"`
}

// GenerateWireGuardKeyPair generates a WireGuard public and private key pair using Curve25519
func (ws *WarpScanner) GenerateWireGuardKeyPair() (publicKey, privateKey string, err error) {
	privateKeyBytes := make([]byte, 32)
	if _, err = rand.Read(privateKeyBytes); err != nil {
		return "", "", fmt.Errorf("error generating wireguard private key: %w", err)
	}

	privateKeyBytes[0] &= 248
	privateKeyBytes[31] &= 127
	privateKeyBytes[31] |= 64

	var publicKeyBytes [32]byte
	curve25519.ScalarBaseMult(&publicKeyBytes, (*[32]byte)(privateKeyBytes))

	publicKey = base64.StdEncoding.EncodeToString(publicKeyBytes[:])
	privateKey = base64.StdEncoding.EncodeToString(privateKeyBytes)

	return publicKey, privateKey, nil
}

// Base64ToDecimal converts a base64 string to a decimal slice of ints
func (ws *WarpScanner) Base64ToDecimal(base64Str string) ([]int, error) {
	decoded, err := base64.StdEncoding.DecodeString(base64Str)
	if err != nil {
		return nil, fmt.Errorf("error decoding reserved: %w", err)
	}

	decimalArray := make([]int, len(decoded))
	for i, b := range decoded {
		decimalArray[i] = int(b)
	}
	return decimalArray, nil
}

// RegisterAccount calls Cloudflare API to register a new WARP account and returns its params
func (ws *WarpScanner) RegisterAccount(ctx context.Context, client *http.Client) (*WarpParams, error) {
	if client == nil {
		client = &http.Client{
			Timeout: 15 * time.Second,
		}
	}

	pubKey, privKey, err := ws.GenerateWireGuardKeyPair()
	if err != nil {
		return nil, err
	}

	payload := map[string]interface{}{
		"install_id":   "",
		"fcm_token":    "",
		"tos":          time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		"type":         "Android",
		"model":        "PC",
		"locale":       "en_US",
		"warp_enabled": true,
		"key":          pubKey,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("error marshaling warp reg payload: %w", err)
	}

	apiBaseURL := "https://api.cloudflareclient.com/v0a4005/reg"
	req, err := http.NewRequestWithContext(ctx, "POST", apiBaseURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("error creating warp reg request: %w", err)
	}

	req.Header.Set("User-Agent", "insomnia/8.6.1")
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending warp reg request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Cloudflare API error (status %d): %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading warp config: %w", err)
	}

	var regResp WarpRegisterResponse
	if err := json.Unmarshal(body, &regResp); err != nil {
		return nil, fmt.Errorf("failed to parse API response: %w", err)
	}

	reserved, err := ws.Base64ToDecimal(regResp.Config.ClientID)
	if err != nil {
		return nil, fmt.Errorf("error extracting warp client id / reserved bytes: %w", err)
	}

	ipv6Addr := regResp.Config.Interface.Addresses.V6
	if ipv6Addr != "" {
		ipv6Addr = ipv6Addr + "/128"
	}
	ipv4Addr := regResp.Config.Interface.Addresses.V4
	if ipv4Addr != "" {
		ipv4Addr = ipv4Addr + "/32"
	}

	peerPubKey := ""
	if len(regResp.Config.Peers) > 0 {
		peerPubKey = regResp.Config.Peers[0].PublicKey
	}

	return &WarpParams{
		IPv4:       ipv4Addr,
		IPv6:       ipv6Addr,
		Reserved:   reserved,
		PublicKey:  peerPubKey,
		PrivateKey: privKey,
		ClientID:   regResp.Config.ClientID,
	}, nil
}

