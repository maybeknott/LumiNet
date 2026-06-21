package proxy

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestWarpScanner_GenerateNoisePayload(t *testing.T) {
	ws := NewWarpScanner()

	// Test Hex noise
	cfgHex := WarpScanConfig{
		NoiseType: NoiseHex,
		NoiseVal:  "48656c6c6f", // "Hello" in hex
	}
	hexPayload, err := ws.GenerateNoisePayload(cfgHex)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(hexPayload) != "Hello" {
		t.Errorf("expected 'Hello', got %q", string(hexPayload))
	}

	// Test Base64 noise
	cfgB64 := WarpScanConfig{
		NoiseType: NoiseBase64,
		NoiseVal:  base64.StdEncoding.EncodeToString([]byte("Base64Test")),
	}
	b64Payload, err := ws.GenerateNoisePayload(cfgB64)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(b64Payload) != "Base64Test" {
		t.Errorf("expected 'Base64Test', got %q", string(b64Payload))
	}

	// Test Random noise length
	cfgRand := WarpScanConfig{
		NoiseType:   NoiseRandom,
		NoiseMinLen: 100,
		NoiseMaxLen: 200,
	}
	randPayload, err := ws.GenerateNoisePayload(cfgRand)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(randPayload) < 100 || len(randPayload) > 200 {
		t.Errorf("expected random payload size between 100 and 200, got %d", len(randPayload))
	}
}

func TestWarpScanner_Scan(t *testing.T) {
	// Start mock UDP listener
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to resolve UDP address: %v", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("failed to listen UDP: %v", err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().String()

	// Handle mock responses in goroutine
	go func() {
		buf := make([]byte, 2048)
		for {
			n, rAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			// Send response back
			if n > 0 {
				_, _ = conn.WriteToUDP([]byte{0x02, 0x02, 0x03}, rAddr)
			}
		}
	}()

	ws := NewWarpScanner()
	cfg := WarpScanConfig{
		Endpoints:   []string{localAddr, "127.0.0.1:9999"}, // One active, one inactive
		NoiseType:   NoiseHex,
		NoiseVal:    "aabbcc",
		NoiseCount:  2,
		Timeout:     500 * time.Millisecond,
		Concurrency: 2,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	results, err := ws.Scan(ctx, cfg)
	if err != nil {
		t.Fatalf("failed scanning: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	var foundSuccess bool
	for _, r := range results {
		if r.Endpoint == localAddr {
			if r.Error != nil {
				t.Errorf("expected localAddr to succeed, but got error: %v", r.Error)
			} else {
				foundSuccess = true
				if r.RTT < 0 {
					t.Errorf("expected RTT >= 0, got %v", r.RTT)
				}
			}
		}
	}

	if !foundSuccess {
		t.Error("expected at least one successful endpoint scan")
	}
}

type mockRoundTripper struct {
	roundTripFunc func(req *http.Request) (*http.Response, error)
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.roundTripFunc(req)
}

func TestWarpScanner_GenerateWireGuardKeyPair(t *testing.T) {
	ws := NewWarpScanner()
	pub, priv, err := ws.GenerateWireGuardKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}
	if pub == "" || priv == "" {
		t.Error("expected non-empty keys")
	}
	if _, err := base64.StdEncoding.DecodeString(pub); err != nil {
		t.Errorf("invalid base64 public key: %v", err)
	}
	if _, err := base64.StdEncoding.DecodeString(priv); err != nil {
		t.Errorf("invalid base64 private key: %v", err)
	}
}

func TestWarpScanner_Base64ToDecimal(t *testing.T) {
	ws := NewWarpScanner()
	b64Val := base64.StdEncoding.EncodeToString([]byte{1, 2, 3, 4})
	decimalBytes, err := ws.Base64ToDecimal(b64Val)
	if err != nil {
		t.Fatalf("failed decoding: %v", err)
	}
	if len(decimalBytes) != 4 {
		t.Fatalf("expected length 4, got %d", len(decimalBytes))
	}
	for i, v := range []int{1, 2, 3, 4} {
		if decimalBytes[i] != v {
			t.Errorf("expected value at index %d to be %d, got %d", i, v, decimalBytes[i])
		}
	}
}

func TestWarpScanner_RegisterAccount(t *testing.T) {
	ws := NewWarpScanner()

	mockClient := &http.Client{
		Transport: &mockRoundTripper{
			roundTripFunc: func(req *http.Request) (*http.Response, error) {
				if req.URL.Host != "api.cloudflareclient.com" || req.URL.Path != "/v0a4005/reg" {
					return &http.Response{
						StatusCode: http.StatusNotFound,
						Body:       io.NopCloser(bytes.NewBufferString("Not Found")),
					}, nil
				}

				var payload map[string]interface{}
				if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
					return &http.Response{
						StatusCode: http.StatusBadRequest,
						Body:       io.NopCloser(bytes.NewBufferString("Bad Request")),
					}, nil
				}

				if payload["key"] == nil || payload["key"] == "" {
					return &http.Response{
						StatusCode: http.StatusBadRequest,
						Body:       io.NopCloser(bytes.NewBufferString("Missing Key")),
					}, nil
				}

				response := `{
					"config": {
						"interface": {
							"addresses": {
								"v4": "172.16.0.2",
								"v6": "fd00::2"
							}
						},
						"client_id": "AQIDBAU=",
						"peers": [
							{
								"public_key": "some_peer_public_key",
								"endpoint": {
									"host": "engage.cloudflareclient.com:2408",
									"v4": "162.159.192.1",
									"v6": "2606:4700:d0::a29f:c001"
								}
							}
						]
					}
				}`
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(bytes.NewBufferString(response)),
				}, nil
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	params, err := ws.RegisterAccount(ctx, mockClient)
	if err != nil {
		t.Fatalf("failed registering WARP account: %v", err)
	}

	if params.IPv4 != "172.16.0.2/32" {
		t.Errorf("expected IPv4 to be '172.16.0.2/32', got %q", params.IPv4)
	}
	if params.IPv6 != "fd00::2/128" {
		t.Errorf("expected IPv6 to be 'fd00::2/128', got %q", params.IPv6)
	}
	if params.PublicKey != "some_peer_public_key" {
		t.Errorf("expected PublicKey to be 'some_peer_public_key', got %q", params.PublicKey)
	}
	if params.ClientID != "AQIDBAU=" {
		t.Errorf("expected ClientID to be 'AQIDBAU=', got %q", params.ClientID)
	}

	expectedReserved := []int{1, 2, 3, 4, 5}
	if len(params.Reserved) != len(expectedReserved) {
		t.Fatalf("expected 5 reserved bytes, got %d", len(params.Reserved))
	}
	for i, v := range expectedReserved {
		if params.Reserved[i] != v {
			t.Errorf("expected reserved[%d] = %d, got %d", i, v, params.Reserved[i])
		}
	}
}

func TestWarpScanner_ConstructWireGuardHandshakeWithObfuscation(t *testing.T) {
	// Test standard / empty ifpm
	pktEmpty := ConstructWireGuardHandshakeWithObfuscation("")
	if len(pktEmpty) != 148 {
		t.Fatalf("Expected standard handshake length 148, got %d", len(pktEmpty))
	}
	if pktEmpty[0] != 1 {
		t.Errorf("Expected WireGuard initiation packet type 1, got %d", pktEmpty[0])
	}

	// Test m1 mode (QUIC Long Header, 4 bytes)
	pktM1 := ConstructWireGuardHandshakeWithObfuscation("m1")
	if len(pktM1) != 148 {
		t.Fatalf("Expected length 148, got %d", len(pktM1))
	}
	if (pktM1[4] & 0xc0) != 0xc0 {
		t.Errorf("Expected index 4 to have long header bits set (0xc0), got 0x%x", pktM1[4])
	}

	// Test m4 mode (QUIC Short Header, 4 bytes)
	pktM4 := ConstructWireGuardHandshakeWithObfuscation("m4")
	if len(pktM4) != 148 {
		t.Fatalf("Expected length 148, got %d", len(pktM4))
	}
	if (pktM4[4] & 0xc0) != 0x40 {
		t.Errorf("Expected index 4 to have short header bits set (0x40), got 0x%x", pktM4[4])
	}

	// Test hHEX mode (h + hex string)
	pktHex := ConstructWireGuardHandshakeWithObfuscation("h0a0b0c0d")
	if len(pktHex) != 148 {
		t.Fatalf("Expected length 148, got %d", len(pktHex))
	}
	if pktHex[4] != 0x0a || pktHex[5] != 0x0b || pktHex[6] != 0x0c || pktHex[7] != 0x0d {
		t.Errorf("Expected index 4..7 to contain 0x0a, 0x0b, 0x0c, 0x0d, got %v", pktHex[4:8])
	}

	// Test gHEX mode (g + hex string)
	pktHexG := ConstructWireGuardHandshakeWithObfuscation("g02030405")
	if len(pktHexG) != 148 {
		t.Fatalf("Expected length 148, got %d", len(pktHexG))
	}
	if pktHexG[4] != 0x02 || pktHexG[5] != 0x03 || pktHexG[6] != 0x04 || pktHexG[7] != 0x05 {
		t.Errorf("Expected index 4..7 to contain 0x02, 0x03, 0x04, 0x05, got %v", pktHexG[4:8])
	}
}


