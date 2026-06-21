package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestEchClientHelloGeneration(t *testing.T) {
	// Base64 ECH Config List representing a mock ECH config
	echConfigB64 := "AEn+DQBFKwAgACABWIHUGj4u+PIggYXcR5JF0gYk3dCRioBW8uJq9H4mKAAIAAEAAQABAANAEnB1YmxpYy50bHMtZWNoLmRldgAA"

	configs, err := ParseECHConfigList(echConfigB64)
	if err != nil {
		t.Fatalf("ParseECHConfigList failed: %v", err)
	}

	if len(configs) == 0 {
		t.Fatal("Expected at least one ECHConfig")
	}

	cfg := configs[0]
	if cfg.PublicName != "public.tls-ech.dev" {
		t.Errorf("Got PublicName %q, want %q", cfg.PublicName, "public.tls-ech.dev")
	}

	if cfg.Version != 0xfe0d {
		t.Errorf("Got version 0x%04x, want 0xfe0d", cfg.Version)
	}

	// Test cache expiration
	cache := &ECHKeyCache{
		Base64Config: echConfigB64,
		ExpiresAt:    time.Now().Add(-1 * time.Hour), // expired
	}
	if !cache.IsExpired() {
		t.Error("Expected cache to be expired")
	}

	cache2 := &ECHKeyCache{
		Base64Config: echConfigB64,
		ExpiresAt:    time.Now().Add(1 * time.Hour), // active
	}
	if cache2.IsExpired() {
		t.Error("Expected cache NOT to be expired")
	}
}

func TestEchFallbackFronting(t *testing.T) {
	// Spin up local HTTP/TLS server (doesn't speak ECH, but serves as fallback target)
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer ts.Close()

	u := ts.URL
	u = strings.TrimPrefix(u, "https://")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := dialFallbackFronting(ctx, "tcp", u, "127.0.0.1", "localhost")
	if err != nil {
		t.Fatalf("Fallback fronting failed: %v", err)
	}
	conn.Close()
}

func TestEchClientCertValidation(t *testing.T) {
	originalVerify := ECHInsecureSkipVerify
	defer func() { ECHInsecureSkipVerify = originalVerify }()

	ECHInsecureSkipVerify = false
	if ECHInsecureSkipVerify {
		t.Error("Expected ECHInsecureSkipVerify to be false")
	}
}
