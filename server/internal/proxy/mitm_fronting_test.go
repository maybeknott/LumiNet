package proxy

import (
	"testing"
)

func TestMitmFrontingProxy(t *testing.T) {
	proxy, err := NewMitmFrontingProxy("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to initialize MITM proxy: %v", err)
	}

	err = proxy.Start()
	if err != nil {
		t.Fatalf("Failed to start MITM proxy: %v", err)
	}
	defer proxy.Stop()

	// Verify headers normalization
	headers := map[string][]string{
		"Accept-Encoding": {"gzip"},
		"User-Agent":      {"Mozilla/5.0"},
		"Host":            {"example.com"},
		"X-Custom-Header": {"custom"},
	}

	normalized := NormalizeHttpHeaders(headers)

	if len(normalized["Host"]) == 0 || normalized["Host"][0] != "example.com" {
		t.Errorf("Expected Host 'example.com', got %v", normalized["Host"])
	}

	if len(normalized["X-Custom-Header"]) == 0 || normalized["X-Custom-Header"][0] != "custom" {
		t.Errorf("Expected Custom header, got %v", normalized["X-Custom-Header"])
	}
}
