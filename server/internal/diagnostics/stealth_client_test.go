package diagnostics

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPerformStealthRequest(t *testing.T) {
	// Create mock test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua := r.Header.Get("User-Agent")
		accept := r.Header.Get("Accept")
		secChUa := r.Header.Get("Sec-Ch-Ua")

		if ua == "" {
			t.Errorf("User-Agent header is missing")
		}
		if accept == "" {
			t.Errorf("Accept header is missing")
		}
		if secChUa == "" {
			t.Errorf("Sec-Ch-Ua header is missing")
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Stealth audit payload successful"))
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	opts := StealthClientOptions{}
	resp, err := PerformStealthRequest(ctx, server.URL, opts)
	if err != nil {
		t.Fatalf("Failed to perform stealth request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status code 200, got %d", resp.StatusCode)
	}
}

func TestPerformStealthRequest_WithProxy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	opts := StealthClientOptions{
		ProxyAddr: "127.0.0.1:54321", // unreachable local port
	}
	_, err := PerformStealthRequest(ctx, "http://example.com", opts)
	if err == nil {
		t.Errorf("Expected connection error due to unreachable proxy, got nil")
	} else if !strings.Contains(err.Error(), "54321") && !strings.Contains(err.Error(), "proxy") && !strings.Contains(err.Error(), "connect") {
		t.Errorf("Expected error to mention proxy or connect, got: %v", err)
	}
}
