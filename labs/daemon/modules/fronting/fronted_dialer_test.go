package fronting

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHostRewriteTransport(t *testing.T) {
	var capturedHost string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedHost = r.Host
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := &http.Client{
		Transport: &HostRewriteTransport{
			Transport:  http.DefaultTransport,
			HostHeader: "fronted.example.org",
		},
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("Failed to execute request: %v", err)
	}
	defer resp.Body.Close()

	if capturedHost != "fronted.example.org" {
		t.Errorf("Expected Host 'fronted.example.org', got %s", capturedHost)
	}
}

func TestNewCovertHTTPClient_Config(t *testing.T) {
	cfg := CovertTransportConfig{
		TargetIP:           "127.0.0.1:443",
		SNI:                "decoy.domain.com",
		HostHeader:         "actual.api.com",
		InsecureSkipVerify: true,
		ConnectTimeout:     5 * time.Second,
	}

	client := NewCovertHTTPClient(cfg)
	if client == nil {
		t.Fatal("NewCovertHTTPClient returned nil")
	}

	rt, ok := client.Transport.(*HostRewriteTransport)
	if !ok {
		t.Fatalf("Expected *HostRewriteTransport, got %T", client.Transport)
	}
	if rt.HostHeader != "actual.api.com" {
		t.Errorf("Expected HostHeader 'actual.api.com', got %s", rt.HostHeader)
	}
}
