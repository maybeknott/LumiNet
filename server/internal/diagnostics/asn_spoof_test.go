package diagnostics

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

type mockTransport struct {
	base http.RoundTripper
	host string
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = "http"
	req.URL.Host = m.host
	return m.base.RoundTrip(req)
}

func TestAsnSpoof_Success(t *testing.T) {
	// Mock CAIDA Spoofer API response
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/sessions" {
			sessions := []caidaSpoofSession{
				{
					Timestamp:     "2026-06-18T04:27:44+03:30",
					RoutedSpoof:   "received",
					PrivateSpoof:  "sent",
					RoutedSpoof6:  "received",
					PrivateSpoof6: "sent",
					Client4:       "1.1.1.1",
					Asn4:          "13335",
					Country:       "us",
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(sessions)
			return
		}
		http.NotFound(w, r)
	}))
	defer mockServer.Close()

	pipeline := NewPipeline()
	client := mockServer.Client()
	client.Transport = &mockTransport{
		base: client.Transport,
		host: mockServer.Listener.Addr().String(),
	}
	pipeline.httpClient = client

	job := &DiagnosticJob{
		Type:   MetricAsnSpoof,
		Target: "13335",
	}

	result := &DiagnosticResult{
		Type:    MetricAsnSpoof,
		Metrics: make(map[string]interface{}),
	}

	res, err := pipeline.runAsnSpoof(context.Background(), job, result)
	if err != nil {
		t.Fatalf("runAsnSpoof failed: %v", err)
	}

	if !res.Success {
		t.Fatal("expected diagnostic success")
	}

	spoofable, ok := res.Metrics["spoofable"].(bool)
	if !ok || !spoofable {
		t.Errorf("expected spoofable true, got %v", res.Metrics["spoofable"])
	}

	asn, ok := res.Metrics["asn"].(string)
	if !ok || asn != "AS13335" {
		t.Errorf("expected AS13335, got %v", res.Metrics["asn"])
	}
}
