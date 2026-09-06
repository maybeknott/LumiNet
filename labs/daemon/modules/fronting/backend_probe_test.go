package fronting

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBackendProberSuccess(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "websocket" {
			http.Error(w, "missing upgrade header", http.StatusBadRequest)
			return
		}
		if r.URL.Path != "/custom-path" {
			http.Error(w, "unexpected path", http.StatusNotFound)
			return
		}
		w.Header().Set("Upgrade", "websocket")
		w.Header().Set("Connection", "Upgrade")
		w.WriteHeader(http.StatusSwitchingProtocols)
	}))
	defer ts.Close()

	prober := NewBackendProber()
	res, err := prober.Probe(context.Background(), BackendProbeConfig{
		TargetURL: ts.URL,
		Path:      "/custom-path",
		Timeout:   2 * time.Second,
	})

	if err != nil {
		t.Fatalf("Probe returned error: %v", err)
	}
	if !res.OK {
		t.Fatalf("Expected OK=true, got false. Steps: %v", res.Steps)
	}
	if !res.GotWebSocket {
		t.Fatalf("Expected GotWebSocket=true")
	}
	if res.UpstreamStatus != http.StatusSwitchingProtocols {
		t.Fatalf("Expected status 101, got %d", res.UpstreamStatus)
	}
}

func TestBackendProberSSRFHintOnRawIP403(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer ts.Close()

	prober := NewBackendProber()
	res, err := prober.Probe(context.Background(), BackendProbeConfig{
		TargetURL: ts.URL, // 127.0.0.1:port is a raw IP
		Path:      "/novavpn",
	})

	if err != nil {
		t.Fatalf("Probe returned error: %v", err)
	}
	if res.OK {
		t.Fatalf("Expected OK=false for 403 response")
	}
	if !strings.Contains(res.FixHint, "DNS-only") {
		t.Fatalf("Expected DNS-only hint for fast raw IP 403, got: %s", res.FixHint)
	}
}

func TestBackendProbeHandler(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Upgrade", "websocket")
		w.WriteHeader(http.StatusSwitchingProtocols)
	}))
	defer ts.Close()

	prober := NewBackendProber()
	handler := BackendProbeHandler(prober)

	// Test GET
	reqGet := httptest.NewRequest(http.MethodGet, "/probe?target="+ts.URL+"&path=/novavpn", nil)
	recGet := httptest.NewRecorder()
	handler(recGet, reqGet)

	if recGet.Code != http.StatusOK {
		t.Fatalf("GET /probe expected 200, got %d: %s", recGet.Code, recGet.Body.String())
	}
	var resGet BackendProbeResult
	if err := json.NewDecoder(recGet.Body).Decode(&resGet); err != nil {
		t.Fatalf("Failed to decode GET probe result: %v", err)
	}
	if !resGet.OK {
		t.Fatalf("Expected GET probe OK=true, got false")
	}

	// Test POST
	body, _ := json.Marshal(BackendProbeConfig{
		TargetURL: ts.URL,
		Path:      "/novavpn",
	})
	reqPost := httptest.NewRequest(http.MethodPost, "/probe", bytes.NewReader(body))
	recPost := httptest.NewRecorder()
	handler(recPost, reqPost)

	if recPost.Code != http.StatusOK {
		t.Fatalf("POST /probe expected 200, got %d", recPost.Code)
	}
}

func TestSessionTrafficMeterRegistry(t *testing.T) {
	reg := NewMeterRegistry()
	m1 := reg.GetOrCreate("user_alpha")
	m2 := reg.GetOrCreate("user_beta")

	if m1 != reg.GetOrCreate("user_alpha") {
		t.Fatalf("Expected same pointer for user_alpha")
	}

	m1.RecordUp(500)
	m1.RecordDown(1500)

	if m1.TotalBytes() != 2000 {
		t.Fatalf("Expected 2000 total bytes, got %d", m1.TotalBytes())
	}
	if m2.TotalBytes() != 0 {
		t.Fatalf("Expected 0 total bytes for m2, got %d", m2.TotalBytes())
	}
}
