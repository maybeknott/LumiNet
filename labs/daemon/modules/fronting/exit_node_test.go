package fronting

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSanitizeOutboundHeaders(t *testing.T) {
	in := map[string]string{
		"Host":             "example.com",
		"Connection":       "keep-alive",
		"Content-Length":   "123",
		"X-Forwarded-For":  "1.2.3.4",
		"X-Mhr-Hop":        "1",
		"Accept-Encoding":  "gzip, deflate, br",
		"User-Agent":       "LumiNet-Test",
		"Authorization":    "Bearer secret",
		"X-Custom-Header":  "lumi-value",
	}

	sanitized := SanitizeOutboundHeaders(in)

	// Stripped
	for _, stripped := range []string{"Host", "Connection", "Content-Length", "X-Forwarded-For", "X-Mhr-Hop", "Accept-Encoding"} {
		if _, ok := sanitized[stripped]; ok {
			t.Errorf("expected header %s to be stripped", stripped)
		}
	}

	// Preserved
	if sanitized["User-Agent"] != "LumiNet-Test" {
		t.Errorf("expected User-Agent preserved, got %s", sanitized["User-Agent"])
	}
	if sanitized["Authorization"] != "Bearer secret" {
		t.Errorf("expected Authorization preserved, got %s", sanitized["Authorization"])
	}
	if sanitized["X-Custom-Header"] != "lumi-value" {
		t.Errorf("expected X-Custom-Header preserved, got %s", sanitized["X-Custom-Header"])
	}
}

func TestIsSafeTargetURL(t *testing.T) {
	safe := []string{
		"https://example.com/api",
		"http://93.184.216.34:8080/index",
		"https://cloudflare.com/",
	}
	for _, u := range safe {
		if !IsSafeTargetURL(u) {
			t.Errorf("expected safe: %s", u)
		}
	}

	unsafe := []string{
		"http://localhost:8080/",
		"https://localhost/",
		"http://myhost.local/",
		"http://router.lan/",
		"http://127.0.0.1/",
		"http://127.0.0.5:9000/",
		"http://0.0.0.0:80/",
		"http://10.1.2.3/",
		"http://172.20.0.1/",
		"http://192.168.1.1/",
		"http://169.254.169.254/",
		"http://[::1]/",
		"ftp://example.com/file",
	}
	for _, u := range unsafe {
		if IsSafeTargetURL(u) {
			t.Errorf("expected unsafe: %s", u)
		}
	}
}

func TestCheckRelayLoop(t *testing.T) {
	// Self loop
	if err := CheckRelayLoop("https://exit.example.com/api", "exit.example.com:443", false); err == nil {
		t.Error("expected self loop error")
	}

	// GAS hop loop
	if err := CheckRelayLoop("https://script.google.com/macros/s/xyz/exec", "other.exit.com", true); err == nil {
		t.Error("expected GAS hop loop error")
	}

	// Safe request
	if err := CheckRelayLoop("https://target.com/path", "exit.example.com", false); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestExitNodeServer_HealthCheck(t *testing.T) {
	server := NewExitNodeServer("my-secret-key")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	server.ServeHTTP(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	var data map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		t.Fatalf("json decode failed: %v", err)
	}
	if data["status"] != "healthy" {
		t.Errorf("expected status 'healthy', got %v", data["status"])
	}
}

func TestExitNodeServer_Unauthorized(t *testing.T) {
	server := NewExitNodeServer("secret-123")
	body := strings.NewReader(`{"k": "wrong-key", "u": "https://example.com"}`)
	req := httptest.NewRequest(http.MethodPost, "/", body)
	w := httptest.NewRecorder()

	server.ServeHTTP(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", resp.StatusCode)
	}
}

func TestExitNodeServerAndClient_EndToEnd(t *testing.T) {
	// Target HTTP server
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Echo-Method", r.Method)
		w.Header().Set("X-Echo-Header", r.Header.Get("X-App-Header"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Target origin response"))
	}))
	defer targetServer.Close()

	// Exit node server
	psk := "luminet-psk-test"
	exitServerHandler := NewExitNodeServer(psk, WithAllowPrivateTargets(true))
	exitServer := httptest.NewServer(exitServerHandler)
	defer exitServer.Close()

	// Exit node client
	client := NewExitNodeClient(exitServer.URL, psk, 5*time.Second)

	// Forward request through exit node
	ctx := context.Background()
	headers := map[string]string{
		"X-App-Header": "hello-luminet",
	}

	res, err := client.Forward(ctx, targetServer.URL+"/test", http.MethodGet, headers, nil)
	if err != nil {
		t.Fatalf("forward failed: %v", err)
	}

	if res.S != http.StatusOK {
		t.Fatalf("expected status 200, got %d", res.S)
	}

	if val, ok := res.H["X-Echo-Method"]; !ok || val != "GET" {
		t.Errorf("expected X-Echo-Method GET, got %v", val)
	}
	if val, ok := res.H["X-Echo-Header"]; !ok || val != "hello-luminet" {
		t.Errorf("expected X-Echo-Header hello-luminet, got %v", val)
	}
}
