package proxy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestFetchSubscription_WithCaptchaBypass(t *testing.T) {
	var requestCount int32
	var pollCount int32

	// 1. Start mock target site that serves a Turnstile challenge on first try, then accepts token
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&requestCount, 1)
		if count == 1 {
			// Serve challenge HTML page
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `
				<html>
					<head><title>Challenge</title></head>
					<body>
						<div class="cf-turnstile" data-sitekey="0x4AAAAAAAMockKey"></div>
					</body>
				</html>
			`)
			return
		}

		// Second request should contain the solved token
		token := r.URL.Query().Get("cf-turnstile-response")
		if token != "mock-turnstile-token-resolved" {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, "invalid token: %s", token)
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "vmess://eyJhZGQiOiJleGFtcGxlLmNvbSIsInBvcnQiOjgwODAsInBzIjoiTW9ja1ZtZXNzIiwiaWQiOiI5ZGU3OGEyZS00YjdiLTQxNzEtYmE0Ny0xOWFkMGQ3Zjk1MDMifQ==")
	}))
	defer targetServer.Close()

	// 2. Start mock CAPTCHA solver API server
	solverServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/in.php") {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  1,
				"request": "task-abc-123",
			})
			return
		}
		if strings.HasSuffix(r.URL.Path, "/res.php") {
			pc := atomic.AddInt32(&pollCount, 1)
			if pc == 1 {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"status":  0,
					"request": "CAPCHA_NOT_READY",
				})
			} else {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"status":  1,
					"request": "mock-turnstile-token-resolved",
				})
			}
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer solverServer.Close()

	// 3. Configure Solver
	solver := NewCaptchaSolver("my-secret-key", solverServer.URL)
	solver.PollingInterval = 10 * time.Millisecond
	solver.Timeout = 200 * time.Millisecond

	// Put solver in context
	ctx := WithCaptchaSolver(context.Background(), solver)

	// Fetch subscription
	configs, err := FetchSubscription(ctx, targetServer.URL)
	if err != nil {
		t.Fatalf("FetchSubscription failed: %v", err)
	}

	if len(configs) != 1 {
		t.Fatalf("expected 1 parsed proxy, got %d", len(configs))
	}

	if configs[0].Name != "MockVmess" {
		t.Errorf("expected MockVmess, got %s", configs[0].Name)
	}

	if atomic.LoadInt32(&requestCount) != 2 {
		t.Errorf("expected 2 requests to target server, got %d", atomic.LoadInt32(&requestCount))
	}
}

func TestFetchSubscription_WithCoalescer(t *testing.T) {
	// Start mock server representing the Apps Script backend
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)

		// Checks auth key
		if req["k"] != "test-coalescer-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		subContent := "vmess://eyJhZGQiOiJleGFtcGxlLmNvbSIsInBvcnQiOjgwODAsInBzIjoiQ29hbGVzY2VkVm1lc3MiLCJpZCI6IjlkZTc4YTJlLTRiN2ItNDE3MS1iYTQ3LTE5YWQwZDdmOTUwMyJ9"
		resp := workerResponse{
			Status: 200,
			Headers: map[string]interface{}{
				"Content-Type": "text/plain",
			},
			Body: base64.StdEncoding.EncodeToString([]byte(subContent)),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	parsedURL, _ := url.Parse(server.URL)
	c := NewCoalescer(nil, []string{server.URL}, parsedURL.Host, "test-coalescer-key", 2*time.Second)
	defer c.Stop()

	// Put coalescer in context
	ctx := WithCoalescer(context.Background(), c)

	// Fetch subscription
	configs, err := FetchSubscription(ctx, "https://mock-blocked-subscription.com/sub")
	if err != nil {
		t.Fatalf("FetchSubscription failed: %v", err)
	}

	if len(configs) != 1 {
		t.Fatalf("expected 1 parsed proxy, got %d", len(configs))
	}

	if configs[0].Name != "CoalescedVmess" {
		t.Errorf("expected CoalescedVmess, got %s", configs[0].Name)
	}
}

func TestParseSingBoxOutbounds_WithDetour(t *testing.T) {
	jsonData := `{
		"outbounds": [
			{
				"type": "wireguard",
				"tag": "Warp-IR",
				"server": "162.159.195.93",
				"server_port": 2506,
				"local_address": "172.16.0.2/32",
				"private_key": "CBVIIWvXdLr4PbSrnm11ZJJ300IiPudRD4R62/IxV1g=",
				"peer_public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
				"reserved": "AAAA",
				"mtu": 1280
			},
			{
				"type": "wireguard",
				"tag": "Warp-Main",
				"server": "162.159.195.93",
				"server_port": 2506,
				"local_address": "172.16.0.2/32",
				"private_key": "CCC/TQTc82ub9i8f37Rpix2v425Sv/mxTzvE/iKRMkw=",
				"peer_public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
				"reserved": "AAAA",
				"mtu": 1280,
				"detour": "Warp-IR"
			}
		]
	}`

	configs, err := ParseSingBoxOutbounds([]byte(jsonData))
	if err != nil {
		t.Fatalf("ParseSingBoxOutbounds failed: %v", err)
	}

	if len(configs) != 2 {
		t.Fatalf("Expected 2 configurations, got %d", len(configs))
	}

	var warpMain *ProxyConfig
	var warpIR *ProxyConfig

	for _, c := range configs {
		if c.Name == "Warp-Main" {
			warpMain = c
		} else if c.Name == "Warp-IR" {
			warpIR = c
		}
	}

	if warpMain == nil {
		t.Fatal("Warp-Main not found")
	}
	if warpIR == nil {
		t.Fatal("Warp-IR not found")
	}

	if warpMain.DialerProxy != "Warp-IR" {
		t.Errorf("Expected Warp-Main DialerProxy to be 'Warp-IR', got '%s'", warpMain.DialerProxy)
	}

	if warpMain.Detour != warpIR {
		t.Errorf("Expected Warp-Main Detour to link to Warp-IR config struct, got %v", warpMain.Detour)
	}
}


