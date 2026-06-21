package provision

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestProvisionConfigValidation(t *testing.T) {
	vpsCfg := VpsConfig{
		IP:          "127.0.0.1",
		SSHUser:     "root",
		SSHPassword: "password123",
		Domain:      "example.com",
		CFToken:     "cloudflare-token",
		CFAccountID: "cloudflare-account-id",
	}

	if vpsCfg.IP != "127.0.0.1" {
		t.Errorf("Expected IP 127.0.0.1, got %s", vpsCfg.IP)
	}

	edgeCfg := EdgeConfig{
		CFToken:     "cloudflare-token",
		CFAccountID: "cloudflare-account-id",
		ScriptName:  "edge-relay",
		TargetHost:  "127.0.0.1",
		TargetPort:  10888,
	}

	if edgeCfg.TargetPort != 10888 {
		t.Errorf("Expected target port 10888, got %d", edgeCfg.TargetPort)
	}

	edgeVlessCfg := EdgeConfig{
		CFToken:     "cloudflare-token",
		CFAccountID: "cloudflare-account-id",
		ScriptName:  "edge-vless",
		UUID:        "9de78a2e-4b7b-4171-ba47-19ad0d7f9503",
		Type:        "vless",
	}

	if edgeVlessCfg.Type != "vless" {
		t.Errorf("Expected type vless, got %s", edgeVlessCfg.Type)
	}
	if edgeVlessCfg.UUID != "9de78a2e-4b7b-4171-ba47-19ad0d7f9503" {
		t.Errorf("Expected UUID 9de78a2e-4b7b-4171-ba47-19ad0d7f9503, got %s", edgeVlessCfg.UUID)
	}
}

func TestProvisionLoggerSubscriber(t *testing.T) {
	logger := NewProvisionLogger()
	ch, unsubscribe := logger.Subscribe()
	defer unsubscribe()

	logger.Log("Setting up network node...")
	select {
	case line := <-ch:
		if !contains(line, "Setting up network node...") {
			t.Errorf("Expected log containing setup message, got %s", line)
		}
	default:
		t.Errorf("Subscriber did not receive the log message")
	}

	if !contains(logger.GetLogs(), "Setting up network node...") {
		t.Errorf("GetLogs did not return the expected logs: %s", logger.GetLogs())
	}
}

func TestCloudflareClientInvalidToken(t *testing.T) {
	client := NewCFClient("invalid-token")
	ctx := context.Background()

	err := client.VerifyToken(ctx)
	if err == nil {
		t.Errorf("Expected verification error for invalid token, got nil")
	}

	_, err = client.GetZoneID(ctx, "invalid-domain.com")
	if err == nil {
		t.Errorf("Expected zone lookup error for invalid domain, got nil")
	}
}

func TestBuildMultipartBody(t *testing.T) {
	script := "console.log('test script');"
	binding := "IOT_DB"
	dbID := "db-uuid-12345"

	body, contentType, err := buildMultipartBody(script, binding, dbID)
	if err != nil {
		t.Fatalf("buildMultipartBody failed: %v", err)
	}

	if !contains(contentType, "multipart/form-data") {
		t.Errorf("Expected multipart content type, got %s", contentType)
	}

	bodyStr := string(body)
	if !contains(bodyStr, "db-uuid-12345") {
		t.Errorf("Expected D1 database ID in body, but not found")
	}
	if !contains(bodyStr, "IOT_DB") {
		t.Errorf("Expected D1 binding name in body, but not found")
	}
	if !contains(bodyStr, "console.log('test script');") {
		t.Errorf("Expected script content in body, but not found")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || s[0:len(substr)] == substr || s[len(s)-len(substr):] == substr || checkIndex(s, substr))
}

func checkIndex(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

type mockRoundTripper struct {
	roundTripFunc func(req *http.Request) (*http.Response, error)
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.roundTripFunc(req)
}

func TestCFClientSSLAndCertificate(t *testing.T) {
	t.Run("SetSSLModeStrict Success", func(t *testing.T) {
		client := NewCFClient("mock-token")
		called := false
		client.client.Transport = &mockRoundTripper{
			roundTripFunc: func(req *http.Request) (*http.Response, error) {
				called = true
				if req.Method != "PATCH" {
					t.Errorf("Expected PATCH request, got %s", req.Method)
				}
				expectedURL := "https://api.cloudflare.com/client/v4/zones/zone-123/settings/ssl"
				if req.URL.String() != expectedURL {
					t.Errorf("Expected URL %s, got %s", expectedURL, req.URL.String())
				}
				authHeader := req.Header.Get("Authorization")
				if authHeader != "Bearer mock-token" {
					t.Errorf("Expected Authorization header 'Bearer mock-token', got '%s'", authHeader)
				}
				contentType := req.Header.Get("Content-Type")
				if contentType != "application/json" {
					t.Errorf("Expected Content-Type 'application/json', got '%s'", contentType)
				}

				respBody := `{"success": true, "result": {"id": "ssl", "value": "strict"}}`
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(respBody)),
				}, nil
			},
		}

		err := client.SetSSLModeStrict(context.Background(), "zone-123")
		if err != nil {
			t.Fatalf("SetSSLModeStrict failed: %v", err)
		}
		if !called {
			t.Error("Mock transport was not called")
		}
	})

	t.Run("CreateOriginCertificate Success", func(t *testing.T) {
		client := NewCFClient("mock-token")
		called := false
		client.client.Transport = &mockRoundTripper{
			roundTripFunc: func(req *http.Request) (*http.Response, error) {
				called = true
				if req.Method != "POST" {
					t.Errorf("Expected POST request, got %s", req.Method)
				}
				expectedURL := "https://api.cloudflare.com/client/v4/certificates"
				if req.URL.String() != expectedURL {
					t.Errorf("Expected URL %s, got %s", expectedURL, req.URL.String())
				}

				respBody := `{
					"success": true,
					"result": {
						"certificate": "-----BEGIN CERTIFICATE-----\nMOCK_CERT\n-----END CERTIFICATE-----"
					}
				}`
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(respBody)),
				}, nil
			},
		}

		cert, err := client.CreateOriginCertificate(context.Background(), []string{"*.example.com"}, "mock-csr", 365)
		if err != nil {
			t.Fatalf("CreateOriginCertificate failed: %v", err)
		}
		if !called {
			t.Error("Mock transport was not called")
		}
		expectedCert := "-----BEGIN CERTIFICATE-----\nMOCK_CERT\n-----END CERTIFICATE-----"
		if string(cert) != expectedCert {
			t.Errorf("Expected certificate '%s', got '%s'", expectedCert, string(cert))
		}
	})
}

func TestProvisionVPS_SetSSLModeStrict(t *testing.T) {
	// Backup original DefaultTransport
	origTransport := http.DefaultTransport
	defer func() {
		http.DefaultTransport = origTransport
	}()

	zoneIDCall := false
	upsertCall := false
	sslModeCall := false

	http.DefaultTransport = &mockRoundTripper{
		roundTripFunc: func(req *http.Request) (*http.Response, error) {
			urlStr := req.URL.String()

			// 1. GetZoneID
			if req.Method == "GET" && strings.Contains(urlStr, "/client/v4/zones?name=") {
				zoneIDCall = true
				resp := `{"success":true,"result":[{"id":"zone-123"}]}`
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(resp)),
				}, nil
			}

			// 2. Search existing record
			if req.Method == "GET" && strings.Contains(urlStr, "/dns_records?type=A") {
				resp := `{"success":true,"result":[]}` // empty result -> will POST/create
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(resp)),
				}, nil
			}

			// 3. Upsert (Create)
			if req.Method == "POST" && strings.Contains(urlStr, "/dns_records") {
				upsertCall = true
				resp := `{"success":true,"result":{"id":"rec-456"}}`
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(resp)),
				}, nil
			}

			// 4. SetSSLModeStrict
			if req.Method == "PATCH" && strings.Contains(urlStr, "/settings/ssl") {
				sslModeCall = true
				resp := `{"success":true,"result":{"id":"ssl","value":"strict"}}`
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(resp)),
				}, nil
			}

			return &http.Response{
				StatusCode: http.StatusNotFound,
				Body:       io.NopCloser(strings.NewReader(`{"success":false}`)),
			}, nil
		},
	}

	logger := NewProvisionLogger()
	cfg := VpsConfig{
		IP:          "127.0.0.1",
		SSHUser:     "root",
		SSHPassword: "password123",
		Domain:      "example.com",
		CFToken:     "cloudflare-token",
		CFAccountID: "cloudflare-account-id",
	}

	err := ProvisionVPS(context.Background(), cfg, logger)
	if err == nil {
		t.Fatal("Expected ProvisionVPS to return SSH connection failure, but got no error")
	}

	// Verify the error is indeed about SSH dialing (so execution reached the SSH phase)
	if !strings.Contains(err.Error(), "failed to dial SSH") {
		t.Errorf("Expected SSH connection failure error, got: %v", err)
	}

	// Verify that the Cloudflare DNS and hardening endpoints were called successfully
	if !zoneIDCall {
		t.Error("Cloudflare GetZoneID was not called")
	}
	if !upsertCall {
		t.Error("Cloudflare UpsertDNSRecord was not called")
	}
	if !sslModeCall {
		t.Error("Cloudflare SetSSLModeStrict was not called")
	}

	// Verify logger outputs
	logs := logger.GetLogs()
	if !strings.Contains(logs, "Cloudflare SSL: Strict SSL mode enabled successfully!") {
		t.Errorf("Expected log containing Strict SSL confirmation, got: %s", logs)
	}
}


