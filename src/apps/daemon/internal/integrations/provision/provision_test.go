package provision

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
)

func validRuntimeSupplyChainConfig() VpsConfig {
	return VpsConfig{
		ThreeXUIImage: "ghcr.io/mhsanaei/3x-ui@sha256:" + strings.Repeat("a", 64),
		PostgresImage: "postgres@sha256:" + strings.Repeat("b", 64),
		AlpineImage:   "alpine@sha256:" + strings.Repeat("c", 64),
		TorAPKVersion: "0.4.8.14-r0",
	}
}

func TestProvisionConfigValidation(t *testing.T) {
	vpsCfg := validRuntimeSupplyChainConfig()
	vpsCfg.IP = "127.0.0.1"
	vpsCfg.SSHUser = "root"
	vpsCfg.SSHPassword = "password123"
	vpsCfg.SSHHostKeySHA256 = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	vpsCfg.Domain = "example.com"
	vpsCfg.CFToken = "cloudflare-token"
	vpsCfg.CFAccountID = "cloudflare-account-id"

	if vpsCfg.IP != "127.0.0.1" {
		t.Errorf("Expected IP 127.0.0.1, got %s", vpsCfg.IP)
	}
	if err := vpsCfg.validateRuntimeSupplyChain(); err != nil {
		t.Fatalf("valid pinned supply chain rejected: %v", err)
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

func TestRuntimeSupplyChainRejectsMutableInputs(t *testing.T) {
	cfg := validRuntimeSupplyChainConfig()
	cfg.ThreeXUIImage = "ghcr.io/mhsanaei/3x-ui:latest"
	if err := cfg.validateRuntimeSupplyChain(); err == nil || !strings.Contains(err.Error(), "three_xui_image") {
		t.Fatalf("mutable 3x-ui image should fail closed, got %v", err)
	}

	cfg = validRuntimeSupplyChainConfig()
	cfg.PostgresImage = "postgres:17"
	if err := cfg.validateRuntimeSupplyChain(); err == nil || !strings.Contains(err.Error(), "postgres_image") {
		t.Fatalf("mutable postgres image should fail closed, got %v", err)
	}

	cfg = validRuntimeSupplyChainConfig()
	cfg.AlpineImage = "alpine:3.22"
	if err := cfg.validateRuntimeSupplyChain(); err == nil || !strings.Contains(err.Error(), "alpine_image") {
		t.Fatalf("mutable alpine image should fail closed, got %v", err)
	}

	cfg = validRuntimeSupplyChainConfig()
	cfg.TorAPKVersion = "latest"
	if err := cfg.validateRuntimeSupplyChain(); err == nil || !strings.Contains(err.Error(), "tor_apk_version") {
		t.Fatalf("unpinned Tor package should fail closed, got %v", err)
	}
}

func TestProvisionLoggerRecordsMessages(t *testing.T) {
	logger := NewProvisionLogger()
	logger.Log("Setting up network node...")
	if !contains(logger.GetLogs(), "Setting up network node...") {
		t.Errorf("GetLogs did not return the expected logs: %s", logger.GetLogs())
	}
}

func TestProvisionLoggerConcurrentWrites(t *testing.T) {
	logger := NewProvisionLogger()
	const writers = 100
	var wg sync.WaitGroup
	wg.Add(writers)
	for i := 0; i < writers; i++ {
		go func() {
			defer wg.Done()
			logger.Log("concurrent-message")
		}()
	}
	wg.Wait()
	if got := strings.Count(logger.GetLogs(), "concurrent-message"); got != writers {
		t.Fatalf("logged messages=%d, want %d", got, writers)
	}
}

func TestBoundedCaptureTruncatesWithoutShortWrites(t *testing.T) {
	capture := newBoundedCapture(4)
	if n, err := capture.Write([]byte("abcdef")); err != nil || n != 6 {
		t.Fatalf("Write() = (%d, %v), want (6, nil)", n, err)
	}
	if got := capture.String(); got != "abcd\n[output truncated]" {
		t.Fatalf("capture=%q", got)
	}
	if n, err := capture.Write([]byte("more")); err != nil || n != 4 {
		t.Fatalf("post-limit Write() = (%d, %v), want (4, nil)", n, err)
	}
	if got := capture.String(); got != "abcd\n[output truncated]" {
		t.Fatalf("capture changed after limit: %q", got)
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
				if authHeader := req.Header.Get("Authorization"); authHeader != "Bearer mock-token" {
					t.Errorf("Expected Authorization header 'Bearer mock-token', got '%s'", authHeader)
				}
				if contentType := req.Header.Get("Content-Type"); contentType != "application/json" {
					t.Errorf("Expected Content-Type 'application/json', got '%s'", contentType)
				}

				respBody := `{"success": true, "result": {"id": "ssl", "value": "strict"}}`
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(respBody)),
				}, nil
			},
		}

		if err := client.SetSSLModeStrict(context.Background(), "zone-123"); err != nil {
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

			if req.Method == "GET" && strings.Contains(urlStr, "/client/v4/zones?name=") {
				zoneIDCall = true
				resp := `{"success":true,"result":[{"id":"zone-123"}]}`
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(resp))}, nil
			}
			if req.Method == "GET" && strings.Contains(urlStr, "/dns_records?type=A") {
				resp := `{"success":true,"result":[]}`
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(resp))}, nil
			}
			if req.Method == "POST" && strings.Contains(urlStr, "/dns_records") {
				upsertCall = true
				resp := `{"success":true,"result":{"id":"rec-456"}}`
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(resp))}, nil
			}
			if req.Method == "PATCH" && strings.Contains(urlStr, "/settings/ssl") {
				sslModeCall = true
				resp := `{"success":true,"result":{"id":"ssl","value":"strict"}}`
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(resp))}, nil
			}
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Body:       io.NopCloser(strings.NewReader(`{"success":false}`)),
			}, nil
		},
	}

	logger := NewProvisionLogger()
	cfg := validRuntimeSupplyChainConfig()
	cfg.IP = "127.0.0.1"
	cfg.SSHUser = "root"
	cfg.SSHPassword = "password123"
	cfg.SSHHostKeySHA256 = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	cfg.Domain = "example.com"
	cfg.CFToken = "cloudflare-token"
	cfg.CFAccountID = "cloudflare-account-id"

	err := ProvisionVPS(context.Background(), cfg, logger)
	if err == nil {
		t.Fatal("Expected ProvisionVPS to return SSH connection failure, but got no error")
	}
	if !strings.Contains(err.Error(), "failed to dial SSH") {
		t.Errorf("Expected SSH connection failure error, got: %v", err)
	}
	if !zoneIDCall {
		t.Error("Cloudflare GetZoneID was not called")
	}
	if !upsertCall {
		t.Error("Cloudflare UpsertDNSRecord was not called")
	}
	if !sslModeCall {
		t.Error("Cloudflare SetSSLModeStrict was not called")
	}
	logs := logger.GetLogs()
	if !strings.Contains(logs, "Cloudflare SSL: Strict SSL mode enabled successfully!") {
		t.Errorf("Expected log containing Strict SSL confirmation, got: %s", logs)
	}
}

type scriptedRemoteRunner struct {
	responses map[string]string
	errors    map[string]error
	commands  []string
}

func (r *scriptedRemoteRunner) Run(_ context.Context, command string) (string, error) {
	r.commands = append(r.commands, command)
	if err := r.errors[command]; err != nil {
		return "", err
	}
	return r.responses[command], nil
}

func TestAptCandidateVersion(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  string
		ok    bool
	}{
		{"5:24.0.5-0ubuntu1~22.04.1\n", "5:24.0.5-0ubuntu1~22.04.1", true},
		{"(none)\n", "", false},
		{"1.2.3;curl evil", "", false},
	} {
		got, err := aptCandidateVersion(tc.input)
		if tc.ok && (err != nil || got != tc.want) {
			t.Fatalf("aptCandidateVersion(%q)=(%q,%v), want %q", tc.input, got, err, tc.want)
		}
		if !tc.ok && err == nil {
			t.Fatalf("aptCandidateVersion(%q) unexpectedly succeeded with %q", tc.input, got)
		}
	}
}

func TestInstallDockerFromTrustedRepoPinsSignedCandidate(t *testing.T) {
	r := &scriptedRemoteRunner{responses: map[string]string{
		"apt-cache policy docker.io | awk '/Candidate:/ {print $2; exit}'": "5:24.0.5-0ubuntu1~22.04.1\n",
	}, errors: map[string]error{}}
	if err := installDockerFromTrustedRepo(context.Background(), r, NewProvisionLogger()); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(r.commands, "\n")
	if strings.Contains(joined, "get.docker.com") || strings.Contains(joined, "| sh") {
		t.Fatalf("mutable remote bootstrap leaked into commands: %s", joined)
	}
	if !strings.Contains(joined, "docker.io=5:24.0.5-0ubuntu1~22.04.1") {
		t.Fatalf("exact docker.io version not pinned: %s", joined)
	}
}
