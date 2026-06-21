package proxy

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestClashMetaRouterMatching(t *testing.T) {
	router, err := NewClashMetaRouter("")
	if err != nil {
		t.Fatalf("failed to create router: %v", err)
	}

	rules := []string{
		"DOMAIN,google.com,proxy",
		"DOMAIN-SUFFIX,cn,direct",
		"DOMAIN-KEYWORD,bypass,direct",
		"IP-CIDR,192.168.1.0/24,direct",
		"MATCH,proxy",
	}

	if err := router.AddRules(rules); err != nil {
		t.Fatalf("failed to add rules: %v", err)
	}

	// Test Domain Exact Match
	if tag := router.MatchOutbound("google.com", nil, nil); tag != "proxy" {
		t.Errorf("expected proxy, got: %s", tag)
	}

	// Test Domain Suffix Match
	if tag := router.MatchOutbound("baidu.cn", nil, nil); tag != "direct" {
		t.Errorf("expected direct, got: %s", tag)
	}

	// Test Domain Keyword Match
	if tag := router.MatchOutbound("mybypasssite.com", nil, nil); tag != "direct" {
		t.Errorf("expected direct, got: %s", tag)
	}

	// Test IP CIDR Match
	ip := net.ParseIP("192.168.1.50")
	if tag := router.MatchOutbound("random.com", ip, nil); tag != "direct" {
		t.Errorf("expected direct, got: %s", tag)
	}

	// Test Match Fallback
	if tag := router.MatchOutbound("facebook.com", nil, nil); tag != "proxy" {
		t.Errorf("expected proxy, got: %s", tag)
	}
}

func TestProviderConfigLoader(t *testing.T) {
	router, err := NewClashMetaRouter("")
	if err != nil {
		t.Fatalf("failed to create router: %v", err)
	}

	// Set up local server acting as a provider subscription source
	mockConfig := `
rules:
  - DOMAIN,google.com,proxy
  - DOMAIN-SUFFIX,cn,direct
`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/yaml")
		w.Write([]byte(mockConfig))
	}))
	defer server.Close()

	loader := NewProviderConfigLoader(router)
	defer loader.StopAll()

	loader.AddProvider("test-provider", server.URL, 50*time.Millisecond)

	// Wait for the update loop to run at least once
	time.Sleep(150 * time.Millisecond)

	router.mu.RLock()
	defer router.mu.RUnlock()

	if len(router.Rules) != 2 {
		t.Fatalf("expected 2 rules loaded from provider, got: %d", len(router.Rules))
	}

	if router.Rules[0].Payload != "google.com" || router.Rules[0].OutboundTag != "proxy" {
		t.Errorf("unexpected rule payload or tag: %+v", router.Rules[0])
	}
}

func TestDashboardTokenAuthAndRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()

	router, err := NewClashMetaRouter("")
	if err != nil {
		t.Fatalf("failed to create router: %v", err)
	}

	token := "secure_secret_token"
	RegisterDashboardRoutes(engine, "/tmp/non-existent-dir", token, router)

	// Case 1: Unauthorized request (no token)
	req1 := httptest.NewRequest("GET", "/api/v1/rules", nil)
	resp1 := httptest.NewRecorder()
	engine.ServeHTTP(resp1, req1)

	if resp1.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized, got: %d", resp1.Code)
	}

	// Case 2: Authorized request via query param
	req2 := httptest.NewRequest("GET", "/api/v1/rules?token=secure_secret_token", nil)
	resp2 := httptest.NewRecorder()
	engine.ServeHTTP(resp2, req2)

	if resp2.Code != http.StatusOK {
		t.Errorf("expected 200 OK, got: %d", resp2.Code)
	}

	// Case 3: Authorized request via Bearer header
	req3 := httptest.NewRequest("GET", "/api/v1/rules", nil)
	req3.Header.Set("Authorization", "Bearer secure_secret_token")
	resp3 := httptest.NewRecorder()
	engine.ServeHTTP(resp3, req3)

	if resp3.Code != http.StatusOK {
		t.Errorf("expected 200 OK, got: %d", resp3.Code)
	}

	// Case 4: POST new rules via authorized endpoint
	var reqBody struct {
		Rules []string `json:"rules"`
	}
	reqBody.Rules = []string{"DOMAIN,apple.com,direct"}
	bodyBytes, _ := json.Marshal(reqBody)

	req4 := httptest.NewRequest("POST", "/api/v1/rules", bytes.NewReader(bodyBytes))
	req4.Header.Set("Authorization", "Bearer secure_secret_token")
	req4.Header.Set("Content-Type", "application/json")
	resp4 := httptest.NewRecorder()
	engine.ServeHTTP(resp4, req4)

	if resp4.Code != http.StatusOK {
		t.Errorf("expected 200 OK, got: %d, body: %s", resp4.Code, resp4.Body.String())
	}

	// Assert rule was added
	router.mu.RLock()
	defer router.mu.RUnlock()
	if len(router.Rules) != 1 || router.Rules[0].Payload != "apple.com" {
		t.Errorf("expected apple.com rule, rules list: %+v", router.Rules)
	}
}
