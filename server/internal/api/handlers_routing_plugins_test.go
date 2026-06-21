package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/proxy"
)

func TestRoutingPluginHandlers(t *testing.T) {
	gin.SetMode(gin.TestMode)

	server := &Server{}
	router := gin.New()
	apiGroup := router.Group("/api")
	server.setupRoutingPluginRoutes(apiGroup)

	t.Run("GET /api/system/plugins", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/api/system/plugins", nil)
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d", w.Code)
		}

		var resp map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to unmarshal plugins: %v", err)
		}

		if val, ok := resp["schema_version"]; !ok || val.(float64) != 1 {
			t.Errorf("expected schema_version 1, got %v", val)
		}

		plugins, ok := resp["plugins"].([]interface{})
		if !ok || len(plugins) == 0 {
			t.Error("expected non-empty plugins catalog list")
		}
	})

	t.Run("POST /api/system/plugins/validate - Valid Generic Proxy", func(t *testing.T) {
		cfg := proxy.RoutingPluginConfig{
			SchemaVersion: 1,
			RouteID:       "test-route-1",
			PluginID:      "generic-proxy",
			Enabled:       true,
			RemoteDNS:     true,
			Endpoint:      "socks5://127.0.0.1:1080",
		}

		body, _ := json.Marshal(cfg)
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/api/system/plugins/validate", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d (body: %s)", w.Code, w.Body.String())
		}

		var result proxy.RoutingPluginConfigValidation
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatalf("failed to unmarshal validation result: %v", err)
		}

		if !result.Valid {
			t.Error("expected validation to be valid")
		}
		if result.PluginType != "generic_proxy" {
			t.Errorf("expected plugin_type generic_proxy, got %s", result.PluginType)
		}
	})

	t.Run("POST /api/system/plugins/validate - Invalid Endpoint", func(t *testing.T) {
		cfg := proxy.RoutingPluginConfig{
			SchemaVersion: 1,
			RouteID:       "test-route-2",
			PluginID:      "generic-proxy",
			Enabled:       true,
			Endpoint:      "invalid-endpoint",
		}

		body, _ := json.Marshal(cfg)
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/api/system/plugins/validate", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected status 400, got %d", w.Code)
		}

		var resp map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to unmarshal error body: %v", err)
		}

		if resp["valid"].(bool) {
			t.Error("expected valid to be false")
		}
		if resp["error_code"].(string) != "PLUGIN_CONFIG_INVALID" {
			t.Errorf("expected error_code PLUGIN_CONFIG_INVALID, got %v", resp["error_code"])
		}
	})
}
