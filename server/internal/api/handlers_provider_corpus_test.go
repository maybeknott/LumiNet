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

func TestProviderCorpusHandlers(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Ensure built-in corpus is initialized
	_ = proxy.InitBuiltinProviderCorpus()

	server := &Server{}
	router := gin.New()
	apiGroup := router.Group("/api")
	server.setupProviderCorpusRoutes(apiGroup)

	t.Run("GET /api/provider-corpus", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/api/provider-corpus", nil)
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d. Body: %s", w.Code, w.Body.String())
		}

		var status proxy.ProviderCorpusStatus
		if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil {
			t.Fatalf("failed to unmarshal provider corpus status: %v", err)
		}

		if status.CorpusID != "builtin-provider-prefixes-v1" {
			t.Errorf("expected CorpusID 'builtin-provider-prefixes-v1', got '%s'", status.CorpusID)
		}
	})

	t.Run("POST /api/provider-corpus - valid", func(t *testing.T) {
		validJSON := `{
			"schema_version": 1,
			"corpus_id": "test-uploaded-corpus",
			"generator_version": "v1.2",
			"generated_at": "2026-06-21T00:00:00Z",
			"fetched_at": "2026-06-21T00:00:00Z",
			"stale_after": "2026-07-21T00:00:00Z",
			"checksum": "test-checksum-abcd",
			"providers": [
				{
					"provider_id": "custom-cdn",
					"display_name": "Custom CDN",
					"source_url": "custom://prefixes",
					"source_license": "MIT",
					"source_kind": "test",
					"confidence": "high",
					"priority": 50,
					"ipv4_prefixes": ["192.0.2.0/24"],
					"ipv6_prefixes": []
				}
			]
		}`

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/api/provider-corpus", bytes.NewBufferString(validJSON))
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d. Body: %s", w.Code, w.Body.String())
		}

		var resp map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to unmarshal response: %v", err)
		}

		if resp["status"] != "swapped" {
			t.Errorf("expected status 'swapped', got '%v'", resp["status"])
		}

		// Verify lookup works on the new corpus
		obs := proxy.ObserveProvider("192.0.2.55")
		if obs.ProviderID != "custom-cdn" {
			t.Errorf("expected newly uploaded provider 'custom-cdn', got '%s'", obs.ProviderID)
		}
	})

	t.Run("POST /api/provider-corpus - invalid schema", func(t *testing.T) {
		invalidJSON := `{
			"schema_version": 2,
			"corpus_id": "invalid"
		}`

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/api/provider-corpus", bytes.NewBufferString(invalidJSON))
		router.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected status 400, got %d", w.Code)
		}
	})
}
