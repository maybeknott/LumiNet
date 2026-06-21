package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestExtensionAPIs(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create test server config
	sConfig := &ServerConfig{
		Host:   "127.0.0.1",
		Port:   8080,
		APIKey: "test-api-key-9876",
	}

	// Create test server structure manually to bypass JobManager initialization
	server := &Server{
		config: sConfig,
	}

	r := gin.New()
	api := r.Group("/api")
	api.Use(AuthMiddleware(server.config.APIKey))

	server.SetupExtensionRoutes(api)
	r.GET("/go/:name", server.HandleShortlinkRedirect)

	// 1. Assert status endpoint returns correct structure
	t.Run("Get Extension Status", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/api/extension/status", nil)
		req.Header.Set("X-API-Key", "test-api-key-9876")

		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d. Body: %s", w.Code, w.Body.String())
		}

		var resp map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to parse response: %v", err)
		}

		if resp["status"] != "connected" || resp["active_profile"] == "" {
			t.Errorf("unexpected status structure: %+v", resp)
		}
	})

	// 2. Assert profile selection behaves correctly
	t.Run("Select Extension Profile", func(t *testing.T) {
		// Valid profile
		w := httptest.NewRecorder()
		body, _ := json.Marshal(gin.H{"profile": "Secure Evasion Mode"})
		req, _ := http.NewRequest(http.MethodPost, "/api/extension/profile", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-Key", "test-api-key-9876")

		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d. Body: %s", w.Code, w.Body.String())
		}

		// Invalid profile
		w = httptest.NewRecorder()
		body, _ = json.Marshal(gin.H{"profile": "Nonexistent Profile"})
		req, _ = http.NewRequest(http.MethodPost, "/api/extension/profile", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-Key", "test-api-key-9876")

		r.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected status 400 for invalid profile, got %d", w.Code)
		}
	})

	// 3. Assert pattern rules setting/getting works
	t.Run("Rewrite Rules Lifecycle", func(t *testing.T) {
		w := httptest.NewRecorder()
		rules := []RewriteRule{
			{Pattern: "*.blocked.com", Action: "PROXY"},
			{Pattern: "*.direct.com", Action: "DIRECT"},
		}
		body, _ := json.Marshal(rules)
		req, _ := http.NewRequest(http.MethodPost, "/api/extension/rules", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-Key", "test-api-key-9876")

		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d", w.Code)
		}

		// Read rules back
		w = httptest.NewRecorder()
		req, _ = http.NewRequest(http.MethodGet, "/api/extension/rules", nil)
		req.Header.Set("X-API-Key", "test-api-key-9876")

		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d", w.Code)
		}

		var resp []RewriteRule
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to unmarshal rules: %v", err)
		}

		if len(resp) != 2 || resp[0].Pattern != "*.blocked.com" || resp[0].Action != "PROXY" {
			t.Errorf("unexpected rewrite rules: %+v", resp)
		}
	})

	// 4. Assert corporate shortlinks redirect correctly
	t.Run("Shortlink Redirection Paths", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/go/wiki", nil)

		r.ServeHTTP(w, req)

		if w.Code != http.StatusFound {
			t.Errorf("expected redirect status 302, got %d", w.Code)
		}

		loc := w.Header().Get("Location")
		if loc != "https://wiki.corp.net/" {
			t.Errorf("expected redirection location to match target: %q, got: %q", "https://wiki.corp.net/", loc)
		}

		// Non-existent shortlink
		w = httptest.NewRecorder()
		req, _ = http.NewRequest(http.MethodGet, "/go/nonexistent", nil)

		r.ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("expected status 404 for unknown shortlink, got %d", w.Code)
		}
	})

	// 5. Assert shortlink creation
	t.Run("Add Shortlink Endpoint", func(t *testing.T) {
		w := httptest.NewRecorder()
		body, _ := json.Marshal(Shortlink{Name: "mail", Target: "https://mail.google.com/"})
		req, _ := http.NewRequest(http.MethodPost, "/api/extension/shortlinks", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-Key", "test-api-key-9876")

		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d", w.Code)
		}

		// Verify redirect works
		w = httptest.NewRecorder()
		req, _ = http.NewRequest(http.MethodGet, "/go/mail", nil)

		r.ServeHTTP(w, req)

		if w.Code != http.StatusFound || w.Header().Get("Location") != "https://mail.google.com/" {
			t.Errorf("new shortlink redirect failed: code %d, Location: %q", w.Code, w.Header().Get("Location"))
		}
	})

	// 6. Assert clipboard import parses configurations
	t.Run("Clipboard Auth Importing", func(t *testing.T) {
		w := httptest.NewRecorder()
		textPayload := "Check out these nodes:\nss://YWVzLTEyOC1nY206cGFzc3dvcmQ@1.1.1.1:8388#SS-Node\nSome junk text\nvmess://eyJ2IjoiMiIsInBzIjoiVk1lc3MtTm9kZSIsImFkZCI6IjIuMi4yLjIiLCJwb3J0Ijo0NDMsImlkIjoiMTExMTExMTEtMjIyMi0zMzMzLTQ0NDQtNTU1NTU1NTU1NTU1IiwidHlwZSI6IndzIiwic2VjdXJpdHkiOiJ0bHMifQ=="
		body, _ := json.Marshal(ClipboardImportRequest{Text: textPayload})
		req, _ := http.NewRequest(http.MethodPost, "/api/extension/clipboard-import", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-Key", "test-api-key-9876")

		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d. Body: %s", w.Code, w.Body.String())
		}

		var resp map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to parse response: %v", err)
		}

		imported := resp["imported_count"].(float64)
		if imported != 2 {
			t.Errorf("expected 2 configs parsed, got %f", imported)
		}
	})

	// 7. Verify security boundaries block unauthorized request
	t.Run("Auth Bypass Verification", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/api/extension/status", nil)
		// Missing authorization header

		r.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected status 401 Unauthorized for missing API key, got %d", w.Code)
		}
	})
}
