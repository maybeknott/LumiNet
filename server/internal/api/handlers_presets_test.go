package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/proxy"
)

func TestPresetHandlers(t *testing.T) {
	gin.SetMode(gin.TestMode)

	server := &Server{}
	router := gin.New()
	apiGroup := router.Group("/api")
	server.setupPresetRoutes(apiGroup)

	t.Run("GET /api/presets/cdn", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/api/presets/cdn", nil)
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d", w.Code)
		}

		var presets []proxy.CDNPreset
		if err := json.Unmarshal(w.Body.Bytes(), &presets); err != nil {
			t.Fatalf("failed to unmarshal CDN presets: %v", err)
		}

		if len(presets) == 0 {
			t.Error("expected at least one CDN preset")
		}
	})

	t.Run("GET /api/presets/doh", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/api/presets/doh", nil)
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d", w.Code)
		}

		var presets []proxy.DoHPreset
		if err := json.Unmarshal(w.Body.Bytes(), &presets); err != nil {
			t.Fatalf("failed to unmarshal DoH presets: %v", err)
		}

		if len(presets) == 0 {
			t.Error("expected at least one DoH preset")
		}
	})

	t.Run("GET /api/presets/dns", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/api/presets/dns", nil)
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d", w.Code)
		}

		var presets []proxy.DNSPreset
		if err := json.Unmarshal(w.Body.Bytes(), &presets); err != nil {
			t.Fatalf("failed to unmarshal DNS presets: %v", err)
		}

		if len(presets) == 0 {
			t.Error("expected at least one DNS preset")
		}
	})

	t.Run("GET /api/presets/scanner", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/api/presets/scanner", nil)
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d", w.Code)
		}

		var presets []proxy.ScanPreset
		if err := json.Unmarshal(w.Body.Bytes(), &presets); err != nil {
			t.Fatalf("failed to unmarshal scanner presets: %v", err)
		}

		if len(presets) == 0 {
			t.Error("expected at least one scanner preset")
		}
	})

	t.Run("GET /api/presets", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/api/presets", nil)
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d", w.Code)
		}

		var unified map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &unified); err != nil {
			t.Fatalf("failed to unmarshal unified presets: %v", err)
		}

		if _, ok := unified["cdn"]; !ok {
			t.Error("expected cdn key in unified presets response")
		}
		if _, ok := unified["doh"]; !ok {
			t.Error("expected doh key in unified presets response")
		}
		if _, ok := unified["dns"]; !ok {
			t.Error("expected dns key in unified presets response")
		}
		if _, ok := unified["scanner"]; !ok {
			t.Error("expected scanner key in unified presets response")
		}
	})
}
