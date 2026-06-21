package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/proxy"
)

func TestSystemTrafficAPI(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Reset any previous stats before running the test
	proxy.ResetEvasionTrafficStats()

	// Add mock bytes
	proxy.AddUploadBytes(1024)
	proxy.AddDownloadBytes(2048)

	server := &Server{}

	t.Run("Get System Traffic Stats", func(t *testing.T) {
		w := httptest.NewRecorder()
		_, r := gin.CreateTestContext(w)
		r.GET("/api/system/traffic", server.GetSystemTraffic)

		req, err := http.NewRequest(http.MethodGet, "/api/system/traffic", nil)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}

		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d. Body: %s", w.Code, w.Body.String())
		}

		var resp map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to parse response: %v", err)
		}

		if resp["upload_bytes"] != float64(1024) {
			t.Errorf("expected upload_bytes 1024, got %v", resp["upload_bytes"])
		}
		if resp["download_bytes"] != float64(2048) {
			t.Errorf("expected download_bytes 2048, got %v", resp["download_bytes"])
		}
	})

	t.Run("Reset System Traffic Stats", func(t *testing.T) {
		w := httptest.NewRecorder()
		_, r := gin.CreateTestContext(w)
		r.POST("/api/system/traffic/reset", server.ResetSystemTraffic)

		req, err := http.NewRequest(http.MethodPost, "/api/system/traffic/reset", nil)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}

		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d. Body: %s", w.Code, w.Body.String())
		}

		var resp map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to parse response: %v", err)
		}

		if resp["status"] != "ok" {
			t.Errorf("expected status 'ok', got '%v'", resp["status"])
		}

		// Verify stats are reset to 0
		up, down := proxy.GetEvasionTrafficStats()
		if up != 0 || down != 0 {
			t.Errorf("expected stats to be reset, got up=%d, down=%d", up, down)
		}
	})
}
