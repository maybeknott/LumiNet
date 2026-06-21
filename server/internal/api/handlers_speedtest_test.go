package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestSpeedtestHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create a mock speedtest target server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server-Timing", "dur=100") // 100ms timing
		w.WriteHeader(http.StatusOK)
		// Send 10KB of mock data
		data := make([]byte, 10*1024)
		_, _ = w.Write(data)
	}))
	defer mockServer.Close()

	server := &Server{}
	router := gin.New()
	apiGroup := router.Group("/api")
	server.setupSpeedtestRoutes(apiGroup)

	t.Run("POST /api/system/speedtest - Run mock download", func(t *testing.T) {
		cfg := SpeedtestRequest{
			URL:            mockServer.URL,
			Bytes:          10 * 1024,
			TimeoutSeconds: 5,
		}

		body, _ := json.Marshal(cfg)
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/api/system/speedtest", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d (body: %s)", w.Code, w.Body.String())
		}

		var result SpeedtestResponse
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatalf("failed to unmarshal speedtest response: %v", err)
		}

		if !result.Success {
			t.Errorf("expected speedtest success, got error: %s", result.Error)
		}
		if result.DownloadSpeedMbps <= 0 {
			t.Errorf("expected download speed > 0, got %f", result.DownloadSpeedMbps)
		}
		if result.ServerTimingSeconds != 0.1 {
			t.Errorf("expected Server-Timing 0.1s, got %f", result.ServerTimingSeconds)
		}
	})

	t.Run("POST /api/system/speedtest - Invalid Request Body", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/api/system/speedtest", bytes.NewBufferString("invalid json"))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected status 400, got %d", w.Code)
		}

		var result SpeedtestResponse
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatalf("failed to unmarshal error response: %v", err)
		}

		if result.Success {
			t.Error("expected speedtest success to be false")
		}
	})
}
