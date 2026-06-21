package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/jobs"
)

func TestCreateTlsScan_Handler(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		req            CreateTlsScanRequest
		expectedStatus int
	}{
		{
			name: "Valid Single TLS Scan",
			req: CreateTlsScanRequest{
				Target:    "example.com",
				Port:      443,
				TimeoutMs: 1000,
			},
			expectedStatus: http.StatusAccepted,
		},
		{
			name: "Valid CDN Sweep Scan",
			req: CreateTlsScanRequest{
				Mode:        "cdn_sweep",
				Targets:     []string{"104.16.0.0/12"},
				TimeoutMs:   1000,
				Concurrency: 10,
				SampleRate:  1,
				Sni:         "speed.cloudflare.com",
			},
			expectedStatus: http.StatusAccepted,
		},
		{
			name: "CDN Sweep Missing Targets",
			req: CreateTlsScanRequest{
				Mode: "cdn_sweep",
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Single Scan Missing Target",
			req: CreateTlsScanRequest{},
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			_, r := gin.CreateTestContext(w)

			// Instantiate server with a clean memory JobManager
			jobMgr := jobs.NewJobManager(nil)
			server := &Server{
				jobManager: jobMgr,
			}
			r.POST("/api/tls-scans", server.CreateTlsScan)

			body, err := json.Marshal(tt.req)
			if err != nil {
				t.Fatalf("failed to marshal request: %v", err)
			}

			req, err := http.NewRequest(http.MethodPost, "/api/tls-scans", bytes.NewReader(body))
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")

			r.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d. Body: %s", tt.expectedStatus, w.Code, w.Body.String())
			}

			if tt.expectedStatus == http.StatusAccepted {
				var resp map[string]interface{}
				if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}
				if resp["id"] == nil || resp["id"].(string) == "" {
					t.Errorf("expected non-empty job ID in response")
				}
			}
		})
	}
}
