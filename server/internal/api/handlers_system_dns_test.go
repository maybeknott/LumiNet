package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestSetDns_Validation(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		req            SetDNSRequest
		expectedStatus int
	}{
		{
			name: "Valid DNS Servers",
			req: SetDNSRequest{
				Interface: "Ethernet",
				Servers:   []string{"8.8.8.8", "1.1.1.1"},
			},
			// In a test environment without elevation/mocking, it may return 500
			// (due to execution failure of system command), but it must NOT return 400.
			expectedStatus: http.StatusOK,
		},
		{
			name: "Invalid DNS Server - Command Injection Payload",
			req: SetDNSRequest{
				Interface: "Ethernet",
				Servers:   []string{"8.8.8.8'); Start-Process calc; ('"},
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Invalid DNS Server - Empty entry",
			req: SetDNSRequest{
				Interface: "Ethernet",
				Servers:   []string{""},
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Invalid DNS Server - Too many servers",
			req: SetDNSRequest{
				Interface: "Ethernet",
				Servers:   []string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5", "6.6.6.6", "7.7.7.7", "8.8.8.8", "9.9.9.9"},
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Invalid Interface - Command Injection Payload",
			req: SetDNSRequest{
				Interface: "Ethernet; reboot",
				Servers:   []string{"8.8.8.8"},
			},
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			_, r := gin.CreateTestContext(w)

			// Simple mock server setup
			server := &Server{}
			r.POST("/api/system/dns", server.SetDns)

			body, err := json.Marshal(tt.req)
			if err != nil {
				t.Fatalf("failed to marshal request body: %v", err)
			}

			req, err := http.NewRequest(http.MethodPost, "/api/system/dns", bytes.NewReader(body))
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")

			r.ServeHTTP(w, req)

			if tt.expectedStatus == http.StatusBadRequest {
				if w.Code != http.StatusBadRequest {
					t.Errorf("expected status 400 Bad Request, got %d. Body: %s", w.Code, w.Body.String())
				}
			} else {
				// Valid request: either gets 200 OK (if execution succeeds on local machine)
				// or 500 Internal Server Error (if system interface / platform is not present).
				// Crucially, it must NOT return 400.
				if w.Code == http.StatusBadRequest {
					t.Errorf("expected valid inputs to pass validation (got %d), got 400 Bad Request. Body: %s", w.Code, w.Body.String())
				}
			}
		})
	}
}
