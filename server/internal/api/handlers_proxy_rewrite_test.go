package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestRewriteProxyContent_Handler(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		req            RewriteProxyRequest
		expectedStatus int
	}{
		{
			name: "Valid Rewrite Request",
			req: RewriteProxyRequest{
				Content:  "vless://11111111-2222-3333-4444-555555555555@example.com:443?type=ws&security=tls#node1",
				CleanIPs: []string{"104.16.1.1", "104.16.2.2"},
				NewPort:  8080,
				NewName:  "{name} | {ip}",
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "Empty Content",
			req: RewriteProxyRequest{
				Content:  "",
				CleanIPs: []string{"104.16.1.1"},
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Empty Clean IPs",
			req: RewriteProxyRequest{
				Content:  "vless://11111111-2222-3333-4444-555555555555@example.com:443?type=ws",
				CleanIPs: []string{},
			},
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			_, r := gin.CreateTestContext(w)

			server := &Server{}
			r.POST("/api/proxies/rewrite", server.RewriteProxyContent)

			body, err := json.Marshal(tt.req)
			if err != nil {
				t.Fatalf("failed to marshal request body: %v", err)
			}

			req, err := http.NewRequest(http.MethodPost, "/api/proxies/rewrite", bytes.NewReader(body))
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")

			r.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d. Body: %s", tt.expectedStatus, w.Code, w.Body.String())
			}

			if tt.expectedStatus == http.StatusOK {
				var resp RewriteProxyResponse
				if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}
				if resp.Count != 2 {
					t.Errorf("expected 2 rewritten results, got %d", resp.Count)
				}
				if len(resp.Results) != 2 {
					t.Errorf("expected 2 result strings, got %d", len(resp.Results))
				}
			}
		})
	}
}
