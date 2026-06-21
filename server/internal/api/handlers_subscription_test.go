package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestAggregateSubscriptionsHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	_, r := gin.CreateTestContext(w)

	server := &Server{}
	r.POST("/api/subscriptions/aggregate", server.AggregateSubscriptionsHandler)

	reqPayload := SubscriptionAggregateRequest{
		Inputs: []string{
			"vless://9de78a2e-4b7b-4171-ba47-19ad0d7f9503@example.com:443?type=tcp&security=tls#VlessTest",
			"vmess://eyJhZGQiOiJleGFtcGxlLmNvbSIsImFpZCI6MCwiaG9zdCI6IiIsImlkIjoiOWRlNzhhMmUtNGI3Yi00MTcxLWJhNDctMTlhZDBkN2Y5NTAzIiwibmV0Ijoid3MiLCJwYXRoIjoiLyIsInBvcnQiOjgwODAsInBzIjoiVk1lc3NUZXN0Iiwic2N5IjoiYXV0byIsInNuaSI6IiIsInRscyI6IiIsInR5cGUiOiJub25lIiwidiI6IjIifQ==",
		},
		AllowProtocols: []string{"vless"},
	}

	body, _ := json.Marshal(reqPayload)
	req, err := http.NewRequest("POST", "/api/subscriptions/aggregate", bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d. Body: %s", w.Code, w.Body.String())
	}

	var resp SubscriptionActionResponse
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	if err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	// Should filter out VMess and only return VLESS
	if resp.Count != 1 {
		t.Errorf("expected count 1, got %d", resp.Count)
	}
	if len(resp.Results) != 1 || resp.Results[0].Protocol != "vless" {
		t.Errorf("expected 1 vless result, got: %+v", resp.Results)
	}
}

func TestShapeSubscriptionHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	_, r := gin.CreateTestContext(w)

	server := &Server{}
	r.POST("/api/subscriptions/shape", server.ShapeSubscriptionHandler)

	reqPayload := SubscriptionShapeRequest{
		TemplateURI:  "vless://9de78a2e-4b7b-4171-ba47-19ad0d7f9503@my-cdn.com:443?type=ws&security=tls#MyProxy",
		CleanIPs:     []string{"1.1.1.1", "2.2.2.2"},
		NameTemplate: "{name} | {ip}",
	}

	body, _ := json.Marshal(reqPayload)
	req, err := http.NewRequest("POST", "/api/subscriptions/shape", bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d. Body: %s", w.Code, w.Body.String())
	}

	var resp SubscriptionActionResponse
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	if err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp.Count != 2 {
		t.Errorf("expected count 2, got %d", resp.Count)
	}
	if len(resp.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(resp.Results))
	}
	if resp.Results[0].Address != "1.1.1.1" || resp.Results[0].Name != "MyProxy | 1.1.1.1" {
		t.Errorf("unexpected shaped result: %+v", resp.Results[0])
	}
}
