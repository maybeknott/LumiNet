package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestSidecarServer_Heartbeat(t *testing.T) {
	tempLog := "sidecar_test.log"
	defer os.Remove(tempLog)
	gov := NewSafetyGovernor(tempLog)
	defer gov.Close()

	srv := NewSidecarServer("127.0.0.1:0", "test-secret-token", gov)

	// Test case: Unauthorized
	req, _ := http.NewRequest("GET", "/api/heartbeat", nil)
	rr := httptest.NewRecorder()
	
	mux := http.NewServeMux()
	mux.HandleFunc("/api/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		if !srv.verifyToken(r) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized for missing token, got: %d", rr.Code)
	}

	// Test case: Authorized Bearer Token
	req2, _ := http.NewRequest("GET", "/api/heartbeat", nil)
	req2.Header.Set("Authorization", "Bearer test-secret-token")
	rr2 := httptest.NewRecorder()
	mux.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Errorf("expected 200 OK with valid bearer token, got: %d", rr2.Code)
	}

	// Test case: Authorized X-Sidecar-Token
	req3, _ := http.NewRequest("GET", "/api/heartbeat", nil)
	req3.Header.Set("X-Sidecar-Token", "test-secret-token")
	rr3 := httptest.NewRecorder()
	mux.ServeHTTP(rr3, req3)
	if rr3.Code != http.StatusOK {
		t.Errorf("expected 200 OK with valid custom header token, got: %d", rr3.Code)
	}
}

func TestSidecarServer_DNS_Streaming(t *testing.T) {
	tempLog := "sidecar_test.log"
	defer os.Remove(tempLog)
	gov := NewSafetyGovernor(tempLog)
	defer gov.Close()

	srv := NewSidecarServer("127.0.0.1:0", "secret", gov)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !srv.verifyToken(r) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		var req struct {
			Domain                 string         `json:"domain"`
			SafetySettings         SafetySettings `json:"safety_settings"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		if srv.governor != nil {
			if err := srv.governor.ValidateScan(req.Domain, req.SafetySettings); err != nil {
				w.WriteHeader(http.StatusForbidden)
				return
			}
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		_ = json.NewEncoder(w).Encode(map[string]any{"domain": req.Domain, "resolved": "1.1.1.1"})
	})

	// Test case: Blocked Private IP Target
	bodyBlocked := `{"domain": "10.0.0.1", "safety_settings": {"respect_safety": true, "authorization_confirmed": false, "rate_ceiling": 100}}`
	reqBlocked, _ := http.NewRequest("POST", "/api/dns", bytes.NewBufferString(bodyBlocked))
	reqBlocked.Header.Set("X-Sidecar-Token", "secret")
	rrBlocked := httptest.NewRecorder()
	
	handler.ServeHTTP(rrBlocked, reqBlocked)
	if rrBlocked.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for blocked IP scan, got: %d", rrBlocked.Code)
	}

	// Test case: Approved Target
	bodyApproved := `{"domain": "localhost", "safety_settings": {"respect_safety": true, "authorization_confirmed": true, "rate_ceiling": 100}}`
	reqApproved, _ := http.NewRequest("POST", "/api/dns", bytes.NewBufferString(bodyApproved))
	reqApproved.Header.Set("X-Sidecar-Token", "secret")
	rrApproved := httptest.NewRecorder()
	
	handler.ServeHTTP(rrApproved, reqApproved)
	if rrApproved.Code != http.StatusOK {
		t.Errorf("expected 200 OK for approved target, got: %d", rrApproved.Code)
	}

	resBody, _ := io.ReadAll(rrApproved.Body)
	if !strings.Contains(string(resBody), "localhost") {
		t.Errorf("expected localhost in response, got: %s", string(resBody))
	}
}
