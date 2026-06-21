package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCaptchaSolver_SolveCaptcha(t *testing.T) {
	var pollCount int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/in.php") {
			if r.Method != "POST" {
				t.Errorf("expected POST method, got %s", r.Method)
			}
			err := r.ParseForm()
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if r.FormValue("key") != "test-api-key" {
				t.Errorf("expected key test-api-key, got %s", r.FormValue("key"))
			}
			if r.FormValue("method") != "turnstile" {
				t.Errorf("expected method turnstile, got %s", r.FormValue("method"))
			}
			if r.FormValue("pageurl") != "https://example.com" {
				t.Errorf("expected pageurl https://example.com, got %s", r.FormValue("pageurl"))
			}
			if r.FormValue("sitekey") != "test-sitekey" {
				t.Errorf("expected sitekey test-sitekey, got %s", r.FormValue("sitekey"))
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  1,
				"request": "task-id-100",
			})
			return
		}

		if strings.HasSuffix(r.URL.Path, "/res.php") {
			if r.Method != "GET" {
				t.Errorf("expected GET method, got %s", r.Method)
			}
			q := r.URL.Query()
			if q.Get("key") != "test-api-key" {
				t.Errorf("expected key test-api-key, got %s", q.Get("key"))
			}
			if q.Get("id") != "task-id-100" {
				t.Errorf("expected id task-id-100, got %s", q.Get("id"))
			}
			if q.Get("action") != "get" {
				t.Errorf("expected action get, got %s", q.Get("action"))
			}

			w.Header().Set("Content-Type", "application/json")
			count := atomic.AddInt32(&pollCount, 1)
			if count == 1 {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"status":  0,
					"request": "CAPCHA_NOT_READY",
				})
			} else {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"status":  1,
					"request": "solution-token-xyz",
				})
			}
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	solver := NewCaptchaSolver("test-api-key", server.URL)
	solver.PollingInterval = 10 * time.Millisecond
	solver.Timeout = 100 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	token, err := solver.SolveTurnstile(ctx, "https://example.com", "test-sitekey", "test-ua")
	if err != nil {
		t.Fatalf("SolveTurnstile failed: %v", err)
	}

	if token != "solution-token-xyz" {
		t.Errorf("expected solution-token-xyz, got %s", token)
	}

	if atomic.LoadInt32(&pollCount) < 2 {
		t.Errorf("expected at least 2 polls, got %d", atomic.LoadInt32(&pollCount))
	}
}

func TestCaptchaSolver_SolveCaptcha_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/in.php") {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  0,
				"request": "ERROR_KEY_DOES_NOT_EXIST",
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	solver := NewCaptchaSolver("invalid-key", server.URL)
	_, err := solver.SolveReCAPTCHA(context.Background(), "https://example.com", "sitekey")
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "ERROR_KEY_DOES_NOT_EXIST") {
		t.Errorf("expected ERROR_KEY_DOES_NOT_EXIST in error message, got: %v", err)
	}
}
