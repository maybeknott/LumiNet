package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGsaTunnelConn(t *testing.T) {
	var lastReceivedData []byte
	var lastAuthKey string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastAuthKey = r.Header.Get("X-GSA-Auth-Key")

		var payload TunnelPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if len(payload.Data) > 0 {
			lastReceivedData = payload.Data
		}

		resp := TunnelResponse{}
		if len(payload.Data) > 0 {
			// Echo the data back
			resp.Data = payload.Data
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	authKey := "test-gsa-key"
	target := "example.com:80"
	conn := NewGsaTunnelConn(server.URL, authKey, target)
	defer conn.Close()

	// Test writing
	payload := []byte("hello gsa")
	n, err := conn.Write(payload)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != len(payload) {
		t.Errorf("Expected to write %d bytes, wrote %d", len(payload), n)
	}

	// Wait a brief moment for HTTP polling to catch up and echo
	time.Sleep(300 * time.Millisecond)

	// Test reading
	buf := make([]byte, 64)
	n, err = conn.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if string(buf[:n]) != "hello gsa" {
		t.Errorf("Expected 'hello gsa', got '%s'", string(buf[:n]))
	}

	if string(lastReceivedData) != "hello gsa" {
		t.Errorf("Expected server to receive 'hello gsa', got '%s'", string(lastReceivedData))
	}

	if lastAuthKey != authKey {
		t.Errorf("Expected auth key '%s', got '%s'", authKey, lastAuthKey)
	}
}
