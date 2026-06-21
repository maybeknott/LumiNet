package proxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

func TestCoalescer_SubmitSingle(t *testing.T) {
	// A simple echo mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)

		// Checks auth key
		if req["k"] != "my-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		bodyB64, _ := req["b"].(string)
		bodyBytes, _ := base64.StdEncoding.DecodeString(bodyB64)

		resp := workerResponse{
			Status: 200,
			Headers: map[string]interface{}{
				"Content-Type": "text/plain",
			},
			Body: base64.StdEncoding.EncodeToString(bodyBytes),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	parsedURL, _ := url.Parse(server.URL)
	c := NewCoalescer(nil, []string{server.URL}, parsedURL.Host, "my-key", 2*time.Second)
	defer c.Stop()

	res, err := c.Submit("POST", "https://example.com/api", map[string]string{"Accept": "text/html"}, []byte("hello single coalescer"))
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}

	if string(res.Body) != "hello single coalescer" {
		t.Errorf("Expected body 'hello single coalescer', got %q", string(res.Body))
	}
}

func TestCoalescer_BatchCoalescing(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var env batchEnvelope
		err := json.NewDecoder(r.Body).Decode(&env)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if env.Key != "batch-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		results := make([]workerResponse, len(env.Items))
		for i, item := range env.Items {
			bodyBytes, _ := base64.StdEncoding.DecodeString(item.Body)
			results[i] = workerResponse{
				Status: 200,
				Headers: map[string]interface{}{
					"Content-Type": "text/plain",
				},
				Body: base64.StdEncoding.EncodeToString([]byte("response: " + string(bodyBytes))),
			}
		}

		respEnvelope := batchResponseEnvelope{Items: results}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(respEnvelope)
	}))
	defer server.Close()

	parsedURL, _ := url.Parse(server.URL)
	c := NewCoalescer(nil, []string{server.URL}, parsedURL.Host, "batch-key", 2*time.Second)
	defer c.Stop()

	// Speed up the collection window for testing
	c.window = 50 * time.Millisecond

	var wg sync.WaitGroup
	errs := make(chan error, 3)
	bodies := make(chan string, 3)

	submitTask := func(msg string) {
		defer wg.Done()
		res, err := c.Submit("POST", "https://example.com/api", map[string]string{}, []byte(msg))
		if err != nil {
			errs <- err
			return
		}
		bodies <- string(res.Body)
	}

	wg.Add(3)
	go submitTask("one")
	go submitTask("two")
	go submitTask("three")
	wg.Wait()

	close(errs)
	close(bodies)

	for err := range errs {
		t.Fatalf("Concurrent submit failed: %v", err)
	}

	expected := map[string]bool{
		"response: one":   true,
		"response: two":   true,
		"response: three": true,
	}

	for body := range bodies {
		if !expected[body] {
			t.Errorf("Unexpected body response: %q", body)
		}
	}
}

func TestAppsScriptRoundTrip_Redirect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect-target" {
			w.Header().Set("Content-Type", "application/json")
			resp := workerResponse{
				Status: 200,
				Body:   base64.StdEncoding.EncodeToString([]byte("redirect success")),
			}
			_ = json.NewEncoder(w).Encode(resp)
			return
		}

		w.Header().Set("Location", "/redirect-target")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()

	parsedURL, _ := url.Parse(server.URL)
	client := NewHTTPClient(2 * time.Second)
	ctx := context.Background()

	body, err := AppsScriptRoundTrip(ctx, client, server.URL, parsedURL.Host, `{"k":"key"}`, 2*time.Second)
	if err != nil {
		t.Fatalf("AppsScriptRoundTrip failed: %v", err)
	}

	var workerResp workerResponse
	if err := json.Unmarshal(body, &workerResp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	decoded, _ := base64.StdEncoding.DecodeString(workerResp.Body)
	if string(decoded) != "redirect success" {
		t.Errorf("Expected 'redirect success', got %q", string(decoded))
	}
}

func TestDecompressRelayResponse_Gzip(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	_, _ = gw.Write([]byte("gzip data payload"))
	gw.Close()

	envelope := struct {
		Z string `json:"z"`
	}{
		Z: base64.StdEncoding.EncodeToString(buf.Bytes()),
	}

	envelopeBytes, _ := json.Marshal(envelope)
	decompressed := decompressRelayResponse(envelopeBytes)

	if string(decompressed) != "gzip data payload" {
		t.Errorf("Expected 'gzip data payload', got %q", string(decompressed))
	}
}

func TestRequestPriority(t *testing.T) {
	tests := []struct {
		item coalescerItem
		want int
	}{
		{coalescerItem{method: "POST", targetURL: "https://google.com/upload", headers: map[string]string{"Content-Type": "multipart/form-data"}}, 2},
		{coalescerItem{method: "GET", targetURL: "https://example.com/page.html", headers: map[string]string{"Accept": "text/html"}}, 0},
		{coalescerItem{method: "GET", targetURL: "https://example.com/style.css", headers: map[string]string{"Accept": "text/css"}}, 5},
		{coalescerItem{method: "GET", targetURL: "https://example.com/script.js", headers: map[string]string{"Accept": "application/javascript"}}, 10},
		{coalescerItem{method: "GET", targetURL: "https://example.com/font.woff2", headers: map[string]string{}}, 20},
		{coalescerItem{method: "GET", targetURL: "https://example.com/image.png", headers: map[string]string{}}, 30},
		{coalescerItem{method: "GET", targetURL: "https://example.com/analytics/collect", headers: map[string]string{}}, 80},
		{coalescerItem{method: "POST", targetURL: "https://example.com/analytics/collect", headers: map[string]string{}}, 80},
		{coalescerItem{method: "GET", targetURL: "https://example.com/api/data", headers: map[string]string{}}, 40},
	}

	for _, tt := range tests {
		got := requestPriority(&tt.item)
		if got != tt.want {
			t.Errorf("requestPriority(%s %s) = %d; want %d", tt.item.method, tt.item.targetURL, got, tt.want)
		}
	}
}
