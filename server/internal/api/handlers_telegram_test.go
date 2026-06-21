package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestGetTelegramMTProtoProxies_Channel(t *testing.T) {
	// 1. Start a mock TCP listener to simulate a working proxy endpoint
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock TCP listener: %v", err)
	}
	defer listener.Close()

	_, portStr, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("failed to parse listener port: %v", err)
	}

	mockPort, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("failed to convert port to int: %v", err)
	}

	// Run a goroutine to accept and immediately close connections on the mock TCP port
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	// 2. Start a mock HTTP server to serve a mock Telegram public channel HTML preview page
	mockHtml := fmt.Sprintf(`
		<html>
		<body>
			tg://proxy?server=127.0.0.1&port=%d&secret=dd00112233445566778899aabbccddeeff
		</body>
		</html>
	`, mockPort)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(mockHtml))
	}))
	defer ts.Close()

	// 3. Set up Gin engine and request context
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	_, r := gin.CreateTestContext(w)

	server := &Server{}
	r.GET("/api/telegram/mtproto", server.GetTelegramMTProtoProxies)

	// Make request passing the mock HTTP server URL as the channel parameter
	req, err := http.NewRequest("GET", "/api/telegram/mtproto?channel="+url.QueryEscape(ts.URL), nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	// Execute route
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d. Body: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Success bool `json:"success"`
		Proxies []struct {
			Host   string `json:"host"`
			Port   int    `json:"port"`
			Secret string `json:"secret"`
			PingMs int    `json:"ping_ms"`
		} `json:"proxies"`
	}

	err = json.Unmarshal(w.Body.Bytes(), &resp)
	if err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if !resp.Success {
		t.Errorf("expected success true, got false")
	}

	if len(resp.Proxies) != 1 {
		t.Fatalf("expected 1 proxy, got %d", len(resp.Proxies))
	}

	p := resp.Proxies[0]
	if p.Host != "127.0.0.1" || p.Port != mockPort {
		t.Errorf("unexpected proxy: %+v", p)
	}
}
