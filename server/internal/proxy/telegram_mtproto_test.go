package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestFetchAndTestMTProto(t *testing.T) {
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

	// 2. Start a mock HTTP server to serve the proxy list JSON
	mockProxies := []MTProtoProxy{
		{
			Host:   "127.0.0.1",
			Port:   mockPort,
			Secret: "dd00112233445566778899aabbccddeeff",
		},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(mockProxies)
	}))
	defer ts.Close()

	// 3. Override mtprotoMirrors for testing
	oldMirrors := mtprotoMirrors
	mtprotoMirrors = []string{ts.URL}
	defer func() { mtprotoMirrors = oldMirrors }()

	// 4. Run the function
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	results, err := FetchAndTestMTProto(ctx)
	if err != nil {
		t.Fatalf("FetchAndTestMTProto failed: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 tested proxy, got %d", len(results))
	}

	res := results[0]
	if res.Host != "127.0.0.1" || res.Port != mockPort {
		t.Errorf("unexpected proxy data: %+v", res)
	}

	if res.PingMs < 0 {
		t.Errorf("expected non-negative ping, got %d", res.PingMs)
	}
}

func TestFetchAndTestMTProtoFromChannel(t *testing.T) {
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

	// 2. Start a mock HTTP server to serve a mock Telegram public channel web HTML
	mockHtml := fmt.Sprintf(`
		<html>
		<body>
			<div class="tgme_page">
				<div class="tgme_page_description">
					Check out this proxy:
					tg://proxy?server=127.0.0.1&port=%d&secret=dd00112233445566778899aabbccddeeff
					Also check this web link:
					href="https://t.me/proxy?server=127.0.0.1&port=%d&secret=dd00112233445566778899aabbccddeeff"
				</div>
			</div>
		</body>
		</html>
	`, mockPort, mockPort)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(mockHtml))
	}))
	defer ts.Close()

	// 3. Run the function passing ts.URL (which starts with http://)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	results, err := FetchAndTestMTProtoFromChannel(ctx, ts.URL)
	if err != nil {
		t.Fatalf("FetchAndTestMTProtoFromChannel failed: %v", err)
	}

	// Because of deduplication, we expect 1 proxy to be parsed and returned
	if len(results) != 1 {
		t.Fatalf("expected 1 tested proxy, got %d", len(results))
	}

	res := results[0]
	if res.Host != "127.0.0.1" || res.Port != mockPort {
		t.Errorf("unexpected proxy data: %+v", res)
	}

	if res.PingMs < 0 {
		t.Errorf("expected non-negative ping, got %d", res.PingMs)
	}
}
