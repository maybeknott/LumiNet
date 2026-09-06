package speedtest

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestBatchSpeedEvaluatorTcpPing(t *testing.T) {
	// Start local TCP listener
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on local port: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	opts := DefaultEvaluatorOptions()
	opts.ProbeTimeout = 500 * time.Millisecond
	eval := NewBatchSpeedEvaluator(opts)

	ctx := context.Background()
	lat, err := eval.EvaluateTcpPing(ctx, ln.Addr().String())
	if err != nil {
		t.Fatalf("expected successful TCP ping, got: %v", err)
	}
	if lat < 0 {
		t.Fatalf("invalid negative latency: %d", lat)
	}

	// Test unreachable target
	_, err = eval.EvaluateTcpPing(ctx, "127.0.0.1:59999")
	if err == nil {
		t.Fatalf("expected error on closed port, got nil")
	}
}

func TestBatchSpeedEvaluatorRealPingAndSpeedtest(t *testing.T) {
	// Start test HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ping" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.URL.Path == "/speed" {
			chunk := make([]byte, 1024)
			for i := 0; i < 100; i++ {
				_, _ = w.Write(chunk)
			}
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	opts := DefaultEvaluatorOptions()
	opts.ProbeTimeout = 1 * time.Second
	opts.RealPingURL = server.URL + "/ping"
	opts.SpeedtestURL = server.URL + "/speed"
	opts.MaxDownloadBytes = 100 * 1024
	eval := NewBatchSpeedEvaluator(opts)

	ctx := context.Background()

	// RealPing
	lat, err := eval.EvaluateRealPing(ctx, server.URL+"/ping")
	if err != nil {
		t.Fatalf("real ping failed: %v", err)
	}
	if lat < 0 {
		t.Fatalf("invalid latency: %d", lat)
	}

	// Speedtest
	mbps, bytes, err := eval.EvaluateSpeedtest(ctx, server.URL+"/speed")
	if err != nil {
		t.Fatalf("speedtest failed: %v", err)
	}
	if bytes != 100*1024 {
		t.Fatalf("expected 102400 bytes, got %d", bytes)
	}
	if mbps <= 0 {
		t.Fatalf("expected positive mbps, got %f", mbps)
	}

	// Batch evaluation
	targets := []string{
		server.URL + "/ping",
		server.URL + "/ping",
	}
	batchRes := eval.EvaluateBatch(ctx, ActionRealPing, targets)
	if len(batchRes) != 2 {
		t.Fatalf("expected 2 results, got %d", len(batchRes))
	}
	for i, res := range batchRes {
		if !res.Success {
			t.Fatalf("result %d failed: %s", i, res.Error)
		}
	}
}
