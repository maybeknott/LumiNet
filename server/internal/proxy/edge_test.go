package proxy

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestWindscribeAdapterSuccess(t *testing.T) {
	adapter := NewWindscribeAdapter()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := RoutingPluginConfig{
		SchemaVersion: 1,
		RouteID:       "route-ws-1",
		PluginID:      "windscribe",
		Fields: map[string]string{
			"mode":      "wireguard",
			"auth_mode": "wsnet_session_ref",
		},
		CredentialRef: "ref:session-token",
	}

	var mu sync.Mutex
	statusChanges := []string{}
	successCount := 0
	failureCount := 0

	cb := &WindscribeCallback{
		OnStatusChanged: func(status string, details string) {
			mu.Lock()
			defer mu.Unlock()
			statusChanges = append(statusChanges, status)
		},
		OnSuccess: func(readiness ProviderRouteReadiness) {
			mu.Lock()
			defer mu.Unlock()
			successCount++
		},
		OnFailure: func(errorCode string, err error) {
			mu.Lock()
			defer mu.Unlock()
			failureCount++
		},
	}

	resChan, errChan := adapter.StartSession(ctx, cfg, cb)

	select {
	case readiness := <-resChan:
		if readiness.Status != "success" || readiness.ReadinessState != "probe_passed" {
			t.Fatalf("unexpected success readiness state: %#v", readiness)
		}
	case err := <-errChan:
		t.Fatalf("unexpected error received: %v", err)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout waiting for session result")
	}

	mu.Lock()
	defer mu.Unlock()
	if successCount != 1 {
		t.Fatalf("expected 1 success, got %d", successCount)
	}
	if failureCount != 0 {
		t.Fatalf("expected 0 failures, got %d", failureCount)
	}
	if len(statusChanges) < 2 {
		t.Fatalf("expected status transitions, got %v", statusChanges)
	}
}

func TestWindscribeAdapterCancellation(t *testing.T) {
	adapter := NewWindscribeAdapter()
	ctx, cancel := context.WithCancel(context.Background())

	cfg := RoutingPluginConfig{
		SchemaVersion: 1,
		RouteID:       "route-ws-2",
		PluginID:      "windscribe",
		Fields: map[string]string{
			"mode": "wireguard",
		},
	}

	cb := &WindscribeCallback{}

	// Cancel context immediately to test early cancellation propagation
	cancel()

	resChan, errChan := adapter.StartSession(ctx, cfg, cb)

	select {
	case readiness := <-resChan:
		if readiness.ReadinessState != "cancelled" || readiness.Status != "failed" {
			t.Fatalf("expected cancelled readiness, got: %#v", readiness)
		}
	case err := <-errChan:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled error, got: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout waiting for cancellation result")
	}
}

func TestWindscribeAdapterFailureMode(t *testing.T) {
	adapter := NewWindscribeAdapter()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := RoutingPluginConfig{
		SchemaVersion: 1,
		RouteID:       "route-ws-3",
		PluginID:      "windscribe",
		Fields: map[string]string{
			"mode":      "wireguard",
			"auth_mode": "wsnet_login_required",
		},
	}

	resChan, errChan := adapter.StartSession(ctx, cfg, nil)

	select {
	case readiness := <-resChan:
		t.Fatalf("unexpected success readiness state: %#v", readiness)
	case err := <-errChan:
		if err == nil || err.Error() != "login required on Android layer" {
			t.Fatalf("unexpected failure error: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout waiting for failure result")
	}
}

func TestPsiphonNoticeParserDetectsProxyReadiness(t *testing.T) {
	state, err := ParsePsiphonNoticeStream("route-psiphon", strings.NewReader(
		`{"notice_type":"ListeningSocksProxyPort","ListeningSocksProxyPort":1080}`+"\n",
	))
	if err != nil {
		t.Fatal(err)
	}
	if state.Status != "success" || state.ReadinessState != "proxy_listening" || state.SOCKSPort != 1080 {
		t.Fatalf("unexpected psiphon readiness: %#v", state)
	}
}

func TestWindscribeRouteObserverDetectsExternalVPNAndDNSDelta(t *testing.T) {
	observer := WindscribeRouteObserver{Connectivity: staticConnectivitySnapshotter{snapshot: ConnectivitySnapshot{
		ExternalIP:       "198.51.100.200",
		DNSResolvers:     []string{"10.255.0.1"},
		DefaultInterface: "tun0",
	}}}
	state, err := observer.Observe(context.Background(), RoutingPluginConfig{
		SchemaVersion: 1,
		RouteID:       "route-windscribe",
		PluginID:      "windscribe",
		ProfileRef:    "ref:profile",
		Fields: map[string]string{
			"mode":       "wireguard",
			"dns_policy": "ctrld",
		},
	}, ConnectivitySnapshot{
		ExternalIP:   "203.0.113.20",
		DNSResolvers: []string{"192.0.2.53"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if state.Status != "success" || !state.ExternalVPNObserved || state.DNSPolicyObserved != "ctrld" {
		t.Fatalf("unexpected windscribe observation: %#v", state)
	}
}

func TestProbeLocalHTTPProxyDetectsListeningPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()
	state := ProbeLocalHTTPProxy(context.Background(), "http://"+ln.Addr().String(), time.Second)
	if state.Status != "success" || !state.LocalProxyObserved {
		t.Fatalf("unexpected local proxy state: %#v", state)
	}
	<-done
}
