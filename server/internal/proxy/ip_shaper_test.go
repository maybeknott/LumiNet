package proxy

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestShapeProxyConfig(t *testing.T) {
	template := &ProxyConfig{
		Protocol:  ProtocolVLESS,
		Address:   "my-cdn.com",
		Port:      443,
		UUID:      "9de78a2e-4b7b-4171-ba47-19ad0d7f9503",
		TLS:       true,
		Transport: "ws",
		Name:      "TemplateProxy",
	}

	cleanIPs := []string{
		"104.16.0.1",
		"104.16.0.2",
	}

	reshaped, err := ShapeProxyConfig(template, cleanIPs, "{name} - {ip}")
	if err != nil {
		t.Fatalf("ShapeProxyConfig error: %v", err)
	}

	if len(reshaped) != 2 {
		t.Fatalf("expected 2 reshaped configs, got %d", len(reshaped))
	}

	if reshaped[0].Address != "104.16.0.1" || reshaped[0].SNI != "my-cdn.com" || reshaped[0].Host != "my-cdn.com" || reshaped[0].Name != "TemplateProxy - 104.16.0.1" {
		t.Errorf("reshaped[0] properties mismatch: %+v", reshaped[0])
	}

	if reshaped[1].Address != "104.16.0.2" || reshaped[1].SNI != "my-cdn.com" || reshaped[1].Host != "my-cdn.com" || reshaped[1].Name != "TemplateProxy - 104.16.0.2" {
		t.Errorf("reshaped[1] properties mismatch: %+v", reshaped[1])
	}
}

func TestTokenBucket_RateLimiting(t *testing.T) {
	tb := NewTokenBucket(1000, 100) // 1000 B/s, capacity 100

	t0 := time.Now()
	tb.Limit(50) // Immediate, within capacity
	if time.Since(t0) > 10*time.Millisecond {
		t.Errorf("Limit within capacity took too long: %v", time.Since(t0))
	}

	tb.Limit(100) // Exceeds capacity, should delay
	elapsed := time.Since(t0)
	if elapsed < 50*time.Millisecond {
		t.Errorf("Expected rate limiting delay, got elapsed time: %v", elapsed)
	}
}

func TestPacedConn_ReadWrite(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer l.Close()

	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn) // Echo server
	}()

	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	// Wrap in PacedConn with 5000 bytes/sec limit
	paced := NewPacedConn(conn, 5000, 5000)

	payload := []byte("paced test message payload")
	t0 := time.Now()
	_, err = paced.Write(payload)
	if err != nil {
		t.Fatalf("failed to write to paced connection: %v", err)
	}

	buf := make([]byte, len(payload))
	_, err = io.ReadFull(paced, buf)
	if err != nil {
		t.Fatalf("failed to read from paced connection: %v", err)
	}

	if string(buf) != string(payload) {
		t.Errorf("expected %q, got %q", string(payload), string(buf))
	}

	if time.Since(t0) > 100*time.Millisecond {
		t.Logf("Paced connection write/read completed in: %v", time.Since(t0))
	}
}

func TestLocalIPPool_GenerationAndSelection(t *testing.T) {
	pool, err := NewLocalIPPool("192.168.1.0/28")
	if err != nil {
		t.Fatalf("failed to create IP pool: %v", err)
	}

	if len(pool.ips) != 16 {
		t.Errorf("expected 16 IPs in CIDR, got %d", len(pool.ips))
	}

	firstIP := pool.SelectIP()
	if !firstIP.Equal(net.ParseIP("192.168.1.0")) {
		t.Errorf("expected first IP to be 192.168.1.0, got %s", firstIP)
	}

	secondIP := pool.SelectIP()
	if !secondIP.Equal(net.ParseIP("192.168.1.1")) {
		t.Errorf("expected second IP to be 192.168.1.1, got %s", secondIP)
	}
}

func TestLossRateMonitor_Adaptation(t *testing.T) {
	monitor := NewLossRateMonitor(10000, 2000, 50000)

	if monitor.GetRate() != 10000 {
		t.Errorf("expected initial rate 10000, got %d", monitor.GetRate())
	}

	// Trigger a failure -> rate should drop by 20% to 8000
	monitor.RecordFailure()
	if monitor.GetRate() != 8000 {
		t.Errorf("expected dropped rate 8000 after failure, got %d", monitor.GetRate())
	}

	// Record successes to clear the window that has the failure
	for i := 0; i < 10; i++ {
		monitor.RecordSuccess()
	}
	// Record 10 successes with 0 failures -> rate should scale up by 10% to 8800
	for i := 0; i < 10; i++ {
		monitor.RecordSuccess()
	}
	if monitor.GetRate() != 8800 {
		t.Errorf("expected rate scaled up to 8800, got %d", monitor.GetRate())
	}

	// Dynamic clamp test
	for i := 0; i < 100; i++ {
		monitor.RecordFailure()
	}
	if monitor.GetRate() != 2000 {
		t.Errorf("expected rate to clamp to minRate 2000, got %d", monitor.GetRate())
	}
}

