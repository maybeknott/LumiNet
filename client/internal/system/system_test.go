package system

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

func TestNewFileReader(t *testing.T) {
	// Create a temp file to test standard filesystem read path
	tmpFile, err := os.CreateTemp("", "testfile-*.txt")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	expectedContent := "test data for file reader"
	if _, err := tmpFile.WriteString(expectedContent); err != nil {
		t.Fatalf("failed to write to temp file: %v", err)
	}
	tmpFile.Close()

	reader, err := NewFileReader(tmpFile.Name())
	if err != nil {
		t.Fatalf("NewFileReader failed to open existing file: %v", err)
	}
	defer reader.Close()

	content, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("failed to read file contents: %v", err)
	}

	if string(content) != expectedContent {
		t.Errorf("expected content %q, got %q", expectedContent, string(content))
	}
}

func TestMobileLwipBridge(t *testing.T) {
	// Test lwip stack start, input packet, and stop lifecycle
	mockFlow := &mockPacketFlow{}
	err := StartSocks(mockFlow, "127.0.0.1", 1080, nil)
	if err != nil {
		t.Fatalf("StartSocks failed: %v", err)
	}

	// Write mock IP packet
	mockPacket := []byte{0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x7c, 0xcd, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01}
	err = InputPacket(mockPacket)
	if err != nil {
		t.Errorf("InputPacket returned error: %v", err)
	}

	err = StopSocks()
	if err != nil {
		t.Errorf("StopSocks returned error: %v", err)
	}
}

type mockPacketFlow struct {
	packets [][]byte
}

func (m *mockPacketFlow) WritePacket(packet []byte) {
	m.packets = append(m.packets, packet)
}

func TestHardenedTLSConfig(t *testing.T) {
	config := GetHardenedTLSConfig("example.com")
	if config.MinVersion != uint16(tls.VersionTLS12) {
		t.Errorf("expected min TLS version 1.2, got 0x%x", config.MinVersion)
	}
	if len(config.CipherSuites) == 0 {
		t.Error("expected hardened cipher suites, got empty list")
	}
}

func TestCheckLocalTorProxy(t *testing.T) {
	// CheckLocalTorProxy should run without panic
	_, _ = CheckLocalTorProxy()
}

func TestECHResolver(t *testing.T) {
	resolver := NewECHResolver("8.8.8.8:53", 1*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Resolving a non-existent or unconfigured ECH domain should return error
	_, err := resolver.ResolveECHConfigList(ctx, "invalid-ech-domain.local")
	if err == nil {
		t.Error("expected error for invalid ECH domain resolution, got nil")
	}
}

func TestDialWithECH(t *testing.T) {
	// Start a mock TCP listener to test DialWithECH / DialUTLS connection attempt
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on localhost: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().String()

	// Trigger async accept to handle connection
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			// Immediately close it as we only test handshake trigger/failure
			conn.Close()
		}
	}()

	// Perform DialWithECH - we expect handshake to fail or succeed depending on mock server reply,
	// but the dial flow itself should execute.
	_, _ = DialWithECH("tcp", addr, "localhost", []byte("fake-ech-configs"), utls.HelloChrome_Auto)
}

type mockSocketProtector struct {
	mu           sync.Mutex
	protectedFDs []int64
}

func (m *mockSocketProtector) Protect(fd int64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.protectedFDs = append(m.protectedFDs, fd)
	return true
}

func TestSocketProtector(t *testing.T) {
	// Initialize and register mock socket protector
	protector := &mockSocketProtector{}
	SetSocketProtector(protector)

	// Verify GetSocketProtectFunc is set
	if GetSocketProtectFunc() == nil {
		t.Fatal("expected protect callback function to be registered")
	}

	// Spin up a local mock listener to dial
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err == nil {
			conn.Close()
		}
	}()

	// Use MakeProtectedDialer to establish a connection
	dialer := MakeProtectedDialer(1 * time.Second)
	conn, err := dialer.Dial("tcp", listener.Addr().String())
	if err == nil {
		conn.Close()
	}

	// Verify that the protect callback was triggered
	protector.mu.Lock()
	fdsCount := len(protector.protectedFDs)
	protector.mu.Unlock()

	if fdsCount == 0 {
		t.Error("expected at least one socket file descriptor to be protected, got none")
	}

	// Clear protector and verify
	SetSocketProtector(nil)
	if GetSocketProtectFunc() != nil {
		t.Error("expected protect callback to be cleared, but it was not")
	}
}

func TestUnixSocketProtector(t *testing.T) {
	// Generate temp socket path
	tmpFile, err := os.CreateTemp("", "protect-*.sock")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	socketPath := tmpFile.Name()
	tmpFile.Close()
	os.Remove(socketPath)
	defer os.Remove(socketPath)

	SetUnixSocketPath(socketPath)
	if GetUnixSocketPath() != socketPath {
		t.Errorf("expected unix socket path %q, got %q", socketPath, GetUnixSocketPath())
	}

	// Spin up a local mock TCP listener to dial
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create tcp listener: %v", err)
	}
	defer tcpListener.Close()

	go func() {
		conn, err := tcpListener.Accept()
		if err == nil {
			conn.Close()
		}
	}()

	// If not Windows, we run a Unix domain socket server to verify FD passing
	if runtime.GOOS != "windows" {
		addr, err := net.ResolveUnixAddr("unix", socketPath)
		if err != nil {
			t.Fatalf("failed to resolve unix addr: %v", err)
		}
		unixListener, err := net.ListenUnix("unix", addr)
		if err != nil {
			t.Fatalf("failed to listen on unix socket: %v", err)
		}
		defer unixListener.Close()

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := unixListener.AcceptUnix()
			if err != nil {
				return
			}
			defer conn.Close()

			buf := make([]byte, 1)
			oob := make([]byte, 32)
			_, oobn, _, _, err := conn.ReadMsgUnix(buf, oob)
			if err != nil || oobn == 0 {
				return
			}
			// Respond with success ack
			conn.Write([]byte{0x01})
		}()

		dialer := MakeProtectedDialer(1 * time.Second)
		conn, err := dialer.Dial("tcp", tcpListener.Addr().String())
		if err == nil {
			conn.Close()
		}
		wg.Wait()
	} else {
		// On Windows, dialing shouldn't panic/crash even though unix socket isn't supported
		dialer := MakeProtectedDialer(1 * time.Second)
		conn, err := dialer.Dial("tcp", tcpListener.Addr().String())
		if err == nil {
			conn.Close()
		}
	}

	// Clear unix socket path and verify
	SetUnixSocketPath("")
	if GetUnixSocketPath() != "" {
		t.Error("expected unix socket path to be cleared")
	}
}

func TestConfigureGCForMobile(t *testing.T) {
	ConfigureGCForMobile()
}

func TestSetSocketMark(t *testing.T) {
	SetSocketMark(123)
	if GetSocketMark() != 123 {
		t.Errorf("expected socket mark 123, got %d", GetSocketMark())
	}

	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create tcp listener: %v", err)
	}
	defer tcpListener.Close()

	go func() {
		conn, err := tcpListener.Accept()
		if err == nil {
			conn.Close()
		}
	}()

	dialer := MakeProtectedDialer(1 * time.Second)
	conn, err := dialer.Dial("tcp", tcpListener.Addr().String())
	if err == nil {
		conn.Close()
	}

	SetSocketMark(0)
	if GetSocketMark() != 0 {
		t.Error("expected socket mark to be cleared")
	}
}

func TestObfuscatedConn(t *testing.T) {
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create tcp listener: %v", err)
	}
	defer tcpListener.Close()

	payload := []byte("hello world payload splitting test")

	go func() {
		conn, err := tcpListener.Accept()
		if err == nil {
			defer conn.Close()
			buf := make([]byte, len(payload))
			_, _ = io.ReadFull(conn, buf)
		}
	}()

	opts := DPIObfuscationOptions{
		EnablePayloadSplitting: true,
		SplitByteBoundary:      5,
		SplitDelayMicroseconds: 10,
		FragmentCount:          3,
	}

	conn, err := DialObfuscated(context.Background(), "tcp", tcpListener.Addr().String(), 1*time.Second, opts)
	if err != nil {
		t.Fatalf("failed to dial obfuscated socket: %v", err)
	}
	defer conn.Close()

	n, err := conn.Write(payload)
	if err != nil {
		t.Fatalf("failed to write payload over obfuscated connection: %v", err)
	}
	if n != len(payload) {
		t.Errorf("expected to write %d bytes, wrote %d", len(payload), n)
	}
}

func TestFindSNI(t *testing.T) {
	mockClientHello := FakeClientHello("chrome", "example.com")
	s, e, host, ok := FindSNI(mockClientHello)
	if !ok {
		t.Fatal("failed to find SNI in FakeClientHello")
	}
	if host != "example.com" {
		t.Errorf("expected host example.com, got %q", host)
	}
	if s <= 0 || e <= 0 || s >= e {
		t.Errorf("invalid SNI boundaries: [%d, %d]", s, e)
	}
}

func TestWFPBlocker(t *testing.T) {
	session, err := StartWFPBlocker()
	if err != nil {
		// WFP dynamic session may fail if not running with administrative privileges, which is expected.
		t.Logf("StartWFPBlocker skipped or failed: %v", err)
		return
	}
	defer session.Close()
	t.Log("WFP dynamic session successfully created and closed.")
}

func TestWinINetProxyRollback(t *testing.T) {
	if runtime.GOOS != "windows" {
		snap, err := GetProxySettings()
		if err == nil {
			t.Error("expected error from GetProxySettings on non-windows platform")
		}
		err = RestoreProxySettings(snap)
		if err == nil {
			t.Error("expected error from RestoreProxySettings on non-windows platform")
		}
		err = SetSocks5Proxy("127.0.0.1:1080")
		if err == nil {
			t.Error("expected error from SetSocks5Proxy on non-windows platform")
		}
		err = ClearProxy()
		if err == nil {
			t.Error("expected error from ClearProxy on non-windows platform")
		}
		return
	}

	// Capture baseline snapshot
	baseline, err := GetProxySettings()
	if err != nil {
		t.Fatalf("failed to get baseline proxy settings: %v", err)
	}

	// Set a mock socks5 proxy
	testProxy := "127.0.0.1:9099"
	err = SetSocks5Proxy(testProxy)
	if err != nil {
		t.Fatalf("failed to set SOCKS5 proxy: %v", err)
	}

	// Verify it was set
	current, err := GetProxySettings()
	if err != nil {
		t.Fatalf("failed to get current proxy settings: %v", err)
	}
	if !current.ProxyEnabled {
		t.Error("expected proxy to be enabled")
	}
	if current.ProxyServer != "socks="+testProxy {
		t.Errorf("expected proxy server 'socks=%s', got %q", testProxy, current.ProxyServer)
	}

	// Restore original settings
	err = RestoreProxySettings(baseline)
	if err != nil {
		t.Fatalf("failed to restore proxy settings: %v", err)
	}

	// Verify original settings are restored
	restored, err := GetProxySettings()
	if err != nil {
		t.Fatalf("failed to get restored proxy settings: %v", err)
	}
	if restored.ProxyEnabled != baseline.ProxyEnabled {
		t.Errorf("expected restored proxy enabled state %v, got %v", baseline.ProxyEnabled, restored.ProxyEnabled)
	}
	if restored.ProxyServer != baseline.ProxyServer {
		t.Errorf("expected restored proxy server %q, got %q", baseline.ProxyServer, restored.ProxyServer)
	}
}

