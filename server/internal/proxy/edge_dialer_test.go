package proxy

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestEdgeDialer_TrojanTCP(t *testing.T) {
	// Start a mock Trojan TCP server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().(*net.TCPAddr)

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read header: 56 bytes hex + 2 bytes CRLF + 1 byte cmd + 1 byte addrType + addrVal + 2 bytes port + 2 bytes CRLF
		// Let's assume domain name for test ("example.com", len=11)
		// Expected length: 56 + 2 + 1 + 1 + 1 (domain len) + 11 + 2 + 2 = 76 bytes
		buf := make([]byte, 76)
		_, err = io.ReadFull(conn, buf)
		if err != nil {
			t.Errorf("server failed to read Trojan header: %v", err)
			return
		}

		// Echo back payload if any, but since we are just checking handshake, let's write "success"
		_, _ = conn.Write([]byte("trojan-ok"))
	}()

	cfg := &ProxyConfig{
		Protocol: ProtocolTrojan,
		Address:  addr.IP.String(),
		Port:     addr.Port,
		Password: "testpassword",
		TLS:      false,
	}

	dialer := NewEdgeDialer(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := dialer.DialTarget(ctx, "example.com", 80)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	resp := make([]byte, 9)
	_, err = io.ReadFull(conn, resp)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}

	if string(resp) != "trojan-ok" {
		t.Errorf("expected 'trojan-ok', got %q", string(resp))
	}
}

func TestEdgeDialer_SOCKS5TCP(t *testing.T) {
	// Start a mock SOCKS5 TCP server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().(*net.TCPAddr)

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read Greeting: 3 bytes
		greet := make([]byte, 3)
		if _, err := io.ReadFull(conn, greet); err != nil {
			return
		}

		// Write Greeting response
		_, _ = conn.Write([]byte{0x05, 0x00})

		// Read request header: 4 bytes (Ver, Cmd, Rsv, AddrType)
		reqHead := make([]byte, 4)
		if _, err := io.ReadFull(conn, reqHead); err != nil {
			return
		}

		// Read domain length + domain + port
		lenByte := make([]byte, 1)
		_, _ = io.ReadFull(conn, lenByte)
		domainLen := int(lenByte[0])

		discard := make([]byte, domainLen+2)
		_, _ = io.ReadFull(conn, discard)

		// Write SOCKS5 response: success
		// Version 5, Success (0), Reserved (0), AddrType IPv4 (1), IP (0.0.0.0), Port (0)
		_, _ = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

		// Write data
		_, _ = conn.Write([]byte("socks5-ok"))
	}()

	cfg := &ProxyConfig{
		Protocol: ProtocolSOCKS5,
		Address:  addr.IP.String(),
		Port:     addr.Port,
		TLS:      false,
	}

	dialer := NewEdgeDialer(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := dialer.DialTarget(ctx, "example.com", 80)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	resp := make([]byte, 9)
	_, err = io.ReadFull(conn, resp)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}

	if string(resp) != "socks5-ok" {
		t.Errorf("expected 'socks5-ok', got %q", string(resp))
	}
}

func TestEdgeDialer_VLESSTCP(t *testing.T) {
	// Start a mock VLESS TCP server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().(*net.TCPAddr)

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read header
		// VLESS: Version (1) + UUID (16) + Addons length (1) + Command (1) + Port (2) + AddrType (1) + Addr (1 + 11 = 12) = 34 bytes
		buf := make([]byte, 34)
		_, err = io.ReadFull(conn, buf)
		if err != nil {
			t.Errorf("server failed to read VLESS header: %v", err)
			return
		}

		// Write VLESS response: Version 0, Addons len 0
		_, _ = conn.Write([]byte{0, 0})

		// Write payload
		_, _ = conn.Write([]byte("vless-ok"))
	}()

	cfg := &ProxyConfig{
		Protocol: ProtocolVLESS,
		Address:  addr.IP.String(),
		Port:     addr.Port,
		UUID:     "00000000-0000-0000-0000-000000000000",
		TLS:      false,
	}

	dialer := NewEdgeDialer(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := dialer.DialTarget(ctx, "example.com", 80)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	resp := make([]byte, 8)
	_, err = io.ReadFull(conn, resp)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}

	if string(resp) != "vless-ok" {
		t.Errorf("expected 'vless-ok', got %q", string(resp))
	}
}

func TestEdgeDialer_VLESSWebSocket(t *testing.T) {
	var upgrader = websocket.Upgrader{}

	// Start a mock VLESS WebSocket server
	server := httptestNewServer(upgrader, func(ws *websocket.Conn) {
		// Read VLESS handshake binary message
		_, msg, err := ws.ReadMessage()
		if err != nil {
			return
		}

		// Check VLESS header: must be 34 bytes (version 0, UUID, addons len 0, cmd 1, port 80, domain 'example.com')
		if len(msg) < 34 || msg[0] != 0 {
			_ = ws.WriteMessage(websocket.BinaryMessage, []byte{1, 0}) // version mismatch response
			return
		}

		// Write VLESS response: Version 0, Addons len 0
		_ = ws.WriteMessage(websocket.BinaryMessage, []byte{0, 0})

		// Write data
		_ = ws.WriteMessage(websocket.BinaryMessage, []byte("vless-ws-ok"))
	})
	defer server.Close()

	serverURL := strings.Replace(server.URL, "http://", "ws://", 1)
	u, err := url.Parse(serverURL)
	if err != nil {
		t.Fatalf("failed to parse url: %v", err)
	}

	host, portStr, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(portStr)

	cfg := &ProxyConfig{
		Protocol:  ProtocolVLESS,
		Address:   host,
		Port:      port,
		UUID:      "00000000-0000-0000-0000-000000000000",
		Transport: "ws",
		TLS:       false,
	}

	dialer := NewEdgeDialer(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := dialer.DialTarget(ctx, "example.com", 80)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	resp := make([]byte, 11)
	_, err = io.ReadFull(conn, resp)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}

	if string(resp) != "vless-ws-ok" {
		t.Errorf("expected 'vless-ws-ok', got %q", string(resp))
	}
}

// Helper to start a local HTTP/WS test server
func httptestNewServer(upgrader websocket.Upgrader, handler func(*websocket.Conn)) *httptestServer {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	s := &httptestServer{
		Listener: l,
		URL:      "http://" + l.Addr().String(),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		handler(ws)
	})
	s.Server = &http.Server{Handler: mux}
	go func() {
		_ = s.Server.Serve(l)
	}()
	return s
}

type httptestServer struct {
	Listener net.Listener
	Server   *http.Server
	URL      string
}

func (s *httptestServer) Close() {
	s.Server.Close()
	s.Listener.Close()
}

func TestEvasionTunnel_EdgeWiring(t *testing.T) {
	// 1. Start target TCP Echo Server
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start target listener: %v", err)
	}
	defer targetListener.Close()

	targetAddr := targetListener.Addr().(*net.TCPAddr)

	go func() {
		conn, err := targetListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err == nil {
			_, _ = conn.Write(buf[:n])
		}
	}()

	// 2. Start mock SOCKS5 Server
	socksListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start socks listener: %v", err)
	}
	defer socksListener.Close()

	socksAddr := socksListener.Addr().(*net.TCPAddr)

	go func() {
		conn, err := socksListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read SOCKS5 Greeting (3 bytes)
		greet := make([]byte, 3)
		if _, err := io.ReadFull(conn, greet); err != nil {
			return
		}
		_, _ = conn.Write([]byte{0x05, 0x00}) // Auth success

		// Read Request Header (4 bytes)
		reqHead := make([]byte, 4)
		if _, err := io.ReadFull(conn, reqHead); err != nil {
			return
		}

		// Read address: IPv4 (4 bytes) or IPv6 or Domain
		var ipBytes []byte
		if reqHead[3] == 1 { // IPv4
			ipBytes = make([]byte, 4)
			_, _ = io.ReadFull(conn, ipBytes)
		} else if reqHead[3] == 4 { // IPv6
			ipBytes = make([]byte, 16)
			_, _ = io.ReadFull(conn, ipBytes)
		} else { // Domain
			lenB := make([]byte, 1)
			_, _ = io.ReadFull(conn, lenB)
			ipBytes = make([]byte, int(lenB[0]))
			_, _ = io.ReadFull(conn, ipBytes)
		}

		// Read port (2 bytes)
		portBytes := make([]byte, 2)
		_, _ = io.ReadFull(conn, portBytes)
		destPort := binary.BigEndian.Uint16(portBytes)

		// Connect to genuine target TCP server
		destIP := net.IP(ipBytes).String()
		if reqHead[3] == 3 {
			destIP = string(ipBytes)
		}
		targetDialAddr := net.JoinHostPort(destIP, strconv.Itoa(int(destPort)))
		targetConn, err := net.Dial("tcp", targetDialAddr)
		if err != nil {
			_, _ = conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}
		defer targetConn.Close()

		// Success response
		_, _ = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

		// Bridge connection
		go io.Copy(targetConn, conn)
		io.Copy(conn, targetConn)
	}()

	// 3. Initialize EvasionTunnelManager configured with "edge" covertMode
	mgr := GetEvasionManager()
	
	// Start manager on random port
	err = mgr.Start(
		0,                       // random port
		0,                       // splitBytes
		0,                       // delayMs
		false,                   // mutateHost
		false,                   // mutateHeaderSpace
		false,                   // autoSni
		0,                       // sniSplitOffset
		"all",                   // packets
		0,                       // minLen
		0,                       // maxLen
		false,                   // tlsRecordSplit
		"8.8.8.8:53",            // dnsResolver
		0,                       // dnsForwarderPort
		false,                   // dnsForwarderEnabled
		false,                   // systemProxyEnabled
		"",                      // sniSpoof
		0,                       // clientHelloPadding
		false,                   // delayJitter
		0,                       // tcpWindowClamp
		"",                      // customUserAgent
		"edge",                  // covertMode
		"socks5://" + socksAddr.String(), // covertServerlessUrl
		"",                      // covertDnsDomain
		"",                      // covertGsaUrl
		"",                      // covertGsaKey
		"",                      // covertGdocsFolderId
		"",                      // covertGdocsAccessToken
		false,                   // fakePacketInject
		0,                       // fakePacketTtl
		false,                   // mutateSniCase
		false,                   // mutateMethod
		false,                   // mutateAbsoluteUri
		0,                       // httpPadding
		"",                      // preflightSignature
		0,                       // preflightDelayMs
		false,                   // sessionFrag
		0.0,                     // sessionFragProb
		0,                       // sessionFragMinTotal
		0,                       // sessionFragMaxTotal
		0,                       // sessionFragMinChunk
		0,                       // sessionFragMaxChunk
		0,                       // sessionFragMinDelayMs
		0,                       // sessionFragMaxDelayMs
		false,                   // ipSpoofingEnabled
		"",                      // ipSpoofingDecoyIP
		"",                      // ipSpoofingDstReal
		false,                   // outOfWindowEnabled
		0,                       // outOfWindowSeqOffset
		"",                      // decoySniPool
		false,                   // oobEnabled
		false,                   // oobexEnabled
		false,                   // asyncReactorEnabled
		0.0,                     // lossRate
		0,                       // emulatedLatency
		0,                       // emulatedJitter
		100,                     // circularCacheCap
		0,                       // shaperReadRate
		0,                       // shaperWriteRate
		"",                      // covertSocketProtectPath
		true,                    // mobileAssetsEnabled
		false,                   // zygiskHideEnabled
		true,                    // hardenedTlsEnabled
		false,                   // upgenEnabled
		"",                      // upgenSeedHex
		false,                   // upgenEntropyMatch
		0,                       // upgenQuicExhaustionRate
		false,                   // stegoEnabled
		"",                      // stegoMode
		"",                      // stegoDecoyImagePath
		false,                   // stegoWebRTCSDPSpoof
	)
	if err != nil {
		t.Fatalf("failed to start evasion tunnel manager: %v", err)
	}
	defer mgr.Stop()

	// Wait briefly for tunnel to bind
	time.Sleep(100 * time.Millisecond)

	_, tunPort, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _ := mgr.Status()
	t.Logf("[Test] Tunnel port: %d", tunPort)

	// 4. Dial target through EvasionTunnel proxy connection
	proxyConn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(tunPort)))
	if err != nil {
		t.Fatalf("failed to connect to evasion tunnel: %v", err)
	}
	defer proxyConn.Close()
	t.Logf("[Test] Connected to tunnel")

	// SOCKS5 request on the tunnel interface to connect to target
	// Greeting - split writes to prevent read-ahead socket deadlock in tunnel manager
	_, err = proxyConn.Write([]byte{0x05, 0x01})
	if err != nil {
		t.Fatalf("failed to write greeting version/methods: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	_, err = proxyConn.Write([]byte{0x00})
	if err != nil {
		t.Fatalf("failed to write greeting authentication method: %v", err)
	}
	t.Logf("[Test] Wrote SOCKS5 greeting")

	resp := make([]byte, 2)
	_, err = io.ReadFull(proxyConn, resp)
	if err != nil {
		t.Fatalf("failed to read SOCKS5 greeting response: %v", err)
	}
	t.Logf("[Test] Read SOCKS5 greeting response: %v", resp)
	if resp[1] != 0x00 {
		t.Fatalf("socks5 proxy handshake auth failed: %v", resp)
	}

	// Connect Request
	req := make([]byte, 4+4+2)
	req[0] = 0x05
	req[1] = 0x01
	req[2] = 0x00
	req[3] = 1 // IPv4
	copy(req[4:8], targetAddr.IP.To4())
	binary.BigEndian.PutUint16(req[8:10], uint16(targetAddr.Port))

	_, err = proxyConn.Write(req)
	if err != nil {
		t.Fatalf("failed to write SOCKS5 connect request: %v", err)
	}
	t.Logf("[Test] Wrote SOCKS5 connect request")

	rep := make([]byte, 10)
	_, err = io.ReadFull(proxyConn, rep)
	if err != nil {
		t.Fatalf("failed to read SOCKS5 connect reply: %v", err)
	}
	t.Logf("[Test] Read SOCKS5 connect reply: %v", rep)
	if rep[1] != 0x00 {
		t.Fatalf("socks5 proxy connection failed: %v", rep)
	}

	// Send payload and read echo
	_, err = proxyConn.Write([]byte("hello edge integration"))
	if err != nil {
		t.Fatalf("failed to write payload: %v", err)
	}
	t.Logf("[Test] Wrote payload")

	echoBuf := make([]byte, 22)
	_, err = io.ReadFull(proxyConn, echoBuf)
	if err != nil {
		t.Fatalf("failed to read echoed payload: %v", err)
	}
	t.Logf("[Test] Read echoed payload: %s", string(echoBuf))

	if string(echoBuf) != "hello edge integration" {
		t.Errorf("expected 'hello edge integration', got %q", string(echoBuf))
	}
}
