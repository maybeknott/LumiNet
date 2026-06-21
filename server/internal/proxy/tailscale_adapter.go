package proxy

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// TailscaleNodeCreds represents a configuration block for saving and loading Tailscale credentials.
type TailscaleNodeCreds struct {
	NodeKey      string    `json:"node_key"`
	MachineKey   string    `json:"machine_key"`
	AuthKey      string    `json:"auth_key"`
	Hostname     string    `json:"hostname"`
	LastSeen     time.Time `json:"last_seen"`
	AssignedIP   string    `json:"assigned_ip"`
}

// TailscaleAdapter manages the userspace netstack, state directory, credentials, and DERP client connections.
type TailscaleAdapter struct {
	mu           sync.Mutex
	authKey      string
	hostname     string
	stateDir     string
	isRunning    bool
	creds        *TailscaleNodeCreds
	udpBlocked   bool
	derpClient   *DerpClient
	netstack     *MockUserspaceNetstack
	stopChan     chan struct{}
	derpServer   *mockDerpServer
}

// NewTailscaleAdapter initializes a new instance of the Tailscale engine adapter.
func NewTailscaleAdapter(authKey, hostname, stateDir string) *TailscaleAdapter {
	return &TailscaleAdapter{
		authKey:    authKey,
		hostname:   hostname,
		stateDir:   stateDir,
		udpBlocked: true, // Default to blocked to ensure DERP fallback is verified in tests
	}
}

// SetUDPBlocked toggles whether direct UDP routing is blocked, triggering fallback paths.
func (a *TailscaleAdapter) SetUDPBlocked(blocked bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.udpBlocked = blocked
}

// Start loads node credentials, initializes mock netstacks, and begins the relay connection loop.
func (a *TailscaleAdapter) Start() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.isRunning {
		return nil
	}

	// 1. Create state directory and load/save credentials
	if err := os.MkdirAll(a.stateDir, 0755); err != nil {
		return fmt.Errorf("failed to create state dir: %w", err)
	}

	if err := a.loadCreds(); err != nil {
		return fmt.Errorf("failed to load credentials: %w", err)
	}

	a.stopChan = make(chan struct{})
	a.netstack = NewMockUserspaceNetstack(a.creds.AssignedIP, 1420)

	// 2. Start mock local DERP server to facilitate offline loopback testing
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("failed to start local mock DERP server: %w", err)
	}
	a.derpServer = newMockDerpServer(listener)
	a.derpServer.Start()

	// 3. Connect to the mock DERP server via HTTP Upgrade
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	derpConn, err := a.DialDERP(ctx, listener.Addr().String())
	if err != nil {
		a.derpServer.Stop()
		return fmt.Errorf("failed to dial and upgrade to DERP server: %w", err)
	}

	a.derpClient = NewDerpClient(derpConn, a.creds.NodeKey)
	a.derpClient.Start()

	a.isRunning = true
	go a.packetRoutingLoop()

	return nil
}

// Stop shuts down routing loops, closes relay client channels, and persists engine credentials.
func (a *TailscaleAdapter) Stop() {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.isRunning {
		return
	}

	close(a.stopChan)

	if a.derpClient != nil {
		a.derpClient.Close()
	}
	if a.derpServer != nil {
		a.derpServer.Stop()
	}

	a.creds.LastSeen = time.Now()
	_ = a.saveCreds()

	a.isRunning = false
}

// IsRunning returns status of the Tailscale adapter.
func (a *TailscaleAdapter) IsRunning() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.isRunning
}

// DialDERP connects to a relay server and performs the HTTPS-upgraded binary stream handshake.
func (a *TailscaleAdapter) DialDERP(ctx context.Context, serverAddr string) (net.Conn, error) {
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return nil, err
	}

	// Construct HTTP upgrade request to mimic real HTTPS-upgraded DERP handshake
	req, err := http.NewRequestWithContext(ctx, "GET", "/derp", nil)
	if err != nil {
		conn.Close()
		return nil, err
	}
	req.Header.Set("Upgrade", "DERP")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("X-Tailscale-Node-Key", a.creds.NodeKey)

	// Write HTTP request to connection
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to write DERP handshake request: %w", err)
	}

	// Read HTTP response header
	respReader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(respReader, req)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read DERP response: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSwitchingProtocols || resp.Header.Get("Upgrade") != "DERP" {
		conn.Close()
		return nil, fmt.Errorf("invalid switching protocols response from DERP server status: %d", resp.StatusCode)
	}

	return conn, nil
}

func (a *TailscaleAdapter) loadCreds() error {
	path := filepath.Join(a.stateDir, "node_creds.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			a.creds = &TailscaleNodeCreds{
				NodeKey:    generateRandomHex(32),
				MachineKey: generateRandomHex(32),
				AuthKey:    a.authKey,
				Hostname:   a.hostname,
				LastSeen:   time.Now(),
				AssignedIP: "100.64.0.5",
			}
			return a.saveCreds()
		}
		return err
	}
	var creds TailscaleNodeCreds
	if err := json.Unmarshal(data, &creds); err != nil {
		return err
	}
	a.creds = &creds
	return nil
}

func (a *TailscaleAdapter) saveCreds() error {
	path := filepath.Join(a.stateDir, "node_creds.json")
	data, err := json.MarshalIndent(a.creds, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func (a *TailscaleAdapter) packetRoutingLoop() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-a.stopChan:
			return
		case <-ticker.C:
			// Process routing and simulation logic
			a.mu.Lock()
			blocked := a.udpBlocked
			client := a.derpClient
			ns := a.netstack
			a.mu.Unlock()

			if blocked && client != nil && ns != nil {
				// Pull packets from netstack outbound queue and relay them over DERP client
				packets := ns.GetOutboundPackets()
				for _, pkt := range packets {
					_ = client.SendPacket(pkt.DstIP, pkt.Payload)
				}
			}
		}
	}
}

func generateRandomHex(n int) string {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("%x", bytes)
}

// DerpClient handles exchange of length-prefixed binary frames over the upgraded HTTP connection.
type DerpClient struct {
	conn       net.Conn
	nodeKey    string
	mu         sync.Mutex
	inboundCh  chan []byte
	stopChan   chan struct{}
}

// NewDerpClient creates a new DerpClient instance.
func NewDerpClient(conn net.Conn, nodeKey string) *DerpClient {
	return &DerpClient{
		conn:      conn,
		nodeKey:   nodeKey,
		inboundCh: make(chan []byte, 100),
		stopChan:  make(chan struct{}),
	}
}

// Start launches the frame reading loop from the connection stream.
func (c *DerpClient) Start() {
	go c.readLoop()
}

// Close shuts down the client connection and resources.
func (c *DerpClient) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	select {
	case <-c.stopChan:
		return
	default:
		close(c.stopChan)
		c.conn.Close()
	}
}

// SendPacket frames an IP payload and transmits it over the upgraded relay stream.
func (c *DerpClient) SendPacket(dstIP string, payload []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Frame structure:
	// - uint32 total size (1 + length of IP string + payload)
	// - uint8 type (0x01 for packet data)
	// - uint8 length of IP string
	// - []byte IP string bytes
	// - []byte payload
	ipBytes := []byte(dstIP)
	headerLen := 4 + 1 + 1 + len(ipBytes)
	frame := make([]byte, headerLen+len(payload))

	binary.BigEndian.PutUint32(frame[0:4], uint32(1+1+len(ipBytes)+len(payload)))
	frame[4] = 0x01 // packet data type
	frame[5] = uint8(len(ipBytes))
	copy(frame[6:6+len(ipBytes)], ipBytes)
	copy(frame[6+len(ipBytes):], payload)

	_, err := c.conn.Write(frame)
	return err
}

func (c *DerpClient) readLoop() {
	reader := bufio.NewReader(c.conn)
	for {
		select {
		case <-c.stopChan:
			return
		default:
			var length uint32
			if err := binary.Read(reader, binary.BigEndian, &length); err != nil {
				c.Close()
				return
			}

			payload := make([]byte, length)
			if _, err := io.ReadFull(reader, payload); err != nil {
				c.Close()
				return
			}

			if len(payload) > 0 && payload[0] == 0x01 {
				// Frame data: type (1 byte), ipLen (1 byte), ip string, packet payload
				ipLen := int(payload[1])
				if len(payload) >= 2+ipLen {
					packetData := payload[2+ipLen:]
					select {
					case c.inboundCh <- packetData:
					default:
					}
				}
			}
		}
	}
}

// MockOutboundPacket represents a simulated packet queued for transmission.
type MockOutboundPacket struct {
	DstIP   string
	Payload []byte
}

// MockUserspaceNetstack implements a simplified userspace stack to queue and dispatch outbound packets.
type MockUserspaceNetstack struct {
	mu        sync.Mutex
	ipAddress string
	mtu       int
	outbound  []MockOutboundPacket
}

// NewMockUserspaceNetstack creates a simulated local network stack interface.
func NewMockUserspaceNetstack(ipAddress string, mtu int) *MockUserspaceNetstack {
	return &MockUserspaceNetstack{
		ipAddress: ipAddress,
		mtu:       mtu,
	}
}

// QueuePacket inserts an IP packet into the userspace stack outbound queue.
func (n *MockUserspaceNetstack) QueuePacket(dstIP string, payload []byte) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.outbound = append(n.outbound, MockOutboundPacket{DstIP: dstIP, Payload: payload})
}

// GetOutboundPackets extracts and clears all packets queued in the adapter's outgoing buffer.
func (n *MockUserspaceNetstack) GetOutboundPackets() []MockOutboundPacket {
	n.mu.Lock()
	defer n.mu.Unlock()
	pkts := n.outbound
	n.outbound = nil
	return pkts
}

// mockDerpServer hosts standard switching protocol listeners representing DERP relay targets.
type mockDerpServer struct {
	listener net.Listener
	conns    []net.Conn
	mu       sync.Mutex
	stopChan chan struct{}
}

func newMockDerpServer(listener net.Listener) *mockDerpServer {
	return &mockDerpServer{
		listener: listener,
		stopChan: make(chan struct{}),
	}
}

func (s *mockDerpServer) Start() {
	go s.acceptLoop()
}

func (s *mockDerpServer) Stop() {
	close(s.stopChan)
	s.listener.Close()

	s.mu.Lock()
	for _, c := range s.conns {
		c.Close()
	}
	s.mu.Unlock()
}

func (s *mockDerpServer) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}

		s.mu.Lock()
		s.conns = append(s.conns, conn)
		s.mu.Unlock()

		go s.handleConnection(conn)
	}
}

func (s *mockDerpServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	// Parse HTTP Upgrade request header
	reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		return
	}

	if req.Header.Get("Upgrade") != "DERP" {
		resp := http.Response{
			StatusCode: http.StatusBadRequest,
			ProtoMajor: 1,
			ProtoMinor: 1,
		}
		_ = resp.Write(conn)
		return
	}

	// Write Switching Protocols status response to upgrade the stream
	resp := http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
	}
	resp.Header.Set("Upgrade", "DERP")
	resp.Header.Set("Connection", "Upgrade")
	if err := resp.Write(conn); err != nil {
		return
	}

	// Relay connection loop - bounce received frames back to the client as echo fallback route
	for {
		var length uint32
		if err := binary.Read(reader, binary.BigEndian, &length); err != nil {
			return
		}

		payload := make([]byte, length)
		if _, err := io.ReadFull(reader, payload); err != nil {
			return
		}

		// Echo back the frame to simulate destination reachability over DERP channel
		s.mu.Lock()
		_ = binary.Write(conn, binary.BigEndian, length)
		_, _ = conn.Write(payload)
		s.mu.Unlock()
	}
}
