package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

type TunnelPayload struct {
	SessionID string  `json:"session_id"`
	Target    string  `json:"target,omitempty"`
	Data      []byte  `json:"data,omitempty"`
	Wseq      *uint64 `json:"wseq,omitempty"`
	Seq       *uint64 `json:"seq,omitempty"`
}

type TunnelResponse struct {
	Data  []byte  `json:"data,omitempty"`
	Error string  `json:"error,omitempty"`
	Seq   *uint64 `json:"seq,omitempty"`
}

type activeConn struct {
	conn          net.Conn
	lastActive    time.Time
	nextWriteSeq  *uint64
	pendingWrites map[uint64][]byte
	writeMu       sync.Mutex
}

// EvasionRelayServer represents a server-side proxy relay node
// that forwards hijacked TCP connections or handles stateless GSA long-polling tunnels.
type EvasionRelayServer struct {
	Addr            string
	DecoyTarget     string
	SecretPaths     []string
	BlockedCIDRs    []string
	RealityVerifier *RealityVerifier
	listener        net.Listener
	localListener   net.Listener
	fallbackProxy   *FallbackProxy
	conns           map[string]*activeConn
	connsMu         sync.Mutex
	cleanupCtx      chan struct{}
}

// NewEvasionRelayServer creates a new instance of EvasionRelayServer.
func NewEvasionRelayServer(addr string) *EvasionRelayServer {
	s := &EvasionRelayServer{
		Addr:       addr,
		conns:      make(map[string]*activeConn),
		cleanupCtx: make(chan struct{}),
	}
	go s.startCleanupLoop()
	return s
}

// Start launches the evasion HTTP relay server, wrapping it in FallbackProxy if DecoyTarget is set.
func (s *EvasionRelayServer) Start() error {
	if s.DecoyTarget != "" {
		localL, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return err
		}
		s.localListener = localL

		server := &http.Server{
			Handler: http.HandlerFunc(s.handleRequest),
		}
		go func() {
			_ = server.Serve(localL)
		}()

		paths := s.SecretPaths
		if len(paths) == 0 {
			paths = []string{"/tunnel", "X-Actual-Host"}
		}
		fb := NewFallbackProxy(s.Addr, localL.Addr().String(), s.DecoyTarget, paths)
		fb.RealityVerifier = s.RealityVerifier
		if len(s.BlockedCIDRs) > 0 {
			var nets []*net.IPNet
			for _, cidrStr := range s.BlockedCIDRs {
				_, ipNet, err := net.ParseCIDR(cidrStr)
				if err == nil {
					nets = append(nets, ipNet)
				}
			}
			fb.SetBlockedCIDRs(nets)
		}
		if err := fb.Start(); err != nil {
			localL.Close()
			return err
		}
		s.fallbackProxy = fb
		s.listener = fb.listener
		return nil
	}

	l, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}
	s.listener = l

	server := &http.Server{
		Handler: http.HandlerFunc(s.handleRequest),
	}

	go func() {
		_ = server.Serve(l)
	}()

	return nil
}

// Stop gracefully shuts down the listeners and cleans up connections.
func (s *EvasionRelayServer) Stop() {
	close(s.cleanupCtx)
	if s.listener != nil {
		_ = s.listener.Close()
	}
	if s.localListener != nil {
		_ = s.localListener.Close()
	}
	if s.fallbackProxy != nil {
		s.fallbackProxy.Stop()
	}
	s.connsMu.Lock()
	for _, ac := range s.conns {
		ac.conn.Close()
	}
	s.conns = make(map[string]*activeConn)
	s.connsMu.Unlock()
}

func (s *EvasionRelayServer) startCleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.cleanupCtx:
			return
		case <-ticker.C:
			s.connsMu.Lock()
			now := time.Now()
			for id, ac := range s.conns {
				if now.Sub(ac.lastActive) > 60*time.Second {
					ac.conn.Close()
					delete(s.conns, id)
				}
			}
			s.connsMu.Unlock()
		}
	}
}

func (s *EvasionRelayServer) handleRequest(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/tunnel" {
		s.handleTunnel(w, r)
		return
	}
	s.handleRelay(w, r)
}

func (s *EvasionRelayServer) handleTunnel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var payload TunnelPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.connsMu.Lock()
	ac, exists := s.conns[payload.SessionID]
	if !exists && payload.Target != "" {
		var conn net.Conn
		var err error
		if isUDPGWDest(payload.Target) {
			cHalf, sHalf := newChanPipe()
			go runUDPGWServer(sHalf)
			conn = cHalf
		} else {
			conn, err = net.DialTimeout("tcp", payload.Target, 5*time.Second)
		}
		if err != nil {
			s.connsMu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(TunnelResponse{Error: err.Error(), Seq: payload.Seq})
			return
		}
		ac = &activeConn{
			conn:          conn,
			lastActive:    time.Now(),
			pendingWrites: make(map[uint64][]byte),
		}
		s.conns[payload.SessionID] = ac
	}
	s.connsMu.Unlock()

	if ac == nil {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(TunnelResponse{Error: "connection not found or no target provided", Seq: payload.Seq})
		return
	}

	ac.lastActive = time.Now()

	// Write data to target connection if present, obeying sequence ordering if wseq is specified
	if len(payload.Data) > 0 {
		var writeErr error
		if payload.Wseq != nil {
			ac.writeMu.Lock()
			if ac.nextWriteSeq == nil {
				initVal := *payload.Wseq
				ac.nextWriteSeq = &initVal
			}
			expected := *ac.nextWriteSeq
			wseq := *payload.Wseq

			if wseq < expected {
				// Stale or duplicate write sequence - skip writing.
			} else if wseq == expected {
				_, writeErr = ac.conn.Write(payload.Data)
				expected++
				for {
					bufferedData, exists := ac.pendingWrites[expected]
					if !exists {
						break
					}
					delete(ac.pendingWrites, expected)
					if writeErr == nil {
						_, writeErr = ac.conn.Write(bufferedData)
					}
					expected++
				}
				*ac.nextWriteSeq = expected
			} else {
				// Out of order - buffer for later sequence matching.
				ac.pendingWrites[wseq] = payload.Data
			}
			ac.writeMu.Unlock()
		} else {
			_, writeErr = ac.conn.Write(payload.Data)
		}

		if writeErr != nil {
			s.connsMu.Lock()
			ac.conn.Close()
			delete(s.conns, payload.SessionID)
			s.connsMu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(TunnelResponse{Error: writeErr.Error(), Seq: payload.Seq})
			return
		}
	}

	// Read pending data from target connection
	buf := make([]byte, 8192)
	_ = ac.conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	n, err := ac.conn.Read(buf)

	var readData []byte
	if n > 0 {
		readData = buf[:n]
	}

	if err != nil {
		if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
			// Real connection error, close the connection
			s.connsMu.Lock()
			ac.conn.Close()
			delete(s.conns, payload.SessionID)
			s.connsMu.Unlock()
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(TunnelResponse{
		Data: readData,
		Seq:  payload.Seq,
	})
}


func (s *EvasionRelayServer) handleRelay(w http.ResponseWriter, r *http.Request) {
	targetHost := r.Header.Get("X-Actual-Host")
	if targetHost == "" {
		http.Error(w, "Missing X-Actual-Host header", http.StatusBadRequest)
		return
	}

	targetConn, err := net.Dial("tcp", targetHost)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to dial target: %v", err), http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	// Hijack the underlying TCP connection from HTTP writer
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Webserver does not support hijacking", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hj.Hijack()
	if err != nil {
		http.Error(w, fmt.Sprintf("Hijack failed: %v", err), http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	// Write OK handshake response to the hijacked client connection
	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Pipe bidirectional connection streams
	errChan := make(chan error, 2)
	go func() {
		_, err := io.Copy(targetConn, clientConn)
		errChan <- err
	}()
	go func() {
		_, err := io.Copy(clientConn, targetConn)
		errChan <- err
	}()

	<-errChan
}

// StartEvasionRelayServer launches a server-side proxy relay node and blocks until the server stops or encounters an error.
func StartEvasionRelayServer(addr string) error {
	server := NewEvasionRelayServer(addr)
	return server.Start()
}

// StartEvasionRelayServerWithDecoy launches a server-side proxy relay node with active-probing deflection.
func StartEvasionRelayServerWithDecoy(addr, decoyTarget string, secretPaths []string, blockedCIDRs []string) error {
	server := NewEvasionRelayServer(addr)
	server.DecoyTarget = decoyTarget
	server.SecretPaths = secretPaths
	server.BlockedCIDRs = blockedCIDRs
	return server.Start()
}

