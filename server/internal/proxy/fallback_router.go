package proxy

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// FallbackProxy represents an active-probing prevention reverse proxy.
// It inspects the initial bytes of a connection and routes it to a local proxy
// node if it matches any secret keywords/paths, otherwise it redirects to a decoy.
type FallbackProxy struct {
	BindAddr        string
	LocalTarget     string
	DecoyTarget     string
	SecretPaths     [][]byte
	RealityVerifier *RealityVerifier
	listener        net.Listener
	mu              sync.Mutex
	isRunning       bool
	blockedCIDRs    []*net.IPNet
}

// NewFallbackProxy creates a new FallbackProxy instance.
func NewFallbackProxy(bindAddr, localTarget, decoyTarget string, secretPaths []string) *FallbackProxy {
	var paths [][]byte
	for _, p := range secretPaths {
		paths = append(paths, []byte(p))
	}
	return &FallbackProxy{
		BindAddr:    bindAddr,
		LocalTarget: localTarget,
		DecoyTarget: decoyTarget,
		SecretPaths: paths,
	}
}

// SetBlockedCIDRs configures CIDR blocks for geographic/country blocking.
func (p *FallbackProxy) SetBlockedCIDRs(cidrs []*net.IPNet) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.blockedCIDRs = cidrs
}

// Addr returns the net.Addr of the underlying listener if it exists.
func (p *FallbackProxy) Addr() net.Addr {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.listener == nil {
		return nil
	}
	return p.listener.Addr()
}


// Start launches the fallback proxy TCP listener.
func (p *FallbackProxy) Start() error {
	p.mu.Lock()
	if p.isRunning {
		p.mu.Unlock()
		return nil
	}
	l, err := net.Listen("tcp", p.BindAddr)
	if err != nil {
		p.mu.Unlock()
		return err
	}
	p.listener = l
	p.isRunning = true
	p.mu.Unlock()

	go p.acceptLoop()
	return nil
}

// Stop terminates the fallback proxy listener.
func (p *FallbackProxy) Stop() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.isRunning {
		return
	}
	if p.listener != nil {
		_ = p.listener.Close()
	}
	p.isRunning = false
}

func (p *FallbackProxy) acceptLoop() {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			p.mu.Lock()
			running := p.isRunning
			p.mu.Unlock()
			if !running {
				return
			}
			continue
		}
		go p.handleConnection(conn)
	}
}

func (p *FallbackProxy) isCountryBlocked(ip net.IP) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, cidr := range p.blockedCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func (p *FallbackProxy) handleConnection(client net.Conn) {
	defer client.Close()
	// Apply country filter check
	remoteAddr, ok := client.RemoteAddr().(*net.TCPAddr)
	if ok && p.isCountryBlocked(remoteAddr.IP) {
		// Drop connection immediately using TCP RST
		if tcpConn, ok := client.(*net.TCPConn); ok {
			_ = tcpConn.SetLinger(0)
		}
		_ = client.Close()
		return
	}

	if p.RealityVerifier != nil {
		wrapped, ok, err := p.RealityVerifier.InterceptAndVerify(client)
		if err != nil {
			_ = client.Close()
			return
		}
		if !ok {
			return
		}
		p.pipeToTarget(wrapped, p.LocalTarget)
		return
	}

	// Read initial payload bytes to inspect the path
	buf := make([]byte, 1024)
	_ = client.SetReadDeadline(time.Now().Add(1 * time.Second))
	n, err := client.Read(buf)
	if err != nil && n == 0 {
		_ = client.Close()
		return
	}
	_ = client.SetReadDeadline(time.Time{}) // reset deadline

	initialData := buf[:n]
	matched := false
	for _, path := range p.SecretPaths {
		if bytes.Contains(initialData, path) {
			matched = true
			break
		}
	}

	target := p.DecoyTarget
	if matched {
		target = p.LocalTarget
	}

	if !matched && (target == "" || target == "nginx404") {
		dateStr := time.Now().UTC().Format(time.RFC1123)
		resp := fmt.Sprintf("HTTP/1.1 404 Not Found\r\n"+
			"Server: nginx/1.22.1\r\n"+
			"Date: %s\r\n"+
			"Content-Type: text/html\r\n"+
			"Content-Length: 153\r\n"+
			"Connection: close\r\n\r\n"+
			"<html>\r\n"+
			"<head><title>404 Not Found</title></head>\r\n"+
			"<body>\r\n"+
			"<center><h1>404 Not Found</h1></center>\r\n"+
			"<hr><center>nginx/1.22.1</center>\r\n"+
			"</body>\r\n"+
			"</html>\r\n", dateStr)
		_, _ = client.Write([]byte(resp))
		return
	}

	upstream, err := net.DialTimeout("tcp", target, 4*time.Second)
	if err != nil {
		_ = client.Close()
		return
	}
	defer upstream.Close()

	// Write back the initial read bytes
	_, err = upstream.Write(initialData)
	if err != nil {
		_ = client.Close()
		return
	}

	// Bidirectional forwarding
	errChan := make(chan error, 2)
	go func() {
		_, err := io.Copy(upstream, client)
		errChan <- err
	}()
	go func() {
		_, err := io.Copy(client, upstream)
		errChan <- err
	}()

	<-errChan
}

func (p *FallbackProxy) pipeToTarget(client net.Conn, target string) {
	defer client.Close()
	upstream, err := net.DialTimeout("tcp", target, 4*time.Second)
	if err != nil {
		return
	}
	defer upstream.Close()

	errChan := make(chan error, 2)
	go func() {
		_, err := io.Copy(upstream, client)
		errChan <- err
	}()
	go func() {
		_, err := io.Copy(client, upstream)
		errChan <- err
	}()

	<-errChan
}

