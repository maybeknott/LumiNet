package proxy

import (
	"context"
	"errors"
	"io"
	"net"

	"github.com/maybeknott/luminet/internal/foundation/flowregistry"
	"github.com/maybeknott/luminet/internal/platform/system"
	"github.com/maybeknott/luminet/internal/protocols/asyncreactor"
)

type flowCountingWriter struct {
	writer io.Writer
	add    func(uint64)
}

func (w flowCountingWriter) Write(p []byte) (int, error) {
	n, err := w.writer.Write(p)
	if n > 0 && w.add != nil {
		w.add(uint64(n))
	}
	return n, err
}

func closeFlowPair(client, target net.Conn) error {
	var errs []error
	if client != nil {
		if err := client.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
	}
	if target != nil {
		if err := target.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func connectionAddress(conn net.Conn, local bool) string {
	if conn == nil {
		return ""
	}
	var addr net.Addr
	if local {
		addr = conn.LocalAddr()
	} else {
		addr = conn.RemoteAddr()
	}
	if addr == nil {
		return ""
	}
	return addr.String()
}

// handleSocksConnection handles the negotiation and forwarding of a SOCKS5 client connection.
func (m *EvasionTunnelManager) handleSocksConnection(ctx context.Context, client net.Conn, cfg EvasionConfig) {
	shouldClose := true
	defer func() {
		if shouldClose {
			_ = client.Close()
		}
	}()

	buf := make([]byte, 256)
	// SOCKS5 is a framed protocol. Read the fixed greeting header exactly;
	// ReadAtLeast over the whole scratch buffer may consume the method byte (or
	// even the following CONNECT request) and leave the next framed read blocked.
	if _, err := io.ReadFull(client, buf[:2]); err != nil {
		return
	}
	if buf[0] != 0x05 {
		return
	}
	numMethods := int(buf[1])
	if numMethods == 0 || numMethods > len(buf) {
		return
	}
	if _, err := io.ReadFull(client, buf[:numMethods]); err != nil {
		return
	}
	noAuthOffered := false
	for _, method := range buf[:numMethods] {
		if method == 0x00 {
			noAuthOffered = true
			break
		}
	}
	if !noAuthOffered {
		_, _ = client.Write([]byte{0x05, 0xff})
		return
	}
	if _, err := client.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	if _, err := io.ReadFull(client, buf[:4]); err != nil {
		return
	}
	if buf[0] != 0x05 {
		return
	}

	host, port, err := readSocksAddress(client, buf[3])
	if err != nil {
		return
	}

	if buf[1] == 0x03 {
		localIP, _, _ := net.SplitHostPort(connectionAddress(client, true))
		expectedIP := expectedSocksUDPClientIP(client.RemoteAddr(), host)
		HandleSocksUDPAssociate(client, localIP, expectedIP, port)
		return
	}
	if buf[1] != 0x01 {
		return
	}

	m.log("Routing request to %s:%d through evasion engine...", host, port)
	target, err := m.dialWithEvasion(ctx, host, port, cfg)
	if err != nil {
		m.log("Dial failure to %s:%d: %v", host, port, err)
		_, _ = client.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer func() {
		if shouldClose {
			_ = target.Close()
		}
	}()

	if _, err = client.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0}); err != nil {
		return
	}

	var flow *flowregistry.Handle
	declareEvasionFlowCoverage()
	epoch := system.GetNetworkMonitor().Snapshot().Revision
	flow, flowErr := flowregistry.Default().Register(flowregistry.Descriptor{
		Owner: "evasion-socks", Network: "tcp", Protocol: "socks5-connect",
		Source: connectionAddress(client, false), Destination: net.JoinHostPort(host, fmtPort(int(port))), Host: host,
		Chain: []string{"evasion"}, NetworkEpoch: epoch,
	}, func(context.Context) error { return closeFlowPair(client, target) })
	if flowErr != nil {
		m.log("Flow observability registration skipped: %v", flowErr)
	}
	flowTransferred := false
	defer func() {
		if flow != nil && !flowTransferred {
			flow.End()
		}
	}()

	m.mu.Lock()
	reactorEnabled := cfg.AsyncReactorEnabled
	reactor := m.reactor
	m.mu.Unlock()

	if reactorEnabled && reactor != nil {
		observer := asyncreactor.Observer{}
		if flow != nil {
			observer.OnClientToTarget = func(n int) { flow.AddUpload(uint64(n)) }
			observer.OnTargetToClient = func(n int) { flow.AddDownload(uint64(n)) }
			observer.OnClose = flow.End
		}
		err = reactor.RegisterObserved(client, target, observer)
		if err == nil {
			m.log("Asynchronously registered connection pair (%s:%d) with AsyncReactor.", host, port)
			flowTransferred = flow != nil
			shouldClose = false
			return
		}
		m.log("Failed to register with AsyncReactor: %v. Falling back to copy goroutines.", err)
	}

	errChan := make(chan error, 2)
	go func() {
		writer := io.Writer(target)
		if flow != nil {
			writer = flowCountingWriter{writer: target, add: flow.AddUpload}
		}
		_, err := io.Copy(writer, client)
		errChan <- err
	}()
	go func() {
		writer := io.Writer(client)
		if flow != nil {
			writer = flowCountingWriter{writer: client, add: flow.AddDownload}
		}
		_, err := io.Copy(writer, target)
		errChan <- err
	}()

	firstErr := <-errChan
	_ = client.Close()
	_ = target.Close()
	secondErr := <-errChan
	if firstErr != nil {
		m.log("Connection closed with log: %v", firstErr)
	} else if secondErr != nil {
		m.log("Connection closed with log: %v", secondErr)
	} else {
		m.log("Connection to %s:%d closed normally.", host, port)
	}
}

func fmtPort(port int) string {
	if port <= 0 {
		return "0"
	}
	var buf [5]byte
	i := len(buf)
	for port > 0 {
		i--
		buf[i] = byte('0' + port%10)
		port /= 10
	}
	return string(buf[i:])
}
