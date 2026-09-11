package asyncreactor

import (
	"bytes"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func tcpSocketPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	type acceptResult struct {
		conn net.Conn
		err  error
	}
	accepted := make(chan acceptResult, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		accepted <- acceptResult{conn: conn, err: acceptErr}
	}()

	peer, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial socket pair: %v", err)
	}
	result := <-accepted
	if result.err != nil {
		peer.Close()
		t.Fatalf("accept socket pair: %v", result.err)
	}
	return result.conn, peer
}

func TestAsyncReactorForwarding(t *testing.T) {
	// 1. Start a local mock echo destination server.
	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock echo server: %v", err)
	}
	defer echoListener.Close()

	go func() {
		for {
			conn, err := echoListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c) // echo back
			}(conn)
		}
	}()

	// 2. Start a local proxy mock server.
	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock proxy listener: %v", err)
	}
	defer proxyListener.Close()

	reactor, err := NewAsyncReactor()
	if err != nil {
		t.Fatalf("failed to create async reactor: %v", err)
	}
	defer reactor.Close()

	go func() {
		clientConn, err := proxyListener.Accept()
		if err != nil {
			return
		}

		targetConn, err := net.Dial("tcp", echoListener.Addr().String())
		if err != nil {
			clientConn.Close()
			return
		}

		if err := reactor.Register(clientConn, targetConn); err != nil {
			clientConn.Close()
			targetConn.Close()
		}
	}()

	// 3. Dial proxy mock server as client, send payload, and receive echo response.
	client, err := net.Dial("tcp", proxyListener.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial proxy server: %v", err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))

	payload := []byte("hello reactor async forwarding")
	if _, err := client.Write(payload); err != nil {
		t.Fatalf("failed to write payload: %v", err)
	}

	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatalf("failed to read response: %v", err)
	}
	if !bytes.Equal(buf, payload) {
		t.Errorf("got response %q, want %q", string(buf), string(payload))
	}

	payload2 := []byte("chunk two of forwarding test")
	if _, err := client.Write(payload2); err != nil {
		t.Fatalf("failed to write second payload: %v", err)
	}
	buf = make([]byte, len(payload2))
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatalf("failed to read second response: %v", err)
	}
	if !bytes.Equal(buf, payload2) {
		t.Errorf("got second response %q, want %q", string(buf), string(payload2))
	}
}

func TestAsyncReactorForwarding_NoEcho(t *testing.T) {
	var received bytes.Buffer
	var mu sync.Mutex

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock listener: %v", err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				mu.Lock()
				received.Write(buf[:n])
				mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()

	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start proxy listener: %v", err)
	}
	defer proxyListener.Close()

	reactor, err := NewAsyncReactor()
	if err != nil {
		t.Fatalf("failed to create async reactor: %v", err)
	}
	defer reactor.Close()

	go func() {
		clientConn, err := proxyListener.Accept()
		if err != nil {
			return
		}
		targetConn, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			clientConn.Close()
			return
		}
		if err := reactor.Register(clientConn, targetConn); err != nil {
			clientConn.Close()
			targetConn.Close()
		}
	}()

	client, err := net.Dial("tcp", proxyListener.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial proxy: %v", err)
	}
	defer client.Close()
	_ = client.SetWriteDeadline(time.Now().Add(2 * time.Second))

	if _, err := client.Write([]byte("chunk1")); err != nil {
		t.Fatalf("write 1 failed: %v", err)
	}
	if _, err := client.Write([]byte("chunk2")); err != nil {
		t.Fatalf("write 2 failed: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		got := received.String()
		mu.Unlock()
		if got == "chunk1chunk2" {
			return
		}
		time.Sleep(time.Millisecond)
	}
	mu.Lock()
	got := received.String()
	mu.Unlock()
	t.Fatalf("received %q, want %q", got, "chunk1chunk2")
}

func TestObserverReportsDirectionsAndClose(t *testing.T) {
	reactor, err := NewAsyncReactor()
	if err != nil {
		t.Fatal(err)
	}
	defer reactor.Close()

	clientSide, clientPeer := tcpSocketPair(t)
	targetSide, targetPeer := tcpSocketPair(t)
	defer clientPeer.Close()
	defer targetPeer.Close()
	_ = clientPeer.SetDeadline(time.Now().Add(3 * time.Second))
	_ = targetPeer.SetDeadline(time.Now().Add(3 * time.Second))

	var up, down, closed atomic.Int64
	if err := reactor.RegisterObserved(clientSide, targetSide, Observer{
		OnClientToTarget: func(n int) { up.Add(int64(n)) },
		OnTargetToClient: func(n int) { down.Add(int64(n)) },
		OnClose:          func() { closed.Add(1) },
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := clientPeer.Write([]byte("upload")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("upload"))
	if _, err := io.ReadFull(targetPeer, buf); err != nil {
		t.Fatal(err)
	}
	if _, err := targetPeer.Write([]byte("down")); err != nil {
		t.Fatal(err)
	}
	buf = make([]byte, len("down"))
	if _, err := io.ReadFull(clientPeer, buf); err != nil {
		t.Fatal(err)
	}

	_ = clientPeer.Close()
	deadline := time.Now().Add(2 * time.Second)
	for closed.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if up.Load() != int64(len("upload")) || down.Load() != int64(len("down")) {
		t.Fatalf("up=%d down=%d", up.Load(), down.Load())
	}
	if closed.Load() != 1 {
		t.Fatalf("closed=%d", closed.Load())
	}
}

func TestObserverCloseCallbackRunsOutsideReactorLock(t *testing.T) {
	reactor, err := NewAsyncReactor()
	if err != nil {
		t.Fatal(err)
	}
	defer reactor.Close()

	clientSide, clientPeer := tcpSocketPair(t)
	targetSide, targetPeer := tcpSocketPair(t)
	defer targetPeer.Close()

	callbackDone := make(chan struct{}, 1)
	if err := reactor.RegisterObserved(clientSide, targetSide, Observer{
		OnClose: func() {
			// A lifecycle observer may inspect reactor-owned state. This would
			// deadlock if OnClose were invoked while release held reactor.mu.
			reactor.mu.Lock()
			reactor.mu.Unlock()
			callbackDone <- struct{}{}
		},
	}); err != nil {
		t.Fatal(err)
	}

	if err := clientPeer.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-callbackDone:
	case <-time.After(2 * time.Second):
		t.Fatal("OnClose could not re-enter reactor lifecycle state; callback likely ran under reactor.mu")
	}
}
