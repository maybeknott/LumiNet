package api

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestIpcListener_AcceptLoop(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "test.ipc")
	if runtime.GOOS == "windows" {
		// Named pipes are global rather than temporary-directory resources.
		// A per-test name prevents collisions with a stale or externally-owned
		// \\.\pipe\test.ipc, which may carry an ACL this process cannot open.
		path = fmt.Sprintf("luminet-%s-%d", t.Name(), time.Now().UnixNano())
	}

	listener, err := NewIpcListener(path)
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	handlerCalledChan := make(chan bool, 1)
	handler := func(conn net.Conn) {
		handlerCalledChan <- true
	}

	go listener.AcceptLoop(ctx, handler)

	// Sleep briefly to let loop start
	time.Sleep(50 * time.Millisecond)

	// Connect using the platform-native IPC transport. Keeping the dialer in
	// build-tagged test helpers avoids importing Windows-only packages on Unix.
	conn, err := dialTestIPC(listener.path)
	if err != nil {
		t.Fatalf("failed to dial listener: %v", err)
	}
	defer conn.Close()

	// Wait a moment for background handler
	select {
	case <-handlerCalledChan:
		// success
	case <-time.After(200 * time.Millisecond):
		t.Error("expected handler to be called")
	}
}
