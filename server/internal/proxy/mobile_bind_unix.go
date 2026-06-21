//go:build !windows

package proxy

import (
	"fmt"
	"net"
	"os"
	"syscall"
)

// ProtectSocketUnixListener listens on a local Unix socket and processes FDs to protect.
func ProtectSocketUnixListener(socketPath string, protectCallback func(int) error) error {
	_ = os.Remove(socketPath)

	addr, err := net.ResolveUnixAddr("unix", socketPath)
	if err != nil {
		return fmt.Errorf("resolve unix addr failed: %w", err)
	}

	listener, err := net.ListenUnix("unix", addr)
	if err != nil {
		return fmt.Errorf("listen unix failed: %w", err)
	}
	defer listener.Close()

	_ = os.Chmod(socketPath, 0600)

	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			continue
		}
		go handleProtectConnection(conn, protectCallback)
	}
}

func handleProtectConnection(conn *net.UnixConn, protectCallback func(int) error) {
	defer conn.Close()

	buf := make([]byte, 1)
	oob := make([]byte, syscall.CmsgSpace(4)) // space for 1 int fd

	n, oobn, _, _, err := conn.ReadMsgUnix(buf, oob)
	if err != nil || n == 0 || oobn == 0 {
		return
	}

	cmsgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil || len(cmsgs) == 0 {
		return
	}

	fds, err := syscall.ParseUnixRights(&cmsgs[0])
	if err != nil || len(fds) == 0 {
		return
	}

	targetFD := fds[0]
	defer syscall.Close(targetFD)

	var status byte = 0x01
	if protectCallback == nil {
		if !ProtectSocket(targetFD) {
			status = 0x00
		}
	} else if err := protectCallback(targetFD); err != nil {
		status = 0x00
	}

	_, _ = conn.Write([]byte{status})
}
