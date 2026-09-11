//go:build !windows && !android && !ios

package api

import "net"

const defaultSocketPath = "/tmp/luminet-daemon.sock"

// IPCListener is the legacy desktop-Unix listener contract retained for
// compatibility with callers that still use NewIPCListener. New code should
// use IpcListener/NewIpcListener.
type IPCListener interface {
	Accept() (net.Conn, error)
	Addr() string
	Close() error
}

// UnixIPCListener adapts the current IpcListener implementation to the legacy
// IPCListener surface. Keeping this adapter avoids duplicating socket cleanup
// and permission logic in two implementations.
type UnixIPCListener struct {
	listener *IpcListener
}

func NewIPCListener(sockPath string) (IPCListener, error) {
	if sockPath == "" {
		sockPath = defaultSocketPath
	}
	listener, err := NewIpcListener(sockPath)
	if err != nil {
		return nil, err
	}
	return &UnixIPCListener{listener: listener}, nil
}

func (l *UnixIPCListener) Accept() (net.Conn, error) { return l.listener.listener.Accept() }
func (l *UnixIPCListener) Addr() string              { return l.listener.path }
func (l *UnixIPCListener) Close() error              { return l.listener.Close() }
