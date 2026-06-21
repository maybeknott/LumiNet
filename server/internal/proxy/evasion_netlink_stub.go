//go:build !linux

package proxy

import (
	"context"
	"errors"
)

// ErrUnsupported is returned when netlink or namespace features are called on non-Linux platforms.
var ErrUnsupported = errors.New("operation not supported on this platform")

// ExecuteInNamespace is a stub for non-Linux platforms.
func ExecuteInNamespace(nsName string, fn func() error) error {
	return ErrUnsupported
}

// CreateNamespace is a stub for non-Linux platforms.
func CreateNamespace(name string) error {
	return ErrUnsupported
}

// DeleteNamespace is a stub for non-Linux platforms.
func DeleteNamespace(name string) error {
	return ErrUnsupported
}

// SetupNamespaceInterface is a stub for non-Linux platforms.
func SetupNamespaceInterface(nsName, vethHost, vethPeer, hostCIDR, peerCIDR, gateway string) error {
	return ErrUnsupported
}

// SetupRedirectRules is a stub for non-Linux platforms.
func SetupRedirectRules(nsName string, localPort, redirectPort int) error {
	return ErrUnsupported
}

// ClearRedirectRules is a stub for non-Linux platforms.
func ClearRedirectRules(nsName string, localPort, redirectPort int) error {
	return ErrUnsupported
}

// WormholeForwarder is a stub for non-Linux platforms.
type WormholeForwarder struct {
	nsName     string
	listenAddr string
	targetAddr string
}

// NewWormholeForwarder is a stub for non-Linux platforms.
func NewWormholeForwarder(nsName, listenAddr, targetAddr string) *WormholeForwarder {
	return &WormholeForwarder{
		nsName:     nsName,
		listenAddr: listenAddr,
		targetAddr: targetAddr,
	}
}

// Start is a stub for non-Linux platforms.
func (w *WormholeForwarder) Start(ctx context.Context) error {
	return ErrUnsupported
}

// Stop is a stub for non-Linux platforms.
func (w *WormholeForwarder) Stop() error {
	return nil
}
