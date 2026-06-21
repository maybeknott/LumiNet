//go:build !linux

package proxy

import (
	"net"
)

func applyTCPBrutal(conn net.Conn, rateBps uint64, cwndGain uint32) error {
	// TCP Brutal is not supported on non-Linux platforms.
	// Return nil to degrade gracefully without breaking.
	return nil
}
