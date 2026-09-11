//go:build !windows

package api

import "net"

func dialTestIPC(addr string) (net.Conn, error) {
	return net.Dial("unix", addr)
}
