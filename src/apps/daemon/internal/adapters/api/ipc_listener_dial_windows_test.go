//go:build windows

package api

import (
	"net"

	"github.com/Microsoft/go-winio"
)

func dialTestIPC(addr string) (net.Conn, error) {
	return winio.DialPipe(addr, nil)
}
