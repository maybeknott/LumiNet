//go:build linux || android

package system

import (
	"net"
	"syscall"
)

func sendRaw(dst net.IP, seg []byte) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		return err
	}
	var addr syscall.SockaddrInet4
	copy(addr.Addr[:], dst.To4())
	return syscall.Sendto(fd, seg, 0, &addr)
}
