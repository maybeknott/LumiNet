//go:build linux

package proxy

import (
	"errors"
	"net"
	"syscall"
	"unsafe"
)

const (
	tcpCongestion   = 13
	tcpBrutalParams = 23301
)

type brutalParams struct {
	Rate     uint64 // rate in bytes per second
	CwndGain uint32 // cwnd_gain in tenths (10 = 1.0)
}

func applyTCPBrutal(conn net.Conn, rateBps uint64, cwndGain uint32) error {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return errors.New("connection is not a TCP connection")
	}

	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return err
	}

	var setCongestionErr error
	var setParamsErr error

	err = rawConn.Control(func(fd uintptr) {
		// 1. Set congestion control to "brutal"
		setCongestionErr = syscall.SetsockoptString(int(fd), syscall.IPPROTO_TCP, tcpCongestion, "brutal")
		if setCongestionErr != nil {
			return
		}

		// 2. Set TCP Brutal parameters
		params := brutalParams{
			Rate:     rateBps,
			CwndGain: cwndGain,
		}
		ptr := unsafe.Pointer(&params)
		size := unsafe.Sizeof(params)

		_, _, errno := syscall.Syscall6(
			syscall.SYS_SETSOCKOPT,
			fd,
			uintptr(syscall.IPPROTO_TCP),
			uintptr(tcpBrutalParams),
			uintptr(ptr),
			size,
			0,
		)
		if errno != 0 {
			setParamsErr = errno
		}
	})

	if err != nil {
		return err
	}
	if setCongestionErr != nil {
		return setCongestionErr
	}
	if setParamsErr != nil {
		return setParamsErr
	}
	return nil
}
