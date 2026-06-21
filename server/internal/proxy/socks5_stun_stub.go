//go:build !linux

package proxy

func applySocketMark(fd uintptr, fwmark int) {
	// No-op for non-Linux systems
}
