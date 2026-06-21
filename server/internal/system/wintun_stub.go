//go:build !windows

package system

import (
	"errors"
)

type wintunAdapter struct {
	handle uintptr
}

type wintunSession struct {
	handle uintptr
}

func createWintunAdapter(name string, tunnelType string, requestedGUID interface{}) (*wintunAdapter, error) {
	return nil, errors.New("Wintun is only supported on Windows")
}

func (w *wintunAdapter) Close() error {
	return nil
}

func (w *wintunAdapter) StartSession(capacity uint32) (*wintunSession, error) {
	return nil, errors.New("Wintun is only supported on Windows")
}

func (s *wintunSession) End() {}

func (s *wintunSession) ReadWaitEvent() uintptr {
	return 0
}

func (s *wintunSession) ReceivePacket() ([]byte, error) {
	return nil, errors.New("Wintun is only supported on Windows")
}

func (s *wintunSession) ReleaseReceivePacket(packet []byte) {}

func (s *wintunSession) AllocateSendPacket(packetSize int) ([]byte, error) {
	return nil, errors.New("Wintun is only supported on Windows")
}

func (s *wintunSession) SendPacket(packet []byte) {}

func (w *wintunAdapter) LUID() uint64 {
	return 0
}
