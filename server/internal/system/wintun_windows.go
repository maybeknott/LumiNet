//go:build windows

package system

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type wintunAdapter struct {
	handle uintptr
}

type wintunSession struct {
	handle uintptr
}

var (
	modwintun                         *syscall.LazyDLL
	procWintunCreateAdapter           *syscall.LazyProc
	procWintunOpenAdapter             *syscall.LazyProc
	procWintunCloseAdapter            *syscall.LazyProc
	procWintunDeleteDriver            *syscall.LazyProc
	procWintunGetAdapterLUID          *syscall.LazyProc
	procWintunGetRunningDriverVersion *syscall.LazyProc
	procWintunAllocateSendPacket      *syscall.LazyProc
	procWintunEndSession              *syscall.LazyProc
	procWintunGetReadWaitEvent        *syscall.LazyProc
	procWintunReceivePacket           *syscall.LazyProc
	procWintunReleaseReceivePacket    *syscall.LazyProc
	procWintunSendPacket              *syscall.LazyProc
	procWintunStartSession            *syscall.LazyProc
)

func initWintunProcs() error {
	if modwintun != nil {
		return nil
	}
	modwintun = syscall.NewLazyDLL("wintun.dll")
	if err := modwintun.Load(); err != nil {
		return fmt.Errorf("failed to load wintun.dll: %w", err)
	}

	procWintunCreateAdapter = modwintun.NewProc("WintunCreateAdapter")
	procWintunOpenAdapter = modwintun.NewProc("WintunOpenAdapter")
	procWintunCloseAdapter = modwintun.NewProc("WintunCloseAdapter")
	procWintunDeleteDriver = modwintun.NewProc("WintunDeleteDriver")
	procWintunGetAdapterLUID = modwintun.NewProc("WintunGetAdapterLUID")
	procWintunGetRunningDriverVersion = modwintun.NewProc("WintunGetRunningDriverVersion")
	procWintunAllocateSendPacket = modwintun.NewProc("WintunAllocateSendPacket")
	procWintunEndSession = modwintun.NewProc("WintunEndSession")
	procWintunGetReadWaitEvent = modwintun.NewProc("WintunGetReadWaitEvent")
	procWintunReceivePacket = modwintun.NewProc("WintunReceivePacket")
	procWintunReleaseReceivePacket = modwintun.NewProc("WintunReleaseReceivePacket")
	procWintunSendPacket = modwintun.NewProc("WintunSendPacket")
	procWintunStartSession = modwintun.NewProc("WintunStartSession")

	return nil
}

func closeWintunAdapter(w *wintunAdapter) {
	if w.handle != 0 {
		syscall.SyscallN(procWintunCloseAdapter.Addr(), w.handle)
	}
}

func createWintunAdapter(name string, tunnelType string, requestedGUID *windows.GUID) (*wintunAdapter, error) {
	if err := initWintunProcs(); err != nil {
		return nil, err
	}
	name16, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	tunnelType16, err := windows.UTF16PtrFromString(tunnelType)
	if err != nil {
		return nil, err
	}
	r0, _, e1 := syscall.SyscallN(procWintunCreateAdapter.Addr(), uintptr(unsafe.Pointer(name16)), uintptr(unsafe.Pointer(tunnelType16)), uintptr(unsafe.Pointer(requestedGUID)))
	if r0 == 0 {
		if e1 != 0 {
			return nil, e1
		}
		return nil, syscall.EINVAL
	}
	w := &wintunAdapter{handle: r0}
	runtime.SetFinalizer(w, closeWintunAdapter)
	return w, nil
}

func (w *wintunAdapter) Close() error {
	runtime.SetFinalizer(w, nil)
	if w.handle != 0 {
		r1, _, e1 := syscall.SyscallN(procWintunCloseAdapter.Addr(), w.handle)
		w.handle = 0
		if r1 == 0 && e1 != 0 {
			return e1
		}
	}
	return nil
}

func (w *wintunAdapter) StartSession(capacity uint32) (*wintunSession, error) {
	r0, _, e1 := syscall.SyscallN(procWintunStartSession.Addr(), w.handle, uintptr(capacity))
	if r0 == 0 {
		if e1 != 0 {
			return nil, e1
		}
		return nil, syscall.EINVAL
	}
	return &wintunSession{handle: r0}, nil
}

func (s *wintunSession) End() {
	if s.handle != 0 {
		syscall.SyscallN(procWintunEndSession.Addr(), s.handle)
		s.handle = 0
	}
}

func (s *wintunSession) ReadWaitEvent() windows.Handle {
	r0, _, _ := syscall.SyscallN(procWintunGetReadWaitEvent.Addr(), s.handle)
	return windows.Handle(r0)
}

func (s *wintunSession) ReceivePacket() ([]byte, error) {
	var packetSize uint32
	r0, _, e1 := syscall.SyscallN(procWintunReceivePacket.Addr(), s.handle, uintptr(unsafe.Pointer(&packetSize)))
	if r0 == 0 {
		if e1 != 0 {
			return nil, e1
		}
		return nil, syscall.EINVAL
	}
	// packetSize limits how much we slice. Ring capacity dictates actual bounds.
	packet := unsafe.Slice((*byte)(unsafe.Pointer(r0)), packetSize)
	return packet, nil
}

func (s *wintunSession) ReleaseReceivePacket(packet []byte) {
	syscall.SyscallN(procWintunReleaseReceivePacket.Addr(), s.handle, uintptr(unsafe.Pointer(&packet[0])))
}

func (s *wintunSession) AllocateSendPacket(packetSize int) ([]byte, error) {
	r0, _, e1 := syscall.SyscallN(procWintunAllocateSendPacket.Addr(), s.handle, uintptr(packetSize))
	if r0 == 0 {
		if e1 != 0 {
			return nil, e1
		}
		return nil, syscall.EINVAL
	}
	packet := unsafe.Slice((*byte)(unsafe.Pointer(r0)), packetSize)
	return packet, nil
}

func (s *wintunSession) SendPacket(packet []byte) {
	syscall.SyscallN(procWintunSendPacket.Addr(), s.handle, uintptr(unsafe.Pointer(&packet[0])))
}

func (w *wintunAdapter) LUID() uint64 {
	var luid uint64
	syscall.SyscallN(procWintunGetAdapterLUID.Addr(), w.handle, uintptr(unsafe.Pointer(&luid)))
	return luid
}
