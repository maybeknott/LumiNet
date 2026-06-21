//go:build windows

package system

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"unsafe"
)

const (
	winDivertLayerNetwork  = 0
	winDivertFlagWriteOnly = 0x0008 // SEND_ONLY: handle may only inject
	addrOutboundBit        = 1 << 17
)

var (
	wdOnce   sync.Once
	wdDLL    *syscall.LazyDLL
	wdOpen   *syscall.LazyProc
	wdSend   *syscall.LazyProc
	iphlp    *syscall.LazyDLL
	getBestI *syscall.LazyProc

	wdMu     sync.Mutex
	wdHandle uintptr // 0 = not open
)

func wdDLLPath() string {
	var cands []string
	add := func(d string) {
		if d != "" {
			cands = append(cands, filepath.Join(d, "WinDivert.dll"), filepath.Join(d, "windivert", "WinDivert.dll"))
		}
	}
	if exe, err := os.Executable(); err == nil {
		add(filepath.Dir(exe))
	}
	if wd, err := os.Getwd(); err == nil {
		add(wd)
	}
	for _, p := range cands {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

func setDllDir(dir string) {
	k := syscall.NewLazyDLL("kernel32.dll")
	p := k.NewProc("SetDllDirectoryW")
	if u, err := syscall.UTF16PtrFromString(dir); err == nil {
		p.Call(uintptr(unsafe.Pointer(u)))
	}
}

func wdLoad() {
	if path := wdDLLPath(); path != "" {
		setDllDir(filepath.Dir(path))
		wdDLL = syscall.NewLazyDLL(path)
	} else {
		wdDLL = syscall.NewLazyDLL("WinDivert.dll")
	}
	wdOpen = wdDLL.NewProc("WinDivertOpen")
	wdSend = wdDLL.NewProc("WinDivertSend")
	iphlp = syscall.NewLazyDLL("iphlpapi.dll")
	getBestI = iphlp.NewProc("GetBestInterface")
}

const invalidHandle = ^uintptr(0)

func wdEnsureHandle() error {
	wdOnce.Do(wdLoad)
	if err := wdDLL.Load(); err != nil {
		return fmt.Errorf("WinDivert.dll not found: %v", err)
	}
	wdMu.Lock()
	defer wdMu.Unlock()
	if wdHandle != 0 && wdHandle != invalidHandle {
		return nil
	}
	filter, _ := syscall.BytePtrFromString("false")
	h, _, callErr := wdOpen.Call(
		uintptr(unsafe.Pointer(filter)),
		uintptr(winDivertLayerNetwork),
		uintptr(0),
		uintptr(winDivertFlagWriteOnly),
	)
	if h == invalidHandle || h == 0 {
		return fmt.Errorf("WinDivertOpen failed (%v)", callErr)
	}
	wdHandle = h
	return nil
}

func bestInterface(dst net.IP) uint32 {
	d4 := dst.To4()
	if d4 == nil {
		return 0
	}
	addr := uint32(d4[0]) | uint32(d4[1])<<8 | uint32(d4[2])<<16 | uint32(d4[3])<<24
	var idx uint32
	ret, _, _ := getBestI.Call(uintptr(addr), uintptr(unsafe.Pointer(&idx)))
	if ret != 0 {
		return 0
	}
	return idx
}

func sendRaw(dst net.IP, seg []byte) error {
	if len(seg) == 0 {
		return nil
	}
	if err := wdEnsureHandle(); err != nil {
		return err
	}
	var addr [80]byte
	binary.LittleEndian.PutUint32(addr[8:12], addrOutboundBit)
	binary.LittleEndian.PutUint32(addr[16:20], bestInterface(dst))

	var sendLen uint32
	wdMu.Lock()
	h := wdHandle
	wdMu.Unlock()
	ret, _, callErr := wdSend.Call(
		h,
		uintptr(unsafe.Pointer(&seg[0])),
		uintptr(uint32(len(seg))),
		uintptr(unsafe.Pointer(&sendLen)),
		uintptr(unsafe.Pointer(&addr[0])),
	)
	if ret == 0 {
		return fmt.Errorf("WinDivertSend failed (%v)", callErr)
	}
	return nil
}
