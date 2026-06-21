//go:build windows && cgo

package cmd

import (
	"context"
	"log"
	"runtime"
	"syscall"
	"unsafe"
)

var (
	modUser32             = syscall.NewLazyDLL("user32.dll")
	procRegisterHotKey    = modUser32.NewProc("RegisterHotKey")
	procUnregisterHotKey  = modUser32.NewProc("UnregisterHotKey")
	procGetMessage        = modUser32.NewProc("GetMessageW")
	procPostThreadMessage = modUser32.NewProc("PostThreadMessageW")

	modKernel32            = syscall.NewLazyDLL("kernel32.dll")
	procGetCurrentThreadId = modKernel32.NewProc("GetCurrentThreadId")
)

const (
	WM_HOTKEY = 0x0312
	WM_QUIT   = 0x0012
	MOD_ALT   = 0x0001
	MOD_CTRL  = 0x0002
)

type tagMSG struct {
	HWND    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      struct{ X, Y int32 }
}

func startGlobalHotkeyListener(ctx context.Context, onTrigger func()) {
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		threadID, _, _ := procGetCurrentThreadId.Call()

		// Register Ctrl+Alt+P (virtual key code for 'P' is 0x50)
		res, _, err := procRegisterHotKey.Call(
			0,  // NULL hwnd (thread-level hotkey)
			99, // ID
			MOD_CTRL|MOD_ALT,
			0x50, // 'P'
		)
		if res == 0 {
			log.Printf("[Hotkey] Failed to register global hotkey (Ctrl+Alt+P): %v", err)
			return
		}
		log.Printf("[Hotkey] Successfully registered global hotkey: Ctrl+Alt+P")

		defer func() {
			_, _, _ = procUnregisterHotKey.Call(0, 99)
			log.Printf("[Hotkey] Unregistered global hotkey")
		}()

		// Start background goroutine to post WM_QUIT when context is cancelled
		go func() {
			<-ctx.Done()
			_, _, _ = procPostThreadMessage.Call(threadID, WM_QUIT, 0, 0)
		}()

		var msg tagMSG
		for {
			ret, _, _ := procGetMessage.Call(
				uintptr(unsafe.Pointer(&msg)),
				0,
				0,
				0,
			)
			// GetMessage returns 0 on WM_QUIT, and -1 on error
			if int32(ret) == -1 || ret == 0 {
				return
			}
			if msg.Message == WM_HOTKEY && msg.WParam == 99 {
				go onTrigger()
			}
		}
	}()
}
