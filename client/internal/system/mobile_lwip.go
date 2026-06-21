package system

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// SocketProtector is implemented by the Android/iOS host to prevent routing loops
// by excluding sockets from the VPN interface routing tables.
type SocketProtector interface {
	Protect(fd int64) bool
}

// PacketFlow is implemented in Java/Kotlin on Android to write IP packets
// back to the virtual TUN device file descriptor.
type PacketFlow interface {
	WritePacket(packet []byte)
}

// LWIPStack represents the userspace TCP/IP networking engine contract.
type LWIPStack interface {
	Write(data []byte) (int, error)
	Close() error
}

var (
	lwipStack            LWIPStack
	stackMu              sync.RWMutex
	globalFlow           PacketFlow
	socketProtectFuncVal atomic.Value // stores func(fd int)
	unixSocketPathVal    atomic.Value // stores string
	socketMarkVal        atomic.Value // stores int
	wfpSessionVal        *WFPSession
)

// SetSocketMark sets the socket mark (SO_MARK) for policy routing on compatible Unix systems.
// Pass 0 to clear it. Thread-safe.
func SetSocketMark(mark int) {
	socketMarkVal.Store(mark)
}

// GetSocketMark returns the registered socket mark, if any.
func GetSocketMark() int {
	if val, ok := socketMarkVal.Load().(int); ok {
		return val
	}
	return 0
}

// ConfigureGCForMobile configures the garbage collector parameters for memory-constrained mobile environments.
// It sets GCPercent to 10 to trigger garbage collection more aggressively and prevent memory-limit terminations.
func ConfigureGCForMobile() {
	debug.SetGCPercent(10)
}

// SetSocketProtectFunc registers the per-socket protect callback.
// Pass nil to clear it. Thread-safe.
func SetSocketProtectFunc(fn func(fd int)) {
	if fn == nil {
		socketProtectFuncVal.Store((func(int))(nil))
	} else {
		socketProtectFuncVal.Store(fn)
	}
}

// GetSocketProtectFunc returns the registered protect callback.
func GetSocketProtectFunc() func(fd int) {
	if fn, ok := socketProtectFuncVal.Load().(func(int)); ok {
		return fn
	}
	return nil
}

// SetSocketProtector registers the VPN socket protector interface from Android.
func SetSocketProtector(p SocketProtector) {
	if p == nil {
		SetSocketProtectFunc(nil)
	} else {
		SetSocketProtectFunc(func(fd int) {
			p.Protect(int64(fd))
		})
	}
}

// SetUnixSocketPath sets the Unix domain socket path used for SCM_RIGHTS socket protection.
// Pass "" to clear it. Thread-safe.
func SetUnixSocketPath(path string) {
	unixSocketPathVal.Store(path)
}

// GetUnixSocketPath returns the registered Unix domain socket path, if any.
func GetUnixSocketPath() string {
	if val, ok := unixSocketPathVal.Load().(string); ok {
		return val
	}
	return ""
}

// MakeProtectedDialer returns a dialer that protects its socket before dialing.
func MakeProtectedDialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				if fn := GetSocketProtectFunc(); fn != nil {
					fn(int(fd))
				} else if path := GetUnixSocketPath(); path != "" {
					_ = protectViaUnixSocket(path, int(fd))
				}
				if mark := GetSocketMark(); mark != 0 {
					_ = setSocketMark(int(fd), mark)
				}
			})
		},
	}
}

// InputPacket writes raw IP packets captured from the virtual TUN file descriptor
// into the userspace lwIP stack for packet dissection and SOCKS routing.
func InputPacket(data []byte) error {
	stackMu.RLock()
	defer stackMu.RUnlock()
	if lwipStack == nil {
		return errors.New("lwip stack is not initialized")
	}
	_, err := lwipStack.Write(data)
	return err
}

// StartSocks starts the userspace TCP/IP stack routing to SOCKS proxy.
func StartSocks(flow PacketFlow, proxyHost string, proxyPort int, stackInitializer func(string, int, func([]byte)) (LWIPStack, error)) error {
	stackMu.Lock()
	defer stackMu.Unlock()

	if flow == nil {
		return errors.New("packet flow interface cannot be nil")
	}
	if lwipStack != nil {
		return errors.New("socks bridge is already running")
	}

	globalFlow = flow

	outputFn := func(data []byte) {
		if globalFlow != nil {
			globalFlow.WritePacket(data)
		}
	}

	if stackInitializer != nil {
		stack, err := stackInitializer(proxyHost, proxyPort, outputFn)
		if err != nil {
			return err
		}
		lwipStack = stack
	} else {
		// Fallback mock stack for test runs and cross-compiles
		lwipStack = &mockLWIPStack{outputFn: outputFn}
	}

	// Connect dynamic DNS leak blocker for Windows system integrations
	if session, err := StartWFPBlocker(); err == nil {
		wfpSessionVal = session
	}

	// Trigger traffic warmup asynchronously to prime connection routes (ported from WhiteDNS-Android)
	TriggerTrafficWarmup(proxyHost, proxyPort)

	return nil
}

// StopSocks shuts down the lwIP stack and cleans up references.
func StopSocks() error {
	stackMu.Lock()
	defer stackMu.Unlock()

	if lwipStack == nil {
		return nil
	}

	// Close dynamic DNS leak blocker if active
	if wfpSessionVal != nil {
		wfpSessionVal.Close()
		wfpSessionVal = nil
	}

	_ = lwipStack.Close()
	lwipStack = nil
	globalFlow = nil
	return nil
}

type mockLWIPStack struct {
	outputFn func([]byte)
	closed   bool
}

func (m *mockLWIPStack) Write(data []byte) (int, error) {
	if m.closed {
		return 0, errors.New("stack closed")
	}
	return len(data), nil
}

func (m *mockLWIPStack) Close() error {
	m.closed = true
	return nil
}

// TriggerTrafficWarmup starts an asynchronous traffic warmup to prime the proxy connection pathways.
func TriggerTrafficWarmup(proxyHost string, proxyPort int) {
	go func() {
		proxyURL, err := url.Parse(fmt.Sprintf("socks5://%s:%d", proxyHost, proxyPort))
		if err != nil {
			return
		}

		client := &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyURL(proxyURL),
			},
			Timeout: 4 * time.Second,
		}

		targets := []string{
			"https://www.cloudflare.com/cdn-cgi/trace",
			"https://www.google.com/generate_204",
		}

		var wg sync.WaitGroup
		for _, targetURL := range targets {
			wg.Add(1)
			go func(u string) {
				defer wg.Done()
				req, err := http.NewRequest("GET", u, nil)
				if err != nil {
					return
				}
				resp, err := client.Do(req)
				if err == nil {
					_, _ = io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
			}(targetURL)
		}
		wg.Wait()
	}()
}
