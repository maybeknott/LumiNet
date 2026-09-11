package immunization

import (
	"errors"
	"net"
	"os"
	"strings"
	"syscall"
	"time"
)

// Detector analyzes connection errors and flow timing to identify middlebox interference.
type Detector struct{}

// NewDetector creates a new DPI interference detector.
func NewDetector() *Detector {
	return &Detector{}
}

// DetectInterference analyzes network errors and timing metrics to diagnose middlebox tampering.
func (d *Detector) DetectInterference(err error, timing PacketTimingProfile) (InterferenceType, string) {
	if err == nil {
		// Inspect HTTP blockpage signatures
		if timing.StatusCode == 403 || timing.StatusCode == 451 || timing.StatusCode == 302 || timing.StatusCode == 307 {
			bodyLower := strings.ToLower(timing.ResponseBody)
			signatures := []string{
				"access denied", "blocked by administrator", "policy violation",
				"content filtered", "forbidden domain", "firewall", "internet censor",
				"site blocked", "restricted category",
			}
			for _, sig := range signatures {
				if strings.Contains(bodyLower, sig) {
					return InterferenceHTTPBlockpage, "HTTP blockpage/redirect middlebox detected: " + sig
				}
			}
		}
		return InterferenceNone, ""
	}

	errStr := strings.ToLower(err.Error())

	// 1. Check for TCP RST injection
	// Middleboxes frequently inject TCP RST immediately after observing a forbidden ClientHello or SNI.
	isRST := isConnReset(err) ||
		strings.Contains(errStr, "connection reset") ||
		strings.Contains(errStr, "reset by peer") ||
		strings.Contains(errStr, "wsarecv: an existing connection was forcibly closed")

	if isRST {
		if timing.TLSClientHello {
			return InterferenceSNIReset, "DPI RST injected immediately following TLS ClientHello SNI inspection"
		}
		if timing.BytesSent > 0 && timing.BytesReceived == 0 && timing.Elapsed < 250*time.Millisecond {
			return InterferenceRSTInjection, "DPI rapid TCP RST injected before destination response"
		}
		return InterferenceRSTInjection, "TCP connection abruptly reset by middlebox"
	}

	// 2. Check for Silent Handshake Drops
	// Stateful firewalls drop packets post-SYN or post-ClientHello, inducing timeouts.
	isTimeout := false
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		isTimeout = true
	}
	if strings.Contains(errStr, "i/o timeout") || strings.Contains(errStr, "timed out") || strings.Contains(errStr, "deadline exceeded") {
		isTimeout = true
	}

	if isTimeout {
		if timing.BytesSent > 0 && timing.BytesReceived == 0 {
			return InterferenceHandshakeDrop, "Silent DPI packet drop detected: ClientHello transmitted with zero response bytes before deadline"
		}
		return InterferenceConnectionTimeout, "Connection deadline exceeded with unresponsive target"
	}

	return InterferenceNone, ""
}

// isConnReset checks whether an error indicates a TCP reset.
func isConnReset(err error) bool {
	if err == nil {
		return false
	}
	var sysErr *os.SyscallError
	if errors.As(err, &sysErr) {
		if sysErr.Err == syscall.ECONNRESET {
			return true
		}
	}
	return false
}
