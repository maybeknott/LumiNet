//go:build cgo

// Package bridge provides the CGO bridge to the Rust liblumicore shared library.
// It wraps all FFI calls with safe Go types and proper memory management.
//
// NOTE: This file requires CGO and the compiled Rust library at build time.
// Build with: CGO_ENABLED=1 go build
package bridge

/*
#cgo LDFLAGS: -L../../../core/target/release -llumicore
#cgo windows LDFLAGS: -liphlpapi -lbcrypt -luserenv -lntdll
#include <stdlib.h>

// Forward declarations for Rust FFI functions from liblumicore.
char* scan_icmp_ffi(const char* input_json);
char* probe_tcp_ffi(const char* input_json);
char* scan_ports_ffi(const char* input_json);
char* scan_dns_ffi(const char* input_json);
char* probe_tls_ffi(const char* input_json);
char* probe_socks5_ffi(const char* input_json);
char* probe_http_ffi(const char* input_json);
char* detect_sni_ffi(const char* input_json);
char* test_speed_ffi(const char* input_json);
char* expand_cidr_ffi(const char* input_json);
char* probe_wg_ffi(const char* input_json);
char* detect_captive_portal_ffi(const char* input_json);
char* pad_client_hello_ffi(const char* input_json);
char* inject_fake_packet_ffi(const char* input_json);
void free_string(char* ptr);
*/
import "C"
import (
	"encoding/json"
	"fmt"
	"unsafe"
)

// MockMode indicates whether the bridge is a CGO-disabled mock version.
const MockMode = false

// Helper to free a C-allocated char pointer returned from Rust
func freeCString(cStr *C.char) {
	if cStr != nil {
		C.free_string(cStr)
	}
}

// IcmpScan performs an ICMP ping sweep against the specified targets using the Rust core.
// It expands CIDR/range targets and sends concurrent probes with the given configuration.
func IcmpScan(targets []string, config ScanConfig) ([]ProbeResult, error) {
	input := map[string]interface{}{
		"targets": targets,
		"config":  config,
	}

	payload, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}

	cInput := C.CString(string(payload))
	defer C.free(unsafe.Pointer(cInput))

	// Catch panics or missing CGO library during local test runs safely
	cResult := C.scan_icmp_ffi(cInput)
	if cResult == nil {
		return nil, fmt.Errorf("scan_icmp_ffi returned null")
	}
	defer freeCString(cResult)

	resJSON := C.GoString(cResult)

	var results []ProbeResult
	if err := json.Unmarshal([]byte(resJSON), &results); err != nil {
		// Handle potential FFI-level error envelope
		var errEnv map[string]string
		if json.Unmarshal([]byte(resJSON), &errEnv) == nil && errEnv["error"] != "" {
			return nil, fmt.Errorf("Rust Core: %s", errEnv["error"])
		}
		return nil, fmt.Errorf("failed to unmarshal results: %w", err)
	}

	return results, nil
}

// TcpConnect tests TCP connectivity to a specific host:port using the Rust core.
func TcpConnect(target string, port uint16, timeout uint32) (*ProbeResult, error) {
	input := map[string]interface{}{
		"target":     target,
		"port":       port,
		"timeout_ms": timeout,
	}

	payload, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}

	cInput := C.CString(string(payload))
	defer C.free(unsafe.Pointer(cInput))

	cResult := C.probe_tcp_ffi(cInput)
	if cResult == nil {
		return nil, fmt.Errorf("probe_tcp_ffi returned null")
	}
	defer freeCString(cResult)

	resJSON := C.GoString(cResult)

	var result ProbeResult
	if err := json.Unmarshal([]byte(resJSON), &result); err != nil {
		var errEnv map[string]string
		if json.Unmarshal([]byte(resJSON), &errEnv) == nil && errEnv["error"] != "" {
			return nil, fmt.Errorf("Rust Core: %s", errEnv["error"])
		}
		return nil, fmt.Errorf("failed to unmarshal result: %w", err)
	}

	return &result, nil
}

// PortScan performs a port scan against a single target across multiple ports.
func PortScan(target string, ports []uint16, config ScanConfig) ([]PortResult, error) {
	input := map[string]interface{}{
		"target": target,
		"ports":  ports,
		"config": config,
	}

	payload, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}

	cInput := C.CString(string(payload))
	defer C.free(unsafe.Pointer(cInput))

	cResult := C.scan_ports_ffi(cInput)
	if cResult == nil {
		return nil, fmt.Errorf("scan_ports_ffi returned null")
	}
	defer freeCString(cResult)

	resJSON := C.GoString(cResult)

	var results []PortResult
	if err := json.Unmarshal([]byte(resJSON), &results); err != nil {
		var errEnv map[string]string
		if json.Unmarshal([]byte(resJSON), &errEnv) == nil && errEnv["error"] != "" {
			return nil, fmt.Errorf("Rust Core: %s", errEnv["error"])
		}
		return nil, fmt.Errorf("failed to unmarshal results: %w", err)
	}

	return results, nil
}

// DnsResolve queries a DNS server for a specific domain and record type.
func DnsResolve(server, domain string, recordType string) (*DnsServerResult, error) {
	protocol := "udp"
	if len(server) >= 8 && (server[:8] == "https://" || server[:7] == "http://") {
		protocol = "doh"
	} else if len(server) > 4 && server[len(server)-4:] == ":853" {
		protocol = "dot"
	}

	input := map[string]interface{}{
		"server":      server,
		"domain":      domain,
		"record_type": recordType,
		"protocol":    protocol,
		"timeout_ms":  3000,
	}

	payload, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}

	cInput := C.CString(string(payload))
	defer C.free(unsafe.Pointer(cInput))

	cResult := C.scan_dns_ffi(cInput)
	if cResult == nil {
		return nil, fmt.Errorf("scan_dns_ffi returned null")
	}
	defer freeCString(cResult)

	resJSON := C.GoString(cResult)

	var result DnsServerResult
	if err := json.Unmarshal([]byte(resJSON), &result); err != nil {
		var errEnv map[string]string
		if json.Unmarshal([]byte(resJSON), &errEnv) == nil && errEnv["error"] != "" {
			return nil, fmt.Errorf("Rust Core: %s", errEnv["error"])
		}
		return nil, fmt.Errorf("failed to unmarshal result: %w", err)
	}

	return &result, nil
}

// TlsHandshake performs a TLS handshake and returns certificate/protocol details.
func TlsHandshake(host string, port uint16, timeout uint32) (*TlsInfo, error) {
	return TlsHandshakeWithSni(host, port, host, timeout)
}

// TlsHandshakeWithSni performs a TLS handshake with a custom SNI and returns certificate/protocol details.
func TlsHandshakeWithSni(host string, port uint16, sni string, timeout uint32) (*TlsInfo, error) {
	input := map[string]interface{}{
		"target":     host,
		"port":       port,
		"timeout_ms": timeout,
		"sni":        sni,
	}

	payload, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}

	cInput := C.CString(string(payload))
	defer C.free(unsafe.Pointer(cInput))

	cResult := C.probe_tls_ffi(cInput)
	if cResult == nil {
		return nil, fmt.Errorf("probe_tls_ffi returned null")
	}
	defer freeCString(cResult)

	resJSON := C.GoString(cResult)

	var result TlsInfo
	if err := json.Unmarshal([]byte(resJSON), &result); err != nil {
		var errEnv map[string]string
		if json.Unmarshal([]byte(resJSON), &errEnv) == nil && errEnv["error"] != "" {
			return nil, fmt.Errorf("Rust Core: %s", errEnv["error"])
		}
		return nil, fmt.Errorf("failed to unmarshal result: %w", err)
	}

	return &result, nil
}

// Socks5Probe tests SOCKS5 proxy connectivity using the Rust core.
func Socks5Probe(proxy string, target string, timeout uint32) (*ProbeResult, error) {
	input := map[string]interface{}{
		"proxy_addr": proxy,
		"target":     target,
		"timeout_ms": timeout,
	}

	payload, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}

	cInput := C.CString(string(payload))
	defer C.free(unsafe.Pointer(cInput))

	cResult := C.probe_socks5_ffi(cInput)
	if cResult == nil {
		return nil, fmt.Errorf("probe_socks5_ffi returned null")
	}
	defer freeCString(cResult)

	resJSON := C.GoString(cResult)

	var result ProbeResult
	if err := json.Unmarshal([]byte(resJSON), &result); err != nil {
		var errEnv map[string]string
		if json.Unmarshal([]byte(resJSON), &errEnv) == nil && errEnv["error"] != "" {
			return nil, fmt.Errorf("Rust Core: %s", errEnv["error"])
		}
		return nil, fmt.Errorf("failed to unmarshal result: %w", err)
	}

	return &result, nil
}

// HttpGet performs an HTTP GET request, optionally through a proxy, using the Rust core.
func HttpGet(url string, timeout uint32, proxy string) (*HttpResponse, error) {
	var proxyVal *string
	if proxy != "" {
		proxyVal = &proxy
	}

	input := map[string]interface{}{
		"url":        url,
		"timeout_ms": timeout,
		"proxy":      proxyVal,
	}

	payload, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}

	cInput := C.CString(string(payload))
	defer C.free(unsafe.Pointer(cInput))

	cResult := C.probe_http_ffi(cInput)
	if cResult == nil {
		return nil, fmt.Errorf("probe_http_ffi returned null")
	}
	defer freeCString(cResult)

	resJSON := C.GoString(cResult)

	var result HttpResponse
	if err := json.Unmarshal([]byte(resJSON), &result); err != nil {
		var errEnv map[string]string
		if json.Unmarshal([]byte(resJSON), &errEnv) == nil && errEnv["error"] != "" {
			return nil, fmt.Errorf("Rust Core: %s", errEnv["error"])
		}
		return nil, fmt.Errorf("failed to unmarshal result: %w", err)
	}

	return &result, nil
}

// SniDetect tests multiple domains for SNI-based filtering/blocking.
func SniDetect(domain string, timeout uint32) (*SniResult, error) {
	input := map[string]interface{}{
		"domain":     domain,
		"timeout_ms": timeout,
	}

	payload, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}

	cInput := C.CString(string(payload))
	defer C.free(unsafe.Pointer(cInput))

	cResult := C.detect_sni_ffi(cInput)
	if cResult == nil {
		return nil, fmt.Errorf("detect_sni_ffi returned null")
	}
	defer freeCString(cResult)

	resJSON := C.GoString(cResult)

	var result SniResult
	if err := json.Unmarshal([]byte(resJSON), &result); err != nil {
		var errEnv map[string]string
		if json.Unmarshal([]byte(resJSON), &errEnv) == nil && errEnv["error"] != "" {
			return nil, fmt.Errorf("Rust Core: %s", errEnv["error"])
		}
		return nil, fmt.Errorf("failed to unmarshal result: %w", err)
	}

	return &result, nil
}

// SpeedTest measures download speed from a URL for the specified duration.
func SpeedTest(url string, timeoutMs uint32) (*SpeedResult, error) {
	input := map[string]interface{}{
		"server_url": url,
		"timeout_ms": timeoutMs,
	}

	payload, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}

	cInput := C.CString(string(payload))
	defer C.free(unsafe.Pointer(cInput))

	cResult := C.test_speed_ffi(cInput)
	if cResult == nil {
		return nil, fmt.Errorf("test_speed_ffi returned null")
	}
	defer freeCString(cResult)

	resJSON := C.GoString(cResult)

	var result SpeedResult
	if err := json.Unmarshal([]byte(resJSON), &result); err != nil {
		var errEnv map[string]string
		if json.Unmarshal([]byte(resJSON), &errEnv) == nil && errEnv["error"] != "" {
			return nil, fmt.Errorf("Rust Core: %s", errEnv["error"])
		}
		return nil, fmt.Errorf("failed to unmarshal result: %w", err)
	}

	return &result, nil
}

// ExpandTargets expands CIDR ranges into a flat list of individual target addresses.
func ExpandTargets(cidr string) ([]string, error) {
	input := map[string]interface{}{
		"cidr": cidr,
	}

	payload, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}

	cInput := C.CString(string(payload))
	defer C.free(unsafe.Pointer(cInput))

	cResult := C.expand_cidr_ffi(cInput)
	if cResult == nil {
		return nil, fmt.Errorf("expand_cidr_ffi returned null")
	}
	defer freeCString(cResult)

	resJSON := C.GoString(cResult)

	var results []string
	if err := json.Unmarshal([]byte(resJSON), &results); err != nil {
		var errEnv map[string]string
		if json.Unmarshal([]byte(resJSON), &errEnv) == nil && errEnv["error"] != "" {
			return nil, fmt.Errorf("Rust Core: %s", errEnv["error"])
		}
		return nil, fmt.Errorf("failed to unmarshal results: %w", err)
	}

	return results, nil
}

// WgProbe sends a WireGuard handshake initiation packet to test endpoint reachability.
func WgProbe(ip string, port uint16, timeoutMs uint32, paddingLen uint32) (*ProbeResult, error) {
	input := map[string]interface{}{
		"ip":          ip,
		"port":        port,
		"timeout_ms":  timeoutMs,
		"padding_len": paddingLen,
	}

	payload, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}

	cInput := C.CString(string(payload))
	defer C.free(unsafe.Pointer(cInput))

	cResult := C.probe_wg_ffi(cInput)
	if cResult == nil {
		return nil, fmt.Errorf("probe_wg_ffi returned null")
	}
	defer freeCString(cResult)

	resJSON := C.GoString(cResult)

	var result ProbeResult
	if err := json.Unmarshal([]byte(resJSON), &result); err != nil {
		var errEnv map[string]string
		if json.Unmarshal([]byte(resJSON), &errEnv) == nil && errEnv["error"] != "" {
			return nil, fmt.Errorf("Rust Core: %s", errEnv["error"])
		}
		return nil, fmt.Errorf("failed to unmarshal result: %w", err)
	}

	return &result, nil
}

// FreeString frees a Rust-allocated C string.
// Must be called for every string returned by the Rust FFI layer.
func FreeString(ptr *C.char) {
	if ptr != nil {
		C.free_string(ptr)
	}
}

// CaptivePortalProbe detects if the current network is behind a captive portal.
func CaptivePortalProbe(timeoutMs uint32) (string, error) {
	input := map[string]interface{}{
		"timeout_ms": timeoutMs,
	}

	payload, err := json.Marshal(input)
	if err != nil {
		return "", err
	}

	cInput := C.CString(string(payload))
	defer C.free(unsafe.Pointer(cInput))

	cResult := C.detect_captive_portal_ffi(cInput)
	if cResult == nil {
		return "", fmt.Errorf("detect_captive_portal_ffi returned null")
	}
	defer freeCString(cResult)

	return C.GoString(cResult), nil
}

// PadClientHello pads a TLS ClientHello record using the Rust core.
func PadClientHello(rawHex string, padLen int) (string, error) {
	input := map[string]interface{}{
		"raw_hex": rawHex,
		"pad_len": padLen,
	}

	payload, err := json.Marshal(input)
	if err != nil {
		return "", err
	}

	cInput := C.CString(string(payload))
	defer C.free(unsafe.Pointer(cInput))

	cResult := C.pad_client_hello_ffi(cInput)
	if cResult == nil {
		return "", fmt.Errorf("pad_client_hello_ffi returned null")
	}
	defer freeCString(cResult)

	resJSON := C.GoString(cResult)

	var result struct {
		PaddedHex string `json:"padded_hex"`
		Success   bool   `json:"success"`
		Error     string `json:"error"`
	}
	if err := json.Unmarshal([]byte(resJSON), &result); err != nil {
		var errEnv map[string]string
		if json.Unmarshal([]byte(resJSON), &errEnv) == nil && errEnv["error"] != "" {
			return "", fmt.Errorf("Rust Core: %s", errEnv["error"])
		}
		return "", fmt.Errorf("failed to unmarshal result: %w", err)
	}

	if !result.Success {
		return "", fmt.Errorf("Rust Core: %s", result.Error)
	}

	return result.PaddedHex, nil
}

// InjectFakePacket sends a custom raw TCP packet with a specific TTL using the Rust core.
func InjectFakePacket(targetIp string, port uint16, ttl uint32, flags *uint8, seq *uint32, ack *uint32, payloadHex string) error {
	input := map[string]interface{}{
		"target_ip":   targetIp,
		"port":        port,
		"ttl":         ttl,
		"flags":       flags,
		"seq":         seq,
		"ack":         ack,
		"payload_hex": payloadHex,
	}

	payload, err := json.Marshal(input)
	if err != nil {
		return err
	}

	cInput := C.CString(string(payload))
	defer C.free(unsafe.Pointer(cInput))

	cResult := C.inject_fake_packet_ffi(cInput)
	if cResult == nil {
		return fmt.Errorf("inject_fake_packet_ffi returned null")
	}
	defer freeCString(cResult)

	resJSON := C.GoString(cResult)

	var result struct {
		Success bool   `json:"success"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal([]byte(resJSON), &result); err != nil {
		var errEnv map[string]string
		if json.Unmarshal([]byte(resJSON), &errEnv) == nil && errEnv["error"] != "" {
			return fmt.Errorf("Rust Core: %s", errEnv["error"])
		}
		return fmt.Errorf("failed to unmarshal result: %w", err)
	}

	if !result.Success {
		return fmt.Errorf("Rust Core: %s", result.Error)
	}

	return nil
}
