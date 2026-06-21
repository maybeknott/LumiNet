// +build !windows

package proxy

// Stubs for non-Windows platforms to maintain clean cross-platform compilation
func init() {
	// OpenSSL FFI fallback loading is not implemented on this platform
	opensslCipherInstance = nil
}
