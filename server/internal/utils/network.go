package utils

import (
	"net"
	"strings"
)

// ContainsPort checks if the address string includes a port number.
func ContainsPort(addr string) bool {
	_, _, err := net.SplitHostPort(addr)
	return err == nil
}

// HasScheme checks if the URL string starts with http:// or https://.
func HasScheme(url string) bool {
	return strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://")
}

// EnsureScheme adds http:// to the URL if it doesn't have a scheme.
func EnsureScheme(url string) string {
	if !HasScheme(url) {
		return "http://" + url
	}
	return url
}
