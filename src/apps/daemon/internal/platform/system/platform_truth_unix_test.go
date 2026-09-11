//go:build !windows

package system

import (
	"context"
	"errors"
	"testing"
)

func TestUnsupportedPlatformControlsFailClosed(t *testing.T) {
	if NCSISupported() {
		t.Fatal("Windows NCSI reported supported on non-Windows build")
	}
	if _, err := GetNCSIConfig(); !errors.Is(err, ErrUnsupportedPlatformFeature) {
		t.Fatalf("GetNCSIConfig: got %v, want unsupported-platform error", err)
	}
	cfg := DefaultNCSIConfig()
	if err := SetNCSIConfig(context.Background(), &cfg); !errors.Is(err, ErrUnsupportedPlatformFeature) {
		t.Fatalf("SetNCSIConfig: got %v, want unsupported-platform error", err)
	}
	if err := ResetNCSIConfig(context.Background()); !errors.Is(err, ErrUnsupportedPlatformFeature) {
		t.Fatalf("ResetNCSIConfig: got %v, want unsupported-platform error", err)
	}

	if _, err := GetDNS(context.Background(), "eth0"); !errors.Is(err, ErrUnsupportedPlatformFeature) {
		t.Fatalf("GetDNS: got %v, want unsupported-platform error", err)
	}
	if err := SetDNS(context.Background(), "eth0", []string{"1.1.1.1"}); !errors.Is(err, ErrUnsupportedPlatformFeature) {
		t.Fatalf("SetDNS: got %v, want unsupported-platform error", err)
	}
	if err := ResetDNS(context.Background(), "eth0"); !errors.Is(err, ErrUnsupportedPlatformFeature) {
		t.Fatalf("ResetDNS: got %v, want unsupported-platform error", err)
	}

	if TunRoutingSupported() {
		t.Fatal("host-route TUN reported supported on non-Windows build")
	}
	if DNSLeakProtectionSupported() {
		t.Fatal("DNS leak protection reported supported on non-Windows build")
	}
	if err := EnableDnsLeakProtection(context.Background(), "tun0"); !errors.Is(err, ErrUnsupportedPlatformFeature) {
		t.Fatalf("EnableDnsLeakProtection: got %v, want unsupported-platform error", err)
	}
}
