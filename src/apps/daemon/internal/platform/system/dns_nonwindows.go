//go:build !windows

package system

import (
	"context"
	"fmt"
)

// GetDNS reports DNS mutation as unsupported on non-Windows builds. The
// host-network transaction owner relies on read-before-write snapshots for
// rollback verification, so returning synthetic resolver state here would make
// crash recovery claims untrue.
func GetDNS(context.Context, string) ([]string, error) {
	return nil, fmt.Errorf("read host DNS: %w", ErrUnsupportedPlatformFeature)
}

// SetDNS fails closed on non-Windows builds until a platform backend can both
// mutate and read back the authoritative resolver configuration.
func SetDNS(context.Context, string, []string) error {
	return fmt.Errorf("set host DNS: %w", ErrUnsupportedPlatformFeature)
}

// ResetDNS fails closed for the same reason as SetDNS: DHCP/default resolver
// restoration must be implemented and verifiable before the transaction owner
// can advertise support.
func ResetDNS(context.Context, string) error {
	return fmt.Errorf("reset host DNS: %w", ErrUnsupportedPlatformFeature)
}

// ClearDNS retains the public helper contract without weakening platform truth.
func ClearDNS(ctx context.Context, adapterName string) error {
	return ResetDNS(ctx, adapterName)
}
