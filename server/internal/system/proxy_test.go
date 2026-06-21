//go:build windows

package system

import (
	"context"
	"testing"
)

func TestSystemProxySettings(t *testing.T) {
	ctx := context.Background()

	// 1. Backup current settings
	backup, err := GetSystemProxy(ctx)
	if err != nil {
		t.Fatalf("failed to backup current system proxy settings: %v", err)
	}

	defer func() {
		// Restore settings after test
		if backup.Enabled {
			_ = SetSystemProxy(ctx, backup)
		} else {
			_ = DisableSystemProxy(ctx)
		}
	}()

	// 2. Test manual proxy server configuration
	testSettings := &ProxySettings{
		Enabled: true,
		Server:  "127.0.0.1:8080",
		Bypass:  "*.local;<local>",
	}

	err = SetSystemProxy(ctx, testSettings)
	if err != nil {
		t.Fatalf("failed to set manual proxy: %v", err)
	}

	current, err := GetSystemProxy(ctx)
	if err != nil {
		t.Fatalf("failed to query proxy settings: %v", err)
	}

	if !current.Enabled {
		t.Error("expected proxy to be enabled")
	}
	if current.Server != testSettings.Server {
		t.Errorf("expected Server %q, got %q", testSettings.Server, current.Server)
	}
	if current.Bypass != testSettings.Bypass {
		t.Errorf("expected Bypass %q, got %q", testSettings.Bypass, current.Bypass)
	}

	// 3. Test PAC URL auto-configuration
	testPACSettings := &ProxySettings{
		Enabled: true,
		PACURL:  "http://127.0.0.1:10888/api/system/proxy.pac",
	}

	err = SetSystemProxy(ctx, testPACSettings)
	if err != nil {
		t.Fatalf("failed to set PAC URL proxy: %v", err)
	}

	current, err = GetSystemProxy(ctx)
	if err != nil {
		t.Fatalf("failed to query PAC settings: %v", err)
	}

	if current.PACURL != testPACSettings.PACURL {
		t.Errorf("expected PACURL %q, got %q", testPACSettings.PACURL, current.PACURL)
	}

	// 4. Test Disable proxy
	err = DisableSystemProxy(ctx)
	if err != nil {
		t.Fatalf("failed to disable system proxy: %v", err)
	}

	current, err = GetSystemProxy(ctx)
	if err != nil {
		t.Fatalf("failed to query disabled settings: %v", err)
	}

	if current.Enabled && current.PACURL != "" {
		t.Error("expected proxy to be disabled and PACURL removed")
	}
}
