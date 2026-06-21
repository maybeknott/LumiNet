//go:build windows

package system

import (
	"fmt"
	"golang.org/x/sys/windows/svc/mgr"
)

// RegisterWindowsService registers a binary as a Windows service.
func RegisterWindowsService(name, displayName, description, binPath string, args ...string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(name)
	if err == nil {
		s.Close()
		return fmt.Errorf("service %s already exists", name)
	}

	config := mgr.Config{
		StartType:   mgr.StartAutomatic,
		DisplayName: displayName,
		Description: description,
	}

	s, err = m.CreateService(name, binPath, config, args...)
	if err != nil {
		return fmt.Errorf("failed to create service: %w", err)
	}
	defer s.Close()

	return nil
}

// UnregisterWindowsService removes a Windows service.
func UnregisterWindowsService(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("service %s not found: %w", name, err)
	}
	defer s.Close()

	err = s.Delete()
	if err != nil {
		return fmt.Errorf("failed to delete service: %w", err)
	}

	return nil
}

// RegisterSingBoxService is a blueprint wrapper to register Sing-box as a background service.
func RegisterSingBoxService(name, binPath, configPath string) error {
	return RegisterWindowsService(name, "LumiNet Core Service", "Background Sing-box proxy driver for LumiNet", binPath, "run", "--config", configPath)
}

