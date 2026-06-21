//go:build windows

package system

import (
	"os"

	"golang.org/x/sys/windows/registry"
)

const runKey = `Software\Microsoft\Windows\CurrentVersion\Run`
const appName = "LumiNet"

// IsStartupEnabled checks if LumiNet is registered in the Windows startup registry.
func IsStartupEnabled() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()

	_, _, err = k.GetStringValue(appName)
	return err == nil
}

// EnableStartup registers the current executable in the Windows startup registry.
func EnableStartup() error {
	execPath, err := os.Executable()
	if err != nil {
		return err
	}

	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()

	return k.SetStringValue(appName, execPath)
}

// DisableStartup removes the LumiNet entry from the Windows startup registry.
func DisableStartup() error {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()

	return k.DeleteValue(appName)
}
