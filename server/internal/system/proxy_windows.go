//go:build windows

// Package system provides operating-system specific APIs for network adapter discovery, Windows Registry proxies, and DNS modifications.
package system

import (
	"context"
	"syscall"

	"golang.org/x/sys/windows/registry"
)

// ProxySettings represents the system-wide WinINet proxy settings.
type ProxySettings struct {
	Enabled    bool   `json:"enabled"`
	Server     string `json:"server"`
	Bypass     string `json:"bypass"`
	HTTPServer string `json:"http_server"`
	BypassList string `json:"bypass_list"`
	PACURL     string `json:"pac_url"`
}

// WinINet option codes for notifying settings changes.
const (
	INTERNET_OPTION_SETTINGS_CHANGED = 39
	INTERNET_OPTION_REFRESH          = 37
)

// refreshWindowsProxySettings notifies Windows applications (IE/Edge/Chrome/etc.) that the system proxy settings have changed.
func refreshWindowsProxySettings() {
	wininet := syscall.NewLazyDLL("wininet.dll")
	internetSetOption := wininet.NewProc("InternetSetOptionW")

	// Notify options refresh
	internetSetOption.Call(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
	internetSetOption.Call(0, INTERNET_OPTION_REFRESH, 0, 0)
}

// SetSystemProxy configures and enables system-wide proxy settings in the Windows WinINet Registry.
func SetSystemProxy(ctx context.Context, settings *ProxySettings) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()

	var enabledVal uint32
	if settings.Enabled {
		enabledVal = 1
	}

	if err := k.SetDWordValue("ProxyEnable", enabledVal); err != nil {
		return err
	}

	if settings.Server != "" {
		if err := k.SetStringValue("ProxyServer", settings.Server); err != nil {
			return err
		}
	}

	if settings.Bypass != "" {
		if err := k.SetStringValue("ProxyOverride", settings.Bypass); err != nil {
			return err
		}
	}

	if settings.PACURL != "" {
		if err := k.SetStringValue("AutoConfigURL", settings.PACURL); err != nil {
			return err
		}
	} else {
		_ = k.DeleteValue("AutoConfigURL")
	}

	refreshWindowsProxySettings()
	return nil
}

// GetSystemProxy reads and parses current system-wide proxy settings from the Windows Registry.
func GetSystemProxy(ctx context.Context) (*ProxySettings, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.QUERY_VALUE)
	if err != nil {
		return nil, err
	}
	defer k.Close()

	enabled, _, err := k.GetIntegerValue("ProxyEnable")
	if err != nil {
		enabled = 0
	}

	server, _, err := k.GetStringValue("ProxyServer")
	if err != nil {
		server = ""
	}

	bypass, _, err := k.GetStringValue("ProxyOverride")
	if err != nil {
		bypass = ""
	}

	pacURL, _, err := k.GetStringValue("AutoConfigURL")
	if err != nil {
		pacURL = ""
	}

	return &ProxySettings{
		Enabled: enabled != 0 || pacURL != "",
		Server:  server,
		Bypass:  bypass,
		PACURL:  pacURL,
	}, nil
}

// DisableSystemProxy clears the WinINet proxy enable toggle flag in registry.
func DisableSystemProxy(ctx context.Context) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()

	if err := k.SetDWordValue("ProxyEnable", 0); err != nil {
		return err
	}

	_ = k.DeleteValue("AutoConfigURL")

	refreshWindowsProxySettings()
	return nil
}

// GetProxySettings reads and parses current system-wide proxy settings, populating compatibility fields.
func GetProxySettings(ctx context.Context) (*ProxySettings, error) {
	settings, err := GetSystemProxy(ctx)
	if err != nil {
		return nil, err
	}
	settings.HTTPServer = settings.Server
	settings.BypassList = settings.Bypass
	return settings, nil
}

// SetProxySettings configures system proxy settings using compatibility fields.
func SetProxySettings(ctx context.Context, settings ProxySettings) error {
	if settings.Server == "" {
		settings.Server = settings.HTTPServer
	}
	if settings.Bypass == "" {
		settings.Bypass = settings.BypassList
	}
	return SetSystemProxy(ctx, &settings)
}

// DisableProxy disables the system-wide proxy.
func DisableProxy(ctx context.Context) error {
	return DisableSystemProxy(ctx)
}
