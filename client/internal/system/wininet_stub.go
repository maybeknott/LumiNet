//go:build !windows

package system

import "errors"

type RegistryValue struct {
	Exists bool   `json:"exists"`
	Value  string `json:"value,omitempty"`
	Dword  uint32 `json:"dword,omitempty"`
	Type   uint32 `json:"type,omitempty"`
}

type ProxySettingsSnapshot struct {
	ProxyEnabled bool                     `json:"proxy_enabled"`
	ProxyServer  string                   `json:"proxy_server,omitempty"`
	Registry     map[string]RegistryValue `json:"registry"`
}

func GetProxySettings() (ProxySettingsSnapshot, error) {
	return ProxySettingsSnapshot{Registry: make(map[string]RegistryValue)}, errors.New("wininet proxy settings not supported on this platform")
}

func RestoreProxySettings(snapshot ProxySettingsSnapshot) error {
	return errors.New("wininet proxy settings not supported on this platform")
}

func SetSocks5Proxy(server string) error {
	return errors.New("wininet proxy settings not supported on this platform")
}

func ClearProxy() error {
	return errors.New("wininet proxy settings not supported on this platform")
}
