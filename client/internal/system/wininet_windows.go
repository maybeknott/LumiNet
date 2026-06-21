//go:build windows

package system

import (
	"fmt"
	"syscall"
	"golang.org/x/sys/windows/registry"
)

var (
	modwininet            = syscall.NewLazyDLL("wininet.dll")
	procInternetSetOption = modwininet.NewProc("InternetSetOptionW")
)

const (
	INTERNET_OPTION_SETTINGS_CHANGED = 39
	INTERNET_OPTION_REFRESH          = 37
)

type RegistryValue struct {
	Exists bool   `json:"exists"`
	Value  string `json:"value,omitempty"`
	Dword  uint32 `json:"dword,omitempty"`
	Type   uint32 `json:"type,omitempty"` // 1 = REG_SZ, 4 = REG_DWORD
}

type ProxySettingsSnapshot struct {
	ProxyEnabled bool                     `json:"proxy_enabled"`
	ProxyServer  string                   `json:"proxy_server,omitempty"`
	Registry     map[string]RegistryValue `json:"registry"`
}

func queryRegistryValue(key registry.Key, name string) RegistryValue {
	val, valType, err := key.GetStringValue(name)
	if err == nil {
		return RegistryValue{Exists: true, Value: val, Type: valType}
	}
	dw, valType, err := key.GetIntegerValue(name)
	if err == nil {
		return RegistryValue{Exists: true, Dword: uint32(dw), Type: valType}
	}
	return RegistryValue{Exists: false}
}

func applyRegistrySnapshotValue(key registry.Key, name string, item RegistryValue) error {
	if !item.Exists {
		_ = key.DeleteValue(name)
		return nil
	}
	switch item.Type {
	case registry.DWORD:
		return key.SetDWordValue(name, item.Dword)
	case registry.SZ:
		return key.SetStringValue(name, item.Value)
	default:
		return key.SetStringValue(name, item.Value)
	}
}

func notifyProxySettingsChanged() error {
	var errs []error
	for _, option := range []uintptr{INTERNET_OPTION_SETTINGS_CHANGED, INTERNET_OPTION_REFRESH} {
		ret, _, err := procInternetSetOption.Call(0, option, 0, 0)
		if ret == 0 {
			if err != nil && err != syscall.Errno(0) {
				errs = append(errs, err)
			} else {
				errs = append(errs, fmt.Errorf("InternetSetOptionW with option %d returned false", option))
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("failed to notify proxy settings change: %v", errs)
	}
	return nil
}

func GetProxySettings() (ProxySettingsSnapshot, error) {
	key, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.QUERY_VALUE)
	if err != nil {
		return ProxySettingsSnapshot{Registry: make(map[string]RegistryValue)}, err
	}
	defer key.Close()

	enabled := queryRegistryValue(key, "ProxyEnable")
	server := queryRegistryValue(key, "ProxyServer")
	override := queryRegistryValue(key, "ProxyOverride")
	autoconfig := queryRegistryValue(key, "AutoConfigURL")

	proxyEnabled := false
	if enabled.Exists && enabled.Dword != 0 {
		proxyEnabled = true
	}

	return ProxySettingsSnapshot{
		ProxyEnabled: proxyEnabled,
		ProxyServer:  server.Value,
		Registry: map[string]RegistryValue{
			"ProxyEnable":   enabled,
			"ProxyServer":   server,
			"ProxyOverride": override,
			"AutoConfigURL": autoconfig,
		},
	}, nil
}

func RestoreProxySettings(snapshot ProxySettingsSnapshot) error {
	key, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()

	for _, name := range []string{"ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL"} {
		if val, ok := snapshot.Registry[name]; ok {
			_ = applyRegistrySnapshotValue(key, name, val)
		}
	}

	return notifyProxySettingsChanged()
}

func SetSocks5Proxy(server string) error {
	key, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()

	if err := key.SetDWordValue("ProxyEnable", 1); err != nil {
		return err
	}
	if err := key.SetStringValue("ProxyServer", "socks="+server); err != nil {
		return err
	}
	if err := key.SetStringValue("ProxyOverride", "<local>;*.local"); err != nil {
		return err
	}

	return notifyProxySettingsChanged()
}

func ClearProxy() error {
	key, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()

	if err := key.SetDWordValue("ProxyEnable", 0); err != nil {
		return err
	}
	_ = key.DeleteValue("ProxyServer")
	_ = key.DeleteValue("ProxyOverride")
	_ = key.DeleteValue("AutoConfigURL")

	return notifyProxySettingsChanged()
}
