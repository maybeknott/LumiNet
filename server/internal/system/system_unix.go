//go:build !windows

package system

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"
)

// ProxySettings represents the system-wide proxy settings.
type ProxySettings struct {
	Enabled    bool   `json:"enabled"`
	Server     string `json:"server"`
	Bypass     string `json:"bypass"`
	HTTPServer string `json:"http_server"`
	BypassList string `json:"bypass_list"`
	PACURL     string `json:"pac_url"`
}

func getDefaultAdapter(ctx context.Context) (string, error) {
	if runtime.GOOS == "darwin" {
		// On macOS, try to find active network service name (e.g. Wi-Fi)
		cmd := exec.CommandContext(ctx, "networksetup", "-listallnetworkservices")
		out, err := cmd.Output()
		if err == nil {
			lines := strings.Split(string(out), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line != "" && !strings.Contains(line, "*") && !strings.Contains(line, "An asterisk") {
					// Return the first service found as a fallback (Wi-Fi, Ethernet, etc.)
					return line, nil
				}
			}
		}
	}
	return "Wi-Fi", nil
}

// SetDNS configures system DNS servers using platform utilities.
func SetDNS(ctx context.Context, adapterName string, dnsServers []string) error {
	if adapterName == "" {
		var err error
		adapterName, err = getDefaultAdapter(ctx)
		if err != nil {
			adapterName = "Wi-Fi"
		}
	}

	if runtime.GOOS == "darwin" {
		args := append([]string{"-setdnsservers", adapterName}, dnsServers...)
		cmd := exec.CommandContext(ctx, "networksetup", args...)
		return cmd.Run()
	} else if runtime.GOOS == "linux" {
		args := append([]string{"dns", adapterName}, dnsServers...)
		cmd := exec.CommandContext(ctx, "resolvectl", args...)
		return cmd.Run()
	}
	return errors.New("DNS configuration is not supported on this platform")
}

// ResetDNS reverts system DNS configuration to DHCP defaults.
func ResetDNS(ctx context.Context, adapterName string) error {
	if adapterName == "" {
		var err error
		adapterName, err = getDefaultAdapter(ctx)
		if err != nil {
			adapterName = "Wi-Fi"
		}
	}

	if runtime.GOOS == "darwin" {
		cmd := exec.CommandContext(ctx, "networksetup", "-setdnsservers", adapterName, "empty")
		return cmd.Run()
	} else if runtime.GOOS == "linux" {
		cmd := exec.CommandContext(ctx, "resolvectl", "revert", adapterName)
		return cmd.Run()
	}
	return errors.New("DNS configuration is not supported on this platform")
}

// GetDNS returns currently active DNS servers for the adapter.
func GetDNS(ctx context.Context, adapterName string) ([]string, error) {
	if adapterName == "" {
		var err error
		adapterName, err = getDefaultAdapter(ctx)
		if err != nil {
			adapterName = "Wi-Fi"
		}
	}

	if runtime.GOOS == "darwin" {
		cmd := exec.CommandContext(ctx, "networksetup", "-getdnsservers", adapterName)
		out, err := cmd.Output()
		if err != nil {
			return nil, err
		}
		lines := strings.Split(string(out), "\n")
		var servers []string
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" && !strings.Contains(line, "any DNS Servers set") {
				servers = append(servers, line)
			}
		}
		return servers, nil
	} else if runtime.GOOS == "linux" {
		cmd := exec.CommandContext(ctx, "resolvectl", "status", adapterName)
		out, err := cmd.Output()
		if err != nil {
			return nil, err
		}
		lines := strings.Split(string(out), "\n")
		var servers []string
		for _, line := range lines {
			if strings.Contains(line, "DNS Servers:") {
				parts := strings.Fields(strings.Split(line, "DNS Servers:")[1])
				servers = append(servers, parts...)
			}
		}
		return servers, nil
	}
	return nil, errors.New("DNS configuration is not supported on this platform")
}

// ClearDNS resets system DNS to default config.
func ClearDNS(ctx context.Context, adapterName string) error {
	return ResetDNS(ctx, adapterName)
}

// SetSystemProxy configures system-wide proxy using macOS networksetup or Linux gsettings.
func SetSystemProxy(ctx context.Context, settings *ProxySettings) error {
	if runtime.GOOS == "darwin" {
		adapter, err := getDefaultAdapter(ctx)
		if err != nil {
			adapter = "Wi-Fi"
		}

		if settings.PACURL != "" {
			cmdPac := exec.CommandContext(ctx, "networksetup", "-setautoproxyurl", adapter, settings.PACURL)
			if err := cmdPac.Run(); err != nil {
				return err
			}
			_ = exec.CommandContext(ctx, "networksetup", "-setautoproxystate", adapter, "on").Run()
			// Turn off manual proxy states
			_ = exec.CommandContext(ctx, "networksetup", "-setwebproxystate", adapter, "off").Run()
			_ = exec.CommandContext(ctx, "networksetup", "-setsecurewebproxystate", adapter, "off").Run()
			return nil
		}

		_ = exec.CommandContext(ctx, "networksetup", "-setautoproxystate", adapter, "off").Run()

		host, portStr, err := net.SplitHostPort(settings.Server)
		if err != nil {
			host = settings.Server
			portStr = "8080"
		}

		cmd1 := exec.CommandContext(ctx, "networksetup", "-setwebproxy", adapter, host, portStr)
		if err := cmd1.Run(); err != nil {
			return err
		}
		cmd2 := exec.CommandContext(ctx, "networksetup", "-setsecurewebproxy", adapter, host, portStr)
		if err := cmd2.Run(); err != nil {
			return err
		}
		_ = exec.CommandContext(ctx, "networksetup", "-setwebproxystate", adapter, "on").Run()
		_ = exec.CommandContext(ctx, "networksetup", "-setsecurewebproxystate", adapter, "on").Run()
		return nil
	} else if runtime.GOOS == "linux" {
		if settings.PACURL != "" {
			_ = exec.CommandContext(ctx, "gsettings", "set", "org.gnome.system.proxy", "mode", "auto").Run()
			_ = exec.CommandContext(ctx, "gsettings", "set", "org.gnome.system.proxy", "autoconfig-url", settings.PACURL).Run()
			return nil
		}

		host, portStr, err := net.SplitHostPort(settings.Server)
		var port int
		if err == nil {
			fmt.Sscanf(portStr, "%d", &port)
		} else {
			host = settings.Server
			port = 8080
		}

		_ = exec.CommandContext(ctx, "gsettings", "set", "org.gnome.system.proxy", "mode", "manual").Run()
		_ = exec.CommandContext(ctx, "gsettings", "set", "org.gnome.system.proxy.http", "host", host).Run()
		_ = exec.CommandContext(ctx, "gsettings", "set", "org.gnome.system.proxy.http", "port", fmt.Sprintf("%d", port)).Run()
		_ = exec.CommandContext(ctx, "gsettings", "set", "org.gnome.system.proxy.https", "host", host).Run()
		_ = exec.CommandContext(ctx, "gsettings", "set", "org.gnome.system.proxy.https", "port", fmt.Sprintf("%d", port)).Run()
		return nil
	}
	return errors.New("system proxy configuration is not supported on this platform")
}

// GetSystemProxy returns current system proxy settings.
func GetSystemProxy(ctx context.Context) (*ProxySettings, error) {
	return GetProxySettings(ctx)
}

// DisableSystemProxy disables system proxy settings.
func DisableSystemProxy(ctx context.Context) error {
	if runtime.GOOS == "darwin" {
		adapter, err := getDefaultAdapter(ctx)
		if err != nil {
			adapter = "Wi-Fi"
		}
		_ = exec.CommandContext(ctx, "networksetup", "-setwebproxystate", adapter, "off").Run()
		_ = exec.CommandContext(ctx, "networksetup", "-setsecurewebproxystate", adapter, "off").Run()
		_ = exec.CommandContext(ctx, "networksetup", "-setautoproxystate", adapter, "off").Run()
		return nil
	} else if runtime.GOOS == "linux" {
		_ = exec.CommandContext(ctx, "gsettings", "set", "org.gnome.system.proxy", "mode", "none").Run()
		return nil
	}
	return nil
}

// GetProxySettings returns current system proxy configuration details.
func GetProxySettings(ctx context.Context) (*ProxySettings, error) {
	if runtime.GOOS == "darwin" {
		adapter, err := getDefaultAdapter(ctx)
		if err != nil {
			adapter = "Wi-Fi"
		}
		cmd := exec.CommandContext(ctx, "networksetup", "-getwebproxy", adapter)
		out, err := cmd.Output()
		if err != nil {
			return &ProxySettings{Enabled: false}, nil
		}
		lines := strings.Split(string(out), "\n")
		server := ""
		port := ""
		enabled := false
		for _, line := range lines {
			if strings.HasPrefix(line, "Enabled:") {
				enabled = strings.Contains(line, "Yes")
			} else if strings.HasPrefix(line, "Server:") {
				server = strings.TrimSpace(strings.Split(line, "Server:")[1])
			} else if strings.HasPrefix(line, "Port:") {
				port = strings.TrimSpace(strings.Split(line, "Port:")[1])
			}
		}
		if enabled && server != "" {
			return &ProxySettings{
				Enabled: true,
				Server:  net.JoinHostPort(server, port),
			}, nil
		}
	}
	return &ProxySettings{Enabled: false}, nil
}

// SetProxySettings applies ProxySettings parameters to the system.
func SetProxySettings(ctx context.Context, settings ProxySettings) error {
	return SetSystemProxy(ctx, &settings)
}

// DisableProxy disables system proxy.
func DisableProxy(ctx context.Context) error {
	return DisableSystemProxy(ctx)
}
