//go:build darwin

package system

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
)

func runNetworkSetup(ctx context.Context, args ...string) error {
	out, err := exec.CommandContext(ctx, "networksetup", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("networksetup %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func networkSetupOutput(ctx context.Context, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, "networksetup", args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("networksetup %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func parseDefaultRouteInterface(out string) string {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "interface:") {
			continue
		}
		return strings.TrimSpace(strings.TrimPrefix(line, "interface:"))
	}
	return ""
}

func parseNetworkServiceHeader(line string) (service string, disabled bool, ok bool) {
	line = strings.TrimSpace(line)
	if len(line) < 4 || line[0] != '(' {
		return "", false, false
	}
	closeIndex := strings.IndexByte(line, ')')
	if closeIndex <= 1 {
		return "", false, false
	}
	for _, r := range line[1:closeIndex] {
		if r < '0' || r > '9' {
			return "", false, false
		}
	}
	service = strings.TrimSpace(line[closeIndex+1:])
	disabled = strings.HasPrefix(service, "*")
	service = strings.TrimSpace(strings.TrimPrefix(service, "*"))
	if service == "" {
		return "", disabled, false
	}
	return service, disabled, true
}

func parseNetworkServiceForDevice(out, device string) string {
	device = strings.TrimSpace(device)
	if device == "" {
		return ""
	}

	service := ""
	disabled := false
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		if candidate, isDisabled, ok := parseNetworkServiceHeader(line); ok {
			service = candidate
			disabled = isDisabled
			continue
		}
		if service == "" || disabled || !strings.Contains(line, "Device:") {
			continue
		}
		deviceField := strings.SplitN(line, "Device:", 2)[1]
		candidate := strings.TrimSpace(strings.TrimSuffix(deviceField, ")"))
		if candidate == device {
			return service
		}
	}
	return ""
}

func getDefaultAdapter(ctx context.Context) (string, error) {
	routeOutput, err := exec.CommandContext(ctx, "route", "-n", "get", "default").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("resolve default route: %w: %s", err, strings.TrimSpace(string(routeOutput)))
	}
	device := parseDefaultRouteInterface(string(routeOutput))
	if device == "" {
		return "", fmt.Errorf("resolve default route: route output did not contain an interface")
	}

	serviceOutput, err := networkSetupOutput(ctx, "-listnetworkserviceorder")
	if err != nil {
		return "", err
	}
	service := parseNetworkServiceForDevice(serviceOutput, device)
	if service == "" {
		return "", fmt.Errorf("resolve default network service: no enabled service owns interface %q", device)
	}
	return service, nil
}

func parseNetworkSetupProxy(out string) (enabled bool, server, port string) {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "Enabled:"):
			enabled = strings.EqualFold(strings.TrimSpace(strings.TrimPrefix(line, "Enabled:")), "Yes")
		case strings.HasPrefix(line, "Server:"):
			server = strings.TrimSpace(strings.TrimPrefix(line, "Server:"))
		case strings.HasPrefix(line, "Port:"):
			port = strings.TrimSpace(strings.TrimPrefix(line, "Port:"))
		}
	}
	return
}

func parseAutoProxy(out string) (enabled bool, url string) {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "Enabled:"):
			enabled = strings.EqualFold(strings.TrimSpace(strings.TrimPrefix(line, "Enabled:")), "Yes")
		case strings.HasPrefix(line, "URL:"):
			url = strings.TrimSpace(strings.TrimPrefix(line, "URL:"))
		}
	}
	return
}

func SetSystemProxy(ctx context.Context, settings *ProxySettings) error {
	if settings == nil {
		return fmt.Errorf("proxy settings are required")
	}
	adapter, err := getDefaultAdapter(ctx)
	if err != nil {
		return err
	}
	if settings.PACURL != "" {
		if err := runNetworkSetup(ctx, "-setautoproxyurl", adapter, settings.PACURL); err != nil {
			return err
		}
		if err := runNetworkSetup(ctx, "-setautoproxystate", adapter, "on"); err != nil {
			return err
		}
		if err := runNetworkSetup(ctx, "-setwebproxystate", adapter, "off"); err != nil {
			return err
		}
		return runNetworkSetup(ctx, "-setsecurewebproxystate", adapter, "off")
	}
	if !settings.Enabled {
		if err := runNetworkSetup(ctx, "-setautoproxystate", adapter, "off"); err != nil {
			return err
		}
		if err := runNetworkSetup(ctx, "-setwebproxystate", adapter, "off"); err != nil {
			return err
		}
		return runNetworkSetup(ctx, "-setsecurewebproxystate", adapter, "off")
	}
	host, port, err := net.SplitHostPort(settings.Server)
	if err != nil {
		return fmt.Errorf("invalid proxy server %q: %w", settings.Server, err)
	}
	if err := runNetworkSetup(ctx, "-setautoproxystate", adapter, "off"); err != nil {
		return err
	}
	if err := runNetworkSetup(ctx, "-setwebproxy", adapter, host, port); err != nil {
		return err
	}
	if err := runNetworkSetup(ctx, "-setsecurewebproxy", adapter, host, port); err != nil {
		return err
	}
	if err := runNetworkSetup(ctx, "-setwebproxystate", adapter, "on"); err != nil {
		return err
	}
	return runNetworkSetup(ctx, "-setsecurewebproxystate", adapter, "on")
}

func GetSystemProxy(ctx context.Context) (*ProxySettings, error) {
	adapter, err := getDefaultAdapter(ctx)
	if err != nil {
		return nil, err
	}
	autoOut, err := networkSetupOutput(ctx, "-getautoproxyurl", adapter)
	if err != nil {
		return nil, err
	}
	if enabled, url := parseAutoProxy(autoOut); enabled {
		if url == "" {
			return nil, fmt.Errorf("automatic proxy enabled without URL")
		}
		return &ProxySettings{Enabled: true, PACURL: url}, nil
	}
	out, err := networkSetupOutput(ctx, "-getwebproxy", adapter)
	if err != nil {
		return nil, err
	}
	enabled, host, port := parseNetworkSetupProxy(out)
	if !enabled {
		return &ProxySettings{}, nil
	}
	if host == "" || port == "" {
		return nil, fmt.Errorf("manual proxy enabled without host/port")
	}
	return &ProxySettings{Enabled: true, Server: net.JoinHostPort(host, port)}, nil
}

func GetProxySettings(ctx context.Context) (*ProxySettings, error) { return GetSystemProxy(ctx) }
func SetProxySettings(ctx context.Context, settings ProxySettings) error {
	return SetSystemProxy(ctx, &settings)
}
func DisableSystemProxy(ctx context.Context) error { return SetSystemProxy(ctx, &ProxySettings{}) }
func DisableProxy(ctx context.Context) error       { return DisableSystemProxy(ctx) }
