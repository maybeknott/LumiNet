package plugin

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
)

const (
	// ActionNativePlugin is the Android intent action for SagerNet / NekoBox plugin services.
	ActionNativePlugin = "io.nekohasekai.sagernet.plugin.ACTION_NATIVE_PLUGIN"
	// ExtraEntry is the bundle key providing the absolute path to the native executable.
	ExtraEntry = "io.nekohasekai.sagernet.plugin.EXTRA_ENTRY"
	// MetadataKeyID identifies the plugin unique ID in manifest metadata.
	MetadataKeyID = "io.nekohasekai.sagernet.plugin.id"
	// MetadataKeyExecutablePath identifies the binary location in manifest metadata.
	MetadataKeyExecutablePath = "io.nekohasekai.sagernet.plguin.executable_path"
	// MethodGetExecutable is the ContentProvider call method to fetch executable location.
	MethodGetExecutable = "sagernet:getExecutable"
	// DefaultPluginFileMode is rwxr-xr-x.
	DefaultPluginFileMode os.FileMode = 0755
)

// NativePluginDescriptor describes an external SagerNet / NekoBox plugin binary.
type NativePluginDescriptor struct {
	ID             string      `json:"id"`
	Name           string      `json:"name"`
	ExecutablePath string      `json:"executable_path"`
	FileMode       os.FileMode `json:"file_mode"`
	EnvArgs        []string    `json:"env_args"`
}

// NewNativePluginDescriptor creates an initialized plugin descriptor.
func NewNativePluginDescriptor(id, name, execPath string) *NativePluginDescriptor {
	return &NativePluginDescriptor{
		ID:             id,
		Name:           name,
		ExecutablePath: execPath,
		FileMode:       DefaultPluginFileMode,
		EnvArgs:        make([]string, 0),
	}
}

// PluginCommandConfig formats execution arguments for the outbound proxy engine.
type PluginCommandConfig struct {
	BindAddress string `json:"bind_address"`
	BindPort    int    `json:"bind_port"`
	RemoteDNS   string `json:"remote_dns"`
	SNI         string `json:"sni,omitempty"`
	DoHURL      string `json:"doh_url,omitempty"`
	SplitSNI    bool   `json:"split_sni"`
	UDPMode     bool   `json:"udp_mode"`
}

// BuildArgs constructs the CLI flag list passed to the plugin subprocess.
func (c *PluginCommandConfig) BuildArgs() []string {
	bind := c.BindAddress
	if bind == "" {
		bind = "127.0.0.1"
	}
	port := c.BindPort
	if port <= 0 {
		port = 10808
	}

	args := []string{
		"-l", fmt.Sprintf("%s:%d", bind, port),
	}

	dns := c.RemoteDNS
	if dns == "" {
		dns = "1.1.1.1"
	}
	args = append(args, "-d", dns)

	if c.SNI != "" {
		args = append(args, "-s", c.SNI)
	}

	if c.DoHURL != "" {
		args = append(args, "--doh", c.DoHURL)
	}

	if c.SplitSNI {
		args = append(args, "--split-sni")
	}

	if c.UDPMode {
		args = append(args, "-u")
	}

	return args
}

// PluginProcessManager manages lifecycle and supervision of external native plugin processes.
type PluginProcessManager struct {
	mu        sync.Mutex
	processes map[string]*exec.Cmd
}

// NewPluginProcessManager creates a new plugin supervisor.
func NewPluginProcessManager() *PluginProcessManager {
	return &PluginProcessManager{
		processes: make(map[string]*exec.Cmd),
	}
}

// ValidateExecutable checks that the target binary exists and is accessible.
func (m *PluginProcessManager) ValidateExecutable(path string) error {
	cleanPath := filepath.Clean(path)
	info, err := os.Stat(cleanPath)
	if err != nil {
		return fmt.Errorf("plugin executable not found: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("plugin executable path is a directory: %s", cleanPath)
	}
	return nil
}

// PrepareCommand constructs an *exec.Cmd configured for plugin execution.
func (m *PluginProcessManager) PrepareCommand(ctx context.Context, desc *NativePluginDescriptor, cfg *PluginCommandConfig) (*exec.Cmd, error) {
	if err := m.ValidateExecutable(desc.ExecutablePath); err != nil {
		return nil, err
	}

	args := cfg.BuildArgs()
	cmd := exec.CommandContext(ctx, desc.ExecutablePath, args...)

	// Pass environment variables including plugin metadata
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("SAGARNET_PLUGIN_ID=%s", desc.ID),
		fmt.Sprintf("SAGARNET_PLUGIN_NAME=%s", desc.Name),
	)
	cmd.Env = append(cmd.Env, desc.EnvArgs...)

	return cmd, nil
}
