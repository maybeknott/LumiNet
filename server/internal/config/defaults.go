// Package config handles the configuration loading, saving, and validation for the server.
package config

// DefaultServerAddr is the default address the server listens on.
const DefaultServerAddr = "127.0.0.1:8080"

// DefaultLogLevel is the default level of logging.
const DefaultLogLevel = "info"

// DefaultDBPath is the default path to the SQLite database.
const DefaultDBPath = "luminet.db"

// DefaultPluginsDir is the default folder to search for plugins.
const DefaultPluginsDir = "./plugins"

// DefaultConfig returns a new Config populated with default values.
func DefaultConfig() *Config {
	return &Config{
		ServerAddr: DefaultServerAddr,
		LogLevel:   DefaultLogLevel,
		DBPath:     DefaultDBPath,
		PluginsDir: DefaultPluginsDir,
		DDNS: DDNSConfig{
			Enabled:  false,
			Provider: "cloudflare",
			Interval: 15,
		},
		SystemProxy: ProxyConfig{
			Enabled: false,
			Address: "127.0.0.1:7890",
			Bypass:  "localhost;127.0.0.1;<local>",
		},
		ProxyNodes: []ProxyNodeConfig{
			{
				ID:    "p1",
				Host:  "127.0.0.1",
				Port:  7890,
				Type:  "HTTP",
				Notes: "Default Local Proxy",
			},
		},
		// ponytail: initialize default parameters for port/network scan limits
		DefaultTimeoutMs: 4000,
		MaxConcurrency:   50,
		DebugLogs:        true,
		DNSResolution:    true,
		DecoyTraffic: DecoyTrafficConfig{
			Enabled:         false, // disabled by default, user-configurable
			Targets:         []string{"https://www.google.com", "https://www.wikipedia.org"},
			VolumePerMinute: 120, // 120 KB/min (2 KB/sec avg)
		},
		CaptchaSolver: CaptchaSolverConfig{
			Enabled:     false,
			APIKey:      "",
			EndpointURL: "https://api.solvecaptcha.com",
		},
		UpgenObfuscation: UpgenObfuscationConfig{
			Enabled:            false,
			SeedHex:            "4a7b9e02c1f8d4",
			EntropyMatch:       true,
			QUICExhaustionRate: 50,
		},
		Steganography: SteganographyConfig{
			Enabled:        false,
			Mode:           "webrtc_voip",
			DecoyImagePath: "/var/lib/luminet/decoy.png",
			WebRTCSDPSpoof: true,
		},
		MihomoRules: MihomoRulesOptions{
			BypassChina: true,
			BypassIran:  true,
		},
		HostsOverride: true,
	}
}
