// Package config handles the configuration loading, saving, and validation for the server.
package config

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/maybeknott/luminet/internal/crypto"
)

// ErrConfigNotFound is returned when the configuration file does not exist.
var ErrConfigNotFound = errors.New("configuration file not found")

// Config represents the application configuration structure.
type Config struct {
	ServerAddr  string            `json:"server_addr"`
	LogLevel    string            `json:"log_level"`
	DBPath      string            `json:"db_path"`
	DDNS        DDNSConfig        `json:"ddns"`
	SystemProxy ProxyConfig       `json:"system_proxy"`
	ProxyNodes  []ProxyNodeConfig `json:"proxy_nodes"`
	PluginsDir  string            `json:"plugins_dir"`

	// ponytail: simplify settings storage by keeping scanner engine values at the root config structure
	DefaultTimeoutMs int  `json:"default_timeout_ms"`
	MaxConcurrency   int  `json:"max_concurrency"`
	DebugLogs        bool `json:"debug_logs"`
	DNSResolution    bool `json:"dns_resolution"`
	DecoyTraffic     DecoyTrafficConfig `json:"decoy_traffic"`
	CaptchaSolver    CaptchaSolverConfig `json:"captcha_solver"`
	UpgenObfuscation UpgenObfuscationConfig `json:"upgen_obfuscation"`
	MihomoRules      MihomoRulesOptions     `json:"mihomo_rules"`
	Steganography    SteganographyConfig    `json:"steganography"`
	HostsOverride    bool                   `json:"hosts_override"`
}

// MihomoRulesOptions defines options for customizing Clash config rules generation.
type MihomoRulesOptions struct {
	BypassIran        bool `json:"bypass_iran"`
	BypassChina       bool `json:"bypass_china"`
	BypassRussia      bool `json:"bypass_russia"`
	BypassOpenAI      bool `json:"bypass_openai"`
	BypassGoogleAI    bool `json:"bypass_google_ai"`
	BypassMicrosoft   bool `json:"bypass_microsoft"`
	BypassOracle      bool `json:"bypass_oracle"`
	BypassDocker      bool `json:"bypass_docker"`
	BypassAdobe       bool `json:"bypass_adobe"`
	BypassEpicGames   bool `json:"bypass_epic_games"`
	BypassIntel       bool `json:"bypass_intel"`
	BypassAMD         bool `json:"bypass_amd"`
	BypassNvidia      bool `json:"bypass_nvidia"`
	BypassAsus        bool `json:"bypass_asus"`
	BypassHP          bool `json:"bypass_hp"`
	BypassLenovo      bool `json:"bypass_lenovo"`
	BlockMalware      bool `json:"block_malware"`
	BlockPhishing     bool `json:"block_phishing"`
	BlockCryptominers bool `json:"block_cryptominers"`
	BlockAds          bool `json:"block_ads"`
	BlockPorn         bool `json:"block_porn"`
}

// SteganographyConfig represents settings for VoIP/WebRTC and Intranet steganographic camouflage.
type SteganographyConfig struct {
	Enabled        bool   `json:"enabled"`
	Mode           string `json:"mode"`
	DecoyImagePath string `json:"decoy_image_path"`
	WebRTCSDPSpoof bool   `json:"webrtc_sdp_spoof"`
}

// UpgenObfuscationConfig represents settings for the context-free grammar and QUIC queue exhaustion obfuscation.
type UpgenObfuscationConfig struct {
	Enabled            bool   `json:"enabled"`
	SeedHex            string `json:"seed_hex"`
	EntropyMatch       bool   `json:"entropy_match"`
	QUICExhaustionRate int    `json:"quic_exhaustion_rate"`
}

// ProxyNodeConfig represents a registered proxy server in the directory.
type ProxyNodeConfig struct {
	ID       string `json:"id"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Type     string `json:"type"`
	Auth     bool   `json:"auth"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Notes    string `json:"notes"`
}

// DDNSConfig represents the DDNS specific configuration parameters.
type DDNSConfig struct {
	Enabled  bool   `json:"enabled"`
	Provider string `json:"provider"`
	Token    string `json:"token"`
	Domain   string `json:"domain"`
	Interval int    `json:"interval_minutes"`
}

// ProxyConfig represents the system proxy specific configuration parameters.
type ProxyConfig struct {
	Enabled bool   `json:"enabled"`
	Address string `json:"address"`
	Bypass  string `json:"bypass"`
}

// DecoyTrafficConfig represents settings for the background decoy traffic generator.
type DecoyTrafficConfig struct {
	Enabled         bool     `json:"enabled"`
	Targets         []string `json:"targets"`
	VolumePerMinute int      `json:"volume_per_minute"`
}

// CaptchaSolverConfig represents settings for the CAPTCHA/WAF solver integration.
type CaptchaSolverConfig struct {
	Enabled     bool   `json:"enabled"`
	APIKey      string `json:"api_key"`
	EndpointURL string `json:"endpoint_url"`
}

// Manager orchestrates loading, saving, and dynamically updating configuration.
type Manager struct {
	configPath string
	mu         sync.RWMutex
	current    *Config
}

// NewManager creates a new config Manager with the specified path.
func NewManager(configPath string) *Manager {
	return &Manager{
		configPath: configPath,
		current:    DefaultConfig(),
	}
}

// EncryptSensitiveFields encrypts sensitive fields in the configuration.
func (c *Config) EncryptSensitiveFields() error {
	// Encrypt DDNS Token
	if c.DDNS.Token != "" {
		enc, err := crypto.Encrypt([]byte(c.DDNS.Token))
		if err != nil {
			return err
		}
		c.DDNS.Token = base64.StdEncoding.EncodeToString(enc)
	}

	// Encrypt Proxy Node Passwords
	for i := range c.ProxyNodes {
		if c.ProxyNodes[i].Password != "" {
			enc, err := crypto.Encrypt([]byte(c.ProxyNodes[i].Password))
			if err != nil {
				return err
			}
			c.ProxyNodes[i].Password = base64.StdEncoding.EncodeToString(enc)
		}
	}

	// Encrypt Captcha Solver API Key
	if c.CaptchaSolver.APIKey != "" {
		enc, err := crypto.Encrypt([]byte(c.CaptchaSolver.APIKey))
		if err != nil {
			return err
		}
		c.CaptchaSolver.APIKey = base64.StdEncoding.EncodeToString(enc)
	}

	// Encrypt Upgen Obfuscation SeedHex
	if c.UpgenObfuscation.SeedHex != "" {
		enc, err := crypto.Encrypt([]byte(c.UpgenObfuscation.SeedHex))
		if err != nil {
			return err
		}
		c.UpgenObfuscation.SeedHex = base64.StdEncoding.EncodeToString(enc)
	}
	return nil
}

// DecryptSensitiveFields decrypts sensitive fields in the configuration.
func (c *Config) DecryptSensitiveFields() error {
	// Decrypt DDNS Token
	if c.DDNS.Token != "" {
		decoded, err := base64.StdEncoding.DecodeString(c.DDNS.Token)
		if err != nil {
			return err
		}
		dec, err := crypto.Decrypt(decoded)
		if err != nil {
			return err
		}
		c.DDNS.Token = string(dec)
	}

	// Decrypt Proxy Node Passwords
	for i := range c.ProxyNodes {
		if c.ProxyNodes[i].Password != "" {
			decoded, err := base64.StdEncoding.DecodeString(c.ProxyNodes[i].Password)
			if err != nil {
				return err
			}
			dec, err := crypto.Decrypt(decoded)
			if err != nil {
				return err
			}
			c.ProxyNodes[i].Password = string(dec)
		}
	}

	// Decrypt Captcha Solver API Key
	if c.CaptchaSolver.APIKey != "" {
		decoded, err := base64.StdEncoding.DecodeString(c.CaptchaSolver.APIKey)
		if err != nil {
			return err
		}
		dec, err := crypto.Decrypt(decoded)
		if err != nil {
			return err
		}
		c.CaptchaSolver.APIKey = string(dec)
	}

	// Decrypt Upgen Obfuscation SeedHex
	if c.UpgenObfuscation.SeedHex != "" {
		decoded, err := base64.StdEncoding.DecodeString(c.UpgenObfuscation.SeedHex)
		if err == nil {
			dec, err := crypto.Decrypt(decoded)
			if err == nil {
				c.UpgenObfuscation.SeedHex = string(dec)
			}
		}
	}
	return nil
}

// Load loads the configuration from the file. If file does not exist, defaults are used.
func (m *Manager) Load() (*Config, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := os.ReadFile(m.configPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// If file does not exist, populate with defaults and write it
			m.current = DefaultConfig()
			m.mu.Unlock()
			saveErr := m.Save(m.current)
			m.mu.Lock()
			if saveErr != nil {
				return nil, saveErr
			}
			return m.current, nil
		}
		return nil, err
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	if err := cfg.DecryptSensitiveFields(); err != nil {
		return nil, err
	}

	m.current = &cfg
	return m.current, nil
}

// Save persists the current configuration to the config file path.
func (m *Manager) Save(cfg *Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Deep clone to avoid modifying the reference being saved
	cfgCopy := *cfg
	if cfg.ProxyNodes != nil {
		cfgCopy.ProxyNodes = make([]ProxyNodeConfig, len(cfg.ProxyNodes))
		copy(cfgCopy.ProxyNodes, cfg.ProxyNodes)
	}

	if err := cfgCopy.EncryptSensitiveFields(); err != nil {
		return err
	}

	// Ensure parent directory exists
	dir := filepath.Dir(m.configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(cfgCopy, "", "  ")
	if err != nil {
		return err
	}

	// Write atomically using a temporary file
	tmpFile := m.configPath + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		return err
	}

	if err := os.Rename(tmpFile, m.configPath); err != nil {
		_ = os.Remove(tmpFile)
		return err
	}

	m.current = cfg
	return nil
}

// Get returns the currently loaded configuration.
func (m *Manager) Get() *Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.current
}
