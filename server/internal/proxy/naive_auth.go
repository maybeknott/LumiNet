package proxy

import (
	"fmt"
	"strings"
	"time"
)

// NaiveOutbound represents the parameters for NaiveProxy configurations.
type NaiveOutbound struct {
	Server   string `json:"server"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// GenerateNaiveConfig generates a standard outbound configuration map for NaiveProxy.
func GenerateNaiveConfig(cfg NaiveOutbound) (map[string]interface{}, error) {
	if cfg.Server == "" {
		return nil, fmt.Errorf("missing naive proxy server address")
	}
	if cfg.Username == "" || cfg.Password == "" {
		return nil, fmt.Errorf("missing naive authentication credentials")
	}

	serverStr := cfg.Server
	if !strings.Contains(serverStr, ":") {
		serverStr = fmt.Sprintf("%s:%d", serverStr, cfg.Port)
	}

	return map[string]interface{}{
		"type":        "naive",
		"tag":         "proxy",
		"server":      cfg.Server,
		"server_port": cfg.Port,
		"username":    cfg.Username,
		"password":    cfg.Password,
	}, nil
}

// SaveNaiveOutboundCredentials encrypts and saves NaiveOutbound credentials to a vault file.
func SaveNaiveOutboundCredentials(vaultPath string, masterPassword string, credentials []NaiveOutbound) error {
	vault := NewCryptoVault(vaultPath, []byte("naive-salt-value-12345"))

	vaultCreds := make([]VaultCredential, len(credentials))
	for i, c := range credentials {
		vaultCreds[i] = VaultCredential{
			ID:        fmt.Sprintf("naive-%d", i),
			Username:  c.Username,
			Password:  c.Password,
			Metadata:  fmt.Sprintf("%s:%d", c.Server, c.Port),
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(30 * 24 * time.Hour), // 30 days expiration
		}
	}

	return vault.Save(masterPassword, vaultCreds)
}

// LoadNaiveOutboundCredentials decrypts and loads NaiveOutbound credentials from a vault file.
func LoadNaiveOutboundCredentials(vaultPath string, masterPassword string) ([]NaiveOutbound, error) {
	vault := NewCryptoVault(vaultPath, []byte("naive-salt-value-12345"))

	vaultCreds, err := vault.GetActiveCredentials(masterPassword)
	if err != nil {
		return nil, err
	}

	outbounds := make([]NaiveOutbound, len(vaultCreds))
	for i, vc := range vaultCreds {
		// Parse server and port from metadata
		server := vc.Metadata
		port := 443
		parts := strings.Split(vc.Metadata, ":")
		if len(parts) == 2 {
			server = parts[0]
			fmt.Sscanf(parts[1], "%d", &port)
		}

		outbounds[i] = NaiveOutbound{
			Server:   server,
			Port:     port,
			Username: vc.Username,
			Password: vc.Password,
		}
	}

	return outbounds, nil
}
