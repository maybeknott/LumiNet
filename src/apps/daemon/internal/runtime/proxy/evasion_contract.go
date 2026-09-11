package proxy

import (
	"fmt"
	"strings"
)

const redactedEvasionSecret = "[REDACTED]"

func normalizeEvasionConfig(cfg EvasionConfig) EvasionConfig {
	cfg.CovertMode = strings.ToLower(strings.TrimSpace(cfg.CovertMode))
	if cfg.CovertMode == "" {
		cfg.CovertMode = "direct"
	}
	cfg.StegoMode = strings.ToLower(strings.TrimSpace(cfg.StegoMode))
	if cfg.StegoMode == "pixel_stego" {
		cfg.StegoMode = "pixel"
	}
	return cfg
}

func validateEvasionConfig(cfg EvasionConfig) error {
	cfg = normalizeEvasionConfig(cfg)
	if cfg.UpgenEnabled && cfg.UpgenQuicExhaustionRate != 0 {
		return fmt.Errorf("UPGen QUIC exhaustion is not a production-supported capability; upgen_quic_exhaustion_rate must be 0")
	}

	if cfg.StegoEnabled {
		switch cfg.StegoMode {
		case "webrtc_voip":
			if cfg.StegoWebRTCSDPSpoof {
				return fmt.Errorf("WebRTC SDP spoofing is not implemented in the production data plane; disable steganography_webrtc_sdp_spoof")
			}
		case "pixel":
			if cfg.StegoWebRTCSDPSpoof {
				return fmt.Errorf("steganography_webrtc_sdp_spoof is not a supported production capability")
			}
		default:
			return fmt.Errorf("unsupported steganography mode %q; supported modes are webrtc_voip and pixel", cfg.StegoMode)
		}
	}

	if cfg.AutoReconnectEnabled {
		return fmt.Errorf("auto reconnect is not production-supported in the canonical proxy dial path")
	}

	switch cfg.CovertMode {
	case "direct", "paqet":
		return nil
	case "serverless", "edge":
		if strings.TrimSpace(cfg.CovertServerlessUrl) == "" {
			return fmt.Errorf("covert mode %q requires a relay URL", cfg.CovertMode)
		}
	case "dnstunnel":
		return fmt.Errorf("covert mode %q is simulation-only and is not available as a production tunnel", cfg.CovertMode)
	case "gsa":
		if strings.TrimSpace(cfg.CovertGsaUrl) == "" {
			return fmt.Errorf("covert mode %q requires a GSA relay URL", cfg.CovertMode)
		}
	case "gdocs", "gdrive":
		if strings.TrimSpace(cfg.CovertGdocsFolderId) == "" {
			return fmt.Errorf("covert mode %q requires a Google Drive folder ID", cfg.CovertMode)
		}
		if strings.TrimSpace(cfg.CovertGdocsAccessToken) == "" {
			return fmt.Errorf("covert mode %q requires an access token; simulator mode is not a production transport", cfg.CovertMode)
		}
	case "wstunnel":
		if strings.TrimSpace(cfg.CovertCfg.WsEndpoint) == "" {
			return fmt.Errorf("covert mode %q requires a WebTunnel endpoint", cfg.CovertMode)
		}
	case "ssh":
		if strings.TrimSpace(cfg.CovertCfg.SshHost) == "" {
			return fmt.Errorf("covert mode %q requires a transport host", cfg.CovertMode)
		}
		if strings.TrimSpace(cfg.CovertCfg.SshHostKeySHA256) == "" {
			return fmt.Errorf("covert mode %q requires ssh_host_key_sha256", cfg.CovertMode)
		}
	case "kcp":
		if strings.TrimSpace(cfg.CovertCfg.SshHost) == "" {
			return fmt.Errorf("covert mode %q requires a transport host", cfg.CovertMode)
		}
	case "tuic":
		return fmt.Errorf("covert mode %q is not production-supported: TUIC v5 requires a QUIC transport; use a normal TUIC proxy outbound instead", cfg.CovertMode)
	default:
		return fmt.Errorf("unsupported covert mode %q", cfg.CovertMode)
	}
	return nil
}

func redactEvasionSecret(secret string) string {
	if secret == "" {
		return ""
	}
	return redactedEvasionSecret
}

func redactedEvasionConfig(cfg EvasionConfig) EvasionConfig {
	cfg.CovertGsaKey = redactEvasionSecret(cfg.CovertGsaKey)
	cfg.CovertGdocsAccessToken = redactEvasionSecret(cfg.CovertGdocsAccessToken)
	cfg.CovertCfg.SshPass = redactEvasionSecret(cfg.CovertCfg.SshPass)
	cfg.CovertCfg.SshKey = redactEvasionSecret(cfg.CovertCfg.SshKey)
	cfg.CovertCfg.SshKeyPassphrase = redactEvasionSecret(cfg.CovertCfg.SshKeyPassphrase)
	cfg.CovertCfg.TuicToken = redactEvasionSecret(cfg.CovertCfg.TuicToken)
	return cfg
}

func (m *EvasionTunnelManager) GetRedactedConfig() EvasionConfig {
	return redactedEvasionConfig(m.GetConfig())
}

func (m *EvasionTunnelManager) RestoreRedactedSecrets(cfg EvasionConfig) EvasionConfig {
	current := m.GetConfig()
	if cfg.CovertGsaKey == redactedEvasionSecret {
		cfg.CovertGsaKey = current.CovertGsaKey
	}
	if cfg.CovertGdocsAccessToken == redactedEvasionSecret {
		cfg.CovertGdocsAccessToken = current.CovertGdocsAccessToken
	}
	if cfg.CovertCfg.SshPass == redactedEvasionSecret {
		cfg.CovertCfg.SshPass = current.CovertCfg.SshPass
	}
	if cfg.CovertCfg.SshKey == redactedEvasionSecret {
		cfg.CovertCfg.SshKey = current.CovertCfg.SshKey
	}
	if cfg.CovertCfg.SshKeyPassphrase == redactedEvasionSecret {
		cfg.CovertCfg.SshKeyPassphrase = current.CovertCfg.SshKeyPassphrase
	}
	if cfg.CovertCfg.TuicToken == redactedEvasionSecret {
		cfg.CovertCfg.TuicToken = current.CovertCfg.TuicToken
	}
	return cfg
}
