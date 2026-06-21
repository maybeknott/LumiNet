package proxy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// HCToolsDecoder decodes .tut, .sks, and .tmt configuration payloads.
type HCToolsDecoder struct{}

var hcToolsPasswords = [][]byte{
	[]byte("fubvx788b46v"),      // .tut
	[]byte("dyv35224nossas!!"),  // .sks
	[]byte("fubvx788B4mev"),     // .tmt
}

func (d *HCToolsDecoder) CanDecode(data []byte) bool {
	s := strings.TrimSpace(string(data))
	// HCTools format is salt.iv.encrypted where all three are base64 encoded strings
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return false
	}
	// Check if all parts are valid base64
	for _, p := range parts {
		if _, err := base64.StdEncoding.DecodeString(p); err != nil {
			return false
		}
	}
	return true
}

func (d *HCToolsDecoder) Decode(data []byte) (*ProxyConfig, error) {
	s := strings.TrimSpace(string(data))
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid hctools layout, must have 3 dot-separated parts")
	}

	salt, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode salt: %w", err)
	}

	iv, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode iv: %w", err)
	}

	encrypted, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	if len(encrypted) < 16 {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Try all known passwords
	var decrypted []byte
	var decryptErr error = fmt.Errorf("no passwords matching")

	for _, pass := range hcToolsPasswords {
		key := pbkdf2.Key(pass, salt, 1000, 32, sha256.New)

		block, err := aes.NewCipher(key)
		if err != nil {
			continue
		}

		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			continue
		}

		decrypted, err = aesgcm.Open(nil, iv, encrypted, nil)
		if err == nil {
			decryptErr = nil
			break
		} else {
			decryptErr = err
		}
	}

	if decryptErr != nil {
		return nil, fmt.Errorf("failed to decrypt using any HCTools password: %w", decryptErr)
	}

	decryptedStr := strings.TrimSpace(string(decrypted))

	// The decrypted content can be a JSON configuration or standard URI.
	if strings.Contains(decryptedStr, "://") {
		return ParseProxyURI(decryptedStr)
	}

	// Try to parse as JSON config
	var cfg ProxyConfig
	if err := json.Unmarshal([]byte(decryptedStr), &cfg); err == nil {
		return &cfg, nil
	}

	// Fallback to parsing decrypted content as proxy config URI if standard format
	return ParseProxyURI(decryptedStr)
}
