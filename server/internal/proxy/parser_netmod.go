package proxy

import (
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"strings"
)

// NetModDecoder decodes NetMod VPN (.nm) config files.
type NetModDecoder struct{}

func (d *NetModDecoder) CanDecode(data []byte) bool {
	s := strings.TrimSpace(string(data))
	if strings.HasPrefix(s, "netmod://") || strings.HasPrefix(s, "nm://") {
		return true
	}
	// Also check if base64 decoding succeeds and length is a multiple of 16
	payload := s
	if idx := strings.Index(s, "://"); idx != -1 {
		payload = s[idx+3:]
	}
	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err == nil && len(decoded) > 0 && len(decoded)%16 == 0 {
		return true
	}
	return false
}

func (d *NetModDecoder) Decode(data []byte) (*ProxyConfig, error) {
	s := strings.TrimSpace(string(data))
	var prefix string
	var payload string

	if idx := strings.Index(s, "://"); idx != -1 {
		prefix = s[:idx]
		payload = s[idx+3:]
	} else {
		payload = s
	}

	// Try standard base64 decoding
	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		// Try URL-safe
		decoded, err = base64.URLEncoding.DecodeString(payload)
		if err != nil {
			return nil, fmt.Errorf("failed to decode netmod base64: %w", err)
		}
	}

	key := []byte("_netsyna_netmod_")
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	if len(decoded)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("invalid netmod cipher size, must be multiple of 16")
	}

	plaintext := make([]byte, len(decoded))
	for i := 0; i < len(decoded); i += block.BlockSize() {
		block.Decrypt(plaintext[i:i+block.BlockSize()], decoded[i:i+block.BlockSize()])
	}

	// Strip trailing null bytes
	decryptedStr := string(plaintext)
	decryptedStr = strings.TrimRight(decryptedStr, "\x00")
	// Also strip typical PKCS7 padding if present
	if len(decryptedStr) > 0 {
		lastByte := decryptedStr[len(decryptedStr)-1]
		if lastByte > 0 && lastByte <= 16 {
			padding := true
			for i := len(decryptedStr) - int(lastByte); i < len(decryptedStr); i++ {
				if decryptedStr[i] != lastByte {
					padding = false
					break
				}
			}
			if padding {
				decryptedStr = decryptedStr[:len(decryptedStr)-int(lastByte)]
			}
		}
	}

	decryptedStr = strings.TrimSpace(decryptedStr)

	// If original link had prefix, prepend it
	var uriToParse string
	if prefix != "" && !strings.Contains(decryptedStr, "://") {
		uriToParse = fmt.Sprintf("%s://%s", prefix, decryptedStr)
	} else {
		uriToParse = decryptedStr
	}

	cfg, err := ParseProxyURI(uriToParse)
	if err != nil {
		return nil, fmt.Errorf("failed to parse decrypted NetMod URI (%s): %w", uriToParse, err)
	}

	return cfg, nil
}
