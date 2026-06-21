package proxy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

// VaultCredential represents a credential record stored in the encrypted safe.
type VaultCredential struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	Password  string    `json:"password"`
	Metadata  string    `json:"metadata"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// CryptoVault coordinates secure, zero-trust storage of credentials on disk.
type CryptoVault struct {
	filePath string
	salt     []byte
}

// NewCryptoVault creates a new CryptoVault instance with a specified salt.
func NewCryptoVault(filePath string, salt []byte) *CryptoVault {
	// Create a copy of the salt to ensure it's not mutated
	saltCopy := make([]byte, len(salt))
	copy(saltCopy, salt)
	return &CryptoVault{
		filePath: filePath,
		salt:     saltCopy,
	}
}

// Save encrypts and persists credentials using AES-256-GCM.
func (v *CryptoVault) Save(password string, creds []VaultCredential) error {
	plaintext, err := json.Marshal(creds)
	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %w", err)
	}

	// Derive AES-256 key using PBKDF2 + SHA-256
	key := pbkdf2.Key([]byte(password), v.salt, 10000, 32, sha256.New)
	defer zeroMemory(key) // Ensure raw key parameters are zeroed immediately

	// Encrypt using AES-GCM
	ciphertext, err := encryptGCM(key, plaintext)
	if err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}

	return os.WriteFile(v.filePath, ciphertext, 0600)
}

// Load decrypts and retrieves credentials from disk.
func (v *CryptoVault) Load(password string) ([]VaultCredential, error) {
	ciphertext, err := os.ReadFile(v.filePath)
	if err != nil {
		return nil, err
	}

	// Derive AES-256 key using PBKDF2 + SHA-256
	key := pbkdf2.Key([]byte(password), v.salt, 10000, 32, sha256.New)
	defer zeroMemory(key) // Ensure raw key parameters are zeroed immediately

	plaintext, err := decryptGCM(key, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	var creds []VaultCredential
	if err := json.Unmarshal(plaintext, &creds); err != nil {
		return nil, fmt.Errorf("failed to unmarshal credentials: %w", err)
	}

	return creds, nil
}

// RotateKey re-encrypts the vault with a new master key/password.
func (v *CryptoVault) RotateKey(oldPassword, newPassword string) error {
	creds, err := v.Load(oldPassword)
	if err != nil {
		return fmt.Errorf("failed to load vault with old password: %w", err)
	}

	// Password validation border: Enforce constant-time verification using subtle compare
	if subtle.ConstantTimeCompare([]byte(oldPassword), []byte(newPassword)) == 1 {
		return errors.New("new password must be different from the old password")
	}

	return v.Save(newPassword, creds)
}

// GetActiveCredentials retrieves only credentials that have not expired.
func (v *CryptoVault) GetActiveCredentials(password string) ([]VaultCredential, error) {
	creds, err := v.Load(password)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	var active []VaultCredential
	for _, c := range creds {
		if c.ExpiresAt.IsZero() || c.ExpiresAt.After(now) {
			active = append(active, c)
		}
	}
	return active, nil
}

// Helper functions for AES-256-GCM
func encryptGCM(key, plaintext []byte) ([]byte, error) {
	// Attempt to use FFI OpenSSL fallback if available and initialized
	if opensslCipherInstance != nil {
		if ciphertext, err := opensslCipherInstance.Encrypt(key, plaintext); err == nil {
			return ciphertext, nil
		}
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func decryptGCM(key, ciphertext []byte) ([]byte, error) {
	// Attempt to use FFI OpenSSL fallback if available and initialized
	if opensslCipherInstance != nil {
		if plaintext, err := opensslCipherInstance.Decrypt(key, ciphertext); err == nil {
			return plaintext, nil
		}
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, encrypted := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// Zero out memory array to prevent core dump extraction
func zeroMemory(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// FallbackCipher defines the FFI-based cipher wrapper behavior.
type FallbackCipher interface {
	Encrypt(key, plaintext []byte) ([]byte, error)
	Decrypt(key, ciphertext []byte) ([]byte, error)
}

var opensslCipherInstance FallbackCipher
