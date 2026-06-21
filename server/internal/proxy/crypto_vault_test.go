package proxy

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCryptoVaultLifecycle(t *testing.T) {
	// Setup temporary vault file
	tmpDir, err := os.MkdirTemp("", "vault-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	vaultPath := filepath.Join(tmpDir, "credentials.safe")
	salt := []byte("test-vault-salt-value")
	password := "master-secret-password-123"

	vault := NewCryptoVault(vaultPath, salt)

	// Create test credentials (one active, one expired)
	creds := []VaultCredential{
		{
			ID:        "node-1",
			Username:  "user1",
			Password:  "pass1",
			Metadata:  "meta1",
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(1 * time.Hour), // active
		},
		{
			ID:        "node-2",
			Username:  "user2",
			Password:  "pass2",
			Metadata:  "meta2",
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(-1 * time.Hour), // expired
		},
	}

	// 1. Assert Save
	if err := vault.Save(password, creds); err != nil {
		t.Fatalf("failed to save vault: %v", err)
	}

	// Verify file was written
	if _, err := os.Stat(vaultPath); os.IsNotExist(err) {
		t.Fatalf("expected vault file to exist at %s", vaultPath)
	}

	// 2. Assert Load with correct password
	loaded, err := vault.Load(password)
	if err != nil {
		t.Fatalf("failed to load vault: %v", err)
	}

	if len(loaded) != 2 {
		t.Errorf("expected 2 credentials loaded, got %d", len(loaded))
	}

	if loaded[0].Username != "user1" || loaded[0].Password != "pass1" {
		t.Errorf("incorrect credential contents: %+v", loaded[0])
	}

	// 3. Assert Load with wrong password fails
	_, err = vault.Load("incorrect-password")
	if err == nil {
		t.Errorf("expected error when loading with incorrect password, got nil")
	}

	// 4. Assert active credentials filters out expired records
	active, err := vault.GetActiveCredentials(password)
	if err != nil {
		t.Fatalf("failed to load active credentials: %v", err)
	}

	if len(active) != 1 {
		t.Errorf("expected 1 active credential, got %d", len(active))
	}

	if active[0].ID != "node-1" {
		t.Errorf("expected node-1 to be the only active credential, got %s", active[0].ID)
	}

	// 5. Assert Key Rotation (RotateKey)
	newPassword := "brand-new-secret-password-456"
	if err := vault.RotateKey(password, newPassword); err != nil {
		t.Fatalf("key rotation failed: %v", err)
	}

	// Verify loading with old password fails
	_, err = vault.Load(password)
	if err == nil {
		t.Errorf("expected load to fail with old password after rotation")
	}

	// Verify loading with new password succeeds
	rotated, err := vault.Load(newPassword)
	if err != nil {
		t.Fatalf("failed to load vault with new password: %v", err)
	}

	if len(rotated) != 2 {
		t.Errorf("expected 2 credentials loaded after rotation, got %d", len(rotated))
	}
}

func TestNaiveAuthVaultIntegration(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "naive-vault-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	vaultPath := filepath.Join(tmpDir, "naive.safe")
	password := "master-naive-key"

	outbounds := []NaiveOutbound{
		{
			Server:   "proxy.corp.net",
			Port:     8443,
			Username: "admin",
			Password: "secure-naive-password",
		},
	}

	// Save using NaiveAuth integration helper
	if err := SaveNaiveOutboundCredentials(vaultPath, password, outbounds); err != nil {
		t.Fatalf("failed to save naive credentials: %v", err)
	}

	// Load back
	loaded, err := LoadNaiveOutboundCredentials(vaultPath, password)
	if err != nil {
		t.Fatalf("failed to load naive credentials: %v", err)
	}

	if len(loaded) != 1 {
		t.Fatalf("expected 1 credential loaded, got %d", len(loaded))
	}

	if loaded[0].Server != "proxy.corp.net" || loaded[0].Port != 8443 || loaded[0].Username != "admin" {
		t.Errorf("loaded credentials mismatch: %+v", loaded[0])
	}
}

func TestZeroMemory(t *testing.T) {
	b := []byte("super-sensitive-raw-key-bytes-123456")
	zeroMemory(b)
	for i, val := range b {
		if val != 0 {
			t.Errorf("index %d was not zeroed, got %d", i, val)
		}
	}
}

type dummyCipher struct{}

func (d *dummyCipher) Encrypt(key, plaintext []byte) ([]byte, error) {
	return append([]byte("dummy-encrypted-"), plaintext...), nil
}

func (d *dummyCipher) Decrypt(key, ciphertext []byte) ([]byte, error) {
	if !bytes.HasPrefix(ciphertext, []byte("dummy-encrypted-")) {
		return nil, errors.New("invalid signature")
	}
	return ciphertext[len("dummy-encrypted-"):], nil
}

func TestFFIFallbackExecution(t *testing.T) {
	// Setup FFI mock instance
	opensslCipherInstance = &dummyCipher{}
	defer func() { opensslCipherInstance = nil }()

	key := sha256.Sum256([]byte("secret-key"))
	plaintext := []byte("payload data")

	ciphertext, err := encryptGCM(key[:], plaintext)
	if err != nil {
		t.Fatalf("FFI encrypt failed: %v", err)
	}

	if !bytes.HasPrefix(ciphertext, []byte("dummy-encrypted-")) {
		t.Errorf("expected cipher to use FFI dummy instance")
	}

	decrypted, err := decryptGCM(key[:], ciphertext)
	if err != nil {
		t.Fatalf("FFI decrypt failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("FFI decrypt output mismatch")
	}
}
