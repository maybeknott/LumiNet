package crypto

import (
	"bytes"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	// Skip on non-windows for now as stub is not implemented/doesn't work
	// In a real scenario, mock this for tests.

	secret := []byte("super-secret-password")

	encrypted, err := Encrypt(secret)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(secret, decrypted) {
		t.Errorf("Decrypted data does not match original: got %s, want %s", decrypted, secret)
	}
}
