package crypto

import (
	"crypto/rsa"
	"crypto/x509"
	"testing"
)

func TestCACertificateAndSigning(t *testing.T) {
	caCert, caKey, err := GenerateCACertificate()
	if err != nil {
		t.Fatalf("Failed to generate root CA: %v", err)
	}

	if !caCert.IsCA {
		t.Errorf("Expected generated certificate to be a CA")
	}

	der, leafKey, err := GenerateCert("test.example.com", caCert, caKey)
	if err != nil {
		t.Fatalf("Failed to sign leaf certificate: %v", err)
	}

	leafCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("Failed to parse signed leaf certificate: %v", err)
	}

	if leafCert.Subject.CommonName != "test.example.com" {
		t.Errorf("Expected CN 'test.example.com', got %q", leafCert.Subject.CommonName)
	}

	if leafKey.PublicKey.N.Cmp(leafCert.PublicKey.(*rsa.PublicKey).N) != 0 {
		t.Errorf("Keys do not match")
	}
}
