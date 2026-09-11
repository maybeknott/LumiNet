package security

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func generateTestCert(t *testing.T, cn string) (*x509.Certificate, []byte) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey failed: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1001),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate failed: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate failed: %v", err)
	}

	return cert, der
}

func TestCertPinningFlow(t *testing.T) {
	cert, der := generateTestCert(t, "test.example.com")
	pin := ComputeCertPin(cert)

	if len(pin.CertSHA256) != 64 {
		t.Errorf("CertSHA256 length != 64, got %d", len(pin.CertSHA256))
	}
	if len(pin.SPKISHA256) != 64 {
		t.Errorf("SPKISHA256 length != 64, got %d", len(pin.SPKISHA256))
	}

	cfg := &PinningConfig{
		ProfileID: "prof-1",
		LeafPins:  []string{pin.SPKISHA256},
		Policy:    PolicyStrict,
	}

	res := VerifyPeerCertificates([][]byte{der}, cfg, time.Now())
	if res.Status != StatusOk {
		t.Fatalf("expected StatusOk, got %v: %v", res.Status, res.Err)
	}
	if res.Matched != pin.SPKISHA256 {
		t.Errorf("expected matched %s, got %s", pin.SPKISHA256, res.Matched)
	}

	// Mismatch test
	badCfg := &PinningConfig{
		ProfileID: "prof-1",
		LeafPins:  []string{"0000000000000000000000000000000000000000000000000000000000000000"},
		Policy:    PolicyStrict,
	}
	resBad := VerifyPeerCertificates([][]byte{der}, badCfg, time.Now())
	if resBad.Status != StatusMismatch || resBad.Err == nil {
		t.Fatalf("expected StatusMismatch with error, got %v", resBad.Status)
	}

	// Lenient policy test
	lenientCfg := &PinningConfig{
		ProfileID: "prof-1",
		LeafPins:  []string{"0000000000000000000000000000000000000000000000000000000000000000"},
		Policy:    PolicyLenient,
	}
	resLenient := VerifyPeerCertificates([][]byte{der}, lenientCfg, time.Now())
	if resLenient.Status != StatusMismatch || resLenient.Err != nil {
		t.Fatalf("expected StatusMismatch without error in lenient mode, got %v, err=%v", resLenient.Status, resLenient.Err)
	}
}
