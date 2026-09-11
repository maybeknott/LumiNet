package security

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// PinningPolicy defines the enforcement level for certificate pinning.
type PinningPolicy string

const (
	PolicyStrict  PinningPolicy = "strict"
	PolicyLenient PinningPolicy = "lenient"
	PolicyOff     PinningPolicy = "off"
)

// CertPin holds certificate fingerprint and SPKI identification.
type CertPin struct {
	Subject        string `json:"subject"`
	Issuer         string `json:"issuer"`
	CertSHA256     string `json:"certSha256"`
	SPKISHA256     string `json:"spkiSha256"`
	NotAfterMillis int64  `json:"notAfterMillis"`
}

// PinningConfig specifies pinning expectations and policies.
type PinningConfig struct {
	ProfileID        string        `json:"profileId"`
	LeafPins         []string      `json:"leafPins"`
	IntermediatePins []string      `json:"intermediatePins"`
	BackupPins       []string      `json:"backupPins"`
	ExpiresAtMillis  int64         `json:"expiresAtMillis"`
	Policy           PinningPolicy `json:"policy"`
}

// PinStatus represents the result of evaluating certificates against pins.
type PinStatus string

const (
	StatusOk                 PinStatus = "ok"
	StatusMismatch           PinStatus = "mismatch"
	StatusNoPeerCertificates PinStatus = "no_peer_certificates"
	StatusExpired            PinStatus = "expired"
	StatusDisabled           PinStatus = "disabled"
)

// PinResult details the outcome of certificate verification.
type PinResult struct {
	Status   PinStatus
	Matched  string
	Expected []string
	Actual   string
	Err      error
}

// NormalizePin standardizes a hex SHA-256 pin string (lowercase, stripped colons and whitespace).
func NormalizePin(raw string) string {
	clean := strings.ToLower(strings.TrimSpace(raw))
	clean = strings.ReplaceAll(clean, ":", "")
	clean = strings.ReplaceAll(clean, " ", "")
	clean = strings.ReplaceAll(clean, "-", "")
	return clean
}

// ComputeCertPin extracts Subject, Issuer, DER SHA-256, and SPKI SHA-256 from an X.509 certificate.
func ComputeCertPin(cert *x509.Certificate) *CertPin {
	if cert == nil {
		return nil
	}

	certHash := sha256.Sum256(cert.Raw)
	certHex := hex.EncodeToString(certHash[:])

	spkiHash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	spkiHex := hex.EncodeToString(spkiHash[:])

	return &CertPin{
		Subject:        cert.Subject.String(),
		Issuer:         cert.Issuer.String(),
		CertSHA256:     certHex,
		SPKISHA256:     spkiHex,
		NotAfterMillis: cert.NotAfter.UnixMilli(),
	}
}

// VerifyPeerCertificates evaluates a peer certificate chain against a PinningConfig.
func VerifyPeerCertificates(rawCerts [][]byte, cfg *PinningConfig, now time.Time) PinResult {
	if cfg == nil || cfg.Policy == PolicyOff {
		return PinResult{Status: StatusDisabled}
	}

	if cfg.ExpiresAtMillis > 0 && now.UnixMilli() > cfg.ExpiresAtMillis {
		if cfg.Policy == PolicyStrict {
			return PinResult{
				Status: StatusExpired,
				Err:    errors.New("pinning configuration has expired in strict mode"),
			}
		}
		// In lenient mode, expired pinning fails open with warning
		return PinResult{Status: StatusDisabled}
	}

	if len(rawCerts) == 0 {
		return PinResult{
			Status: StatusNoPeerCertificates,
			Err:    errors.New("no peer certificates presented"),
		}
	}

	// Parse presented certificates
	var certs []*x509.Certificate
	for _, raw := range rawCerts {
		c, err := x509.ParseCertificate(raw)
		if err == nil && c != nil {
			certs = append(certs, c)
		}
	}

	if len(certs) == 0 {
		return PinResult{
			Status: StatusNoPeerCertificates,
			Err:    errors.New("failed to parse presented peer certificates"),
		}
	}

	// Prepare expected pin sets
	leafExpected := make(map[string]bool)
	var allExpected []string
	for _, p := range cfg.LeafPins {
		norm := NormalizePin(p)
		if norm != "" {
			leafExpected[norm] = true
			allExpected = append(allExpected, norm)
		}
	}

	intermediateExpected := make(map[string]bool)
	for _, p := range cfg.IntermediatePins {
		norm := NormalizePin(p)
		if norm != "" {
			intermediateExpected[norm] = true
			allExpected = append(allExpected, norm)
		}
	}

	backupExpected := make(map[string]bool)
	for _, p := range cfg.BackupPins {
		norm := NormalizePin(p)
		if norm != "" {
			backupExpected[norm] = true
			allExpected = append(allExpected, norm)
		}
	}

	// 1. Check leaf certificate (certs[0])
	leafPin := ComputeCertPin(certs[0])
	actualLeafSpki := leafPin.SPKISHA256
	actualLeafCert := leafPin.CertSHA256

	if leafExpected[actualLeafSpki] {
		return PinResult{Status: StatusOk, Matched: actualLeafSpki}
	}
	if leafExpected[actualLeafCert] {
		return PinResult{Status: StatusOk, Matched: actualLeafCert}
	}

	// 2. Check intermediates if present
	for _, intermediate := range certs[1:] {
		intPin := ComputeCertPin(intermediate)
		if intermediateExpected[intPin.SPKISHA256] {
			return PinResult{Status: StatusOk, Matched: intPin.SPKISHA256}
		}
		if intermediateExpected[intPin.CertSHA256] {
			return PinResult{Status: StatusOk, Matched: intPin.CertSHA256}
		}
	}

	// 3. Check backup pins across all certificates in chain (key rotation)
	for _, cert := range certs {
		p := ComputeCertPin(cert)
		if backupExpected[p.SPKISHA256] {
			return PinResult{Status: StatusOk, Matched: p.SPKISHA256}
		}
		if backupExpected[p.CertSHA256] {
			return PinResult{Status: StatusOk, Matched: p.CertSHA256}
		}
	}

	// Mismatch
	err := fmt.Errorf("certificate pin mismatch: observed %s", actualLeafSpki)
	if cfg.Policy == PolicyLenient {
		// Log warning, allow connection in lenient mode
		return PinResult{
			Status:   StatusMismatch,
			Expected: allExpected,
			Actual:   actualLeafSpki,
			Err:      nil, // Non-fatal in lenient mode
		}
	}

	return PinResult{
		Status:   StatusMismatch,
		Expected: allExpected,
		Actual:   actualLeafSpki,
		Err:      err,
	}
}
