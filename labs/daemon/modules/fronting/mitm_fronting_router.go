// Package fronting provides domain-fronting, TLS interception routing, and multi-SAN validation.
// Conforms strictly to §8 structural rules with zero upstream vendor prefixes.

package fronting

import (
	"crypto/x509"
	"fmt"
	"strings"
)

// MitmAlpn specifies negotiated application-layer protocols.
type MitmAlpn string

const (
	AlpnHttp11    MitmAlpn = "http/1.1"
	AlpnHttp2     MitmAlpn = "h2"
	AlpnHttp2And11 MitmAlpn = "h2,http/1.1"
)

func (a MitmAlpn) Strings() []string {
	switch a {
	case AlpnHttp11:
		return []string{"http/1.1"}
	case AlpnHttp2:
		return []string{"h2"}
	case AlpnHttp2And11:
		return []string{"h2", "http/1.1"}
	default:
		return []string{"http/1.1"}
	}
}

// FrontingActionType defines the decision for a connection.
type FrontingActionType string

const (
	ActionDirect         FrontingActionType = "DIRECT"
	ActionBlock          FrontingActionType = "BLOCK"
	ActionRedirectToMitm FrontingActionType = "REDIRECT_MITM"
	ActionRepackFronted  FrontingActionType = "REPACK_FRONTED"
)

// FrontingRepackConfig defines upstream TLS parameters for fronted connections.
type FrontingRepackConfig struct {
	FrontedSNI     string   `json:"fronted_sni"`
	AllowedSANs    []string `json:"allowed_sans"`
	RedirectTarget string   `json:"redirect_target,omitempty"`
	ALPN           MitmAlpn `json:"alpn"`
	Fingerprint    string   `json:"fingerprint"`
}

// FrontingRouteResult encapsulates the routing decision.
type FrontingRouteResult struct {
	Action       FrontingActionType    `json:"action"`
	RedirectPort int                   `json:"redirect_port,omitempty"`
	Repack       *FrontingRepackConfig `json:"repack,omitempty"`
}

// FrontingProfile defines fronting SNI and allowed certificate SAN pool.
type FrontingProfile struct {
	Name           string
	FrontedSNI     string
	AllowedSANs    []string
	RedirectTarget string
	ALPN           MitmAlpn
}

// DefaultFrontingProfiles provides standard configurations for Google, Fastly, and Meta.
func DefaultFrontingProfiles() []FrontingProfile {
	return []FrontingProfile{
		{
			Name:       "google-video",
			FrontedSNI: "www.google.com",
			AllowedSANs: []string{
				"www.google.com",
				"*.google.com",
				"dns.google",
				"www.googlevideo.com",
				"*.googlevideo.com",
				"www.youtube.com",
				"*.youtube.com",
			},
			ALPN: AlpnHttp11,
		},
		{
			Name:       "google",
			FrontedSNI: "www.google.com",
			AllowedSANs: []string{
				"www.google.com",
				"*.google.com",
				"dns.google",
				"www.googlevideo.com",
				"*.googlevideo.com",
				"www.youtube.com",
				"*.youtube.com",
			},
			ALPN: AlpnHttp2And11,
		},
		{
			Name:           "fastly",
			FrontedSNI:     "github.githubassets.com",
			RedirectTarget: "github.githubassets.com:443",
			AllowedSANs: []string{
				"github.githubassets.com",
				"githubassets.com",
				"*.githubassets.com",
				"github.com",
				"*.github.com",
				"fastly.com",
				"*.fastly.com",
				"reddit.com",
				"*.reddit.com",
				"pypi.org",
				"*.python.org",
			},
			ALPN: AlpnHttp2And11,
		},
		{
			Name:       "meta",
			FrontedSNI: "www.microsoft.com",
			AllowedSANs: []string{
				"www.whatsapp.com",
				"*.whatsapp.com",
				"*.whatsapp.net",
				"www.facebook.com",
				"*.facebook.com",
				"*.fbcdn.net",
				"www.instagram.com",
				"*.instagram.com",
				"*.cdninstagram.com",
				"*.meta.com",
			},
			ALPN: AlpnHttp2And11,
		},
	}
}

// MitmFrontingEngine manages ingress redirection and decrypted egress repacking.
type MitmFrontingEngine struct {
	H11Port       int
	H211Port      int
	Profiles      []FrontingProfile
	DirectDomains []string
}

// NewMitmFrontingEngine creates an initialized engine with default ports and profiles.
func NewMitmFrontingEngine(h11Port, h211Port int) *MitmFrontingEngine {
	if h11Port <= 0 {
		h11Port = 11666
	}
	if h211Port <= 0 {
		h211Port = 11777
	}
	return &MitmFrontingEngine{
		H11Port:  h11Port,
		H211Port: h211Port,
		Profiles: DefaultFrontingProfiles(),
		DirectDomains: []string{
			".ir",
			"geosite:private",
			"geosite:category-ir",
		},
	}
}

// RouteIngress determines whether initial client connection is bypassed or intercepted.
func (e *MitmFrontingEngine) RouteIngress(domain string, isVideo bool) FrontingRouteResult {
	d := strings.ToLower(strings.TrimSpace(domain))

	// 1. Direct bypass check
	for _, dir := range e.DirectDomains {
		if strings.HasPrefix(dir, ".") && strings.HasSuffix(d, dir) {
			return FrontingRouteResult{Action: ActionDirect}
		}
	}

	// 2. Video traffic routes to H1.1 decryption inbound
	if isVideo || strings.Contains(d, "googlevideo.com") {
		return FrontingRouteResult{
			Action:       ActionRedirectToMitm,
			RedirectPort: e.H11Port,
		}
	}

	// 3. Supported frontable domains route to H2/H1.1 decryption inbound
	if e.isFrontableDomain(d) {
		return FrontingRouteResult{
			Action:       ActionRedirectToMitm,
			RedirectPort: e.H211Port,
		}
	}

	// 4. Default to direct connection
	return FrontingRouteResult{Action: ActionDirect}
}

// RouteDecryptedEgress determines outbound TLS parameters for traffic on decrypt inbounds.
func (e *MitmFrontingEngine) RouteDecryptedEgress(domain string, inboundPort int) FrontingRouteResult {
	d := strings.ToLower(strings.TrimSpace(domain))

	// If connection arrived via H1.1 port (video streaming)
	if inboundPort == e.H11Port {
		if strings.Contains(d, "googlevideo.com") {
			prof := e.findProfile("google-video")
			return FrontingRouteResult{
				Action: ActionRepackFronted,
				Repack: &FrontingRepackConfig{
					FrontedSNI:     prof.FrontedSNI,
					AllowedSANs:    prof.AllowedSANs,
					RedirectTarget: prof.RedirectTarget,
					ALPN:           prof.ALPN,
					Fingerprint:    "chrome",
				},
			}
		}
		// Non-video traffic on H1.1 port is strictly blocked
		return FrontingRouteResult{Action: ActionBlock}
	}

	// If connection arrived via H2/H1.1 port
	if inboundPort == e.H211Port {
		if strings.Contains(d, "google") || strings.Contains(d, "youtube") {
			prof := e.findProfile("google")
			return FrontingRouteResult{
				Action: ActionRepackFronted,
				Repack: &FrontingRepackConfig{
					FrontedSNI:     prof.FrontedSNI,
					AllowedSANs:    prof.AllowedSANs,
					RedirectTarget: prof.RedirectTarget,
					ALPN:           prof.ALPN,
					Fingerprint:    "chrome",
				},
			}
		}

		if strings.Contains(d, "fastly") || strings.Contains(d, "reddit") || strings.Contains(d, "github") || strings.Contains(d, "pypi") {
			prof := e.findProfile("fastly")
			return FrontingRouteResult{
				Action: ActionRepackFronted,
				Repack: &FrontingRepackConfig{
					FrontedSNI:     prof.FrontedSNI,
					AllowedSANs:    prof.AllowedSANs,
					RedirectTarget: prof.RedirectTarget,
					ALPN:           prof.ALPN,
					Fingerprint:    "chrome",
				},
			}
		}

		if strings.Contains(d, "meta") || strings.Contains(d, "facebook") || strings.Contains(d, "instagram") || strings.Contains(d, "whatsapp") {
			prof := e.findProfile("meta")
			return FrontingRouteResult{
				Action: ActionRepackFronted,
				Repack: &FrontingRepackConfig{
					FrontedSNI:     prof.FrontedSNI,
					AllowedSANs:    prof.AllowedSANs,
					RedirectTarget: prof.RedirectTarget,
					ALPN:           prof.ALPN,
					Fingerprint:    "chrome",
				},
			}
		}

		// Block unmatched domains to prevent open relay abuse
		return FrontingRouteResult{Action: ActionBlock}
	}

	return FrontingRouteResult{Action: ActionDirect}
}

// VerifyPeerCertificateSANs checks whether any presented SAN satisfies allowed SAN patterns.
func VerifyPeerCertificateSANs(presentedSANs []string, allowedSANs []string) bool {
	for _, presented := range presentedSANs {
		for _, allowed := range allowedSANs {
			if MatchSANPattern(presented, allowed) {
				return true
			}
		}
	}
	return false
}

// VerifyX509Certificate verifies leaf x509 certificate DNSNames against allowed SAN patterns.
func VerifyX509Certificate(cert *x509.Certificate, allowedSANs []string) error {
	if cert == nil {
		return fmt.Errorf("nil peer certificate")
	}
	var allNames []string
	if cert.Subject.CommonName != "" {
		allNames = append(allNames, cert.Subject.CommonName)
	}
	allNames = append(allNames, cert.DNSNames...)

	if !VerifyPeerCertificateSANs(allNames, allowedSANs) {
		return fmt.Errorf("peer certificate does not match any allowed fronting SANs: %v", allNames)
	}
	return nil
}

// MatchSANPattern checks exact and RFC 6125 wildcard matches (*.example.com).
func MatchSANPattern(presented string, pattern string) bool {
	pres := strings.ToLower(strings.TrimSpace(presented))
	pat := strings.ToLower(strings.TrimSpace(pattern))

	if pres == pat {
		return true
	}

	if strings.HasPrefix(pat, "*.") {
		suffix := pat[2:]
		if strings.HasSuffix(pres, suffix) && len(pres) > len(suffix) {
			prefix := pres[:len(pres)-len(suffix)]
			if strings.HasSuffix(prefix, ".") {
				sub := prefix[:len(prefix)-1]
				if !strings.Contains(sub, ".") {
					return true
				}
			}
		}
	}
	return false
}

func (e *MitmFrontingEngine) isFrontableDomain(domain string) bool {
	for _, prof := range e.Profiles {
		for _, allowed := range prof.AllowedSANs {
			if MatchSANPattern(domain, allowed) {
				return true
			}
		}
	}
	return false
}

func (e *MitmFrontingEngine) findProfile(name string) FrontingProfile {
	for _, prof := range e.Profiles {
		if prof.Name == name {
			return prof
		}
	}
	return e.Profiles[0]
}
