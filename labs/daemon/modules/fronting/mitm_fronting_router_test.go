package fronting

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
)

func TestMatchSANPattern(t *testing.T) {
	// Exact matches
	if !MatchSANPattern("www.google.com", "www.google.com") {
		t.Errorf("expected exact match to succeed")
	}
	if !MatchSANPattern("WWW.GOOGLE.COM", "www.google.com") {
		t.Errorf("expected case-insensitive exact match to succeed")
	}

	// Wildcards
	if !MatchSANPattern("api.instagram.com", "*.instagram.com") {
		t.Errorf("expected wildcard match to succeed")
	}
	if !MatchSANPattern("rr1.googlevideo.com", "*.googlevideo.com") {
		t.Errorf("expected wildcard match to succeed")
	}

	// Non-matches
	if MatchSANPattern("deep.sub.api.instagram.com", "*.instagram.com") {
		t.Errorf("wildcard should not match multi-level subdomain")
	}
	if MatchSANPattern("fakeinstagram.com", "*.instagram.com") {
		t.Errorf("wildcard should not match non-subdomain prefix")
	}
	if MatchSANPattern("evil.com", "*.google.com") {
		t.Errorf("wildcard should not match completely different domain")
	}
}

func TestVerifyX509Certificate(t *testing.T) {
	cert := &x509.Certificate{
		Subject:  pkix.Name{CommonName: "edge.fastly.net"},
		DNSNames: []string{"fastly.com", "reddit.com", "*.reddit.com", "github.githubassets.com"},
	}

	allowed := []string{"*.reddit.com", "github.githubassets.com"}
	if err := VerifyX509Certificate(cert, allowed); err != nil {
		t.Fatalf("expected valid cert verification, got %v", err)
	}

	disallowed := []string{"*.google.com", "youtube.com"}
	if err := VerifyX509Certificate(cert, disallowed); err == nil {
		t.Fatalf("expected cert verification failure for unmatched SANs")
	}
}

func TestMitmFrontingEngineRouting(t *testing.T) {
	engine := NewMitmFrontingEngine(11666, 11777)

	// Ingress: Direct bypass
	resDirect := engine.RouteIngress("site.ir", false)
	if resDirect.Action != ActionDirect {
		t.Errorf("expected ActionDirect, got %s", resDirect.Action)
	}

	// Ingress: Video traffic -> H1.1 inbound (11666)
	resVideo := engine.RouteIngress("sn-4g5edn6s.googlevideo.com", false)
	if resVideo.Action != ActionRedirectToMitm || resVideo.RedirectPort != 11666 {
		t.Errorf("expected Redirect to 11666 for video, got %v", resVideo)
	}

	// Ingress: Frontable web service -> H2/H1.1 inbound (11777)
	resMeta := engine.RouteIngress("www.whatsapp.com", false)
	if resMeta.Action != ActionRedirectToMitm || resMeta.RedirectPort != 11777 {
		t.Errorf("expected Redirect to 11777 for whatsapp, got %v", resMeta)
	}

	// Ingress: Unknown domain -> Direct
	resUnknown := engine.RouteIngress("custom-internal-host.com", false)
	if resUnknown.Action != ActionDirect {
		t.Errorf("expected ActionDirect for unknown domain, got %s", resUnknown.Action)
	}

	// Decrypted Egress: Video on H1.1 port -> Repack with google.com SNI and H1.1 ALPN
	egressVideo := engine.RouteDecryptedEgress("r1.googlevideo.com", 11666)
	if egressVideo.Action != ActionRepackFronted || egressVideo.Repack == nil {
		t.Fatalf("expected ActionRepackFronted, got %v", egressVideo)
	}
	if egressVideo.Repack.FrontedSNI != "www.google.com" || egressVideo.Repack.ALPN != AlpnHttp11 {
		t.Errorf("unexpected video repack config: %v", egressVideo.Repack)
	}

	// Decrypted Egress: Non-video on H1.1 port -> BLOCK
	egressBlocked := engine.RouteDecryptedEgress("www.instagram.com", 11666)
	if egressBlocked.Action != ActionBlock {
		t.Errorf("expected ActionBlock for non-video on H1.1 port, got %s", egressBlocked.Action)
	}

	// Decrypted Egress: Meta on H2/H1.1 port -> Repack with www.microsoft.com SNI
	egressMeta := engine.RouteDecryptedEgress("graph.instagram.com", 11777)
	if egressMeta.Action != ActionRepackFronted || egressMeta.Repack == nil {
		t.Fatalf("expected ActionRepackFronted, got %v", egressMeta)
	}
	if egressMeta.Repack.FrontedSNI != "www.microsoft.com" || egressMeta.Repack.ALPN != AlpnHttp2And11 {
		t.Errorf("unexpected meta repack config: %v", egressMeta.Repack)
	}

	// Decrypted Egress: Fastly on H2/H1.1 port -> Repack with github.githubassets.com SNI
	egressFastly := engine.RouteDecryptedEgress("reddit.com", 11777)
	if egressFastly.Action != ActionRepackFronted || egressFastly.Repack == nil {
		t.Fatalf("expected ActionRepackFronted, got %v", egressFastly)
	}
	if egressFastly.Repack.FrontedSNI != "github.githubassets.com" || egressFastly.Repack.RedirectTarget != "github.githubassets.com:443" {
		t.Errorf("unexpected fastly repack config: %v", egressFastly.Repack)
	}
}
