package fronting

import "strings"

// FrontSNIPoolGoogle mirrors FRONT_SNI_POOL_GOOGLE from constants.py: the SNIs
// known to front Google-hosted Apps Script endpoints on new TLS handshakes.
var FrontSNIPoolGoogle = []string{
	"mail.google.com",
	"accounts.google.com",
	"www.google.com",
}

// DefaultCandidateIPs mirrors CANDIDATE_IPS: Google frontend addresses worth
// probing when script.google.com DNS resolution itself is poisoned.
var DefaultCandidateIPs = []string{
	"216.239.32.120", "216.239.34.120", "216.239.36.120", "216.239.38.120",
	"142.250.80.142", "142.250.80.138", "142.250.179.110", "142.250.185.110",
	"142.250.184.206", "142.250.190.238", "142.250.191.78", "172.217.1.206",
	"172.217.14.206", "172.217.16.142", "172.217.22.174", "172.217.164.110",
	"172.217.168.206", "172.217.169.206", "34.107.221.82", "142.251.32.110",
}

// BuildSNIPool normalises operator overrides and expands *.google.com fronts to
// the known-good pool, mirroring build_sni_pool in fronting_support.py.
func BuildSNIPool(frontDomain string, overrides []string) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, len(overrides)+3)
	add := func(host string) {
		host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
		if host == "" {
			return
		}
		if _, dup := seen[host]; dup {
			return
		}
		seen[host] = struct{}{}
		out = append(out, host)
	}
	for _, item := range overrides {
		add(item)
	}
	if len(out) > 0 {
		return out
	}
	front := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(frontDomain), "."))
	if strings.HasSuffix(front, ".google.com") || front == "google.com" {
		pool := append([]string(nil), FrontSNIPoolGoogle...)
		if front != "" {
			if _, dup := seen[front]; !dup {
				pool = append([]string{front}, pool...)
			}
		}
		return dedupe(pool)
	}
	if front != "" {
		return []string{front}
	}
	return []string{"www.google.com"}
}

func dedupe(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := in[:0]
	for _, v := range in {
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}
