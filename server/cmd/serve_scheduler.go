package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/maybeknott/luminet/internal/api"
	"github.com/maybeknott/luminet/internal/bridge"
	"github.com/maybeknott/luminet/internal/config"
	"github.com/maybeknott/luminet/internal/notifier"
	"github.com/maybeknott/luminet/internal/scheduler"
)

// initScheduler configures and registers background automation jobs
func initScheduler(cfg *config.Config) (*scheduler.Runner, error) {
	runner := scheduler.NewRunner()

	if cfg.DDNS.Enabled {
		err := runner.Register(&scheduler.Job{
			ID:       "ddns_update",
			Name:     "Automatic DDNS Update",
			Interval: time.Duration(cfg.DDNS.Interval) * time.Minute,
			RunFunc: func(ctx context.Context) error {
				fmt.Printf("[%s] Running scheduled DDNS update for %s\n", time.Now().Format(time.RFC3339), cfg.DDNS.Domain)
				_, err := api.RunDDNSUpdate(ctx, cfg.DDNS.Provider, cfg.DDNS.Token, cfg.DDNS.Domain)
				return err
			},
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to register DDNS job: %v\n", err)
		}
	}

	// Periodic Network Health Audit (Runs every 5 minutes in background)
	err := runner.Register(&scheduler.Job{
		ID:       "network_health_audit",
		Name:     "Periodic Network Health Audit",
		Interval: 5 * time.Minute,
		RunFunc: func(ctx context.Context) error {
			fmt.Printf("[%s] Running scheduled network health audit...\n", time.Now().Format(time.RFC3339))

			// 1. DNS Poisoning check (google.com UDP vs. DoH comparison)
			dnsServer := "1.1.1.1"
			dohServer := "https://cloudflare-dns.com/dns-query"
			targetDomain := "google.com"

			udpRes, udpErr := bridge.DnsResolve(dnsServer, targetDomain, "A")
			dohRes, dohErr := bridge.DnsResolve(dohServer, targetDomain, "A")

			dnsPoisoned := false
			if udpErr == nil && udpRes.Success && dohErr == nil && dohRes.Success && len(udpRes.Records) > 0 && len(dohRes.Records) > 0 {
				intersect := false
				for _, u := range udpRes.Records {
					for _, d := range dohRes.Records {
						if u.Value == d.Value {
							intersect = true
							break
						}
					}
				}
				if !intersect {
					dnsPoisoned = true
				}
			}

			// 2. SSL/TLS MITM check
			mitmDetected := false
			tlsInfo, tlsErr := bridge.TlsHandshakeWithSni("google.com", 443, "google.com", 3000)
			if tlsErr == nil && tlsInfo != nil {
				issuer := strings.ToLower(tlsInfo.CertIssuer)
				if strings.Contains(issuer, "fortinet") || strings.Contains(issuer, "zscaler") || strings.Contains(issuer, "sophos") {
					mitmDetected = true
				}
			}

			// 3. Dispatch alert if any hazard is detected
			if dnsPoisoned || mitmDetected {
				alertNotifier := notifier.NewNotifier("")
				var title, msg string
				if dnsPoisoned && mitmDetected {
					title = "LumiNet: Severe Network Hijacking!"
					msg = "Both DNS Poisoning and active SSL/TLS MITM interception were detected on this network node."
				} else if dnsPoisoned {
					title = "LumiNet: DNS Poisoning Detected!"
					msg = "Plaintext UDP DNS responses deviate from secure DoH consensus. Local DNS is hijacked."
				} else {
					title = "LumiNet: SSL Interception Detected!"
					msg = "Unrecognized/Interception CA found on HTTPS handshake. Active MITM firewall in place."
				}

				_ = alertNotifier.SendDesktop(ctx, &notifier.Alert{
					Title:    title,
					Message:  msg,
					Severity: notifier.SeverityCritical,
				})
			}
			return nil
		},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to register Network Health Audit job: %v\n", err)
	}

	return runner, nil
}
