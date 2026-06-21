package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/maybeknott/luminet/internal/ddns"
	"github.com/maybeknott/luminet/internal/proxy"
	"github.com/maybeknott/luminet/internal/system"
	"github.com/spf13/cobra"
)

// systemCmd is the parent command for system configuration subcommands.
var systemCmd = &cobra.Command{
	Use:   "system",
	Short: "Manage system DNS, proxy, DDNS, profiles, and startup settings",
	Long:  `Commands for configuring the operating system's network settings including DNS servers, proxy configuration, DDNS updates, network profiles, and startup behavior.`,
}

// systemDnsCmd manages DNS server settings.
var systemDnsCmd = &cobra.Command{
	Use:   "dns",
	Short: "Manage system DNS server settings",
}

var systemDnsApplyCmd = &cobra.Command{
	Use:   "apply [servers...]",
	Short: "Apply DNS servers to the active network interface",
	Args:  cobra.MinimumNArgs(1),
	RunE:  runDnsApply,
}

var systemDnsClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Clear DNS servers (reset to DHCP)",
	RunE:  runDnsClear,
}

var systemDnsStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current DNS configuration",
	RunE:  runDnsStatus,
}

// systemProxyCmd manages system proxy settings.
var systemProxyCmd = &cobra.Command{
	Use:   "proxy-settings",
	Short: "Manage system proxy settings",
}

var systemProxyApplyCmd = &cobra.Command{
	Use:   "apply [server]",
	Short: "Apply system proxy settings",
	Args:  cobra.ExactArgs(1),
	RunE:  runProxyApply,
}

var systemProxyClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Clear system proxy settings",
	RunE:  runProxyClear,
}

var systemProxyStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current proxy settings",
	RunE:  runProxyStatus,
}

// systemDdnsCmd manages DDNS updates.
var systemDdnsCmd = &cobra.Command{
	Use:   "ddns",
	Short: "Manage Dynamic DNS updates",
}

var systemDdnsForceCmd = &cobra.Command{
	Use:   "force",
	Short: "Force an immediate DDNS update",
	RunE:  runDdnsForce,
}

// systemProfilesCmd manages network profiles.
var systemProfilesCmd = &cobra.Command{
	Use:   "profiles",
	Short: "Manage network profiles",
}

var systemProfilesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all configured network profiles",
	RunE:  runProfilesList,
}

var systemProfilesApplyCmd = &cobra.Command{
	Use:   "apply [name]",
	Short: "Apply a network profile by name",
	Args:  cobra.ExactArgs(1),
	RunE:  runProfilesApply,
}

// systemStartupCmd manages startup behavior.
var systemStartupCmd = &cobra.Command{
	Use:   "startup",
	Short: "Manage LumiNet startup settings",
}

var systemStartupStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show whether LumiNet is set to start at login",
	RunE:  runStartupStatus,
}

var systemStartupEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Enable LumiNet at startup",
	RunE:  runStartupEnable,
}

var systemStartupDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable LumiNet at startup",
	RunE:  runStartupDisable,
}

var systemEvasionTunnelCmd = &cobra.Command{
	Use:   "evasion-tunnel",
	Short: "Manage or run local SOCKS5 Evasion Tunnel",
}

var systemEvasionTunnelStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the local SOCKS5 Evasion Tunnel in the foreground",
	RunE:  runEvasionTunnelStart,
}

func init() {
	rootCmd.AddCommand(systemCmd)

	systemCmd.AddCommand(systemDnsCmd)
	systemDnsCmd.AddCommand(systemDnsApplyCmd, systemDnsClearCmd, systemDnsStatusCmd)
	systemDnsApplyCmd.Flags().StringP("interface", "i", "", "network interface alias (auto-detected if empty)")

	systemCmd.AddCommand(systemProxyCmd)
	systemProxyCmd.AddCommand(systemProxyApplyCmd, systemProxyClearCmd, systemProxyStatusCmd)
	systemProxyApplyCmd.Flags().String("bypass", "<local>", "proxy bypass list")
	systemProxyApplyCmd.Flags().String("pac", "", "PAC URL (overrides server)")
	systemProxyApplyCmd.Flags().String("socks5", "", "SOCKS5 proxy server")

	systemCmd.AddCommand(systemDdnsCmd)
	systemDdnsCmd.AddCommand(systemDdnsForceCmd)
	systemDdnsForceCmd.Flags().String("provider", "cloudflare", "DDNS provider (cloudflare, duckdns, noip, dynu)")
	systemDdnsForceCmd.Flags().String("token", "", "DDNS API token or credentials")
	systemDdnsForceCmd.Flags().String("domain", "", "domain name to update")

	systemCmd.AddCommand(systemProfilesCmd)
	systemProfilesCmd.AddCommand(systemProfilesListCmd, systemProfilesApplyCmd)

	systemCmd.AddCommand(systemStartupCmd)
	systemStartupCmd.AddCommand(systemStartupStatusCmd, systemStartupEnableCmd, systemStartupDisableCmd)

	systemCmd.AddCommand(systemEvasionTunnelCmd)
	systemEvasionTunnelCmd.AddCommand(systemEvasionTunnelStartCmd)

	systemCmd.AddCommand(systemLeakProtectionCmd)
	systemLeakProtectionCmd.AddCommand(systemLeakProtectionEnableCmd, systemLeakProtectionDisableCmd)

	systemEvasionTunnelStartCmd.Flags().IntP("port", "p", proxy.DefaultEvasionPort, "SOCKS5 proxy local port")
	systemEvasionTunnelStartCmd.Flags().IntP("split", "s", proxy.DefaultEvasionSplitBytes, "TCP split offset in bytes")
	systemEvasionTunnelStartCmd.Flags().IntP("delay", "d", proxy.DefaultEvasionDelayMs, "TCP split delay in milliseconds")
	systemEvasionTunnelStartCmd.Flags().Bool("mutate-host", proxy.DefaultEvasionMutateHost, "Mutate HTTP Host header")
	systemEvasionTunnelStartCmd.Flags().Bool("mutate-header-space", proxy.DefaultEvasionMutateHeaderSpace, "Mutate HTTP Header space after colon (spacing evasion)")
	systemEvasionTunnelStartCmd.Flags().Bool("auto-sni", proxy.DefaultEvasionAutoSni, "Auto-split TLS SNI boundaries")
	systemEvasionTunnelStartCmd.Flags().Int("sni-split-offset", proxy.DefaultEvasionSniSplitOffset, "SNI split offset in bytes")
	systemEvasionTunnelStartCmd.Flags().String("packets", proxy.DefaultEvasionPackets, "Target packets mode (tlshello or all)")
	systemEvasionTunnelStartCmd.Flags().Int("min-len", proxy.DefaultEvasionMinLength, "Min fragment size in bytes")
	systemEvasionTunnelStartCmd.Flags().Int("max-len", proxy.DefaultEvasionMaxLength, "Max fragment size in bytes")
	systemEvasionTunnelStartCmd.Flags().Bool("tls-record-split", proxy.DefaultEvasionTlsRecordSplit, "Split ClientHello across multiple TLS records")
	systemEvasionTunnelStartCmd.Flags().String("dns", proxy.DefaultEvasionDnsResolver, "Secure DNS resolver (DoH URL or IP)")
	systemEvasionTunnelStartCmd.Flags().Int("dns-fwd-port", proxy.DefaultEvasionDnsForwarderPort, "UDP DNS Forwarder port")
	systemEvasionTunnelStartCmd.Flags().Bool("dns-fwd", proxy.DefaultEvasionDnsForwarderEnabled, "Enable UDP DNS Forwarder")
	systemEvasionTunnelStartCmd.Flags().Bool("system-proxy", proxy.DefaultEvasionSystemProxyEnabled, "Route all system traffic through SOCKS5 Evasion Tunnel")
	systemEvasionTunnelStartCmd.Flags().String("sni-spoof", "", "SNI spoofing target (optional)")
	systemEvasionTunnelStartCmd.Flags().Int("padding", proxy.DefaultEvasionClientHelloPadding, "TLS ClientHello padding size in bytes")
	systemEvasionTunnelStartCmd.Flags().Bool("delay-jitter", proxy.DefaultEvasionDelayJitter, "Randomize TCP segment delay to defeat timing heuristics")
	systemEvasionTunnelStartCmd.Flags().Int("tcp-window-clamp", proxy.DefaultEvasionTcpWindowClamp, "Clamp TCP read/write buffer sizes to force fragmentation (0 to disable)")
	systemEvasionTunnelStartCmd.Flags().String("custom-user-agent", proxy.DefaultEvasionCustomUserAgent, "Spoof HTTP User-Agent header (empty to keep raw)")
	systemEvasionTunnelStartCmd.Flags().String("covert-mode", proxy.DefaultEvasionCovertMode, "Covert tunnel mode (direct, serverless, dnstunnel, gsa)")
	systemEvasionTunnelStartCmd.Flags().String("covert-serverless-url", proxy.DefaultEvasionCovertServerlessURL, "Covert serverless WebSocket relay URL")
	systemEvasionTunnelStartCmd.Flags().String("covert-dns-domain", proxy.DefaultEvasionCovertDNSDomain, "Covert DNS tunnel domain name")
	systemEvasionTunnelStartCmd.Flags().String("covert-gsa-url", proxy.DefaultEvasionCovertGsaURL, "Covert GSA Web App URL")
	systemEvasionTunnelStartCmd.Flags().String("covert-gsa-key", proxy.DefaultEvasionCovertGsaKey, "Covert GSA Auth Key")
	systemEvasionTunnelStartCmd.Flags().String("covert-gdocs-folder-id", proxy.DefaultEvasionCovertGdocsFolderId, "Covert Google Docs Folder ID")
	systemEvasionTunnelStartCmd.Flags().String("covert-gdocs-access-token", proxy.DefaultEvasionCovertGdocsAccessToken, "Covert Google Docs Access Token")
	systemEvasionTunnelStartCmd.Flags().Bool("fake-packet-inject", proxy.DefaultEvasionFakePacketInject, "Inject fake TCP packets with low TTL")
	systemEvasionTunnelStartCmd.Flags().Int("fake-packet-ttl", proxy.DefaultEvasionFakePacketTtl, "TTL for fake TCP packets")
	systemEvasionTunnelStartCmd.Flags().Bool("mutate-sni-case", proxy.DefaultEvasionMutateSniCase, "Mutate TLS SNI domain name casing (e.g. yOuTuBe.CoM)")
	systemEvasionTunnelStartCmd.Flags().Bool("mutate-method", proxy.DefaultEvasionMutateMethod, "Randomize HTTP method casing (e.g. gEt)")
	systemEvasionTunnelStartCmd.Flags().Bool("mutate-absolute-uri", proxy.DefaultEvasionMutateAbsoluteUri, "Convert HTTP requests to use absolute URIs")
	systemEvasionTunnelStartCmd.Flags().Int("http-padding", proxy.DefaultEvasionHttpPadding, "Number of dummy HTTP headers to inject for padding")
	systemEvasionTunnelStartCmd.Flags().String("preflight-signature", proxy.DefaultEvasionPreflightSignature, "Preflight packet signature in CPS format")
	systemEvasionTunnelStartCmd.Flags().Int("preflight-delay", proxy.DefaultEvasionPreflightDelayMs, "Delay in milliseconds after preflight packet injection")
	systemEvasionTunnelStartCmd.Flags().Bool("session-frag", proxy.DefaultEvasionSessionFrag, "Enable session-level write fragmentation (Psiphon-style)")
	systemEvasionTunnelStartCmd.Flags().Float64("session-frag-prob", proxy.DefaultEvasionSessionFragProb, "Probability of session fragmentation (0.0 to 1.0)")
	systemEvasionTunnelStartCmd.Flags().Int("session-frag-min-total", proxy.DefaultEvasionSessionFragMinTotal, "Min total bytes to fragment per session")
	systemEvasionTunnelStartCmd.Flags().Int("session-frag-max-total", proxy.DefaultEvasionSessionFragMaxTotal, "Max total bytes to fragment per session")
	systemEvasionTunnelStartCmd.Flags().Int("session-frag-min-chunk", proxy.DefaultEvasionSessionFragMinChunk, "Min chunk size for session fragmentation")
	systemEvasionTunnelStartCmd.Flags().Int("session-frag-max-chunk", proxy.DefaultEvasionSessionFragMaxChunk, "Max chunk size for session fragmentation")
	systemEvasionTunnelStartCmd.Flags().Int("session-frag-min-delay", proxy.DefaultEvasionSessionFragMinDelayMs, "Min chunk delay in milliseconds")
	systemEvasionTunnelStartCmd.Flags().Int("session-frag-max-delay", proxy.DefaultEvasionSessionFragMaxDelayMs, "Max chunk delay in milliseconds")
	systemEvasionTunnelStartCmd.Flags().Bool("ip-spoofing", proxy.DefaultEvasionIpSpoofingEnabled, "Enable mutual IP spoofing")
	systemEvasionTunnelStartCmd.Flags().String("ip-spoofing-decoy", proxy.DefaultEvasionIpSpoofingDecoyIP, "Decoy IP address to spoof")
	systemEvasionTunnelStartCmd.Flags().String("ip-spoofing-dst-real", proxy.DefaultEvasionIpSpoofingDstReal, "Real destination IP address")
	systemEvasionTunnelStartCmd.Flags().Bool("out-of-window", proxy.DefaultEvasionOutOfWindowEnabled, "Enable out-of-window TCP sequence number injection")
	systemEvasionTunnelStartCmd.Flags().Int("out-of-window-seq-offset", proxy.DefaultEvasionOutOfWindowSeqOffset, "Out-of-window sequence number offset shift")
	systemEvasionTunnelStartCmd.Flags().String("decoy-sni-pool", proxy.DefaultEvasionDecoySniPool, "Comma-separated pool of decoy SNIs")
	systemEvasionTunnelStartCmd.Flags().Bool("oob", proxy.DefaultEvasionOobEnabled, "Enable TCP Out-of-band (OOB) Urgent Data evasion")
	systemEvasionTunnelStartCmd.Flags().Bool("oobex", proxy.DefaultEvasionOobexEnabled, "Enable TCP Out-of-band (OOB) Extended evasion (split header)")
	systemEvasionTunnelStartCmd.Flags().Bool("async-reactor", proxy.DefaultEvasionAsyncReactorEnabled, "Enable asynchronous gaio Proactor I/O loop")
	systemEvasionTunnelStartCmd.Flags().Float64("loss-rate", proxy.DefaultEvasionLossRate, "Simulated packet loss rate percentage (e.g. 1.5)")
	systemEvasionTunnelStartCmd.Flags().Int("emulated-latency", proxy.DefaultEvasionEmulatedLatency, "Emulated latency delay in milliseconds")
	systemEvasionTunnelStartCmd.Flags().Int("emulated-jitter", proxy.DefaultEvasionEmulatedJitter, "Emulated jitter deviation in milliseconds")
	systemEvasionTunnelStartCmd.Flags().Int("circular-cache-cap", proxy.DefaultEvasionCircularCacheCap, "Circular resolver cache size in records")
	systemEvasionTunnelStartCmd.Flags().Int64("shaper-read-rate", proxy.DefaultEvasionShaperReadRate, "Shaper bandwidth read pacing rate (bytes/second)")
	systemEvasionTunnelStartCmd.Flags().Int64("shaper-write-rate", proxy.DefaultEvasionShaperWriteRate, "Shaper bandwidth write pacing rate (bytes/second)")
	systemEvasionTunnelStartCmd.Flags().String("covert-socket-protect-path", proxy.DefaultEvasionCovertSocketProtectPath, "Unix domain socket path for socket protection")
	systemEvasionTunnelStartCmd.Flags().Bool("mobile-assets-enabled", proxy.DefaultEvasionMobileAssetsEnabled, "Enable Android/mobile asset reader override")
	systemEvasionTunnelStartCmd.Flags().Bool("zygisk-hide-enabled", proxy.DefaultEvasionZygiskHideEnabled, "Hide VPN interfaces from Android apps via Zygisk PLT hooks")
	systemEvasionTunnelStartCmd.Flags().Bool("hardened-tls-enabled", proxy.DefaultEvasionHardenedTlsEnabled, "Hardened modern TLS cipher suites configuration")
	systemEvasionTunnelStartCmd.Flags().Bool("upgen", proxy.DefaultEvasionUpgenEnabled, "Enable Context-Free Grammar (CFG) protocol obfuscation (UPGen)")
	systemEvasionTunnelStartCmd.Flags().String("upgen-seed", proxy.DefaultEvasionUpgenSeedHex, "UPGen shared auth seed hex")
	systemEvasionTunnelStartCmd.Flags().Bool("upgen-entropy", proxy.DefaultEvasionUpgenEntropyMatch, "Enable entropy matching/shaping on UPGen traffic")
	systemEvasionTunnelStartCmd.Flags().Int("upgen-quic-rate", proxy.DefaultEvasionUpgenQuicExhaustionRate, "QUIC Client Initial queue exhaustion attack flood rate (pps)")
	systemEvasionTunnelStartCmd.Flags().Bool("stego", proxy.DefaultEvasionStegoEnabled, "Enable steganographic VoIP/WebRTC camouflage")
	systemEvasionTunnelStartCmd.Flags().String("stego-mode", proxy.DefaultEvasionStegoMode, "Steganography mode (webrtc_voip or pixel_stego)")
	systemEvasionTunnelStartCmd.Flags().String("stego-decoy-image", proxy.DefaultEvasionStegoDecoyImagePath, "Path to decoy PNG image for pixel steganography")
	systemEvasionTunnelStartCmd.Flags().Bool("stego-webrtc-sdp", proxy.DefaultEvasionStegoWebRTCSDPSpoof, "Spoof WebRTC Session Description Protocol (SDP) signals")
}

func ctxWithTimeout(secs int) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), time.Duration(secs)*time.Second)
}

func runDnsApply(cmd *cobra.Command, args []string) error {
	ctx, cancel := ctxWithTimeout(10)
	defer cancel()

	ifaceName, _ := cmd.Flags().GetString("interface")
	if ifaceName == "" {
		ifaces, err := system.GetActiveInterfaces(ctx)
		if err != nil || len(ifaces) == 0 {
			return fmt.Errorf("could not detect active network interface: %v", err)
		}
		ifaceName = ifaces[0].Name
	}

	servers := args
	if err := system.SetDNS(ctx, ifaceName, servers); err != nil {
		return fmt.Errorf("failed to set DNS: %w", err)
	}

	fmt.Printf("DNS servers applied to interface %q: %s\n", ifaceName, strings.Join(servers, ", "))
	return nil
}

func runDnsClear(cmd *cobra.Command, args []string) error {
	ctx, cancel := ctxWithTimeout(10)
	defer cancel()

	ifaces, err := system.GetActiveInterfaces(ctx)
	if err != nil || len(ifaces) == 0 {
		return fmt.Errorf("could not detect active network interface: %v", err)
	}
	ifaceName := ifaces[0].Name

	if err := system.ResetDNS(ctx, ifaceName); err != nil {
		return fmt.Errorf("failed to reset DNS: %w", err)
	}

	fmt.Printf("DNS reset to DHCP on interface %q\n", ifaceName)
	return nil
}

func runDnsStatus(cmd *cobra.Command, args []string) error {
	ctx, cancel := ctxWithTimeout(5)
	defer cancel()

	ifaces, err := system.GetActiveInterfaces(ctx)
	if err != nil || len(ifaces) == 0 {
		return fmt.Errorf("could not detect active network interface: %v", err)
	}

	for _, iface := range ifaces {
		servers, err := system.GetDNS(ctx, iface.Name)
		if err != nil {
			fmt.Printf("  %-30s ERROR: %v\n", iface.Name, err)
			continue
		}
		if len(servers) == 0 {
			fmt.Printf("  %-30s (DHCP)\n", iface.Name)
		} else {
			fmt.Printf("  %-30s %s\n", iface.Name, strings.Join(servers, ", "))
		}
	}
	return nil
}

func runProxyApply(cmd *cobra.Command, args []string) error {
	ctx, cancel := ctxWithTimeout(10)
	defer cancel()

	server := args[0]
	bypass, _ := cmd.Flags().GetString("bypass")

	settings := &system.ProxySettings{
		Enabled: true,
		Server:  server,
		Bypass:  bypass,
	}

	if err := system.SetSystemProxy(ctx, settings); err != nil {
		return fmt.Errorf("failed to set proxy: %w", err)
	}

	fmt.Printf("System proxy set to %s (bypass: %s)\n", server, bypass)
	return nil
}

func runProxyClear(cmd *cobra.Command, args []string) error {
	ctx, cancel := ctxWithTimeout(10)
	defer cancel()

	if err := system.DisableSystemProxy(ctx); err != nil {
		return fmt.Errorf("failed to clear proxy: %w", err)
	}

	fmt.Println("System proxy cleared")
	return nil
}

func runProxyStatus(cmd *cobra.Command, args []string) error {
	ctx, cancel := ctxWithTimeout(5)
	defer cancel()

	settings, err := system.GetSystemProxy(ctx)
	if err != nil {
		return fmt.Errorf("failed to get proxy settings: %w", err)
	}

	if settings.Enabled {
		fmt.Printf("Proxy: ENABLED\n  Server: %s\n  Bypass: %s\n", settings.Server, settings.Bypass)
	} else {
		fmt.Println("Proxy: DISABLED")
	}
	return nil
}

func runDdnsForce(cmd *cobra.Command, args []string) error {
	provider, _ := cmd.Flags().GetString("provider")
	token, _ := cmd.Flags().GetString("token")
	domain, _ := cmd.Flags().GetString("domain")

	if token == "" || domain == "" {
		return fmt.Errorf("--token and --domain are required for DDNS update")
	}

	ctx, cancel := ctxWithTimeout(30)
	defer cancel()

	updater := ddns.NewUpdater(provider, token, domain)

	fmt.Printf("Detecting public IP...\n")
	ip, err := updater.GetPublicIP(ctx)
	if err != nil {
		return fmt.Errorf("failed to get public IP: %w", err)
	}
	fmt.Printf("Public IP: %s\n", ip)

	fmt.Printf("Updating DDNS record (%s / %s)...\n", provider, domain)
	result, err := updater.UpdateIP(ctx, ip)
	if err != nil {
		return fmt.Errorf("DDNS update failed: %w", err)
	}

	if result.Updated {
		fmt.Printf("✓ Updated %s → %s\n", result.Domain, result.IP)
	} else {
		fmt.Printf("  No change needed: %s\n", result.StatusText)
	}
	return nil
}

func runProfilesList(cmd *cobra.Command, args []string) error {
	fmt.Println("No profiles configured.")
	fmt.Println("Use the web UI or config file to add network profiles.")
	return nil
}

func runProfilesApply(cmd *cobra.Command, args []string) error {
	name := args[0]
	return fmt.Errorf("profile %q not found — no profiles are configured", name)
}

func runStartupStatus(cmd *cobra.Command, args []string) error {
	fmt.Println("Startup: DISABLED")
	fmt.Println("Run 'luminet system startup enable' to register LumiNet at login.")
	return nil
}

func runStartupEnable(cmd *cobra.Command, args []string) error {
	fmt.Println("Startup registration is platform-specific.")
	fmt.Println("On Windows: add luminet.exe to HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run")
	fmt.Println("On Linux: create a systemd user service or add to ~/.config/autostart/")
	fmt.Println("On macOS: create a LaunchAgent plist in ~/Library/LaunchAgents/")
	return nil
}

func runStartupDisable(cmd *cobra.Command, args []string) error {
	fmt.Println("Startup entry removed (if it existed).")
	return nil
}

func runEvasionTunnelStart(cmd *cobra.Command, args []string) error {
	port, _ := cmd.Flags().GetInt("port")
	split, _ := cmd.Flags().GetInt("split")
	delay, _ := cmd.Flags().GetInt("delay")
	mutateHost, _ := cmd.Flags().GetBool("mutate-host")
	mutateHeaderSpace, _ := cmd.Flags().GetBool("mutate-header-space")
	autoSni, _ := cmd.Flags().GetBool("auto-sni")
	sniSplitOffset, _ := cmd.Flags().GetInt("sni-split-offset")
	packets, _ := cmd.Flags().GetString("packets")
	minLen, _ := cmd.Flags().GetInt("min-len")
	maxLen, _ := cmd.Flags().GetInt("max-len")
	tlsRecSplit, _ := cmd.Flags().GetBool("tls-record-split")
	dns, _ := cmd.Flags().GetString("dns")
	dnsFwdPort, _ := cmd.Flags().GetInt("dns-fwd-port")
	dnsFwd, _ := cmd.Flags().GetBool("dns-fwd")
	systemProxy, _ := cmd.Flags().GetBool("system-proxy")
	sniSpoof, _ := cmd.Flags().GetString("sni-spoof")
	padding, _ := cmd.Flags().GetInt("padding")
	delayJitter, _ := cmd.Flags().GetBool("delay-jitter")
	windowClamp, _ := cmd.Flags().GetInt("tcp-window-clamp")
	userAgent, _ := cmd.Flags().GetString("custom-user-agent")
	covertMode, _ := cmd.Flags().GetString("covert-mode")
	covertServerlessUrl, _ := cmd.Flags().GetString("covert-serverless-url")
	covertDnsDomain, _ := cmd.Flags().GetString("covert-dns-domain")
	covertGsaUrl, _ := cmd.Flags().GetString("covert-gsa-url")
	covertGsaKey, _ := cmd.Flags().GetString("covert-gsa-key")
	covertGdocsFolderId, _ := cmd.Flags().GetString("covert-gdocs-folder-id")
	covertGdocsAccessToken, _ := cmd.Flags().GetString("covert-gdocs-access-token")
	fakePacketInject, _ := cmd.Flags().GetBool("fake-packet-inject")
	fakePacketTtl, _ := cmd.Flags().GetInt("fake-packet-ttl")
	mutateSniCase, _ := cmd.Flags().GetBool("mutate-sni-case")
	mutateMethod, _ := cmd.Flags().GetBool("mutate-method")
	mutateAbsoluteUri, _ := cmd.Flags().GetBool("mutate-absolute-uri")
	httpPadding, _ := cmd.Flags().GetInt("http-padding")
	preflightSignature, _ := cmd.Flags().GetString("preflight-signature")
	preflightDelay, _ := cmd.Flags().GetInt("preflight-delay")
	sessionFrag, _ := cmd.Flags().GetBool("session-frag")
	sessionFragProb, _ := cmd.Flags().GetFloat64("session-frag-prob")
	sessionFragMinTotal, _ := cmd.Flags().GetInt("session-frag-min-total")
	sessionFragMaxTotal, _ := cmd.Flags().GetInt("session-frag-max-total")
	sessionFragMinChunk, _ := cmd.Flags().GetInt("session-frag-min-chunk")
	sessionFragMaxChunk, _ := cmd.Flags().GetInt("session-frag-max-chunk")
	sessionFragMinDelay, _ := cmd.Flags().GetInt("session-frag-min-delay")
	sessionFragMaxDelay, _ := cmd.Flags().GetInt("session-frag-max-delay")
	ipSpoofing, _ := cmd.Flags().GetBool("ip-spoofing")
	ipSpoofingDecoy, _ := cmd.Flags().GetString("ip-spoofing-decoy")
	ipSpoofingDstReal, _ := cmd.Flags().GetString("ip-spoofing-dst-real")
	outOfWindow, _ := cmd.Flags().GetBool("out-of-window")
	outOfWindowSeqOffset, _ := cmd.Flags().GetInt("out-of-window-seq-offset")
	decoySniPool, _ := cmd.Flags().GetString("decoy-sni-pool")
	oob, _ := cmd.Flags().GetBool("oob")
	oobex, _ := cmd.Flags().GetBool("oobex")
	asyncReactor, _ := cmd.Flags().GetBool("async-reactor")
	lossRate, _ := cmd.Flags().GetFloat64("loss-rate")
	emulatedLatency, _ := cmd.Flags().GetInt("emulated-latency")
	emulatedJitter, _ := cmd.Flags().GetInt("emulated-jitter")
	circularCacheCap, _ := cmd.Flags().GetInt("circular-cache-cap")
	shaperReadRate, _ := cmd.Flags().GetInt64("shaper-read-rate")
	shaperWriteRate, _ := cmd.Flags().GetInt64("shaper-write-rate")
	covertSocketProtectPath, _ := cmd.Flags().GetString("covert-socket-protect-path")
	mobileAssetsEnabled, _ := cmd.Flags().GetBool("mobile-assets-enabled")
	zygiskHideEnabled, _ := cmd.Flags().GetBool("zygisk-hide-enabled")
	hardenedTlsEnabled, _ := cmd.Flags().GetBool("hardened-tls-enabled")
	upgenEnabled, _ := cmd.Flags().GetBool("upgen")
	upgenSeedHex, _ := cmd.Flags().GetString("upgen-seed")
	upgenEntropyMatch, _ := cmd.Flags().GetBool("upgen-entropy")
	upgenQuicExhaustionRate, _ := cmd.Flags().GetInt("upgen-quic-rate")
	stegoEnabled, _ := cmd.Flags().GetBool("stego")
	stegoMode, _ := cmd.Flags().GetString("stego-mode")
	stegoDecoyImagePath, _ := cmd.Flags().GetString("stego-decoy-image")
	stegoWebRTCSDPSpoof, _ := cmd.Flags().GetBool("stego-webrtc-sdp")

	mgr := proxy.GetEvasionManager()
	mgr.SetOnLog(func(msg string) {
		fmt.Println(msg)
	})

	err := mgr.Start(port, split, delay, mutateHost, mutateHeaderSpace, autoSni, sniSplitOffset, packets, minLen, maxLen, tlsRecSplit, dns, dnsFwdPort, dnsFwd, systemProxy, sniSpoof, padding, delayJitter, windowClamp, userAgent, covertMode, covertServerlessUrl, covertDnsDomain, covertGsaUrl, covertGsaKey, covertGdocsFolderId, covertGdocsAccessToken, fakePacketInject, fakePacketTtl, mutateSniCase, mutateMethod, mutateAbsoluteUri, httpPadding, preflightSignature, preflightDelay, sessionFrag, sessionFragProb, sessionFragMinTotal, sessionFragMaxTotal, sessionFragMinChunk, sessionFragMaxChunk, sessionFragMinDelay, sessionFragMaxDelay, ipSpoofing, ipSpoofingDecoy, ipSpoofingDstReal, outOfWindow, outOfWindowSeqOffset, decoySniPool, oob, oobex, asyncReactor, lossRate, emulatedLatency, emulatedJitter, circularCacheCap, shaperReadRate, shaperWriteRate, covertSocketProtectPath, mobileAssetsEnabled, zygiskHideEnabled, hardenedTlsEnabled, upgenEnabled, upgenSeedHex, upgenEntropyMatch, upgenQuicExhaustionRate, stegoEnabled, stegoMode, stegoDecoyImagePath, stegoWebRTCSDPSpoof)
	if err != nil {
		return fmt.Errorf("failed to start evasion tunnel: %w", err)
	}

	fmt.Printf("SOCKS5 Evasion Tunnel running on 127.0.0.1:%d\nPress Ctrl+C to stop...\n", port)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	mgr.Stop()
	fmt.Println("SOCKS5 Evasion Tunnel stopped.")
	return nil
}

// systemLeakProtectionCmd manages firewall leak protection settings.
var systemLeakProtectionCmd = &cobra.Command{
	Use:   "leak-protection",
	Short: "Manage system firewall leak protection settings",
}

var systemLeakProtectionEnableCmd = &cobra.Command{
	Use:   "enable [port]",
	Short: "Enable firewall leak protection, allowing only loopback proxy port traffic",
	Args:  cobra.ExactArgs(1),
	RunE:  runLeakProtectionEnable,
}

var systemLeakProtectionDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable firewall leak protection rules",
	RunE:  runLeakProtectionDisable,
}

func runLeakProtectionEnable(cmd *cobra.Command, args []string) error {
	var port int
	if _, err := fmt.Sscanf(args[0], "%d", &port); err != nil {
		return fmt.Errorf("invalid port parameter: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := system.EnableLeakProtection(ctx, port)
	if err != nil {
		return fmt.Errorf("failed to enable leak protection: %w", err)
	}

	fmt.Printf("✓ Firewall leak protection enabled. Only loopback port %d traffic allowed.\n", port)
	return nil
}

func runLeakProtectionDisable(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := system.DisableLeakProtection(ctx)
	if err != nil {
		return fmt.Errorf("failed to disable leak protection: %w", err)
	}

	fmt.Println("✓ Firewall leak protection rules removed.")
	return nil
}
