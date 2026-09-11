package cmd

import (
	"encoding/json"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"

	"github.com/maybeknott/luminet/internal/native/bridge"
	"github.com/spf13/cobra"
)

var scanTargets string
var scanOutput string
var scanTimeout int
var scanConcurrency int

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan Targets (Workflow 2: Run active ICMP, port, DNS, TLS, SNI sweeps)",
	Long:  `Scan Targets workflow provides subcommands for active parallel network sweeps and targeted service discovery.`,
}

var icmpCmd = &cobra.Command{Use: "icmp [targets...]", Short: "Run ICMP ping sweep", Long: `Performs ICMP echo requests against specified targets and reports latency, TTL, and reachability.`, Args: cobra.MinimumNArgs(1), RunE: runIcmpScan}
var portsCmd = &cobra.Command{Use: "ports [targets...]", Short: "Run TCP port scan", Long: `Scans specified TCP ports on target hosts to discover open services.`, Args: cobra.MinimumNArgs(1), RunE: runPortScan}
var dnsCmd = &cobra.Command{Use: "dns [domains...]", Short: "Run DNS scan and resolution", Long: `Resolves domains against specified DNS servers and reports record types, TTL, and response times.`, Args: cobra.MinimumNArgs(1), RunE: runDnsScan}
var tlsCmd = &cobra.Command{Use: "tls [hosts...]", Short: "Run TLS handshake scan", Long: `Connects to hosts and inspects TLS certificates, protocol versions, and cipher suites.`, Args: cobra.MinimumNArgs(1), RunE: runTlsScan}
var sniCmd = &cobra.Command{Use: "sni [domains...]", Short: "Run SNI blocking detection", Long: `Tests domains for SNI-based filtering by analyzing TLS connection behavior.`, Args: cobra.MinimumNArgs(1), RunE: runSniScan}
var wgCmd = &cobra.Command{Use: "wg [endpoints...]", Short: "Probe WireGuard endpoints", Long: `Sends handshake initiation packets to WireGuard endpoints to test reachability.`, Args: cobra.MinimumNArgs(1), RunE: runWgScan}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.AddCommand(icmpCmd, portsCmd, dnsCmd, tlsCmd, sniCmd, wgCmd)

	scanCmd.PersistentFlags().StringVarP(&scanTargets, "targets", "t", "", "comma-separated targets (IPs, CIDRs, hostnames)")
	scanCmd.PersistentFlags().StringVarP(&scanOutput, "output", "o", "table", "output format (table, json, csv)")
	scanCmd.PersistentFlags().IntVar(&scanTimeout, "timeout", 3000, "per-probe timeout in milliseconds")
	scanCmd.PersistentFlags().IntVarP(&scanConcurrency, "concurrency", "c", 64, "number of concurrent probes")

	portsCmd.Flags().String("ports", "1-1024", "port range or comma-separated ports")
	dnsCmd.Flags().String("server", "8.8.8.8", "DNS server to query")
	dnsCmd.Flags().String("record-type", "A", "DNS record type (A, AAAA, MX, CNAME, TXT, etc.)")
	tlsCmd.Flags().Int("port", 443, "TLS port to connect to")
	sniCmd.Flags().String("ip", "", "specific IP to test SNI against")
}

func validatedScanConfig() (bridge.ScanConfig, error) {
	if scanTimeout <= 0 || uint64(scanTimeout) > math.MaxUint32 {
		return bridge.ScanConfig{}, fmt.Errorf("--timeout must be between 1 and %d milliseconds", uint64(math.MaxUint32))
	}
	if scanConcurrency <= 0 || uint64(scanConcurrency) > math.MaxUint32 {
		return bridge.ScanConfig{}, fmt.Errorf("--concurrency must be between 1 and %d", uint64(math.MaxUint32))
	}
	switch scanOutput {
	case "table", "json", "csv":
	default:
		return bridge.ScanConfig{}, fmt.Errorf("--output must be one of table, json, csv")
	}
	return bridge.ScanConfig{
		Timeout:      uint32(scanTimeout),
		Concurrency:  uint32(scanConcurrency),
		RateLimitPPS: 1000,
		RetryCount:   1,
		AdaptiveRate: true,
	}, nil
}

func runIcmpScan(cmd *cobra.Command, args []string) error {
	config, err := validatedScanConfig()
	if err != nil {
		return err
	}
	targets := collectTargets(args)
	fmt.Printf("ICMP sweep: %d targets (timeout=%dms, concurrency=%d)\n", len(targets), scanTimeout, scanConcurrency)
	results, err := bridge.IcmpScan(targets, config)
	if err != nil {
		return fmt.Errorf("ICMP scan failed: %w", err)
	}
	return printResults(results, scanOutput)
}

func runPortScan(cmd *cobra.Command, args []string) error {
	if _, err := validatedScanConfig(); err != nil {
		return err
	}
	target := args[0]
	portRange, err := cmd.Flags().GetString("ports")
	if err != nil {
		return err
	}
	ports, err := parsePorts(portRange)
	if err != nil {
		return err
	}
	fmt.Printf("TCP port scan: %s ports=%s (timeout=%dms)\n", target, portRange, scanTimeout)
	var results []interface{}
	for _, port := range ports {
		result, err := bridge.TcpConnect(target, port, uint32(scanTimeout))
		if err != nil {
			continue
		}
		results = append(results, result)
	}
	return printResults(results, scanOutput)
}

func runDnsScan(cmd *cobra.Command, args []string) error {
	if _, err := validatedScanConfig(); err != nil {
		return err
	}
	server, _ := cmd.Flags().GetString("server")
	recordType, _ := cmd.Flags().GetString("record-type")
	fmt.Printf("DNS scan: %v server=%s type=%s\n", args, server, recordType)
	var results []interface{}
	for _, domain := range args {
		result, err := bridge.DnsResolve(server, domain, recordType)
		if err != nil {
			fmt.Printf("  %-40s ERROR: %v\n", domain, err)
			continue
		}
		results = append(results, result)
	}
	return printResults(results, scanOutput)
}

func runTlsScan(cmd *cobra.Command, args []string) error {
	if _, err := validatedScanConfig(); err != nil {
		return err
	}
	port, err := cmd.Flags().GetInt("port")
	if err != nil {
		return err
	}
	validatedPort, err := validatePort(port)
	if err != nil {
		return fmt.Errorf("invalid --port: %w", err)
	}
	fmt.Printf("TLS scan: %v port=%d (timeout=%dms)\n", args, port, scanTimeout)
	var results []interface{}
	for _, host := range args {
		result, err := bridge.TlsHandshake(host, validatedPort, uint32(scanTimeout))
		if err != nil {
			fmt.Printf("  %-40s ERROR: %v\n", host, err)
			continue
		}
		results = append(results, result)
	}
	return printResults(results, scanOutput)
}

func runSniScan(cmd *cobra.Command, args []string) error {
	if _, err := validatedScanConfig(); err != nil {
		return err
	}
	fmt.Printf("SNI blocking detection: %v (timeout=%dms)\n", args, scanTimeout)
	var results []interface{}
	for _, domain := range args {
		result, err := bridge.SniDetect(domain, uint32(scanTimeout))
		if err != nil {
			fmt.Printf("  %-40s ERROR: %v\n", domain, err)
			continue
		}
		blocked := "ALLOWED"
		if result.Blocked {
			blocked = "BLOCKED"
		}
		fmt.Printf("  %-40s %s (confidence=%.0f%%)\n", domain, blocked, result.Confidence*100)
		results = append(results, result)
	}
	return printResults(results, scanOutput)
}

func runWgScan(cmd *cobra.Command, args []string) error {
	if _, err := validatedScanConfig(); err != nil {
		return err
	}
	fmt.Printf("WireGuard probe: %v (timeout=%dms)\n", args, scanTimeout)
	var results []interface{}
	for _, endpoint := range args {
		host, port, err := parseEndpoint(endpoint, 51820)
		if err != nil {
			return fmt.Errorf("invalid WireGuard endpoint %q: %w", endpoint, err)
		}
		result, err := bridge.WgProbe(host, port, uint32(scanTimeout), 0)
		if err != nil {
			fmt.Printf("  %-40s ERROR: %v\n", endpoint, err)
			continue
		}
		status := "UNREACHABLE"
		if result.Alive {
			status = "REACHABLE"
		}
		fmt.Printf("  %-40s %s latency=%.1fms\n", endpoint, status, result.LatencyMs)
		results = append(results, result)
	}
	return printResults(results, scanOutput)
}

func collectTargets(args []string) []string {
	var targets []string
	for _, a := range args {
		for _, t := range strings.Split(a, ",") {
			t = strings.TrimSpace(t)
			if t != "" {
				targets = append(targets, t)
			}
		}
	}
	if scanTargets != "" {
		for _, t := range strings.Split(scanTargets, ",") {
			t = strings.TrimSpace(t)
			if t != "" {
				targets = append(targets, t)
			}
		}
	}
	return targets
}

func validatePort(port int) (uint16, error) {
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("port must be between 1 and 65535")
	}
	return uint16(port), nil
}

func parsePorts(portRange string) ([]uint16, error) {
	var ports []uint16
	seen := make(map[uint16]struct{})
	for _, raw := range strings.Split(portRange, ",") {
		part := strings.TrimSpace(raw)
		if part == "" {
			return nil, errorsForPortSpec("empty port item")
		}
		if strings.Contains(part, "-") {
			bounds := strings.Split(part, "-")
			if len(bounds) != 2 {
				return nil, errorsForPortSpec("invalid range %q", part)
			}
			start, err := strconv.Atoi(strings.TrimSpace(bounds[0]))
			if err != nil {
				return nil, errorsForPortSpec("invalid range start %q", bounds[0])
			}
			end, err := strconv.Atoi(strings.TrimSpace(bounds[1]))
			if err != nil {
				return nil, errorsForPortSpec("invalid range end %q", bounds[1])
			}
			if start > end {
				return nil, errorsForPortSpec("range start exceeds end in %q", part)
			}
			if _, err := validatePort(start); err != nil {
				return nil, errorsForPortSpec("invalid range start %d", start)
			}
			if _, err := validatePort(end); err != nil {
				return nil, errorsForPortSpec("invalid range end %d", end)
			}
			for p := start; p <= end; p++ {
				port := uint16(p)
				if _, ok := seen[port]; !ok {
					seen[port] = struct{}{}
					ports = append(ports, port)
				}
			}
			continue
		}
		p, err := strconv.Atoi(part)
		if err != nil {
			return nil, errorsForPortSpec("invalid port %q", part)
		}
		port, err := validatePort(p)
		if err != nil {
			return nil, errorsForPortSpec("invalid port %d", p)
		}
		if _, ok := seen[port]; !ok {
			seen[port] = struct{}{}
			ports = append(ports, port)
		}
	}
	if len(ports) == 0 {
		return nil, errorsForPortSpec("no ports supplied")
	}
	return ports, nil
}

func errorsForPortSpec(format string, args ...interface{}) error {
	return fmt.Errorf("invalid --ports: "+format, args...)
}

func parseEndpoint(endpoint string, defaultPort int) (string, uint16, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return "", 0, fmt.Errorf("endpoint is empty")
	}
	defaultPort16, err := validatePort(defaultPort)
	if err != nil {
		return "", 0, err
	}

	if host, portText, err := net.SplitHostPort(endpoint); err == nil {
		if host == "" {
			return "", 0, fmt.Errorf("host is empty")
		}
		port, err := strconv.Atoi(portText)
		if err != nil {
			return "", 0, fmt.Errorf("invalid port %q", portText)
		}
		port16, err := validatePort(port)
		if err != nil {
			return "", 0, err
		}
		return host, port16, nil
	}

	// An unbracketed string containing multiple colons is an IPv6 literal, not
	// host:port. Require brackets when an explicit port is attached to IPv6.
	if strings.Count(endpoint, ":") > 1 {
		if net.ParseIP(endpoint) == nil {
			return "", 0, fmt.Errorf("invalid IPv6 literal; use [address]:port for an explicit port")
		}
		return endpoint, defaultPort16, nil
	}

	if strings.Count(endpoint, ":") == 1 {
		host, portText, _ := strings.Cut(endpoint, ":")
		if host == "" || portText == "" {
			return "", 0, fmt.Errorf("malformed host:port")
		}
		port, err := strconv.Atoi(portText)
		if err != nil {
			return "", 0, fmt.Errorf("invalid port %q", portText)
		}
		port16, err := validatePort(port)
		if err != nil {
			return "", 0, err
		}
		return host, port16, nil
	}
	return endpoint, defaultPort16, nil
}

func printResults(results interface{}, format string) error {
	switch format {
	case "json":
		data, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
	default:
		data, _ := json.MarshalIndent(results, "", "  ")
		fmt.Println(string(data))
	}
	return nil
}
