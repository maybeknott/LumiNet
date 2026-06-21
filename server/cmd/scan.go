package cmd

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/maybeknott/luminet/internal/bridge"
	"github.com/spf13/cobra"
)

// scanTargets is the comma-separated list of targets for scan commands.
var scanTargets string

// scanOutput is the output format for scan results.
var scanOutput string

// scanTimeout is the per-probe timeout in milliseconds.
var scanTimeout int

// scanConcurrency is the number of concurrent probes.
var scanConcurrency int

// scanCmd is the parent command for all scan subcommands.
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run network scans (ICMP, ports, DNS, TLS, SNI, WireGuard)",
	Long:  `Scan provides subcommands for various network probing and discovery tasks.`,
}

var icmpCmd = &cobra.Command{
	Use:   "icmp [targets...]",
	Short: "Run ICMP ping sweep",
	Long:  `Performs ICMP echo requests against specified targets and reports latency, TTL, and reachability.`,
	Args:  cobra.MinimumNArgs(1),
	RunE:  runIcmpScan,
}

var portsCmd = &cobra.Command{
	Use:   "ports [targets...]",
	Short: "Run TCP port scan",
	Long:  `Scans specified TCP ports on target hosts to discover open services.`,
	Args:  cobra.MinimumNArgs(1),
	RunE:  runPortScan,
}

var dnsCmd = &cobra.Command{
	Use:   "dns [domains...]",
	Short: "Run DNS scan and resolution",
	Long:  `Resolves domains against specified DNS servers and reports record types, TTL, and response times.`,
	Args:  cobra.MinimumNArgs(1),
	RunE:  runDnsScan,
}

var tlsCmd = &cobra.Command{
	Use:   "tls [hosts...]",
	Short: "Run TLS handshake scan",
	Long:  `Connects to hosts and inspects TLS certificates, protocol versions, and cipher suites.`,
	Args:  cobra.MinimumNArgs(1),
	RunE:  runTlsScan,
}

var sniCmd = &cobra.Command{
	Use:   "sni [domains...]",
	Short: "Run SNI blocking detection",
	Long:  `Tests domains for SNI-based filtering by analyzing TLS connection behavior.`,
	Args:  cobra.MinimumNArgs(1),
	RunE:  runSniScan,
}

var wgCmd = &cobra.Command{
	Use:   "wg [endpoints...]",
	Short: "Probe WireGuard endpoints",
	Long:  `Sends handshake initiation packets to WireGuard endpoints to test reachability.`,
	Args:  cobra.MinimumNArgs(1),
	RunE:  runWgScan,
}

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

func runIcmpScan(cmd *cobra.Command, args []string) error {
	targets := collectTargets(args)
	config := bridge.ScanConfig{
		Timeout:      uint32(scanTimeout),
		Concurrency:  uint32(scanConcurrency),
		RateLimitPPS: 1000,
		RetryCount:   1,
		AdaptiveRate: true,
	}

	fmt.Printf("ICMP sweep: %d targets (timeout=%dms, concurrency=%d)\n",
		len(targets), scanTimeout, scanConcurrency)

	results, err := bridge.IcmpScan(targets, config)
	if err != nil {
		return fmt.Errorf("ICMP scan failed: %w", err)
	}

	return printResults(results, scanOutput)
}

func runPortScan(cmd *cobra.Command, args []string) error {
	target := args[0]
	portRange, _ := cmd.Flags().GetString("ports")
	ports := parsePorts(portRange)

	fmt.Printf("TCP port scan: %s ports=%s (timeout=%dms)\n", target, portRange, scanTimeout)

	var results []interface{}
	for _, port := range ports {
		result, err := bridge.TcpConnect(target, uint16(port), uint32(scanTimeout))
		if err != nil {
			continue
		}
		results = append(results, result)
	}

	return printResults(results, scanOutput)
}

func runDnsScan(cmd *cobra.Command, args []string) error {
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
	port, _ := cmd.Flags().GetInt("port")

	fmt.Printf("TLS scan: %v port=%d (timeout=%dms)\n", args, port, scanTimeout)

	var results []interface{}
	for _, host := range args {
		result, err := bridge.TlsHandshake(host, uint16(port), uint32(scanTimeout))
		if err != nil {
			fmt.Printf("  %-40s ERROR: %v\n", host, err)
			continue
		}
		results = append(results, result)
	}

	return printResults(results, scanOutput)
}

func runSniScan(cmd *cobra.Command, args []string) error {
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
	fmt.Printf("WireGuard probe: %v (timeout=%dms)\n", args, scanTimeout)

	var results []interface{}
	for _, endpoint := range args {
		ip, port := parseEndpoint(endpoint, 51820)
		result, err := bridge.WgProbe(ip, uint16(port), uint32(scanTimeout), 0)
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

// --- Helpers ---

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

func parsePorts(portRange string) []int {
	var ports []int
	for _, part := range strings.Split(portRange, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			start, _ := strconv.Atoi(bounds[0])
			end, _ := strconv.Atoi(bounds[1])
			for p := start; p <= end && p <= 65535; p++ {
				ports = append(ports, p)
			}
		} else {
			p, err := strconv.Atoi(part)
			if err == nil {
				ports = append(ports, p)
			}
		}
	}
	return ports
}

func parseEndpoint(endpoint string, defaultPort int) (string, int) {
	if idx := strings.LastIndex(endpoint, ":"); idx != -1 {
		ip := endpoint[:idx]
		port, err := strconv.Atoi(endpoint[idx+1:])
		if err == nil {
			return ip, port
		}
	}
	return endpoint, defaultPort
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
		// Table format: already printed inline for most scan types
		data, _ := json.MarshalIndent(results, "", "  ")
		fmt.Println(string(data))
	}
	return nil
}
