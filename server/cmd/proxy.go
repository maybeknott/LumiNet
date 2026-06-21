package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/maybeknott/luminet/internal/diagnostics"
	"github.com/maybeknott/luminet/internal/proxy"
	"github.com/spf13/cobra"
)

// proxyInputFile is the path to a proxy list file.
var proxyInputFile string

// proxyURL is the subscription URL for proxy fetching.
var proxyURL string

// proxyConcurrency is the number of concurrent proxy tests.
var proxyConcurrency int

// proxyTimeout is the per-test timeout in seconds.
var proxyTimeout int

// proxyCmd is the parent command for proxy-related subcommands.
var proxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "Proxy parsing, testing, subscription management, and export",
	Long:  `Commands for working with proxy configurations: parse URIs, test connectivity, manage subscriptions, and export results.`,
}

var proxyTestCmd = &cobra.Command{
	Use:   "test [proxy-uris...]",
	Short: "Test proxy configurations for connectivity and speed",
	RunE:  runProxyTest,
}

var proxyParseCmd = &cobra.Command{
	Use:   "parse [uris...]",
	Short: "Parse proxy URIs into structured configurations",
	RunE:  runProxyParse,
}

var proxySubscribeCmd = &cobra.Command{
	Use:   "subscribe [url]",
	Short: "Fetch and parse proxy subscriptions",
	Args:  cobra.ExactArgs(1),
	RunE:  runProxySubscribe,
}

var proxyExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export proxy configurations to various formats",
	RunE:  runProxyExport,
}

var proxyGenerateCmd = &cobra.Command{
	Use:   "generate [base-uri]",
	Short: "Generate bulk proxy configs from a base URI and IP ranges",
	Args:  cobra.ExactArgs(1),
	RunE:  runProxyGenerate,
}

func init() {
	rootCmd.AddCommand(proxyCmd)
	proxyCmd.AddCommand(proxyTestCmd, proxyParseCmd, proxySubscribeCmd, proxyExportCmd, proxyGenerateCmd)

	proxyCmd.PersistentFlags().StringVarP(&proxyInputFile, "file", "f", "", "input file containing proxy URIs (one per line)")
	proxyCmd.PersistentFlags().IntVarP(&proxyConcurrency, "concurrency", "c", 8, "number of concurrent operations")
	proxyCmd.PersistentFlags().IntVar(&proxyTimeout, "timeout", 10, "per-operation timeout in seconds")

	proxySubscribeCmd.Flags().StringVarP(&proxyURL, "url", "u", "", "subscription URL")

	proxyTestCmd.Flags().Bool("speed-test", false, "run speed tests after connectivity check")
	proxyTestCmd.Flags().Bool("geoip", true, "perform GeoIP lookups on working proxies")
	proxyTestCmd.Flags().String("core", "auto", "core type to use: xray, singbox, auto")
	proxyTestCmd.Flags().String("core-path", "", "path to the core binary")

	proxyExportCmd.Flags().StringP("output", "o", "", "output file path")
	proxyExportCmd.Flags().String("format", "json", "export format (json, csv, clash, singbox)")

	proxyGenerateCmd.Flags().StringSlice("range", []string{}, "IP ranges or CIDRs to expand")
	proxyGenerateCmd.Flags().Int("sample", 0, "Number of IPs to sample per /24 block (0 for all)")
}

func runProxyGenerate(cmd *cobra.Command, args []string) error {
	baseURI := args[0]
	parsedBase, err := proxy.ParseProxyURI(baseURI)
	if err != nil {
		return fmt.Errorf("failed to parse base URI: %w", err)
	}

	ranges, _ := cmd.Flags().GetStringSlice("range")
	if len(ranges) == 0 {
		return fmt.Errorf("no --range specified")
	}

	sampleRate, _ := cmd.Flags().GetInt("sample")
	
	ips := diagnostics.GenerateCdnIPs(ranges, sampleRate)
	
	fmt.Printf("Generated %d configurations:\n", len(ips))
	for _, ip := range ips {
		// Robustly replace the host in the base URI without affecting path or parameters.
		host := parsedBase.Address
		var newURI string
		if parsedBase.Port > 0 {
			oldHostPort := fmt.Sprintf("%s:%d", host, parsedBase.Port)
			newHostPort := fmt.Sprintf("%s:%d", ip, parsedBase.Port)
			newURI = strings.Replace(baseURI, oldHostPort, newHostPort, 1)
		} else {
			// Fallback for URIs without explicit ports
			newURI = strings.Replace(baseURI, host, ip, 1)
		}
		
		fmt.Println(newURI)
	}
	
	return nil
}

// runProxyTest starts proxy connectivity and speed testing.
func runProxyTest(cmd *cobra.Command, args []string) error {
	proxies, err := loadProxyList(args)
	if err != nil {
		return err
	}
	if len(proxies) == 0 {
		return fmt.Errorf("no proxies to test")
	}

	speedTest, _ := cmd.Flags().GetBool("speed-test")
	geoIP, _ := cmd.Flags().GetBool("geoip")
	corePath, _ := cmd.Flags().GetString("core-path")
	coreStr, _ := cmd.Flags().GetString("core")

	coreType := proxy.CoreTypeAuto
	switch strings.ToLower(coreStr) {
	case "xray":
		coreType = proxy.CoreTypeXray
	case "singbox", "sing-box":
		coreType = proxy.CoreTypeSingBox
	}

	coreMgr := proxy.NewCoreManager(coreType, corePath)
	config := proxy.TestConfig{
		TestURLs:         []string{"http://cp.cloudflare.com/"},
		Timeout:          proxyTimeout,
		Concurrency:      proxyConcurrency,
		SpeedTestEnabled: speedTest,
		GeoIPEnabled:     geoIP,
		StabilityRuns:    1,
	}

	tester := proxy.NewProxyTester(config, coreMgr)
	ctx := context.Background()

	fmt.Printf("Testing %d proxies (concurrency=%d, timeout=%ds)...\n",
		len(proxies), proxyConcurrency, proxyTimeout)

	if err := tester.Start(ctx, proxies); err != nil {
		return fmt.Errorf("proxy test failed: %w", err)
	}

	results := tester.Results()
	working := 0
	for _, r := range results {
		if r != nil && r.Status == "working" {
			working++
			fmt.Printf("  ✓ %-50s latency=%.0fms score=%.1f\n",
				r.Proxy.String(), r.Latency, r.Score)
		}
	}

	fmt.Printf("\nResults: %d/%d working\n", working, len(proxies))
	return nil
}

// runProxyParse parses proxy URIs from args or input file.
func runProxyParse(cmd *cobra.Command, args []string) error {
	proxies, err := loadProxyList(args)
	if err != nil {
		return err
	}
	if len(proxies) == 0 {
		return fmt.Errorf("no proxy URIs to parse")
	}

	data, err := json.MarshalIndent(proxies, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

// runProxySubscribe fetches and parses a proxy subscription URL.
func runProxySubscribe(cmd *cobra.Command, args []string) error {
	subURL := args[0]
	if subURL == "" {
		subURL = proxyURL
	}
	if subURL == "" {
		return fmt.Errorf("subscription URL is required")
	}

	fmt.Printf("Fetching subscription: %s\n", subURL)
	ctx := context.Background()

	proxies, err := proxy.FetchSubscription(ctx, subURL)
	if err != nil {
		return fmt.Errorf("subscription fetch failed: %w", err)
	}

	fmt.Printf("Parsed %d proxies from subscription\n", len(proxies))

	data, err := json.MarshalIndent(proxies, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

// runProxyExport exports proxy configurations to the specified format.
func runProxyExport(cmd *cobra.Command, args []string) error {
	proxies, err := loadProxyList(args)
	if err != nil {
		return err
	}
	if len(proxies) == 0 {
		return fmt.Errorf("no proxies to export")
	}

	format, _ := cmd.Flags().GetString("format")
	outputFile, _ := cmd.Flags().GetString("output")

	var data []byte
	switch strings.ToLower(format) {
	case "json":
		data, err = json.MarshalIndent(proxies, "", "  ")
	case "clash":
		data, err = exportClash(proxies)
	case "singbox":
		data, err = exportSingBox(proxies)
	case "csv":
		data, err = exportCSVProxies(proxies)
	default:
		return fmt.Errorf("unsupported export format: %s", format)
	}

	if err != nil {
		return fmt.Errorf("export failed: %w", err)
	}

	if outputFile != "" {
		if err := os.WriteFile(outputFile, data, 0644); err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
		fmt.Printf("Exported %d proxies to %s (%s format)\n", len(proxies), outputFile, format)
	} else {
		fmt.Println(string(data))
	}
	return nil
}

// --- Helpers ---

// loadProxyList loads proxy URIs from args and/or input file.
func loadProxyList(args []string) ([]*proxy.ProxyConfig, error) {
	var uris []string

	// From args
	for _, a := range args {
		for _, line := range strings.Split(a, "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				uris = append(uris, line)
			}
		}
	}

	// From file
	if proxyInputFile != "" {
		data, err := os.ReadFile(proxyInputFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read input file: %w", err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				uris = append(uris, line)
			}
		}
	}

	if len(uris) == 0 {
		return nil, nil
	}

	var proxies []*proxy.ProxyConfig
	for _, uri := range uris {
		cfg, err := proxy.ParseProxyURI(uri)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to parse %q: %v\n", uri, err)
			continue
		}
		proxies = append(proxies, cfg)
	}

	return proxies, nil
}

func exportClash(proxies []*proxy.ProxyConfig) ([]byte, error) {
	var clashProxies []map[string]interface{}
	for _, p := range proxies {
		m := map[string]interface{}{
			"name":   p.Name,
			"type":   string(p.Protocol),
			"server": p.Address,
			"port":   p.Port,
		}
		if p.UUID != "" {
			m["uuid"] = p.UUID
		}
		if p.Password != "" {
			m["password"] = p.Password
		}
		if p.Method != "" {
			m["cipher"] = p.Method
		}
		clashProxies = append(clashProxies, m)
	}
	config := map[string]interface{}{
		"proxies": clashProxies,
	}
	return json.MarshalIndent(config, "", "  ")
}

func exportSingBox(proxies []*proxy.ProxyConfig) ([]byte, error) {
	var outbounds []map[string]interface{}
	for _, p := range proxies {
		m := map[string]interface{}{
			"type":        string(p.Protocol),
			"tag":         p.Name,
			"server":      p.Address,
			"server_port": p.Port,
		}
		if p.UUID != "" {
			m["uuid"] = p.UUID
		}
		if p.Password != "" {
			m["password"] = p.Password
		}
		outbounds = append(outbounds, m)
	}
	config := map[string]interface{}{
		"outbounds": outbounds,
	}
	return json.MarshalIndent(config, "", "  ")
}

func exportCSVProxies(proxies []*proxy.ProxyConfig) ([]byte, error) {
	var sb strings.Builder
	sb.WriteString("protocol,name,address,port,uuid,password,method,transport,tls\n")
	for _, p := range proxies {
		sb.WriteString(fmt.Sprintf("%s,%s,%s,%d,%s,%s,%s,%s,%v\n",
			p.Protocol, p.Name, p.Address, p.Port,
			p.UUID, p.Password, p.Method, p.Transport, p.TLS))
	}
	return []byte(sb.String()), nil
}
