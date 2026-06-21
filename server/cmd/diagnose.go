package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/maybeknott/luminet/internal/diagnostics"
	"github.com/spf13/cobra"
)

// diagPhases is a comma-separated list of phases to run (1-6).
var diagPhases string

// diagOutput is the output file path for diagnostic report.
var diagOutput string

// diagJSON enables JSON output for the diagnostic report.
var diagJSON bool

// diagnoseCmd runs the 8-phase network diagnostic pipeline.
var diagnoseCmd = &cobra.Command{
	Use:   "diagnose",
	Short: "Run the 8-phase network diagnostic pipeline",
	Long: `Runs a comprehensive network diagnostic that covers:
  Phase 1: Basic connectivity (ping gateway and internet)
  Phase 2: DNS resolver analysis
  Phase 3: TLS handshake inspection
  Phase 4: HTTP response and captive portal detection
  Phase 5: SNI blocking detection
  Phase 6: Speed test
  Phase 7: Reliable UDP ARQ sliding window benchmark
  Phase 8: Browser Fingerprinting & Anti-Fingerprint Audit`,
	RunE: runDiagnose,
}

func init() {
	rootCmd.AddCommand(diagnoseCmd)

	diagnoseCmd.Flags().StringVar(&diagPhases, "phases", "1,2,3,4,5,6,7,8", "comma-separated phases to run (1-8)")
	diagnoseCmd.Flags().StringVarP(&diagOutput, "output", "o", "", "output file path for the diagnostic report")
	diagnoseCmd.Flags().BoolVar(&diagJSON, "json", false, "output diagnostic report as JSON")
}

// phaseDefinitions maps phase numbers to their diagnostic jobs.
var phaseDefinitions = map[int]diagnostics.DiagnosticJob{
	1: {Type: diagnostics.MetricPing, Target: "8.8.8.8:53", Timeout: 5 * time.Second,
		Options: map[string]string{"description": "Connectivity — ping Google DNS"}},
	2: {Type: diagnostics.MetricDNS, Target: "google.com", Timeout: 5 * time.Second,
		Options: map[string]string{"server": "8.8.8.8", "description": "DNS — resolve google.com via 8.8.8.8"}},
	3: {Type: diagnostics.MetricHTTP, Target: "https://www.google.com", Timeout: 10 * time.Second,
		Options: map[string]string{"description": "TLS/HTTP — HTTPS request to google.com"}},
	4: {Type: diagnostics.MetricHTTP, Target: "http://connectivitycheck.gstatic.com/generate_204", Timeout: 5 * time.Second,
		Options: map[string]string{"description": "HTTP — captive portal detection"}},
	5: {Type: diagnostics.MetricHTTP, Target: "https://github.com", Timeout: 10 * time.Second,
		Options: map[string]string{"description": "SNI — HTTPS to github.com (SNI probe)"}},
	6: {Type: diagnostics.MetricSpeedTest, Target: "http://speedtest.tele2.net/1MB.zip", Timeout: 30 * time.Second,
		Options: map[string]string{"description": "Speed — download throughput test"}},
	7: {Type: diagnostics.MetricARQ, Target: "loopback", Timeout: 10 * time.Second,
		Options: map[string]string{"description": "Reliability — ARQ sliding window UDP benchmark"}},
	8: {Type: diagnostics.MetricStealth, Target: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36", Timeout: 5 * time.Second,
		Options: map[string]string{"description": "Stealth — Browser Fingerprint & Anti-Fingerprint Audit"}},
}

// runDiagnose initializes and runs the diagnostic pipeline.
func runDiagnose(cmd *cobra.Command, args []string) error {
	// Parse phases
	phases := parsePhases(diagPhases)
	if len(phases) == 0 {
		return fmt.Errorf("no valid phases specified")
	}

	pipeline := diagnostics.NewPipeline()
	ctx := context.Background()

	type phaseReport struct {
		Phase      int                           `json:"phase"`
		Name       string                        `json:"name"`
		Status     string                        `json:"status"`
		DurationMs float64                       `json:"duration_ms"`
		Result     *diagnostics.DiagnosticResult `json:"result,omitempty"`
		Error      string                        `json:"error,omitempty"`
	}

	var report []phaseReport
	overallStart := time.Now()

	for _, phase := range phases {
		jobDef, ok := phaseDefinitions[phase]
		if !ok {
			continue
		}

		desc := jobDef.Options["description"]
		if !diagJSON {
			fmt.Printf("Phase %d: %s ... ", phase, desc)
		}

		start := time.Now()
		result, err := pipeline.Run(ctx, &jobDef)
		elapsed := time.Since(start).Seconds() * 1000.0

		pr := phaseReport{
			Phase:      phase,
			Name:       desc,
			DurationMs: elapsed,
		}

		if err != nil {
			pr.Status = "error"
			pr.Error = err.Error()
			if !diagJSON {
				fmt.Printf("ERROR: %v\n", err)
			}
		} else {
			result.JobID = fmt.Sprintf("phase-%d", phase)
			pr.Result = result
			if result.Success {
				pr.Status = "passed"
				if !diagJSON {
					fmt.Printf("PASSED (%.0fms) — %s\n", elapsed, result.RawOutput)
				}
			} else {
				pr.Status = "failed"
				if !diagJSON {
					fmt.Printf("FAILED (%.0fms) — %s\n", elapsed, result.RawOutput)
				}
			}
		}

		report = append(report, pr)
	}

	totalMs := time.Since(overallStart).Seconds() * 1000.0

	// Count results
	passed, failed, errors := 0, 0, 0
	for _, r := range report {
		switch r.Status {
		case "passed":
			passed++
		case "failed":
			failed++
		case "error":
			errors++
		}
	}

	summary := map[string]interface{}{
		"phases_run": len(report),
		"passed":     passed,
		"failed":     failed,
		"errors":     errors,
		"total_ms":   totalMs,
		"timestamp":  time.Now().UTC(),
	}

	if diagJSON {
		output := map[string]interface{}{
			"phases":  report,
			"summary": summary,
		}
		data, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			return err
		}
		if diagOutput != "" {
			return os.WriteFile(diagOutput, data, 0644)
		}
		fmt.Println(string(data))
		return nil
	}

	fmt.Printf("\n─── Summary ───────────────────────────────────────\n")
	fmt.Printf("  Phases run: %d  |  Passed: %d  |  Failed: %d  |  Errors: %d\n",
		len(report), passed, failed, errors)
	fmt.Printf("  Total time: %.0fms\n", totalMs)

	if diagOutput != "" {
		data, _ := json.MarshalIndent(map[string]interface{}{
			"phases":  report,
			"summary": summary,
		}, "", "  ")
		if err := os.WriteFile(diagOutput, data, 0644); err != nil {
			return fmt.Errorf("failed to write report: %w", err)
		}
		fmt.Printf("  Report saved to: %s\n", diagOutput)
	}

	return nil
}

func parsePhases(s string) []int {
	var phases []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		n, err := strconv.Atoi(part)
		if err == nil && n >= 1 && n <= 8 {
			phases = append(phases, n)
		}
	}
	return phases
}
