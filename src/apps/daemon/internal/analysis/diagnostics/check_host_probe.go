package diagnostics

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// checkHostRequestIDPattern restricts the opaque request ID returned by the
// Check-Host API before it is interpolated into a polling URL. IDs that do
// not match are rejected rather than passed through to URL construction.
var checkHostRequestIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// checkHostBodyLimit caps each Check-Host response body read so a hostile or
// misbehaving upstream cannot exhaust daemon memory.
const checkHostBodyLimit = 1 << 20 // 1 MiB

// readCappedBody reads an upstream Check-Host response bounded to
// checkHostBodyLimit bytes, rejecting bodies that exceed the cap instead of
// silently truncating them.
func readCappedBody(r io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, checkHostBodyLimit+1))
	if err != nil {
		return nil, err
	}
	if len(body) > checkHostBodyLimit {
		return nil, fmt.Errorf("check-host response exceeds %d bytes", checkHostBodyLimit)
	}
	return body, nil
}

// CanonicalIranNodes contains the default Check-Host edge nodes located inside Iran.
var CanonicalIranNodes = []string{
	"ir1.node.check-host.net",
	"ir2.node.check-host.net",
	"ir3.node.check-host.net",
	"ir5.node.check-host.net",
	"ir6.node.check-host.net",
	"ir7.node.check-host.net",
	"ir8.node.check-host.net",
}

// CensorshipVerdict represents the reachability classification for a host under inspection.
type CensorshipVerdict string

const (
	VerdictClean         CensorshipVerdict = "clean"
	VerdictFiltered      CensorshipVerdict = "filtered"
	VerdictHighLoss      CensorshipVerdict = "high_loss"
	VerdictDegraded      CensorshipVerdict = "degraded"
	VerdictIndeterminate CensorshipVerdict = "indeterminate"
)

// NodeProbeResult captures the outcome reported by an individual vantage node.
type NodeProbeResult struct {
	Node       string   `json:"node"`
	Responsive bool     `json:"responsive"`
	RTTMs      *float64 `json:"rtt_ms,omitempty"`
	Error      string   `json:"error,omitempty"`
	ExtraInfo  string   `json:"extra_info,omitempty"`
}

// CheckHostAssessment aggregates vantage node telemetry into a cohesive verdict.
type CheckHostAssessment struct {
	Target          string                     `json:"target"`
	Method          string                     `json:"method"`
	Verdict         CensorshipVerdict          `json:"verdict"`
	TotalNodes      int                        `json:"total_nodes"`
	ResponsiveNodes int                        `json:"responsive_nodes"`
	BlockedNodes    int                        `json:"blocked_nodes"`
	AvgRTTMs        *float64                   `json:"avg_rtt_ms,omitempty"`
	NodeResults     map[string]NodeProbeResult `json:"node_results"`
	IsReady         bool                       `json:"is_ready"`
}

// BuildCheckHostURL generates the initiation query URL for Check-Host API.
func BuildCheckHostURL(target, method string, nodes []string) (string, error) {
	method = strings.ToLower(strings.TrimSpace(method))
	switch method {
	case "http", "ping", "dns":
	default:
		return "", fmt.Errorf("unsupported probe method: %s", method)
	}

	if len(nodes) == 0 {
		nodes = CanonicalIranNodes
	}

	u, err := url.Parse("https://check-host.net/check-" + method)
	if err != nil {
		return "", fmt.Errorf("build check-host URL: %w", err)
	}
	q := u.Query()
	q.Set("host", target)
	for _, n := range nodes {
		q.Add("node", strings.TrimSpace(n))
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// BuildResultURL constructs the polling URL for a pending check request ID.
// It rejects IDs that do not match the opaque token grammar rather than
// interpolating arbitrary upstream-controlled text into the URL.
func BuildResultURL(requestID string) (string, error) {
	if !checkHostRequestIDPattern.MatchString(requestID) {
		return "", fmt.Errorf("check-host returned invalid request_id %q", requestID)
	}
	return "https://check-host.net/check-result/" + requestID, nil
}

// ParseInitiateResponse parses the JSON returned from check-host initiation.
func ParseInitiateResponse(data []byte) (string, error) {
	var resp struct {
		OK        int    `json:"ok"`
		RequestID string `json:"request_id"`
		Error     string `json:"error"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return "", fmt.Errorf("failed to parse initiate response: %w", err)
	}
	if resp.Error != "" {
		return "", fmt.Errorf("check-host initiation error: %s", resp.Error)
	}
	if resp.RequestID == "" {
		return "", fmt.Errorf("no request_id present in response")
	}
	return resp.RequestID, nil
}

// EvaluateVerdict computes the censorship verdict given responsiveness and loss rates.
func EvaluateVerdict(responsive, total int, avgLossPct float64) CensorshipVerdict {
	if total == 0 {
		return VerdictIndeterminate
	}
	ratio := float64(responsive) / float64(total)
	if responsive == 0 || ratio <= 0.35 {
		return VerdictFiltered
	}
	if ratio >= 0.75 {
		if avgLossPct > 40.0 {
			return VerdictHighLoss
		}
		if avgLossPct > 15.0 {
			return VerdictDegraded
		}
		return VerdictClean
	}
	return VerdictDegraded
}

// ParseResultResponse parses the check-host polling JSON payload.
func ParseResultResponse(data []byte, target, method string) (*CheckHostAssessment, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse result response: %w", err)
	}

	results := make(map[string]NodeProbeResult)
	responsiveCount := 0
	blockedCount := 0
	var rttSum float64
	rttCount := 0
	var totalLossSum float64
	anyPending := false

	method = strings.ToLower(strings.TrimSpace(method))

	for nodeName, val := range raw {
		if val == nil {
			anyPending = true
			continue
		}

		res := NodeProbeResult{
			Node: nodeName,
		}

		switch method {
		case "ping":
			// Ping format: [[[status, rtt], ...]]
			if outerArr, ok := val.([]interface{}); ok {
				var samples []float64
				for _, item := range outerArr {
					if innerArr, ok := item.([]interface{}); ok {
						for _, sample := range innerArr {
							if sampleArr, ok := sample.([]interface{}); ok && len(sampleArr) >= 2 {
								status, _ := sampleArr[0].(string)
								if status == "OK" {
									if rttSec, ok := sampleArr[1].(float64); ok {
										samples = append(samples, rttSec*1000.0)
									}
								} else if res.Error == "" {
									res.Error = status
								}
							}
						}
					}
				}
				if len(samples) > 0 {
					res.Responsive = true
					var sum float64
					for _, s := range samples {
						sum += s
					}
					avg := sum / float64(len(samples))
					res.RTTMs = &avg
					rttSum += avg
					rttCount++
					res.ExtraInfo = fmt.Sprintf("samples: %d", len(samples))
				} else {
					totalLossSum += 100.0
				}
			}
		case "http":
			// HTTP format: [[ok_flag, rtt_sec, phrase, status_code, ip]]
			if arr, ok := val.([]interface{}); ok && len(arr) > 0 {
				if attempt, ok := arr[0].([]interface{}); ok && len(attempt) >= 3 {
					okFlag, _ := attempt[0].(float64)
					rttSec, _ := attempt[1].(float64)
					phrase, _ := attempt[2].(string)
					statusCode := ""
					if len(attempt) >= 4 && attempt[3] != nil {
						statusCode = fmt.Sprintf("%v", attempt[3])
					}
					ip := ""
					if len(attempt) >= 5 && attempt[4] != nil {
						ip = fmt.Sprintf("%v", attempt[4])
					}

					if okFlag == 1 {
						res.Responsive = true
						ms := rttSec * 1000.0
						res.RTTMs = &ms
						rttSum += ms
						rttCount++
						res.ExtraInfo = fmt.Sprintf("HTTP %s (%s) -> %s", statusCode, phrase, ip)
					} else {
						if phrase != "" {
							res.Error = phrase
						} else {
							res.Error = "Connection timeout or reset"
						}
						totalLossSum += 100.0
					}
				}
			}
		case "dns":
			// DNS format: [{"A": ["ip1", "ip2"], "TTL": 300}]
			if arr, ok := val.([]interface{}); ok && len(arr) > 0 {
				if dnsMap, ok := arr[0].(map[string]interface{}); ok {
					if aRecords, ok := dnsMap["A"].([]interface{}); ok && len(aRecords) > 0 {
						res.Responsive = true
						var ips []string
						for _, r := range aRecords {
							if s, ok := r.(string); ok {
								ips = append(ips, s)
							}
						}
						res.ExtraInfo = fmt.Sprintf("A: %s", strings.Join(ips, ", "))
					}
				}
			}
			if !res.Responsive {
				res.Error = "DNS resolution timed out or NXDOMAIN"
				totalLossSum += 100.0
			}
		}

		if res.Responsive {
			responsiveCount++
		} else {
			blockedCount++
		}
		results[nodeName] = res
	}

	evaluated := responsiveCount + blockedCount
	avgLoss := 0.0
	if evaluated > 0 {
		avgLoss = totalLossSum / float64(evaluated)
	}

	var avgRTT *float64
	if rttCount > 0 {
		mean := rttSum / float64(rttCount)
		avgRTT = &mean
	}

	verdict := EvaluateVerdict(responsiveCount, evaluated, avgLoss)

	return &CheckHostAssessment{
		Target:          target,
		Method:          method,
		Verdict:         verdict,
		TotalNodes:      evaluated,
		ResponsiveNodes: responsiveCount,
		BlockedNodes:    blockedCount,
		AvgRTTMs:        avgRTT,
		NodeResults:     results,
		IsReady:         !anyPending && evaluated > 0,
	}, nil
}

// ExecuteCheckHostProbe executes the initiation call and polls Check-Host until complete or timeout.
func ExecuteCheckHostProbe(ctx context.Context, client *http.Client, target, method string, nodes []string, maxPollSeconds int) (*CheckHostAssessment, error) {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	initURL, err := BuildCheckHostURL(target, method, nodes)
	if err != nil {
		return nil, err
	}

	// Bound every network round-trip regardless of the caller-supplied
	// client's own timeout configuration; a zero-timeout client must not be
	// able to hang the probe indefinitely.
	initCtx, initCancel := context.WithTimeout(ctx, 10*time.Second)
	req, err := http.NewRequestWithContext(initCtx, http.MethodGet, initURL, nil)
	if err != nil {
		initCancel()
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		initCancel()
		return nil, fmt.Errorf("check-host initiate failed: %w", err)
	}
	body, err := readCappedBody(resp.Body)
	resp.Body.Close()
	initCancel()
	if err != nil {
		return nil, fmt.Errorf("failed to read initiate body: %w", err)
	}

	reqID, err := ParseInitiateResponse(body)
	if err != nil {
		return nil, err
	}

	resultURL, err := BuildResultURL(reqID)
	if err != nil {
		return nil, err
	}
	if maxPollSeconds <= 0 {
		maxPollSeconds = 30
	}

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	timeoutChan := time.After(time.Duration(maxPollSeconds) * time.Second)

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timeoutChan:
			return nil, fmt.Errorf("timed out waiting for check-host results after %d seconds", maxPollSeconds)
		case <-ticker.C:
			pollCtx, pollCancel := context.WithTimeout(ctx, 10*time.Second)
			pollReq, err := http.NewRequestWithContext(pollCtx, http.MethodGet, resultURL, nil)
			if err != nil {
				pollCancel()
				continue
			}
			pollReq.Header.Set("Accept", "application/json")

			pollResp, err := client.Do(pollReq)
			if err != nil {
				pollCancel()
				continue
			}
			pollBody, err := readCappedBody(pollResp.Body)
			pollResp.Body.Close()
			pollCancel()
			if err != nil {
				continue
			}

			assessment, err := ParseResultResponse(pollBody, target, method)
			if err == nil && assessment != nil && assessment.IsReady {
				return assessment, nil
			}
		}
	}
}
