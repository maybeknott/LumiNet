package scanner

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

func TestDeployWorkerScriptRetriesIdempotentUploadAndVerifiesReadback(t *testing.T) {
	deployer := NewCloudflareDeployer()
	const script = "export default {}"
	var getCalls atomic.Int32
	var putCalls atomic.Int32
	deployer.client.Transport = scannerRoundTripperFunc(func(req *http.Request) (*http.Response, error) {
		switch req.Method {
		case http.MethodGet:
			if getCalls.Add(1) == 1 {
				return scannerResponse(http.StatusNotFound, "missing"), nil
			}
			return scannerResponse(http.StatusOK, script), nil
		case http.MethodPut:
			if putCalls.Add(1) == 1 {
				resp := scannerResponse(http.StatusServiceUnavailable, "later")
				resp.Header.Set("Retry-After", "0")
				return resp, nil
			}
			return scannerResponse(http.StatusNoContent, ""), nil
		default:
			t.Fatalf("method=%s, want GET or PUT", req.Method)
			return nil, nil
		}
	})

	if err := deployer.DeployWorkerScript(context.Background(), "user@example.com", "token", "account", "worker", script); err != nil {
		t.Fatalf("DeployWorkerScript() error = %v", err)
	}
	if putCalls.Load() != 2 {
		t.Fatalf("PUT calls=%d, want 2", putCalls.Load())
	}
	if getCalls.Load() != 2 {
		t.Fatalf("GET calls=%d, want preflight + readback", getCalls.Load())
	}
}

type scannerRoundTripperFunc func(*http.Request) (*http.Response, error)

func (f scannerRoundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func scannerResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}
