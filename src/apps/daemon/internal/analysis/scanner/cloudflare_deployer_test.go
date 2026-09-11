package scanner

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

func TestDeployWorkerScriptRejectsExistingWorker(t *testing.T) {
	deployer := NewCloudflareDeployer()
	var putCalls atomic.Int32
	deployer.client.Transport = scannerRoundTripperFunc(func(req *http.Request) (*http.Response, error) {
		switch req.Method {
		case http.MethodGet:
			return scannerResponse(http.StatusOK, "existing script"), nil
		case http.MethodPut:
			putCalls.Add(1)
			return scannerResponse(http.StatusNoContent, ""), nil
		default:
			t.Fatalf("unexpected method %s", req.Method)
			return nil, nil
		}
	})

	err := deployer.DeployWorkerScript(context.Background(), "user@example.com", "token", "account", "worker", "new script")
	if err == nil || !strings.Contains(err.Error(), "refusing implicit replacement") {
		t.Fatalf("DeployWorkerScript() error = %v, want replacement refusal", err)
	}
	if putCalls.Load() != 0 {
		t.Fatalf("PUT calls=%d, want 0 for existing Worker", putCalls.Load())
	}
}

func TestDeployWorkerScriptRejectsMismatchedReadback(t *testing.T) {
	deployer := NewCloudflareDeployer()
	var getCalls atomic.Int32
	deployer.client.Transport = scannerRoundTripperFunc(func(req *http.Request) (*http.Response, error) {
		switch req.Method {
		case http.MethodGet:
			if getCalls.Add(1) == 1 {
				return scannerResponse(http.StatusNotFound, "missing"), nil
			}
			return scannerResponse(http.StatusOK, "different script"), nil
		case http.MethodPut:
			return scannerResponse(http.StatusNoContent, ""), nil
		default:
			t.Fatalf("unexpected method %s", req.Method)
			return nil, nil
		}
	})

	err := deployer.DeployWorkerScript(context.Background(), "user@example.com", "token", "account", "worker", "submitted script")
	if err == nil || !strings.Contains(err.Error(), "readback did not match") {
		t.Fatalf("DeployWorkerScript() error = %v, want readback mismatch", err)
	}
}
