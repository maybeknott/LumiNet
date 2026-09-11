package fronting

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
)

// startFakeGASRelay stands in for script.google.com: accepts POSTed payloads
// and answers with a valid envelope. The TLS certificate is self-signed, so
// tests inject an InsecureSkipVerify transport via WithHTTPClient.
func startFakeGASRelay(t *testing.T) (*httptest.Server, *int64) {
	t.Helper()
	var hits int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		body := base64OrEmpty("OK")
		fmt.Fprintf(w, `{"s":200,"h":{"Content-Type":"text/plain"},"b":%q}`, body)
	}))
	t.Cleanup(server.Close)
	return server, &hits
}

func base64OrEmpty(s string) string {
	return b64(s)
}

// insecureClient builds an http.Client trusting any certificate — required to
// talk to the self-signed test server.
func insecureClient() *http.Client {
	return &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test-only
	}}
}

// TestRelayConcurrentDoExercisesFanout verifies the client's rotation logic
// under concurrency: many goroutines relaying through one Client must all
// succeed against a healthy deployment.
func TestRelayConcurrentDoExercisesFanout(t *testing.T) {
	if testing.Short() {
		t.Skip("relay fanout exercise skipped in -short mode")
	}
	server, hits := startFakeGASRelay(t)
	client := NewClient("test-key", []string{"only-deployment"},
		WithEndpoint(server.URL), WithHTTPClient(insecureClient()))
	const workers = 8
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := range workers {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			result, err := client.Do(context.Background(), http.MethodGet,
				fmt.Sprintf("https://target.example/ping?worker=%d", n), nil, nil)
			if err != nil {
				errs <- err
				return
			}
			if result.Status != 200 {
				errs <- fmt.Errorf("status %d", result.Status)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("worker failed: %v", err)
	}
	if atomic.LoadInt64(hits) < int64(workers) {
		t.Fatalf("relay hits = %d, want >= %d", atomic.LoadInt64(hits), workers)
	}
}

// Benchmarks capture transport-suite shapes: sequential H1 baseline vs
// concurrent fronted requests. Run with `go test -bench . -run xxx`.
func BenchmarkRelaySequential(b *testing.B) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"s":200,"h":{},"b":""}`)
	}))
	defer server.Close()
	client := NewClient("k", []string{"dep"}, WithEndpoint(server.URL), WithHTTPClient(insecureClient()))
	ctx := context.Background()
	b.ResetTimer()
	for b.Loop() {
		if _, err := client.Do(ctx, http.MethodGet, "https://target.example/", nil, nil); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRelayConcurrent8(b *testing.B) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"s":200,"h":{},"b":""}`)
	}))
	defer server.Close()
	client := NewClient("k", []string{"dep"}, WithEndpoint(server.URL), WithHTTPClient(insecureClient()))
	ctx := context.Background()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := client.Do(ctx, http.MethodGet, "https://target.example/", nil, nil); err != nil {
				b.Fatal(err)
			}
		}
	})
}
