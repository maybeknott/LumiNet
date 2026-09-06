package fronting

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestBuildRequestPayloadRejectsRelayLoop(t *testing.T) {
	if _, err := BuildRequestPayload("key", "GET", "https://script.google.com/macros/s/abc/exec", nil, nil); err == nil {
		t.Fatal("expected relay-loop rejection")
	}
	payload, err := BuildRequestPayload("key", "get", "https://example.com/", map[string]string{"x": "y"}, []byte("body"))
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["m"] != "GET" {
		t.Fatalf("method should be uppercased, got %v", decoded["m"])
	}
	if decoded["b"] == "" {
		t.Fatal("body should be base64-encoded")
	}
}

func TestClassifyRelayErrorFamilies(t *testing.T) {
	cases := map[string]string{
		"Service invoked too many times":        ErrCategoryQuota,
		"Authorization is required to perform":  ErrCategoryAuth,
		"Error code Not_Found":                  ErrCategoryDeploy,
		"Server not available. please retry":    ErrCategoryTransient,
		"UrlFetch calls are not permitted":       ErrCategoryQuota, // upstream quota family matches first
		"Apiary is disabled. please contact":     ErrCategoryAdmin,
		"Connection refused to exit node":       ErrCategoryExitNode,
		"something entirely novel happened":     ErrCategoryGeneric,
	}
	for raw, want := range cases {
		if got := ClassifyRelayError(raw); got != want {
			t.Errorf("ClassifyRelayError(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestScriptIDRotatorBlacklistFallback(t *testing.T) {
	rotator := NewScriptIDRotator([]string{"a", "b", "c"}, 50*1e6) // ~50ms ttl via ns
	rotator.Blacklist("a")
	rotator.Blacklist("b")
	if got := rotator.Healthy(); got != 1 {
		t.Fatalf("healthy = %d, want 1", got)
	}
	for range 10 {
		if sid := rotator.Next(); sid != "c" {
			t.Fatalf("expected only c while a,b blacklisted, got %q", sid)
		}
	}
	time.Sleep(60 * time.Millisecond)
	if rotator.Healthy() != 3 {
		t.Fatal("blacklist should expire after ttl")
	}
}

func TestBuildSNIPoolGoogleExpansionAndOverrides(t *testing.T) {
	pool := BuildSNIPool("www.google.com", nil)
	if len(pool) < 3 || pool[0] != "www.google.com" {
		t.Fatalf("google expansion wrong: %v", pool)
	}
	pool = BuildSNIPool("whatever.example", []string{"Front.Example.", "front.example"})
	if len(pool) != 1 || pool[0] != "front.example" {
		t.Fatalf("override pool wrong: %v", pool)
	}
	if got := BuildSNIPool("", nil); len(got) != 1 || got[0] != "www.google.com" {
		t.Fatalf("empty front default wrong: %v", got)
	}
}

func TestRenderRawResponseEnvelopeDecode(t *testing.T) {
	// envelope: 200 OK, gzip body "hello world", set-cookie split across array
	envJSON := `{
	  "s": 200,
	  "h": {"Content-Type": "text/plain", "Set-Cookie": ["a=1; Path=/; Expires=Wed, 21 Oct 2025 07:28:00 GMT", "b=2"], "X-Multi": ["one", "two"]},
	  "b": "` + b64Gzip("hello world") + `",
	  "gz": 1
	}`
	env, err := ParseEnvelope([]byte(envJSON))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := RenderRawResponse(env, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.HasPrefix(text, "HTTP/1.1 200 OK\r\n") {
		t.Fatalf("missing status line: %q", text[:40])
	}
	if !strings.Contains(text, "Content-Length: 11\r\n") {
		t.Fatal("content-length mismatch")
	}
	if strings.Count(text, "Set-Cookie:") != 2 {
		t.Fatal("set-cookie values not split")
	}
	if strings.Contains(text, "Expires=Wed, 21") && !strings.Contains(text, "Expires=Wed, 21 Oct 2025 07:28:00 GMT") {
		t.Fatal("expires date comma must stay intact")
	}
	if !strings.HasSuffix(text, "hello world") {
		t.Fatal("body not reconstructed (gzip decode failed)")
	}
}

func TestRenderRawResponseCap(t *testing.T) {
	env, _ := ParseEnvelope([]byte(`{"s":200,"h":{},"b":"` + b64("aaaa") + `"}`))
	if _, err := RenderRawResponse(env, 2); err == nil {
		t.Fatal("expected cap violation")
	}
}

// helpers

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func b64Gzip(s string) string {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, _ = w.Write([]byte(s))
	_ = w.Close()
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}
