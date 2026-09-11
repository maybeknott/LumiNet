package fronting

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// defaultGASEndpoint is the production Apps Script frontend. Tests override it
// via WithEndpoint to point at an httptest server.
const defaultGASEndpoint = "https://script.google.com"

// Client relays HTTP requests through Google Apps Script deployments using
// domain fronting: the TLS SNI and dial address are a Google frontend while
// the HTTP Host/URL target script.google.com. Deployments that fail with
// quota/deploy-class errors are blacklisted for their TTL and retried on the
// next rotation, mirroring domain_fronter.py retry lineage.
type Client struct {
	AuthKey    string
	Rotator    *ScriptIDRotator
	SNIPool    []string
	DialIPs    []string // optional pinned Google frontend IPs (round-robin)
	HL         string   // Apps Script UI language query param, defaults "en"
	Attempts   int      // max SID rotations per logical request, default 3
	Timeout    time.Duration
	Endpoint   string // overrides defaultGASEndpoint (tests)
	client     *http.Client
	sniIdx     atomic.Uint64
	ipIdx      atomic.Uint64
}

// WithEndpoint overrides the Apps Script frontend origin (tests).
func WithEndpoint(endpoint string) Option {
	return func(c *Client) { c.Endpoint = strings.TrimRight(endpoint, "/") }
}

// Option mutates Client construction.
type Option func(*Client)

// WithHTTPClient overrides the underlying HTTP client (tests inject stubs).
func WithHTTPClient(hc *http.Client) Option { return func(c *Client) { c.client = hc } }

// NewClient builds a fronted relay client.
func NewClient(authKey string, scriptIDs []string, opts ...Option) *Client {
	c := &Client{
		AuthKey:  authKey,
		Rotator:  NewScriptIDRotator(scriptIDs, 0),
		SNIPool:  append([]string(nil), FrontSNIPoolGoogle...),
		HL:       "en",
		Attempts: 3,
		Timeout:  45 * time.Second,
		client: &http.Client{
			Timeout: 45 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:       32,
				IdleConnTimeout:     90 * time.Second,
				TLSHandshakeTimeout: 15 * time.Second,
			},
		},
	}
	for _, opt := range opts {
		opt(c)
	}
	if len(c.SNIPool) == 0 {
		c.SNIPool = BuildSNIPool("", nil)
	}
	if c.DialIPs != nil || true {
		// transport-level SNI/dial override installed below
	}
	transport := c.client.Transport.(*http.Transport).Clone()
	sniPool := c.SNIPool
	dialIPs := c.DialIPs
	var idx uint64
	transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		_ = host
		sni := sniPool[int(atomic.AddUint64(&idx, 1))%len(sniPool)]
		dialAddr := net.JoinHostPort(host, port)
		if len(dialIPs) > 0 {
			dialAddr = net.JoinHostPort(dialIPs[int(c.ipIdx.Add(1))%len(dialIPs)], port)
		}
		conn, err := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, network, dialAddr)
		if err != nil {
			return nil, err
		}
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true, // fronting: certificate belongs to the real host behind the frontend IP
			MinVersion:         tls.VersionTLS12,
		})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, err
		}
		return tlsConn, nil
	}
	c.client.Transport = transport
	return c
}

// RelayResult captures one logical relay attempt outcome.
type RelayResult struct {
	RawResponse []byte        // reconstructed raw HTTP response bytes for the target
	Status      int           // target HTTP status
	SID         string        // deployment ID that served the request
	ErrorClass  string        // classified failure category when Err != nil
	Err         error
	Latency     time.Duration
}

// Do relays a single logical request, rotating deployment IDs across attempts.
// Quota/deploy/transient classified envelope errors trigger SID blacklisting;
// auth/admin errors are terminal (rotating would not help).
func (c *Client) Do(ctx context.Context, method, targetURL string, headers map[string]string, body []byte) (*RelayResult, error) {
	attempts := c.Attempts
	if attempts < 1 {
		attempts = 1
	}
	var last *RelayResult
	for attempt := 0; attempt < attempts; attempt++ {
		sid := c.Rotator.Next()
		if sid == "" {
			return nil, fmt.Errorf("fronting: no script ids configured")
		}
		result := c.doOnce(ctx, sid, method, targetURL, headers, body)
		last = result
		if result.Err == nil {
			return result, nil
		}
		switch result.ErrorClass {
		case ErrCategoryQuota, ErrCategoryDeploy, ErrCategoryTransient:
			c.Rotator.Blacklist(sid)
			continue
		default:
			return result, nil
		}
	}
	return last, nil
}

func (c *Client) doOnce(ctx context.Context, sid, method, targetURL string, headers map[string]string, body []byte) *RelayResult {
	result := &RelayResult{SID: sid}
	payload, err := BuildRequestPayload(c.AuthKey, method, targetURL, headers, body)
	if err != nil {
		result.Err = err
		return result
	}
	base := c.Endpoint
	if base == "" {
		base = defaultGASEndpoint
	}
	endpoint := fmt.Sprintf("%s/macros/s/%s/exec?hl=%s", base, sid, c.hl())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		result.Err = err
		return result
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Length", strconv.Itoa(len(payload)))

	start := time.Now()
	resp, err := c.client.Do(req)
	result.Latency = time.Since(start)
	if err != nil {
		result.Err = fmt.Errorf("fronting transport: %w", err)
		result.ErrorClass = ErrCategoryTransient
		return result
	}
	defer resp.Body.Close()

	envelopeBytes := new(bytes.Buffer)
	if _, err := envelopeBytes.ReadFrom(resp.Body); err != nil && ctx.Err() == nil {
		result.Err = fmt.Errorf("fronting read body: %w", err)
		result.ErrorClass = ErrCategoryTransient
		return result
	}
	envelope, err := ParseEnvelope(envelopeBytes.Bytes())
	if err != nil {
		result.Err = err
		result.ErrorClass = ErrCategoryGeneric
		return result
	}
	if envelope.IsError() {
		class := ClassifyRelayError(envelope.Error)
		result.ErrorClass = class
		result.Err = fmt.Errorf("relay error (%s): %s", class, envelope.Error)
		return result
	}
	raw, err := RenderRawResponse(envelope, 8<<20)
	if err != nil {
		result.Err = err
		result.ErrorClass = ErrCategoryGeneric
		return result
	}
	result.RawResponse = raw
	result.Status = envelope.Status
	return result
}

func (c *Client) hl() string {
	if c.HL == "" {
		return "en"
	}
	return c.HL
}
