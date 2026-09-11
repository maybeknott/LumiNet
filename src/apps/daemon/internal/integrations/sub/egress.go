package sub

import (
	"context"
	"errors"
	"fmt"
	"github.com/maybeknott/luminet/internal/foundation/netpolicy"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

var (
	// ErrRemoteFetchDisabled prevents network egress unless a caller opts in.
	ErrRemoteFetchDisabled = errors.New("subscription remote fetch is disabled")
	// ErrUnsafeRemoteTarget identifies a URL that resolves to a non-public address.
	ErrUnsafeRemoteTarget = errors.New("subscription URL targets a non-public address")
	// ErrSubscriptionRedirectLimit identifies an excessive or cyclic redirect chain.
	ErrSubscriptionRedirectLimit = errors.New("subscription redirect policy rejected follow-up")
)

const (
	maxRemoteSubscriptionBytes int64 = 10 << 20
	maxSubscriptionRedirects         = 10
)

func readBoundedSubscriptionBody(r io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, maxRemoteSubscriptionBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxRemoteSubscriptionBytes {
		return nil, fmt.Errorf("subscription response exceeds %d bytes", maxRemoteSubscriptionBytes)
	}
	return body, nil
}

// EgressConfig configures the subscription-only remote fetch boundary.
type EgressConfig struct {
	Enabled bool
	Timeout time.Duration
	Resolve func(context.Context, string) ([]netip.Addr, error)
	// UserAgent overrides the default "LumiNet/1.0" header sent with every
	// fetch. Callers that fetch public web pages (e.g. Telegram channel
	// previews) can impersonate a browser; it must never carry credentials.
	UserAgent string
}

// EgressResponse is the bounded result of a validated remote fetch.
type EgressResponse struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

// Egress performs opt-in, SSRF-safe subscription fetches.
type Egress struct {
	enabled   bool
	timeout   time.Duration
	client    *http.Client
	resolve   func(context.Context, string) ([]netip.Addr, error)
	userAgent string
}

// NewEgress creates a subscription egress boundary. It is disabled by default.
func NewEgress(config EgressConfig) *Egress {
	timeout := config.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	resolve := config.Resolve
	if resolve == nil {
		resolve = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}
	}
	userAgent := config.UserAgent
	if userAgent == "" {
		userAgent = "LumiNet/1.0"
	}
	egress := &Egress{enabled: config.Enabled, timeout: timeout, resolve: resolve, userAgent: userAgent}
	dialer := &net.Dialer{Timeout: timeout}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		addresses, err := egress.resolvePublic(ctx, host)
		if err != nil {
			return nil, err
		}
		return dialer.DialContext(ctx, network, net.JoinHostPort(addresses[0].String(), port))
	}
	egress.client = &http.Client{Timeout: timeout, Transport: transport, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		// Supplying CheckRedirect disables net/http's default 10-follow-up guard,
		// so the subscription boundary must restore an explicit finite budget.
		if len(via) >= maxSubscriptionRedirects {
			return fmt.Errorf("%w: limit %d", ErrSubscriptionRedirectLimit, maxSubscriptionRedirects)
		}
		if err := egress.validateURL(req.Context(), req.URL); err != nil {
			return err
		}
		identity := subscriptionRedirectIdentity(req.URL)
		for _, previous := range via {
			if subscriptionRedirectIdentity(previous.URL) == identity {
				return fmt.Errorf("%w: loop to %s", ErrSubscriptionRedirectLimit, req.URL.Redacted())
			}
		}
		if len(via) > 0 && !sameSubscriptionOrigin(via[0].URL, req.URL) {
			req.Header.Del("If-None-Match")
		}
		return nil
	}}
	return egress
}

func sameSubscriptionOrigin(a, b *url.URL) bool {
	if a == nil || b == nil {
		return false
	}
	return strings.EqualFold(a.Scheme, b.Scheme) &&
		strings.EqualFold(a.Hostname(), b.Hostname()) &&
		effectiveHTTPSPort(a) == effectiveHTTPSPort(b)
}

func effectiveHTTPSPort(target *url.URL) string {
	if target == nil {
		return ""
	}
	if port := target.Port(); port != "" {
		return port
	}
	if strings.EqualFold(target.Scheme, "https") {
		return "443"
	}
	return ""
}

func subscriptionRedirectIdentity(target *url.URL) string {
	if target == nil {
		return ""
	}
	copyURL := *target
	copyURL.Scheme = strings.ToLower(copyURL.Scheme)
	copyURL.Host = strings.ToLower(net.JoinHostPort(copyURL.Hostname(), effectiveHTTPSPort(&copyURL)))
	copyURL.Fragment = ""
	if copyURL.Path == "" {
		copyURL.Path = "/"
	}
	return copyURL.String()
}

// Fetch validates the URL and returns a bounded response. It never follows a
// redirect to an unsafe address.
func (e *Egress) Fetch(ctx context.Context, rawURL string) (EgressResponse, error) {
	return e.fetch(ctx, rawURL, "")
}

// FetchConditional performs the same bounded SSRF-safe request while attaching
// an origin-scoped If-None-Match validator. Cross-origin redirects never receive
// the validator, preventing an opaque source token from being disclosed to a
// different host.
func (e *Egress) FetchConditional(ctx context.Context, rawURL, etag string) (EgressResponse, error) {
	return e.fetch(ctx, rawURL, normalizeSourceETag(etag))
}

func (e *Egress) fetch(ctx context.Context, rawURL, etag string) (EgressResponse, error) {
	if e == nil || !e.enabled {
		return EgressResponse{}, ErrRemoteFetchDisabled
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return EgressResponse{}, fmt.Errorf("parse subscription URL: %w", err)
	}
	if err := e.validateURL(ctx, parsed); err != nil {
		return EgressResponse{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return EgressResponse{}, fmt.Errorf("create subscription request: %w", err)
	}
	req.Header.Set("User-Agent", e.userAgent)
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return EgressResponse{}, fmt.Errorf("fetch subscription: %w", err)
	}
	defer resp.Body.Close()
	body, err := readBoundedSubscriptionBody(resp.Body)
	if err != nil {
		return EgressResponse{}, fmt.Errorf("read subscription response: %w", err)
	}
	return EgressResponse{StatusCode: resp.StatusCode, Header: resp.Header.Clone(), Body: body}, nil
}

const maxSourceETagLen = 1024

func normalizeSourceETag(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maxSourceETagLen || strings.ContainsAny(value, "\r\n") {
		return ""
	}
	return value
}

// ValidateRemoteURL applies the canonical opt-in URL and DNS safety policy
// without issuing a request. Compatibility adapters use it before delegating
// a request to a specialized transport.
func (e *Egress) ValidateRemoteURL(ctx context.Context, rawURL string) error {
	if e == nil || !e.enabled {
		return ErrRemoteFetchDisabled
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("parse subscription URL: %w", err)
	}
	return e.validateURL(ctx, parsed)
}

// ValidateProfileSourceURL validates the syntax and static authority boundary for
// subscription sources without performing DNS or network I/O.
func ValidateProfileSourceURL(rawURL string) error {
	rawURL = strings.TrimSpace(rawURL)
	if len(rawURL) == 0 || len(rawURL) > maxProfileSourceURLLen {
		return fmt.Errorf("%w: URL length must be 1..%d bytes", ErrUnsafeRemoteTarget, maxProfileSourceURLLen)
	}
	target, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("%w: invalid URL: %v", ErrUnsafeRemoteTarget, err)
	}
	return validateProfileSourceParsedURL(target)
}

func validateProfileSourceParsedURL(target *url.URL) error {
	if target == nil || target.Scheme != "https" || target.Hostname() == "" || target.User != nil || (target.Port() != "" && target.Port() != "443") {
		return fmt.Errorf("%w: URL must be HTTPS on port 443 without user info", ErrUnsafeRemoteTarget)
	}
	return nil
}

func (e *Egress) validateURL(ctx context.Context, target *url.URL) error {
	if err := validateProfileSourceParsedURL(target); err != nil {
		return err
	}
	_, err := e.resolvePublic(ctx, target.Hostname())
	return err
}

func (e *Egress) resolvePublic(ctx context.Context, host string) ([]netip.Addr, error) {
	if address, err := netip.ParseAddr(host); err == nil {
		if !isPublicAddress(address) {
			return nil, ErrUnsafeRemoteTarget
		}
		return []netip.Addr{address}, nil
	}
	addresses, err := e.resolve(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve subscription host %q: %w", host, err)
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("resolve subscription host %q: no addresses", host)
	}
	for _, address := range addresses {
		if !isPublicAddress(address) {
			return nil, ErrUnsafeRemoteTarget
		}
	}
	return addresses, nil
}

func isPublicAddress(address netip.Addr) bool {
	return netpolicy.IsPublicAddress(address)
}
