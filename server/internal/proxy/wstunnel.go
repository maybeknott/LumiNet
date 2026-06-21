package proxy

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	utls "github.com/refraction-networking/utls"
)

// WsTunnelClient represents the WebSocket / TLS proxy connection wrapper.
type WsTunnelClient struct {
	Endpoint      string
	Headers       map[string]string
	TLSName       string
	UseUTLS       bool
	Fingerprint   string // e.g. "chrome", "firefox", "random", "random_no_alpn"
	ExtraPadding  bool
	TunnelType    int          // 1 = WSTunnel (WebSocket), 2 = Stunnel (TCP/TLS)
	SocketProtect func(fd int) // Android socket protection callback
}

// NewWsTunnelClient creates a new WsTunnelClient.
func NewWsTunnelClient(endpoint string) *WsTunnelClient {
	return &WsTunnelClient{
		Endpoint:   endpoint,
		Headers:    make(map[string]string),
		TunnelType: 1, // Default to WSTunnel
	}
}

// EstablishTunnel dials the WebSocket/TLS endpoint and upgrades/wraps the connection.
func (c *WsTunnelClient) EstablishTunnel(ctx context.Context) (net.Conn, error) {
	u, err := url.Parse(c.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid endpoint: %w", err)
	}

	if c.TunnelType == 2 { // Stunnel (raw TCP/TLS)
		conn, err := dialTLSWithUTLS(ctx, "tcp", u.Host, u, c.Fingerprint, c.ExtraPadding, c.TLSName, c.SocketProtect)
		if err != nil {
			return nil, fmt.Errorf("stunnel connection failed: %w", err)
		}
		return conn, nil
	}

	dialer := &websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}

	if c.UseUTLS && (u.Scheme == "wss" || u.Scheme == "https") {
		dialer.NetDialTLSContext = func(dialCtx context.Context, network, addr string) (net.Conn, error) {
			return dialTLSWithUTLS(dialCtx, network, addr, u, c.Fingerprint, c.ExtraPadding, c.TLSName, c.SocketProtect)
		}
	} else {
		// Use standard TCP dialer with protect callback if provided
		dialer.NetDialContext = func(dialCtx context.Context, network, addr string) (net.Conn, error) {
			d := &net.Dialer{}
			if c.SocketProtect != nil {
				d.Control = func(network, address string, rc syscall.RawConn) error {
					return rc.Control(func(fd uintptr) {
						c.SocketProtect(int(fd))
					})
				}
			}
			return d.DialContext(dialCtx, network, addr)
		}
	}

	header := http.Header{}
	for k, v := range c.Headers {
		header.Set(k, v)
	}

	// Enforce custom browser headers for evasion audit if not specified
	if header.Get("User-Agent") == "" {
		header.Set("User-Agent", getRandomUserAgent())
	}
	if header.Get("Accept") == "" {
		header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	}
	if header.Get("Accept-Language") == "" {
		header.Set("Accept-Language", "en-US,en;q=0.5")
	}

	wsConn, _, err := dialer.DialContext(ctx, c.Endpoint, header)
	if err != nil {
		return nil, fmt.Errorf("wstunnel connection failed: %w", err)
	}

	return &serverlessConn{
		Conn: wsConn,
	}, nil
}

func dialTLSWithUTLS(ctx context.Context, network, addr string, u *url.URL, fingerprint string, extraPadding bool, tlsName string, protect func(fd int)) (net.Conn, error) {
	dialer := &net.Dialer{}
	if protect != nil {
		dialer.Control = func(network, address string, rc syscall.RawConn) error {
			return rc.Control(func(fd uintptr) {
				protect(int(fd))
			})
		}
	}
	tcpConn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	serverName := tlsName
	if serverName == "" {
		serverName = u.Hostname()
	}

	uconn := utls.UClient(tcpConn, &utls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
	}, utls.HelloCustom)

	var utlsID utls.ClientHelloID
	switch strings.ToLower(fingerprint) {
	case "chrome":
		utlsID = utls.HelloChrome_Auto
	case "firefox":
		utlsID = utls.HelloFirefox_Auto
	case "random_no_alpn":
		utlsID = utls.HelloRandomizedNoALPN
	default:
		utlsID = utls.HelloRandomizedALPN
	}

	spec, err := utls.UTLSIdToSpec(utlsID)
	if err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("failed to retrieve utls spec: %w", err)
	}

	if extraPadding {
		hasPadding := false
		padLenVal, err := rand.Int(rand.Reader, big.NewInt(10000))
		padLen := 2000
		if err == nil {
			padLen += int(padLenVal.Int64())
		}
		for _, ext := range spec.Extensions {
			if pExt, ok := ext.(*utls.UtlsPaddingExtension); ok {
				hasPadding = true
				pExt.PaddingLen = padLen
				pExt.WillPad = true
				pExt.GetPaddingLen = nil
				break
			}
		}
		if !hasPadding {
			spec.Extensions = append(spec.Extensions, &utls.UtlsPaddingExtension{
				PaddingLen: padLen,
				WillPad:    true,
			})
		}
	}

	err = uconn.ApplyPreset(&spec)
	if err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("failed to apply utls spec preset: %w", err)
	}

	err = uconn.HandshakeContext(ctx)
	if err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("utls handshake failed: %w", err)
	}

	return uconn, nil
}

func getRandomUserAgent() string {
	uas := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(uas))))
	if err != nil {
		return uas[0]
	}
	return uas[n.Int64()]
}
