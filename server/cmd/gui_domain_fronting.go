//go:build windows && cgo

package cmd

import (
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	. "github.com/lxn/walk/declarative"
	"github.com/maybeknott/luminet/internal/bridge"
)

func (s *nativeShell) domainFrontingPage() TabPage {
	return TabPage{
		Title:  "Domain Fronting",
		Layout: VBox{Margins: Margins{Left: 14, Top: 14, Right: 14, Bottom: 14}},
		Children: []Widget{
			GroupBox{
				Title:  "SNI Spoofing & Domain Fronting Config",
				Layout: Grid{Columns: 4, Spacing: 10},
				Children: []Widget{
					Label{Text: "Target HTTPS URL:"},
					LineEdit{AssignTo: &s.frontingTargetEdit},

					Label{Text: "Spoofed SNI ServerName:"},
					LineEdit{AssignTo: &s.frontingSniEdit},

					Label{Text: "ClientHello Padding (bytes):"},
					LineEdit{AssignTo: &s.frontingPaddingEdit},

					Label{Text: "Fronting Status:"},
					Label{AssignTo: &s.frontingStatusLabel, Text: "-"},
				},
			},
			Composite{
				Layout: HBox{MarginsZero: true},
				Children: []Widget{
					PushButton{Text: "Audit Domain Fronting & SNI Spoofing", OnClicked: s.runFrontingAudit},
					HSpacer{},
				},
			},
			GroupBox{
				Title:  "Domain Fronting Diagnostics & Logs",
				Layout: VBox{},
				Children: []Widget{
					TextEdit{AssignTo: &s.frontingResultEdit, ReadOnly: true, VScroll: true, MinSize: Size{Height: 320}},
				},
			},
			VSpacer{},
		},
	}
}

type paddingConn struct {
	net.Conn
	padLen     int
	firstWrite bool
}

func (c *paddingConn) Write(b []byte) (int, error) {
	if c.firstWrite && c.padLen > 0 {
		c.firstWrite = false
		if len(b) > 5 && b[0] == 0x16 {
			hexStr := hex.EncodeToString(b)
			paddedHex, err := bridge.PadClientHello(hexStr, c.padLen)
			if err == nil {
				paddedBytes, err2 := hex.DecodeString(paddedHex)
				if err2 == nil {
					n, err3 := c.Conn.Write(paddedBytes)
					if err3 != nil {
						return n, err3
					}
					return len(b), nil
				}
			}
		}
	}
	return c.Conn.Write(b)
}

func (s *nativeShell) runFrontingAudit() {
	targetURL := "https://ajax.aspnetcdn.com/"
	if s.frontingTargetEdit != nil && s.frontingTargetEdit.Text() != "" {
		targetURL = strings.TrimSpace(s.frontingTargetEdit.Text())
	}

	spoofedSNI := "microsoft.com"
	if s.frontingSniEdit != nil && s.frontingSniEdit.Text() != "" {
		spoofedSNI = strings.TrimSpace(s.frontingSniEdit.Text())
	}

	paddingVal := 0
	if s.frontingPaddingEdit != nil && s.frontingPaddingEdit.Text() != "" {
		pVal, err := strconv.Atoi(strings.TrimSpace(s.frontingPaddingEdit.Text()))
		if err == nil && pVal > 0 {
			paddingVal = pVal
		}
	}

	s.setStatus("Running Domain Fronting & SNI Spoofing Audit...")
	if s.frontingStatusLabel != nil {
		s.frontingStatusLabel.SetText("Testing...")
	}
	if s.frontingResultEdit != nil {
		s.frontingResultEdit.SetText(fmt.Sprintf("SNI Spoofing & Domain Fronting Audit\r\nTarget URL: %s\r\nSpoofed SNI: %s\r\n============================================================\r\n", targetURL, spoofedSNI))
	}

	go func() {
		var sb strings.Builder
		sb.WriteString("Step 1: Parsing Target URL...\r\n")
		parsed, err := url.Parse(targetURL)
		if err != nil {
			s.sync(func() {
				s.setStatus("Fronting audit failed: invalid URL")
				if s.frontingStatusLabel != nil {
					s.frontingStatusLabel.SetText("Failed")
				}
				if s.frontingResultEdit != nil {
					s.frontingResultEdit.AppendText("[!] Error parsing URL: " + err.Error() + "\r\n")
				}
			})
			return
		}

		host := parsed.Host
		port := "443"
		if strings.Contains(host, ":") {
			var err2 error
			host, port, err2 = net.SplitHostPort(parsed.Host)
			if err2 != nil {
				host = parsed.Host
				port = "443"
			}
		}

		sb.WriteString(fmt.Sprintf("  [+] Host: %s, Port: %s\r\n\r\n", host, port))

		// Test A: Direct Connection with Standard SNI
		sb.WriteString(fmt.Sprintf("Step 2: Connecting with Standard SNI (%s)...\r\n", host))
		start := time.Now()
		dialer := &net.Dialer{Timeout: 3 * time.Second}
		connA, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, port), &tls.Config{
			ServerName: host,
		})
		latencyA := time.Since(start)

		var successA bool
		if err != nil {
			sb.WriteString(fmt.Sprintf("  [-] Connection FAILED: %v\r\n\r\n", err))
		} else {
			sb.WriteString(fmt.Sprintf("  [+] Connection SUCCESSFUL (Latency: %v)\r\n", latencyA))
			sb.WriteString(fmt.Sprintf("  [+] Negotiated version: %s\r\n\r\n", versionToString(connA.ConnectionState().Version)))
			successA = true
			connA.Close()
		}

		// Test B: Connection with Spoofed SNI
		sb.WriteString(fmt.Sprintf("Step 3: Connecting with Spoofed SNI (%s)...\r\n", spoofedSNI))
		if paddingVal > 0 {
			sb.WriteString(fmt.Sprintf("  [+] Appending %d bytes of ClientHello padding (uTLS emulation)...\r\n", paddingVal))
		}
		start = time.Now()

		rawConn, err := dialer.Dial("tcp", net.JoinHostPort(host, port))
		var connB *tls.Conn
		if err == nil {
			pConn := &paddingConn{
				Conn:       rawConn,
				padLen:     paddingVal,
				firstWrite: true,
			}
			connB = tls.Client(pConn, &tls.Config{
				ServerName:         spoofedSNI,
				InsecureSkipVerify: true,
			})
			err = connB.Handshake()
		}
		latencyB := time.Since(start)

		var successB bool
		if err != nil {
			sb.WriteString(fmt.Sprintf("  [-] Connection FAILED: %v\r\n\r\n", err))
		} else {
			sb.WriteString(fmt.Sprintf("  [+] Connection SUCCESSFUL (Latency: %v)\r\n", latencyB))
			sb.WriteString(fmt.Sprintf("  [+] Negotiated version: %s\r\n", versionToString(connB.ConnectionState().Version)))
			successB = true

			// Try sending HTTP request over spoofed connection to verify domain fronting
			sb.WriteString("Step 4: Sending HTTP GET request with target Host header...\r\n")
			reqStr := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nUser-Agent: LumiNet/1.0\r\n\r\n", parsed.Path, host)
			connB.SetDeadline(time.Now().Add(3 * time.Second))
			_, err = connB.Write([]byte(reqStr))
			if err != nil {
				sb.WriteString(fmt.Sprintf("  [-] HTTP write failed: %v\r\n\r\n", err))
			} else {
				buf := make([]byte, 512)
				n, err := connB.Read(buf)
				if err != nil && err != io.EOF {
					sb.WriteString(fmt.Sprintf("  [-] HTTP read failed: %v\r\n\r\n", err))
				} else {
					resp := string(buf[:n])
					lines := strings.Split(resp, "\r\n")
					statusLine := "Unknown"
					if len(lines) > 0 {
						statusLine = lines[0]
					}
					sb.WriteString(fmt.Sprintf("  [+] HTTP GET successful. Status: %s\r\n\r\n", statusLine))
				}
			}
			connB.Close()
		}

		// Evaluation
		sb.WriteString("Assessment Summary:\r\n")
		sb.WriteString("------------------------------------------------------------\r\n")
		statusText := "Failed"
		if successB {
			statusText = "Success"
			if !successA {
				sb.WriteString("  [!] SNI SPOOFING SUCCESSFULLY BYPASSED FILTERS!\r\n")
				sb.WriteString("      The network blocks direct SNI checks but allows traffic when SNI is spoofed.\r\n")
			} else {
				sb.WriteString("  [+] Domain Fronting pathway verified. Both direct and spoofed connections succeeded.\r\n")
			}
			sb.WriteString("      This CDN edge allows fronting. You can use it as a TLS routing proxy front.\r\n")
		} else {
			sb.WriteString("  [-] SNI spoofing/domain fronting failed or CDN edge blocked the handshake.\r\n")
		}

		s.sync(func() {
			s.setStatus("Domain Fronting audit completed.")
			if s.frontingStatusLabel != nil {
				s.frontingStatusLabel.SetText(statusText)
			}
			if s.frontingResultEdit != nil {
				s.frontingResultEdit.AppendText(sb.String())
			}
		})
	}()
}

func versionToString(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return fmt.Sprintf("0x%04X", version)
	}
}
