// Package proxy provides proxy parsing, testing, and core process management.
//
// subscription.go implements subscription URL fetching and parsing for
// various subscription formats including base64 URI lists, Clash YAML,
// and sing-box JSON outbound configurations.
package proxy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"gopkg.in/yaml.v3"
)

type contextKey string

const captchaSolverKey contextKey = "captcha_solver"
const coalescerKey contextKey = "coalescer"

// WithCaptchaSolver returns a context containing the CaptchaSolver.
func WithCaptchaSolver(ctx context.Context, solver *CaptchaSolver) context.Context {
	return context.WithValue(ctx, captchaSolverKey, solver)
}

// GetCaptchaSolver retrieves the CaptchaSolver from context.
func GetCaptchaSolver(ctx context.Context) *CaptchaSolver {
	if ctx == nil {
		return nil
	}
	if val := ctx.Value(captchaSolverKey); val != nil {
		if s, ok := val.(*CaptchaSolver); ok {
			return s
		}
	}
	return nil
}

// WithCoalescer returns a context containing the Coalescer.
func WithCoalescer(ctx context.Context, c *Coalescer) context.Context {
	return context.WithValue(ctx, coalescerKey, c)
}

// GetCoalescer retrieves the Coalescer from context.
func GetCoalescer(ctx context.Context) *Coalescer {
	if ctx == nil {
		return nil
	}
	if val := ctx.Value(coalescerKey); val != nil {
		if c, ok := val.(*Coalescer); ok {
			return c
		}
	}
	return nil
}

// FetchSubscription downloads a subscription URL and parses its contents
// into a list of proxy configurations. It auto-detects the subscription
// format (base64, Clash YAML, sing-box JSON).
func FetchSubscription(ctx context.Context, urlStr string) ([]*ProxyConfig, error) {
	coalescer := GetCoalescer(ctx)
	if coalescer != nil {
		headers := map[string]string{
			"User-Agent": "LumiNet/1.0",
		}
		relayResp, err := coalescer.Submit("GET", urlStr, headers, nil)
		if err == nil && relayResp.Status >= 200 && relayResp.Status < 300 {
			return ParseSubscriptionContent(string(relayResp.Body))
		}
	}

	req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "LumiNet/1.0")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var bodyStr string
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		var buf strings.Builder
		_, err = io.Copy(&buf, resp.Body)
		if err != nil {
			return nil, err
		}
		bodyStr = buf.String()
	} else if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		var buf strings.Builder
		_, _ = io.Copy(&buf, resp.Body)
		bodyStr = buf.String()
	} else {
		return nil, fmt.Errorf("subscription HTTP status error: %d", resp.StatusCode)
	}

	// Try to solve captcha if configured and challenge is found
	solver := GetCaptchaSolver(ctx)
	if solver != nil && bodyStr != "" {
		sitekey, captchaType := ExtractSiteKey(bodyStr)
		if sitekey != "" && captchaType != "" {
			token, err := solver.SolveCaptcha(ctx, captchaType, urlStr, sitekey, nil)
			if err == nil {
				parsedURL, err := url.Parse(urlStr)
				if err == nil {
					q := parsedURL.Query()
					if captchaType == "turnstile" {
						q.Set("cf-turnstile-response", token)
					} else if captchaType == "userrecaptcha" {
						q.Set("g-recaptcha-response", token)
					} else {
						q.Set("h-captcha-response", token)
					}
					parsedURL.RawQuery = q.Encode()
					retryURL := parsedURL.String()

					reqRetry, err := http.NewRequestWithContext(ctx, "GET", retryURL, nil)
					if err == nil {
						reqRetry.Header.Set("User-Agent", "LumiNet/1.0")
						respRetry, err := http.DefaultClient.Do(reqRetry)
						if err == nil {
							defer respRetry.Body.Close()
							if respRetry.StatusCode >= 200 && respRetry.StatusCode < 300 {
								var bufRetry strings.Builder
								if _, err := io.Copy(&bufRetry, respRetry.Body); err == nil {
									return ParseSubscriptionContent(bufRetry.String())
								}
							}
						}
					}
				}
			}
		}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("subscription HTTP status error: %d", resp.StatusCode)
	}

	return ParseSubscriptionContent(bodyStr)
}

// ParseSubscriptionContent auto-detects and parses base64 URI lists, Clash YAML,
// sing-box JSON, or plain URI lists.
func ParseSubscriptionContent(content string) ([]*ProxyConfig, error) {
	// 1. Try Base64 parsing
	if configs, err := ParseBase64Subscription(content); err == nil && len(configs) > 0 {
		return configs, nil
	}

	// 2. Try Clash Config parsing
	if configs, err := ParseClashConfig([]byte(content)); err == nil && len(configs) > 0 {
		return configs, nil
	}

	// 3. Try SingBox config parsing
	if configs, err := ParseSingBoxOutbounds([]byte(content)); err == nil && len(configs) > 0 {
		return configs, nil
	}

	// 4. Fallback: Parse plain text URI list directly
	return ParseProxyList(content)
}

// ParseBase64Subscription decodes a base64-encoded subscription body
// containing one proxy URI per line and parses each URI.
func ParseBase64Subscription(data string) ([]*ProxyConfig, error) {
	decoded, err := DecodeBase64Mixed(data)
	if err != nil {
		return nil, err
	}
	return ParseProxyList(decoded)
}

// ParseClashConfig parses a Clash-format YAML configuration and extracts
// proxy configurations from the 'proxies' section.
func ParseClashConfig(yamlData []byte) ([]*ProxyConfig, error) {
	var raw map[string]interface{}
	if err := yaml.Unmarshal(yamlData, &raw); err != nil {
		return nil, err
	}

	proxiesVal, ok := raw["proxies"]
	if !ok {
		return nil, fmt.Errorf("missing 'proxies' section in Clash config")
	}

	proxiesList, ok := proxiesVal.([]interface{})
	if !ok {
		return nil, fmt.Errorf("'proxies' section is not a list")
	}

	var configs []*ProxyConfig
	for _, p := range proxiesList {
		pMap, ok := p.(map[string]interface{})
		if !ok {
			continue
		}

		cfg := &ProxyConfig{}

		if t, exists := pMap["type"]; exists {
			ts := fmt.Sprintf("%v", t)
			switch ts {
			case "ss":
				cfg.Protocol = ProtocolShadowsocks
			case "vmess":
				cfg.Protocol = ProtocolVMess
			case "vless":
				cfg.Protocol = ProtocolVLESS
			case "trojan":
				cfg.Protocol = ProtocolTrojan
			case "socks5":
				cfg.Protocol = ProtocolSOCKS5
			case "http":
				cfg.Protocol = ProtocolHTTP
			case "hysteria2", "hy2":
				cfg.Protocol = ProtocolHysteria2
			case "tuic":
				cfg.Protocol = ProtocolTUIC
			case "wireguard":
				cfg.Protocol = ProtocolWireGuard
			case "awg", "amneziawg":
				cfg.Protocol = ProtocolAmneziaWG
			default:
				continue
			}
		}

		if name, exists := pMap["name"]; exists {
			cfg.Name = fmt.Sprintf("%v", name)
		}

		if server, exists := pMap["server"]; exists {
			cfg.Address = fmt.Sprintf("%v", server)
		}

		if port, exists := pMap["port"]; exists {
			fmt.Sscanf(fmt.Sprintf("%v", port), "%d", &cfg.Port)
		}

		if uuidVal, exists := pMap["uuid"]; exists {
			cfg.UUID = fmt.Sprintf("%v", uuidVal)
		}

		if pass, exists := pMap["password"]; exists {
			cfg.Password = fmt.Sprintf("%v", pass)
		}

		if cipher, exists := pMap["cipher"]; exists {
			cfg.Method = fmt.Sprintf("%v", cipher)
		}

		if pk, exists := pMap["private-key"]; exists {
			cfg.PrivateKey = fmt.Sprintf("%v", pk)
		}
		if pubk, exists := pMap["public-key"]; exists {
			cfg.PublicKey = fmt.Sprintf("%v", pubk)
		}
		if ipVal, exists := pMap["ip"]; exists {
			cfg.LocalAddress = []string{fmt.Sprintf("%v", ipVal)}
		}
		if mtuVal, exists := pMap["mtu"]; exists {
			fmt.Sscanf(fmt.Sprintf("%v", mtuVal), "%d", &cfg.MTU)
		}
		if resVal, exists := pMap["reserved"]; exists {
			cfg.Reserved = parseReservedField(resVal)
		}

		if val, exists := pMap["wnoise"]; exists {
			cfg.WNoise = fmt.Sprintf("%v", val)
		}
		if val, exists := pMap["wnoisecount"]; exists {
			cfg.WNoiseCount = fmt.Sprintf("%v", val)
		}
		if val, exists := pMap["wpayloadsize"]; exists {
			cfg.WPayloadSize = fmt.Sprintf("%v", val)
		}
		if val, exists := pMap["wnoisedelay"]; exists {
			cfg.WNoiseDelay = fmt.Sprintf("%v", val)
		}
		if val, exists := pMap["fake-packets"]; exists {
			cfg.FakePackets = fmt.Sprintf("%v", val)
		} else if val, exists := pMap["fake_packets"]; exists {
			cfg.FakePackets = fmt.Sprintf("%v", val)
		} else if val, exists := pMap["ifp"]; exists {
			cfg.FakePackets = fmt.Sprintf("%v", val)
		}
		if val, exists := pMap["fake-packets-size"]; exists {
			cfg.FakePacketsSize = fmt.Sprintf("%v", val)
		} else if val, exists := pMap["fake_packets_size"]; exists {
			cfg.FakePacketsSize = fmt.Sprintf("%v", val)
		} else if val, exists := pMap["ifps"]; exists {
			cfg.FakePacketsSize = fmt.Sprintf("%v", val)
		}
		if val, exists := pMap["fake-packets-delay"]; exists {
			cfg.FakePacketsDelay = fmt.Sprintf("%v", val)
		} else if val, exists := pMap["fake_packets_delay"]; exists {
			cfg.FakePacketsDelay = fmt.Sprintf("%v", val)
		} else if val, exists := pMap["ifpd"]; exists {
			cfg.FakePacketsDelay = fmt.Sprintf("%v", val)
		}
		if val, exists := pMap["fake-packets-mode"]; exists {
			cfg.FakePacketsMode = fmt.Sprintf("%v", val)
		} else if val, exists := pMap["fake_packets_mode"]; exists {
			cfg.FakePacketsMode = fmt.Sprintf("%v", val)
		} else if val, exists := pMap["ifpm"]; exists {
			cfg.FakePacketsMode = fmt.Sprintf("%v", val)
		}

		if awgOptVal, exists := pMap["amnezia-wg-option"]; exists {
			if awgMap, ok := awgOptVal.(map[string]interface{}); ok {
				cfg.Protocol = ProtocolAmneziaWG
				if val, ok := awgMap["jc"]; ok {
					fmt.Sscanf(fmt.Sprintf("%v", val), "%d", &cfg.Jc)
				}
				if val, ok := awgMap["jmin"]; ok {
					fmt.Sscanf(fmt.Sprintf("%v", val), "%d", &cfg.Jmin)
				}
				if val, ok := awgMap["jmax"]; ok {
					fmt.Sscanf(fmt.Sprintf("%v", val), "%d", &cfg.Jmax)
				}
				if val, ok := awgMap["s1"]; ok {
					fmt.Sscanf(fmt.Sprintf("%v", val), "%d", &cfg.S1)
				}
				if val, ok := awgMap["s2"]; ok {
					fmt.Sscanf(fmt.Sprintf("%v", val), "%d", &cfg.S2)
				}
				if val, ok := awgMap["s3"]; ok {
					fmt.Sscanf(fmt.Sprintf("%v", val), "%d", &cfg.S3)
				}
				if val, ok := awgMap["s4"]; ok {
					fmt.Sscanf(fmt.Sprintf("%v", val), "%d", &cfg.S4)
				}
				if val, ok := awgMap["h1"]; ok {
					cfg.H1 = fmt.Sprintf("%v", val)
				}
				if val, ok := awgMap["h2"]; ok {
					cfg.H2 = fmt.Sprintf("%v", val)
				}
				if val, ok := awgMap["h3"]; ok {
					cfg.H3 = fmt.Sprintf("%v", val)
				}
				if val, ok := awgMap["h4"]; ok {
					cfg.H4 = fmt.Sprintf("%v", val)
				}
				if val, ok := awgMap["i1"]; ok {
					cfg.I1 = fmt.Sprintf("%v", val)
				}
				if val, ok := awgMap["i2"]; ok {
					cfg.I2 = fmt.Sprintf("%v", val)
				}
				if val, ok := awgMap["i3"]; ok {
					cfg.I3 = fmt.Sprintf("%v", val)
				}
				if val, ok := awgMap["i4"]; ok {
					cfg.I4 = fmt.Sprintf("%v", val)
				}
				if val, ok := awgMap["i5"]; ok {
					cfg.I5 = fmt.Sprintf("%v", val)
				}
			}
		}

		if err := cfg.Validate(); err == nil {
			configs = append(configs, cfg)
		}
	}

	return configs, nil
}

// ParseSingBoxOutbounds parses a sing-box JSON configuration and extracts
// proxy configurations from the 'outbounds' array.
func ParseSingBoxOutbounds(jsonData []byte) ([]*ProxyConfig, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal(jsonData, &raw); err != nil {
		return nil, err
	}

	outboundsVal, ok := raw["outbounds"]
	if !ok {
		return nil, fmt.Errorf("missing 'outbounds' section in sing-box config")
	}

	outboundsList, ok := outboundsVal.([]interface{})
	if !ok {
		return nil, fmt.Errorf("'outbounds' section is not a list")
	}

	var configs []*ProxyConfig
	for _, o := range outboundsList {
		oMap, ok := o.(map[string]interface{})
		if !ok {
			continue
		}

		cfg := &ProxyConfig{}

		if t, exists := oMap["type"]; exists {
			ts := fmt.Sprintf("%v", t)
			switch ts {
			case "shadowsocks":
				cfg.Protocol = ProtocolShadowsocks
			case "vmess":
				cfg.Protocol = ProtocolVMess
			case "vless":
				cfg.Protocol = ProtocolVLESS
			case "trojan":
				cfg.Protocol = ProtocolTrojan
			case "socks":
				cfg.Protocol = ProtocolSOCKS5
			case "http":
				cfg.Protocol = ProtocolHTTP
			case "hysteria2":
				cfg.Protocol = ProtocolHysteria2
			case "tuic":
				cfg.Protocol = ProtocolTUIC
			case "wireguard":
				cfg.Protocol = ProtocolWireGuard
			case "awg", "amneziawg":
				cfg.Protocol = ProtocolAmneziaWG
			default:
				continue
			}
		}

		if tag, exists := oMap["tag"]; exists {
			cfg.Name = fmt.Sprintf("%v", tag)
		}

		if detour, exists := oMap["detour"]; exists {
			cfg.DialerProxy = fmt.Sprintf("%v", detour)
		} else if dProxy, exists := oMap["dialer_proxy"]; exists {
			cfg.DialerProxy = fmt.Sprintf("%v", dProxy)
		}

		if server, exists := oMap["server"]; exists {
			cfg.Address = fmt.Sprintf("%v", server)
		}

		if port, exists := oMap["server_port"]; exists {
			fmt.Sscanf(fmt.Sprintf("%v", port), "%d", &cfg.Port)
		}

		if uuidVal, exists := oMap["uuid"]; exists {
			cfg.UUID = fmt.Sprintf("%v", uuidVal)
		}

		if pass, exists := oMap["password"]; exists {
			cfg.Password = fmt.Sprintf("%v", pass)
		}

		if method, exists := oMap["method"]; exists {
			cfg.Method = fmt.Sprintf("%v", method)
		}

		if pk, exists := oMap["private_key"]; exists {
			cfg.PrivateKey = fmt.Sprintf("%v", pk)
		}
		if pubk, exists := oMap["peer_public_key"]; exists {
			cfg.PublicKey = fmt.Sprintf("%v", pubk)
		}
		if localAddrsVal, exists := oMap["local_address"]; exists {
			if list, ok := localAddrsVal.([]interface{}); ok {
				var addrs []string
				for _, a := range list {
					addrs = append(addrs, fmt.Sprintf("%v", a))
				}
				cfg.LocalAddress = addrs
			} else if str, ok := localAddrsVal.(string); ok {
				cfg.LocalAddress = []string{str}
			}
		}
		if mtuVal, exists := oMap["mtu"]; exists {
			fmt.Sscanf(fmt.Sprintf("%v", mtuVal), "%d", &cfg.MTU)
		}
		if resVal, exists := oMap["reserved"]; exists {
			cfg.Reserved = parseReservedField(resVal)
		}

		if val, exists := oMap["wnoise"]; exists {
			cfg.WNoise = fmt.Sprintf("%v", val)
		}
		if val, exists := oMap["wnoisecount"]; exists {
			cfg.WNoiseCount = fmt.Sprintf("%v", val)
		}
		if val, exists := oMap["wpayloadsize"]; exists {
			cfg.WPayloadSize = fmt.Sprintf("%v", val)
		}
		if val, exists := oMap["wnoisedelay"]; exists {
			cfg.WNoiseDelay = fmt.Sprintf("%v", val)
		}
		if val, exists := oMap["fake_packets"]; exists {
			cfg.FakePackets = fmt.Sprintf("%v", val)
		} else if val, exists := oMap["ifp"]; exists {
			cfg.FakePackets = fmt.Sprintf("%v", val)
		}
		if val, exists := oMap["fake_packets_size"]; exists {
			cfg.FakePacketsSize = fmt.Sprintf("%v", val)
		} else if val, exists := oMap["ifps"]; exists {
			cfg.FakePacketsSize = fmt.Sprintf("%v", val)
		}
		if val, exists := oMap["fake_packets_delay"]; exists {
			cfg.FakePacketsDelay = fmt.Sprintf("%v", val)
		} else if val, exists := oMap["ifpd"]; exists {
			cfg.FakePacketsDelay = fmt.Sprintf("%v", val)
		}
		if val, exists := oMap["fake_packets_mode"]; exists {
			cfg.FakePacketsMode = fmt.Sprintf("%v", val)
		} else if val, exists := oMap["ifpm"]; exists {
			cfg.FakePacketsMode = fmt.Sprintf("%v", val)
		}

		// Check for AmneziaWG properties in sing-box outbound
		isAmnezia := false
		if val, exists := oMap["awg_jc"]; exists {
			fmt.Sscanf(fmt.Sprintf("%v", val), "%d", &cfg.Jc)
			isAmnezia = true
		} else if val, exists := oMap["amnezia_jc"]; exists {
			fmt.Sscanf(fmt.Sprintf("%v", val), "%d", &cfg.Jc)
			isAmnezia = true
		}

		if val, exists := oMap["awg_jmin"]; exists {
			fmt.Sscanf(fmt.Sprintf("%v", val), "%d", &cfg.Jmin)
			isAmnezia = true
		} else if val, exists := oMap["amnezia_jmin"]; exists {
			fmt.Sscanf(fmt.Sprintf("%v", val), "%d", &cfg.Jmin)
			isAmnezia = true
		}

		if val, exists := oMap["awg_jmax"]; exists {
			fmt.Sscanf(fmt.Sprintf("%v", val), "%d", &cfg.Jmax)
			isAmnezia = true
		} else if val, exists := oMap["amnezia_jmax"]; exists {
			fmt.Sscanf(fmt.Sprintf("%v", val), "%d", &cfg.Jmax)
			isAmnezia = true
		}

		if val, exists := oMap["awg_s1"]; exists {
			fmt.Sscanf(fmt.Sprintf("%v", val), "%d", &cfg.S1)
			isAmnezia = true
		} else if val, exists := oMap["amnezia_s1"]; exists {
			fmt.Sscanf(fmt.Sprintf("%v", val), "%d", &cfg.S1)
			isAmnezia = true
		}

		if val, exists := oMap["awg_s2"]; exists {
			fmt.Sscanf(fmt.Sprintf("%v", val), "%d", &cfg.S2)
			isAmnezia = true
		} else if val, exists := oMap["amnezia_s2"]; exists {
			fmt.Sscanf(fmt.Sprintf("%v", val), "%d", &cfg.S2)
			isAmnezia = true
		}

		if val, exists := oMap["awg_s3"]; exists {
			fmt.Sscanf(fmt.Sprintf("%v", val), "%d", &cfg.S3)
			isAmnezia = true
		} else if val, exists := oMap["amnezia_s3"]; exists {
			fmt.Sscanf(fmt.Sprintf("%v", val), "%d", &cfg.S3)
			isAmnezia = true
		}

		if val, exists := oMap["awg_s4"]; exists {
			fmt.Sscanf(fmt.Sprintf("%v", val), "%d", &cfg.S4)
			isAmnezia = true
		} else if val, exists := oMap["amnezia_s4"]; exists {
			fmt.Sscanf(fmt.Sprintf("%v", val), "%d", &cfg.S4)
			isAmnezia = true
		}

		if val, exists := oMap["awg_h1"]; exists {
			cfg.H1 = fmt.Sprintf("%v", val)
			isAmnezia = true
		} else if val, exists := oMap["amnezia_h1"]; exists {
			cfg.H1 = fmt.Sprintf("%v", val)
			isAmnezia = true
		}

		if val, exists := oMap["awg_h2"]; exists {
			cfg.H2 = fmt.Sprintf("%v", val)
			isAmnezia = true
		} else if val, exists := oMap["amnezia_h2"]; exists {
			cfg.H2 = fmt.Sprintf("%v", val)
			isAmnezia = true
		}

		if val, exists := oMap["awg_h3"]; exists {
			cfg.H3 = fmt.Sprintf("%v", val)
			isAmnezia = true
		} else if val, exists := oMap["amnezia_h3"]; exists {
			cfg.H3 = fmt.Sprintf("%v", val)
			isAmnezia = true
		}

		if val, exists := oMap["awg_h4"]; exists {
			cfg.H4 = fmt.Sprintf("%v", val)
			isAmnezia = true
		} else if val, exists := oMap["amnezia_h4"]; exists {
			cfg.H4 = fmt.Sprintf("%v", val)
			isAmnezia = true
		}

		if val, exists := oMap["awg_i1"]; exists {
			cfg.I1 = fmt.Sprintf("%v", val)
			isAmnezia = true
		} else if val, exists := oMap["amnezia_i1"]; exists {
			cfg.I1 = fmt.Sprintf("%v", val)
			isAmnezia = true
		}
		if val, exists := oMap["awg_i2"]; exists {
			cfg.I2 = fmt.Sprintf("%v", val)
			isAmnezia = true
		} else if val, exists := oMap["amnezia_i2"]; exists {
			cfg.I2 = fmt.Sprintf("%v", val)
			isAmnezia = true
		}
		if val, exists := oMap["awg_i3"]; exists {
			cfg.I3 = fmt.Sprintf("%v", val)
			isAmnezia = true
		} else if val, exists := oMap["amnezia_i3"]; exists {
			cfg.I3 = fmt.Sprintf("%v", val)
			isAmnezia = true
		}
		if val, exists := oMap["awg_i4"]; exists {
			cfg.I4 = fmt.Sprintf("%v", val)
			isAmnezia = true
		} else if val, exists := oMap["amnezia_i4"]; exists {
			cfg.I4 = fmt.Sprintf("%v", val)
			isAmnezia = true
		}
		if val, exists := oMap["awg_i5"]; exists {
			cfg.I5 = fmt.Sprintf("%v", val)
			isAmnezia = true
		} else if val, exists := oMap["amnezia_i5"]; exists {
			cfg.I5 = fmt.Sprintf("%v", val)
			isAmnezia = true
		}

		if isAmnezia {
			cfg.Protocol = ProtocolAmneziaWG
		}

		if err := cfg.Validate(); err == nil {
			configs = append(configs, cfg)
		}
	}

	// Resolve detours by linking DialerProxy tag to actual Detour pointer
	for _, cfg := range configs {
		if cfg.DialerProxy != "" {
			for _, other := range configs {
				if other.Name == cfg.DialerProxy {
					cfg.Detour = other
					break
				}
			}
		}
	}

	return configs, nil
}

// DecodeBase64Mixed attempts to decode a base64 string using both standard
// and URL-safe alphabets, with and without padding. Returns the decoded
// string or an error if all attempts fail.
func DecodeBase64Mixed(input string) (string, error) {
	input = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, input)

	dec, err := base64.StdEncoding.DecodeString(input)
	if err == nil {
		return string(dec), nil
	}

	dec, err = base64.URLEncoding.DecodeString(input)
	if err == nil {
		return string(dec), nil
	}

	for i := 1; i <= 3; i++ {
		padded := input + strings.Repeat("=", i)
		dec, err = base64.StdEncoding.DecodeString(padded)
		if err == nil {
			return string(dec), nil
		}
		dec, err = base64.URLEncoding.DecodeString(padded)
		if err == nil {
			return string(dec), nil
		}
	}

	dec, err = base64.RawStdEncoding.DecodeString(input)
	if err == nil {
		return string(dec), nil
	}

	dec, err = base64.RawURLEncoding.DecodeString(input)
	if err == nil {
		return string(dec), nil
	}

	return "", fmt.Errorf("failed to decode base64 mixed string")
}

// parseReservedField decodes robust reserved byte arrays from float64, integer, base64 strings, or lists.
func parseReservedField(val interface{}) []int {
	if val == nil {
		return nil
	}
	switch v := val.(type) {
	case []interface{}:
		var res []int
		for _, item := range v {
			var intVal int
			if _, err := fmt.Sscanf(fmt.Sprintf("%v", item), "%d", &intVal); err == nil {
				res = append(res, intVal)
			}
		}
		return res
	case string:
		trimmed := strings.TrimSpace(v)
		if decoded, err := base64.StdEncoding.DecodeString(trimmed); err == nil && len(decoded) > 0 {
			res := make([]int, len(decoded))
			for i, b := range decoded {
				res[i] = int(b)
			}
			return res
		}
		var res []int
		parts := strings.Split(trimmed, ",")
		for _, p := range parts {
			var intVal int
			if _, err := fmt.Sscanf(strings.TrimSpace(p), "%d", &intVal); err == nil {
				res = append(res, intVal)
			}
		}
		return res
	case float64:
		return []int{int(v)}
	case int:
		return []int{v}
	}
	return nil
}
