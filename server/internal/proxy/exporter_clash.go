package proxy

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// ExportToClashYaml converts a slice of ProxyConfigs into a Clash-compatible YAML string.
func ExportToClashYaml(proxies []*ProxyConfig) (string, error) {
	clashProxies := make([]map[string]interface{}, 0, len(proxies))

	for _, p := range proxies {
		if p == nil {
			continue
		}

		var t string
		switch p.Protocol {
		case ProtocolShadowsocks:
			t = "ss"
		case ProtocolVMess:
			t = "vmess"
		case ProtocolVLESS:
			t = "vless"
		case ProtocolTrojan:
			t = "trojan"
		case ProtocolSOCKS5:
			t = "socks5"
		case ProtocolHTTP:
			t = "http"
		case ProtocolHysteria2:
			t = "hysteria2"
		case ProtocolTUIC:
			t = "tuic"
		case ProtocolWireGuard, ProtocolAmneziaWG:
			t = "wireguard"
		default:
			continue
		}

		name := p.Name
		if name == "" {
			name = fmt.Sprintf("%s-%s-%d", t, p.Address, p.Port)
		}

		item := map[string]interface{}{
			"name":        name,
			"type":        t,
			"server":      p.Address,
			"port":        p.Port,
			"udp":         true,
		}

		switch p.Protocol {
		case ProtocolShadowsocks:
			item["cipher"] = p.Method
			item["password"] = p.Password
		case ProtocolVMess:
			item["uuid"] = p.UUID
			item["alterId"] = p.AlterID
			item["cipher"] = "auto"
			if p.Transport == "ws" {
				item["network"] = "ws"
				wsOpts := map[string]interface{}{
					"path": p.Path,
				}
				if p.Host != "" {
					wsOpts["headers"] = map[string]string{
						"Host": p.Host,
					}
				}
				item["ws-opts"] = wsOpts
			}
			if p.TLS {
				item["tls"] = true
				if p.SNI != "" {
					item["servername"] = p.SNI
				}
				item["skip-cert-verify"] = p.SkipCertVerify
			}
		case ProtocolVLESS:
			item["uuid"] = p.UUID
			if p.Transport == "ws" {
				item["network"] = "ws"
				wsOpts := map[string]interface{}{
					"path": p.Path,
				}
				if p.Host != "" {
					wsOpts["headers"] = map[string]string{
						"Host": p.Host,
					}
				}
				item["ws-opts"] = wsOpts
			}
			if p.TLS {
				item["tls"] = true
				if p.SNI != "" {
					item["servername"] = p.SNI
				}
				item["skip-cert-verify"] = p.SkipCertVerify
			}
		case ProtocolTrojan:
			item["password"] = p.Password
			if p.SNI != "" {
				item["sni"] = p.SNI
			}
			item["skip-cert-verify"] = p.SkipCertVerify
		case ProtocolSOCKS5:
			if p.UUID != "" {
				item["username"] = p.UUID
				item["password"] = p.Password
			}
		case ProtocolHTTP:
			if p.UUID != "" {
				item["username"] = p.UUID
				item["password"] = p.Password
			}
		case ProtocolHysteria2:
			item["password"] = p.Password
			if p.SNI != "" {
				item["sni"] = p.SNI
			}
			item["skip-cert-verify"] = p.SkipCertVerify
		case ProtocolTUIC:
			item["uuid"] = p.UUID
			item["password"] = p.Password
			if p.SNI != "" {
				item["sni"] = p.SNI
			}
			item["skip-cert-verify"] = p.SkipCertVerify
		case ProtocolWireGuard, ProtocolAmneziaWG:
			item["private-key"] = p.PrivateKey
			item["public-key"] = p.PublicKey
			if len(p.LocalAddress) > 0 {
				item["ip"] = p.LocalAddress[0]
			}
			if p.MTU > 0 {
				item["mtu"] = p.MTU
			}
			if len(p.Reserved) > 0 {
				item["reserved"] = p.Reserved
			}
			if p.Protocol == ProtocolAmneziaWG || p.Jc > 0 || p.Jmin > 0 || p.Jmax > 0 || p.S1 > 0 || p.S2 > 0 || p.H1 != "" || p.H2 != "" || p.H3 != "" || p.H4 != "" {
				awgOpts := map[string]interface{}{}
				if p.Jc > 0 {
					awgOpts["jc"] = p.Jc
				}
				if p.Jmin > 0 {
					awgOpts["jmin"] = p.Jmin
				}
				if p.Jmax > 0 {
					awgOpts["jmax"] = p.Jmax
				}
				if p.S1 > 0 {
					awgOpts["s1"] = p.S1
				}
				if p.S2 > 0 {
					awgOpts["s2"] = p.S2
				}
				if p.S3 > 0 {
					awgOpts["s3"] = p.S3
				}
				if p.S4 > 0 {
					awgOpts["s4"] = p.S4
				}
				if p.H1 != "" {
					var hVal uint32
					if _, err := fmt.Sscanf(p.H1, "%d", &hVal); err == nil {
						awgOpts["h1"] = hVal
					} else {
						awgOpts["h1"] = p.H1
					}
				}
				if p.H2 != "" {
					var hVal uint32
					if _, err := fmt.Sscanf(p.H2, "%d", &hVal); err == nil {
						awgOpts["h2"] = hVal
					} else {
						awgOpts["h2"] = p.H2
					}
				}
				if p.H3 != "" {
					var hVal uint32
					if _, err := fmt.Sscanf(p.H3, "%d", &hVal); err == nil {
						awgOpts["h3"] = hVal
					} else {
						awgOpts["h3"] = p.H3
					}
				}
				if p.H4 != "" {
					var hVal uint32
					if _, err := fmt.Sscanf(p.H4, "%d", &hVal); err == nil {
						awgOpts["h4"] = hVal
					} else {
						awgOpts["h4"] = p.H4
					}
				}
				item["amnezia-wg-option"] = awgOpts
			}
		}

		if p.SmuxEnabled {
			smuxOpts := map[string]interface{}{
				"enabled": true,
			}
			if p.SmuxConcurrency > 0 {
				smuxOpts["concurrency"] = p.SmuxConcurrency
			}
			item["smux"] = smuxOpts
		}

		clashProxies = append(clashProxies, item)
	}

	clashConfig := map[string]interface{}{
		"proxies": clashProxies,
	}

	yamlData, err := yaml.Marshal(clashConfig)
	if err != nil {
		return "", err
	}

	return string(yamlData), nil
}
