// Package proxy provides proxy parsing, testing, and core process management.
//
// core_manager.go implements Xray and sing-box process lifecycle management,
// ported from the Python proxy-tester engine.py.
package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/maybeknott/luminet/internal/utils"
)

// CoreType represents the type of proxy core binary to use.
type CoreType string

const (
	// CoreTypeXray uses the Xray-core binary.
	CoreTypeXray CoreType = "xray"
	// CoreTypeSingBox uses the sing-box binary.
	CoreTypeSingBox CoreType = "singbox"
	// CoreTypeAuto automatically detects an available core binary.
	CoreTypeAuto CoreType = "auto"
)

// CoreManager manages Xray/sing-box binary discovery and process lifecycle.
type CoreManager struct {
	coreType   CoreType
	binaryPath string
	mu         sync.Mutex
}

// CoreInstance represents a running Xray or sing-box process.
type CoreInstance struct {
	// Cmd is the underlying OS process.
	Cmd *exec.Cmd
	// SocksPort is the SOCKS5 listen port for this instance.
	SocksPort int
	// ConfigPath is the path to the temporary config file used by this instance.
	ConfigPath string
	// cancel stops the instance's context.
	cancel context.CancelFunc
}

// NewCoreManager creates a new CoreManager with the specified core type and binary path.
// If binaryPath is empty, FindBinary will be used to locate the binary.
func NewCoreManager(coreType CoreType, binaryPath string) *CoreManager {
	if coreType == "" {
		coreType = CoreTypeAuto
	}
	return &CoreManager{
		coreType:   coreType,
		binaryPath: binaryPath,
	}
}

// FindBinary searches PATH and common installation locations for the core binary.
// Returns the absolute path to the binary or an error if not found.
func (m *CoreManager) FindBinary() (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.binaryPath != "" {
		if _, err := os.Stat(m.binaryPath); err == nil {
			return m.binaryPath, nil
		}
	}

	// Search locations
	var binaries []string
	if m.coreType == CoreTypeSingBox || m.coreType == CoreTypeAuto {
		binaries = append(binaries,
			"sing-box.exe", "sing-box",
			`C:\Users\ACER\Desktop\quranips\tools\Proxy tester\bin\sing_box\sing-box.exe`,
		)
	}
	if m.coreType == CoreTypeXray || m.coreType == CoreTypeAuto {
		binaries = append(binaries,
			"xray.exe", "xray",
			`C:\Users\ACER\Desktop\quranips\tools\Proxy tester\bin\xray\xray.exe`,
		)
	}

	for _, bin := range binaries {
		path, err := exec.LookPath(bin)
		if err == nil {
			m.binaryPath = path
			return path, nil
		}
		if _, err := os.Stat(bin); err == nil {
			m.binaryPath = bin
			return bin, nil
		}
	}

	return "", fmt.Errorf("failed to locate core binary for type %s", m.coreType)
}

// RunTempInstance starts a temporary core process for testing a single proxy.
// It generates the appropriate config, writes it to a temp file, and starts the process.
// The instance listens on the specified socksPort.
func (m *CoreManager) RunTempInstance(proxy *ProxyConfig, socksPort int) (*CoreInstance, error) {
	binary, err := m.FindBinary()
	if err != nil {
		return nil, err
	}

	var configData []byte
	isSingBox := strings.Contains(strings.ToLower(binary), "sing-box") || m.coreType == CoreTypeSingBox

	if isSingBox {
		configData, err = m.BuildSingBoxConfig(proxy, socksPort)
	} else {
		configData, err = m.BuildXrayConfig(proxy, socksPort)
	}
	if err != nil {
		return nil, err
	}

	tmpFile, err := os.CreateTemp("", "luminet-proxy-*.json")
	if err != nil {
		return nil, err
	}
	defer tmpFile.Close()

	if _, err := tmpFile.Write(configData); err != nil {
		os.Remove(tmpFile.Name())
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	var cmd *exec.Cmd
	if isSingBox {
		cmd = exec.CommandContext(ctx, binary, "run", "-c", tmpFile.Name())
	} else {
		cmd = exec.CommandContext(ctx, binary, "-c", tmpFile.Name())
	}

	cmd.SysProcAttr = utils.GetDaemonSysProcAttr()

	if err := cmd.Start(); err != nil {
		cancel()
		os.Remove(tmpFile.Name())
		return nil, err
	}

	time.Sleep(200 * time.Millisecond)

	return &CoreInstance{
		Cmd:        cmd,
		SocksPort:  socksPort,
		ConfigPath: tmpFile.Name(),
		cancel:     cancel,
	}, nil
}

// RunBatchInstance starts a core process configured with multiple proxies.
// Each proxy gets its own SOCKS5 inbound starting from baseSocksPort.
func (m *CoreManager) RunBatchInstance(proxies []*ProxyConfig, baseSocksPort int) (*CoreInstance, error) {
	binary, err := m.FindBinary()
	if err != nil {
		return nil, err
	}

	isSingBox := strings.Contains(strings.ToLower(binary), "sing-box") || m.coreType == CoreTypeSingBox

	var configData []byte
	if isSingBox {
		var inbounds []interface{}
		var outbounds []interface{}
		var rules []interface{}

		for idx, p := range proxies {
			port := baseSocksPort + idx
			inTag := fmt.Sprintf("in-%d", port)
			outTag := fmt.Sprintf("out-%d", port)

			inbounds = append(inbounds, map[string]interface{}{
				"type":        "socks",
				"tag":         "socks-" + inTag,
				"listen":      "127.0.0.1",
				"listen_port": port,
			})

			curr := p
			tag := outTag
			for curr != nil {
				if curr.Detour != nil {
					nextTag := tag + "-detour"
					if curr.Detour.Name != "" {
						nextTag = curr.Detour.Name
					}
					curr.DialerProxy = nextTag
				}
				outbound, err := m.buildSingBoxOutbound(curr, tag)
				if err != nil {
					return nil, err
				}
				outbounds = append(outbounds, outbound)

				if curr.Detour != nil {
					tag = curr.DialerProxy
					curr = curr.Detour
				} else {
					curr = nil
				}
			}

			rules = append(rules, map[string]interface{}{
				"inbound":  []string{"socks-" + inTag},
				"outbound": outTag,
			})
		}

		config := map[string]interface{}{
			"inbounds":  inbounds,
			"outbounds": outbounds,
			"route": map[string]interface{}{
				"rules": rules,
			},
		}
		configData, _ = json.Marshal(config)
	} else {
		var inbounds []interface{}
		var outbounds []interface{}
		var rules []interface{}

		for idx, p := range proxies {
			port := baseSocksPort + idx
			inTag := fmt.Sprintf("in-%d", port)
			outTag := fmt.Sprintf("out-%d", port)

			inbounds = append(inbounds, map[string]interface{}{
				"port":     port,
				"protocol": "socks",
				"tag":      "socks-" + inTag,
				"settings": map[string]interface{}{
					"auth": "noauth",
					"udp":  true,
				},
			})

			curr := p
			tag := outTag
			for curr != nil {
				if curr.Detour != nil {
					nextTag := tag + "-detour"
					if curr.Detour.Name != "" {
						nextTag = curr.Detour.Name
					}
					curr.DialerProxy = nextTag
				}
				outbound, err := m.buildXrayOutbound(curr, tag)
				if err != nil {
					return nil, err
				}
				outbounds = append(outbounds, outbound)

				if curr.Detour != nil {
					tag = curr.DialerProxy
					curr = curr.Detour
				} else {
					curr = nil
				}
			}

			rules = append(rules, map[string]interface{}{
				"type":        "field",
				"inboundTag":  []string{"socks-" + inTag},
				"outboundTag": outTag,
			})
		}

		config := map[string]interface{}{
			"inbounds":  inbounds,
			"outbounds": outbounds,
			"routing": map[string]interface{}{
				"rules": rules,
			},
		}
		configData, _ = json.Marshal(config)
	}

	tmpFile, err := os.CreateTemp("", "luminet-batch-*.json")
	if err != nil {
		return nil, err
	}
	defer tmpFile.Close()

	if _, err := tmpFile.Write(configData); err != nil {
		os.Remove(tmpFile.Name())
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	var cmd *exec.Cmd
	if isSingBox {
		cmd = exec.CommandContext(ctx, binary, "run", "-c", tmpFile.Name())
	} else {
		cmd = exec.CommandContext(ctx, binary, "-c", tmpFile.Name())
	}

	cmd.SysProcAttr = utils.GetDaemonSysProcAttr()

	if err := cmd.Start(); err != nil {
		cancel()
		os.Remove(tmpFile.Name())
		return nil, err
	}

	time.Sleep(300 * time.Millisecond)

	return &CoreInstance{
		Cmd:        cmd,
		SocksPort:  baseSocksPort,
		ConfigPath: tmpFile.Name(),
		cancel:     cancel,
	}, nil
}

// buildSingBoxOutbound constructs a sing-box outbound configuration map from a ProxyConfig.
func (m *CoreManager) buildSingBoxOutbound(proxy *ProxyConfig, tag string) (map[string]interface{}, error) {
	var outbound map[string]interface{}
	switch proxy.Protocol {
	case ProtocolVMess:
		outbound = map[string]interface{}{
			"type":        "vmess",
			"tag":         tag,
			"server":      proxy.Address,
			"server_port": proxy.Port,
			"uuid":        proxy.UUID,
			"alter_id":    proxy.AlterID,
			"security":    proxy.Security,
		}
	case ProtocolVLESS:
		outbound = map[string]interface{}{
			"type":        "vless",
			"tag":         tag,
			"server":      proxy.Address,
			"server_port": proxy.Port,
			"uuid":        proxy.UUID,
		}
	case ProtocolTrojan:
		outbound = map[string]interface{}{
			"type":        "trojan",
			"tag":         tag,
			"server":      proxy.Address,
			"server_port": proxy.Port,
			"password":    proxy.Password,
		}
	case ProtocolShadowsocks:
		outbound = map[string]interface{}{
			"type":        "shadowsocks",
			"tag":         tag,
			"server":      proxy.Address,
			"server_port": proxy.Port,
			"method":      proxy.Method,
			"password":    proxy.Password,
		}
	case ProtocolHysteria2:
		h2cfg := Hysteria2Outbound{
			Server:      proxy.Address,
			Port:        proxy.Port,
			Password:    proxy.Password,
			Obfuscation: proxy.Obfuscation,
			UpMbps:      proxy.UpMbps,
			DownMbps:    proxy.DownMbps,
		}
		var err error
		outbound, err = GenerateHysteria2Config(h2cfg)
		if err != nil {
			return nil, err
		}
		outbound["tag"] = tag
	case ProtocolTUIC:
		outbound = map[string]interface{}{
			"type":        "tuic",
			"tag":         tag,
			"server":      proxy.Address,
			"server_port": proxy.Port,
			"uuid":        proxy.UUID,
			"password":    proxy.Password,
		}
	case ProtocolNaive:
		ncfg := NaiveOutbound{
			Server:   proxy.Address,
			Port:     proxy.Port,
			Username: proxy.UUID,
			Password: proxy.Password,
		}
		var err error
		outbound, err = GenerateNaiveConfig(ncfg)
		if err != nil {
			return nil, err
		}
		outbound["tag"] = tag
	case ProtocolDNSTT:
		outbound = map[string]interface{}{
			"type":                "dnstt",
			"tag":                 tag,
			"publicKey":           proxy.PublicKey,
			"domain":              proxy.Address,
			"resolvers":           proxy.Resolvers,
			"tunnel_per_resolver": proxy.TunnelPerResolver,
			"udp_over_tcp":        proxy.UDPOverTCP,
		}
	case ProtocolWireGuard, ProtocolAmneziaWG:
		wgOutbound := map[string]interface{}{
			"type":            "wireguard",
			"tag":             tag,
			"server":          proxy.Address,
			"server_port":     proxy.Port,
			"local_address":   proxy.LocalAddress,
			"private_key":     proxy.PrivateKey,
			"peer_public_key": proxy.PublicKey,
		}
		if len(proxy.Reserved) > 0 {
			wgOutbound["reserved"] = proxy.Reserved
		}
		if proxy.MTU > 0 {
			wgOutbound["mtu"] = proxy.MTU
		}
		if proxy.FakePackets != "" {
			wgOutbound["fake_packets"] = proxy.FakePackets
		}
		if proxy.FakePacketsSize != "" {
			wgOutbound["fake_packets_size"] = proxy.FakePacketsSize
		}
		if proxy.FakePacketsDelay != "" {
			wgOutbound["fake_packets_delay"] = proxy.FakePacketsDelay
		}
		if proxy.FakePacketsMode != "" {
			wgOutbound["fake_packets_mode"] = proxy.FakePacketsMode
		}
		if proxy.Protocol == ProtocolAmneziaWG || proxy.Jc > 0 || proxy.Jmin > 0 || proxy.Jmax > 0 || proxy.S1 > 0 || proxy.S2 > 0 || proxy.H1 != "" || proxy.H2 != "" || proxy.H3 != "" || proxy.H4 != "" {
			if proxy.Jc > 0 {
				wgOutbound["awg_jc"] = proxy.Jc
				wgOutbound["amnezia_jc"] = proxy.Jc
			}
			if proxy.Jmin > 0 {
				wgOutbound["awg_jmin"] = proxy.Jmin
				wgOutbound["amnezia_jmin"] = proxy.Jmin
			}
			if proxy.Jmax > 0 {
				wgOutbound["awg_jmax"] = proxy.Jmax
				wgOutbound["amnezia_jmax"] = proxy.Jmax
			}
			if proxy.S1 > 0 {
				wgOutbound["awg_s1"] = proxy.S1
				wgOutbound["amnezia_s1"] = proxy.S1
			}
			if proxy.S2 > 0 {
				wgOutbound["awg_s2"] = proxy.S2
				wgOutbound["amnezia_s2"] = proxy.S2
			}
			if proxy.S3 > 0 {
				wgOutbound["awg_s3"] = proxy.S3
				wgOutbound["amnezia_s3"] = proxy.S3
			}
			if proxy.S4 > 0 {
				wgOutbound["awg_s4"] = proxy.S4
				wgOutbound["amnezia_s4"] = proxy.S4
			}
			if proxy.H1 != "" {
				var hVal uint32
				if _, err := fmt.Sscanf(proxy.H1, "%d", &hVal); err == nil {
					wgOutbound["awg_h1"] = hVal
					wgOutbound["amnezia_h1"] = hVal
				} else {
					wgOutbound["awg_h1"] = proxy.H1
					wgOutbound["amnezia_h1"] = proxy.H1
				}
			}
			if proxy.H2 != "" {
				var hVal uint32
				if _, err := fmt.Sscanf(proxy.H2, "%d", &hVal); err == nil {
					wgOutbound["awg_h2"] = hVal
					wgOutbound["amnezia_h2"] = hVal
				} else {
					wgOutbound["awg_h2"] = proxy.H2
					wgOutbound["amnezia_h2"] = proxy.H2
				}
			}
			if proxy.H3 != "" {
				var hVal uint32
				if _, err := fmt.Sscanf(proxy.H3, "%d", &hVal); err == nil {
					wgOutbound["awg_h3"] = hVal
					wgOutbound["amnezia_h3"] = hVal
				} else {
					wgOutbound["awg_h3"] = proxy.H3
					wgOutbound["amnezia_h3"] = proxy.H3
				}
			}
			if proxy.H4 != "" {
				var hVal uint32
				if _, err := fmt.Sscanf(proxy.H4, "%d", &hVal); err == nil {
					wgOutbound["awg_h4"] = hVal
					wgOutbound["amnezia_h4"] = hVal
				} else {
					wgOutbound["awg_h4"] = proxy.H4
					wgOutbound["amnezia_h4"] = proxy.H4
				}
			}
		}
		outbound = wgOutbound
	case ProtocolAnyTLS:
		outbound = map[string]interface{}{
			"type":              "anytls",
			"tag":               tag,
			"server":            proxy.Address,
			"server_port":       proxy.Port,
			"password":          proxy.Password,
			"min_idle_sessions": proxy.MinIdleSessions,
		}
	case ProtocolJuicity:
		outbound = map[string]interface{}{
			"type":                    "juicity",
			"tag":                     tag,
			"server":                  proxy.Address,
			"server_port":             proxy.Port,
			"uuid":                    proxy.UUID,
			"password":                proxy.Password,
			"congestion_control":      proxy.CongestionControl,
			"pinned_certchain_sha256": proxy.PinnedCertChainSHA256,
		}
	default:
		outbound = map[string]interface{}{
			"type":        "socks",
			"tag":         tag,
			"server":      proxy.Address,
			"server_port": proxy.Port,
		}
	}

	tls := map[string]interface{}{
		"enabled": proxy.TLS,
	}
	if proxy.TLS {
		tls["insecure"] = proxy.SkipCertVerify
		if proxy.SNI != "" {
			tls["server_name"] = proxy.SNI
		} else {
			tls["server_name"] = proxy.Address
		}
		if proxy.Security == "reality" {
			tls["reality"] = map[string]interface{}{
				"enabled":    true,
				"public_key": proxy.PublicKey,
				"short_id":   proxy.ShortID,
			}
		}
		outbound["tls"] = tls
	}
	if proxy.Transport != "" {
		transport := map[string]interface{}{
			"type": proxy.Transport,
		}
		if proxy.Transport == "ws" {
			transport["path"] = proxy.Path
			if proxy.Host != "" {
				transport["headers"] = map[string]string{
					"Host": proxy.Host,
				}
			}
		}
		outbound["transport"] = transport
	}

	if proxy.DialerProxy != "" {
		outbound["dialer_proxy"] = proxy.DialerProxy
	}

	return outbound, nil
}

// buildXrayOutbound constructs an Xray outbound configuration map from a ProxyConfig.
func (m *CoreManager) buildXrayOutbound(proxy *ProxyConfig, tag string) (map[string]interface{}, error) {
	var outbound map[string]interface{}
	switch proxy.Protocol {
	case ProtocolVMess:
		outbound = map[string]interface{}{
			"protocol": "vmess",
			"tag":      tag,
			"settings": map[string]interface{}{
				"vnext": []interface{}{
					map[string]interface{}{
						"address": proxy.Address,
						"port":    proxy.Port,
						"users": []interface{}{
							map[string]interface{}{
								"id":       proxy.UUID,
								"alterId":  proxy.AlterID,
								"security": proxy.Security,
							},
						},
					},
				},
			},
		}
	case ProtocolVLESS:
		users := []interface{}{
			map[string]interface{}{
				"id":         proxy.UUID,
				"encryption": "none",
			},
		}
		if proxy.Flow != "" {
			users[0].(map[string]interface{})["flow"] = proxy.Flow
		}
		outbound = map[string]interface{}{
			"protocol": "vless",
			"tag":      tag,
			"settings": map[string]interface{}{
				"vnext": []interface{}{
					map[string]interface{}{
						"address": proxy.Address,
						"port":    proxy.Port,
						"users":   users,
					},
				},
			},
		}
	case ProtocolTrojan:
		outbound = map[string]interface{}{
			"protocol": "trojan",
			"tag":      tag,
			"settings": map[string]interface{}{
				"servers": []interface{}{
					map[string]interface{}{
						"address":  proxy.Address,
						"port":     proxy.Port,
						"password": proxy.Password,
					},
				},
			},
		}
	case ProtocolShadowsocks:
		outbound = map[string]interface{}{
			"protocol": "shadowsocks",
			"tag":      tag,
			"settings": map[string]interface{}{
				"servers": []interface{}{
					map[string]interface{}{
						"address":  proxy.Address,
						"port":     proxy.Port,
						"method":   proxy.Method,
						"password": proxy.Password,
					},
				},
			},
		}
	case ProtocolWireGuard, ProtocolAmneziaWG:
		peer := map[string]interface{}{
			"endpoint":  fmt.Sprintf("%s:%d", proxy.Address, proxy.Port),
			"publicKey": proxy.PublicKey,
			"keepAlive": 25,
		}
		settings := map[string]interface{}{
			"secretKey": proxy.PrivateKey,
			"peers":     []interface{}{peer},
		}
		if len(proxy.LocalAddress) > 0 {
			settings["address"] = proxy.LocalAddress
		}
		if proxy.MTU > 0 {
			settings["mtu"] = proxy.MTU
		}
		if len(proxy.Reserved) > 0 {
			settings["reserved"] = proxy.Reserved
		}
		if proxy.WNoise != "" {
			settings["wnoise"] = proxy.WNoise
		}
		if proxy.WNoiseCount != "" {
			settings["wnoisecount"] = proxy.WNoiseCount
		}
		if proxy.WPayloadSize != "" {
			settings["wpayloadsize"] = proxy.WPayloadSize
		}
		if proxy.WNoiseDelay != "" {
			settings["wnoisedelay"] = proxy.WNoiseDelay
		}
		outbound = map[string]interface{}{
			"protocol": "wireguard",
			"tag":      tag,
			"settings": settings,
		}
	case ProtocolDNSTT:
		outbound = map[string]interface{}{
			"protocol": "dnstt",
			"tag":      tag,
			"settings": map[string]interface{}{
				"publicKey":           proxy.PublicKey,
				"domain":              proxy.Address,
				"resolvers":           proxy.Resolvers,
				"tunnel_per_resolver": proxy.TunnelPerResolver,
				"udp_over_tcp":        proxy.UDPOverTCP,
			},
		}
	case ProtocolAnyTLS:
		outbound = map[string]interface{}{
			"protocol": "anytls",
			"tag":      tag,
			"settings": map[string]interface{}{
				"address":           proxy.Address,
				"port":              proxy.Port,
				"password":          proxy.Password,
				"sni":               proxy.SNI,
				"allow_insecure":    proxy.SkipCertVerify,
				"min_idle_sessions": proxy.MinIdleSessions,
			},
		}
	case ProtocolJuicity:
		address := proxy.Address
		if strings.Contains(address, ":") && !strings.HasPrefix(address, "[") {
			address = "[" + address + "]"
		}
		address = fmt.Sprintf("%s:%d", address, proxy.Port)
		outbound = map[string]interface{}{
			"protocol": "juicity",
			"tag":      tag,
			"settings": map[string]interface{}{
				"address":                 address,
				"uuid":                    proxy.UUID,
				"password":                proxy.Password,
				"sni":                     proxy.SNI,
				"allow_insecure":          proxy.SkipCertVerify,
				"congestion_control":      proxy.CongestionControl,
				"pinned_certchain_sha256": proxy.PinnedCertChainSHA256,
			},
		}
	default:
		outbound = map[string]interface{}{
			"protocol": "socks",
			"tag":      tag,
			"settings": map[string]interface{}{
				"servers": []interface{}{
					map[string]interface{}{
						"address": proxy.Address,
						"port":    proxy.Port,
					},
				},
			},
		}
	}

	streamSettings := map[string]interface{}{
		"network": proxy.Transport,
	}

	if proxy.Security == "reality" {
		streamSettings["security"] = "reality"
		realitySettings := map[string]interface{}{
			"show":        false,
			"fingerprint": proxy.Fingerprint,
			"serverName":  proxy.SNI,
			"publicKey":   proxy.PublicKey,
		}
		if proxy.ShortID != "" {
			realitySettings["shortId"] = proxy.ShortID
		}
		streamSettings["realitySettings"] = realitySettings
	} else if proxy.TLS || proxy.Security == "tls" {
		streamSettings["security"] = "tls"
		tlsSettings := map[string]interface{}{
			"allowInsecure": proxy.SkipCertVerify,
		}
		if proxy.SNI != "" {
			tlsSettings["serverName"] = proxy.SNI
		} else {
			tlsSettings["serverName"] = proxy.Address
		}
		if proxy.Fingerprint != "" {
			tlsSettings["fingerprint"] = proxy.Fingerprint
		}
		streamSettings["tlsSettings"] = tlsSettings
	}

	if proxy.Transport == "ws" {
		wsSettings := map[string]interface{}{
			"path": proxy.Path,
		}
		if proxy.Host != "" {
			wsSettings["headers"] = map[string]string{
				"Host": proxy.Host,
			}
		}
		streamSettings["wsSettings"] = wsSettings
	} else if proxy.Transport == "grpc" {
		grpcSettings := map[string]interface{}{
			"serviceName": proxy.ServiceName,
		}
		if proxy.Authority != "" {
			grpcSettings["authority"] = proxy.Authority
		} else if proxy.SNI != "" {
			grpcSettings["authority"] = proxy.SNI
		} else if proxy.Address != "" {
			grpcSettings["authority"] = proxy.Address
		}
		if proxy.MultiMode {
			grpcSettings["multiMode"] = true
		}
		streamSettings["grpcSettings"] = grpcSettings
	}

	sockopt := map[string]interface{}{}
	if proxy.FragmentLength != "" || proxy.FragmentInterval != "" {
		packets := proxy.FragmentPackets
		if packets == "" {
			packets = "tlshello"
		}
		sockopt["fragment"] = map[string]interface{}{
			"packets":  packets,
			"length":   proxy.FragmentLength,
			"interval": proxy.FragmentInterval,
		}
	}
	if proxy.DialerProxy != "" {
		sockopt["dialerProxy"] = proxy.DialerProxy
	}
	if len(sockopt) > 0 {
		streamSettings["sockopt"] = sockopt
	}

	outbound["streamSettings"] = streamSettings

	return outbound, nil
}

// BuildXrayConfig generates an Xray JSON configuration for the given proxy
// with a SOCKS5 inbound on the specified port.
func (m *CoreManager) BuildXrayConfig(proxy *ProxyConfig, socksPort int) ([]byte, error) {
	inbounds := []interface{}{
		map[string]interface{}{
			"port":     socksPort,
			"protocol": "socks",
			"settings": map[string]interface{}{
				"auth": "noauth",
				"udp":  true,
			},
		},
	}

	var outbounds []interface{}
	curr := proxy
	tag := "proxy"
	for curr != nil {
		if curr.Detour != nil {
			nextTag := tag + "-detour"
			if curr.Detour.Name != "" {
				nextTag = curr.Detour.Name
			}
			curr.DialerProxy = nextTag
		}
		outbound, err := m.buildXrayOutbound(curr, tag)
		if err != nil {
			return nil, err
		}
		outbounds = append(outbounds, outbound)

		if curr.Detour != nil {
			tag = curr.DialerProxy
			curr = curr.Detour
		} else {
			curr = nil
		}
	}

	config := map[string]interface{}{
		"inbounds":  inbounds,
		"outbounds": outbounds,
	}

	return json.Marshal(config)
}

// BuildSingBoxConfig generates a sing-box JSON configuration for the given proxy
// with a SOCKS5 inbound on the specified port.
func (m *CoreManager) BuildSingBoxConfig(proxy *ProxyConfig, socksPort int) ([]byte, error) {
	inbounds := []interface{}{
		map[string]interface{}{
			"type":        "socks",
			"tag":         "socks-in",
			"listen":      "127.0.0.1",
			"listen_port": socksPort,
		},
	}

	var outbounds []interface{}
	curr := proxy
	tag := "proxy"
	for curr != nil {
		if curr.Detour != nil {
			nextTag := tag + "-detour"
			if curr.Detour.Name != "" {
				nextTag = curr.Detour.Name
			}
			curr.DialerProxy = nextTag
		}
		outbound, err := m.buildSingBoxOutbound(curr, tag)
		if err != nil {
			return nil, err
		}
		outbounds = append(outbounds, outbound)

		if curr.Detour != nil {
			tag = curr.DialerProxy
			curr = curr.Detour
		} else {
			curr = nil
		}
	}

	directOutbound := map[string]interface{}{
		"type": "direct",
		"tag":  "direct-out",
	}
	outbounds = append(outbounds, directOutbound)

	routeRules := []interface{}{
		map[string]interface{}{
			"ip_is_private": true,
			"outbound":      "direct-out",
		},
	}

	config := map[string]interface{}{
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"route": map[string]interface{}{
			"rules": routeRules,
		},
	}

	return json.Marshal(config)
}

// Stop gracefully stops the core instance, killing the process and cleaning up
// the temporary config file.
func (i *CoreInstance) Stop() error {
	if i.cancel != nil {
		i.cancel()
	}
	if i.Cmd != nil && i.Cmd.Process != nil {
		pid := i.Cmd.Process.Pid
		killCmd := exec.Command("taskkill", "/F", "/T", "/PID", fmt.Sprintf("%d", pid))
		killCmd.SysProcAttr = utils.GetHideWindowSysProcAttr()
		killCmd.Run()
		i.Cmd.Process.Kill()
	}

	time.Sleep(50 * time.Millisecond)
	if i.ConfigPath != "" {
		os.Remove(i.ConfigPath)
	}
	return nil
}

// Wait blocks until the core instance exits or the context is cancelled.
func (i *CoreInstance) Wait(ctx context.Context) error {
	done := make(chan error, 1)
	go func() {
		done <- i.Cmd.Wait()
	}()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		i.Stop()
		return ctx.Err()
	}
}

// IsRunning returns true if the core process is still running.
func (i *CoreInstance) IsRunning() bool {
	if i.Cmd == nil || i.Cmd.Process == nil {
		return false
	}
	return i.Cmd.ProcessState == nil
}
