package proxy

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
)

type SubscriptionFilters struct {
	AllowProtocols []string `json:"allow_protocols"`
	SearchQuery    string   `json:"search_query"`
	MinPort        int      `json:"min_port"`
	MaxPort        int      `json:"max_port"`
}

// FilterSafeProxyConfig blocks private subnets, loopbacks, and localhost targets to prevent malicious redirects.
func FilterSafeProxyConfig(cfg *ProxyConfig) bool {
	if cfg == nil {
		return false
	}
	if ip := net.ParseIP(cfg.Address); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
			return false
		}
	}
	hostLower := strings.ToLower(cfg.Address)
	if hostLower == "localhost" || strings.HasSuffix(hostLower, ".local") {
		return false
	}
	return true
}

var DefaultSubscriptionLinks = []string{
	"https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
	"https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile-2.txt",
	"https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS_mobile.txt",
	"https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-checked.txt",
	"https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS.txt",
	"https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_SS+All_RUS.txt",
	"https://raw.githubusercontent.com/Mosifree/-FREE2CONFIG/refs/heads/main/FRAGMENT",
	"https://raw.githubusercontent.com/ThomasJasperthecat/sub/main/sublist1.txt",
	"https://raw.githubusercontent.com/masir-sefid/Sub/main/@Masir_Sefid.txt",
	"https://sub.iampedi5.live/sub/base64.txt",
	"https://sub.whitedns.one/sub/mihomo.yaml",
}

var DefaultTelegramChannels = []string{
	"@ProxyFree_Ru",
	"@TProxyRU",
	"@iRoProxy",
	"@proxyy",
	"@ProxyMTProto",
	"@Masir_Sefid",
	"@v2ray_outlinefree",
	"@ProxyDaemi",
}

func AggregateSubscriptions(ctx context.Context, inputs []string, filters SubscriptionFilters) ([]*ProxyConfig, error) {
	var aggregated []*ProxyConfig

	var resolvedInputs []string
	if len(inputs) == 0 {
		resolvedInputs = append(resolvedInputs, DefaultSubscriptionLinks...)
		resolvedInputs = append(resolvedInputs, DefaultTelegramChannels...)
	} else {
		for _, input := range inputs {
			if strings.ToLower(strings.TrimSpace(input)) == "default" {
				resolvedInputs = append(resolvedInputs, DefaultSubscriptionLinks...)
				resolvedInputs = append(resolvedInputs, DefaultTelegramChannels...)
			} else {
				resolvedInputs = append(resolvedInputs, input)
			}
		}
	}

	for _, input := range resolvedInputs {
		input = strings.TrimSpace(input)
		if input == "" {
			continue
		}

		// Support direct subscription URL downloading
		if strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://") {
			configs, err := FetchSubscription(ctx, input)
			if err == nil {
				for _, cfg := range configs {
					if FilterSafeProxyConfig(cfg) {
						aggregated = append(aggregated, cfg)
					}
				}
			}
			continue
		}

		// Detect and scrape public Telegram channels
		if strings.Contains(input, "t.me/") || (!strings.Contains(input, "\n") && strings.HasPrefix(input, "@")) {
			links, err := FetchMultiProtocolFromChannel(ctx, input)
			if err == nil {
				for _, link := range links {
					cfg, err := ParseProxyURI(link)
					if err == nil {
						if FilterSafeProxyConfig(cfg) {
							aggregated = append(aggregated, cfg)
						}
					}
				}
			}
			continue
		}

		configs, err := ParseSubscriptionContent(input)
		if err != nil {
			configs, err = ParseProxyList(input)
		}

		if err == nil {
			for _, cfg := range configs {
				if FilterSafeProxyConfig(cfg) {
					aggregated = append(aggregated, cfg)
				}
			}
		}
	}

	filtered := []*ProxyConfig{}
	for _, c := range aggregated {
		if !matchFilters(c, filters) {
			continue
		}
		filtered = append(filtered, c)
	}

	return filtered, nil
}

// Subconvert formats the aggregated nodes into Clash YAML or base64 subscription format.
func Subconvert(proxies []*ProxyConfig, targetFormat string) (string, error) {
	switch strings.ToLower(targetFormat) {
	case "clash":
		return ExportToClashYaml(proxies)
	case "base64", "sub":
		var uris []string
		for _, p := range proxies {
			if p == nil {
				continue
			}
			uri := p.ToURI()
			if uri != "" {
				uris = append(uris, uri)
			}
		}
		joined := strings.Join(uris, "\n")
		return base64.StdEncoding.EncodeToString([]byte(joined)), nil
	case "raw":
		var uris []string
		for _, p := range proxies {
			if p == nil {
				continue
			}
			uri := p.ToURI()
			if uri != "" {
				uris = append(uris, uri)
			}
		}
		return strings.Join(uris, "\n"), nil
	default:
		return "", fmt.Errorf("unsupported subconverter format %q", targetFormat)
	}
}

func matchFilters(c *ProxyConfig, f SubscriptionFilters) bool {
	// Protocol check
	if len(f.AllowProtocols) > 0 {
		proto := strings.ToLower(string(c.Protocol))
		matched := false
		for _, allowed := range f.AllowProtocols {
			if strings.EqualFold(proto, strings.TrimSpace(allowed)) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Search query check
	if f.SearchQuery != "" {
		q := strings.ToLower(f.SearchQuery)
		host := strings.ToLower(c.Address)
		name := strings.ToLower(c.Name)
		if !strings.Contains(host, q) && !strings.Contains(name, q) {
			return false
		}
	}

	// Port check
	if f.MinPort > 0 && c.Port < f.MinPort {
		return false
	}
	if f.MaxPort > 0 && c.Port > f.MaxPort {
		return false
	}

	return true
}
