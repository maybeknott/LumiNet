package proxy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

type PsiphonNoticeParser struct {
	readiness ProviderRouteReadiness
}

func NewPsiphonNoticeParser(routeID string) *PsiphonNoticeParser {
	return &PsiphonNoticeParser{readiness: ProviderRouteReadiness{
		ProviderID:           "psiphon",
		RouteID:              routeID,
		ProtocolMode:         "tunnel_core_supervised",
		RouteBinding:         "tunnel_core_local_proxy",
		RouteStrategy:        "auto",
		ConduitMode:          "auto",
		ReadinessState:       "starting",
		Status:               "starting",
		Evidence:             map[string]string{},
		LastTransitionUnixMS: time.Now().UnixMilli(),
	}}
}

func (p *PsiphonNoticeParser) ParseLine(line string) ProviderRouteReadiness {
	line = strings.TrimSpace(line)
	if p.readiness.Evidence == nil {
		p.readiness.Evidence = map[string]string{}
	}
	p.readiness.LastTransitionUnixMS = time.Now().UnixMilli()
	if containsCRLF(line) {
		p.readiness.Status = "failed"
		p.readiness.ReadinessState = "failed"
		p.readiness.ErrorCode = "INPUT_INVALID"
		return p.readiness
	}
	if strings.HasPrefix(line, "{") {
		var notice map[string]any
		if err := json.Unmarshal([]byte(line), &notice); err == nil {
			p.applyPsiphonNoticeMap(notice)
			return p.readiness
		}
	}
	p.applyPsiphonNoticeText(line)
	return p.readiness
}

func (p *PsiphonNoticeParser) applyPsiphonNoticeMap(notice map[string]any) {
	for key, value := range notice {
		switch strings.ToLower(key) {
		case "listeningsocksproxyport", "listening_socks_proxy_port", "socks_port":
			p.readiness.SOCKSPort = intFromAny(value)
		case "listeninghttpproxyport", "listening_http_proxy_port", "http_proxy_port":
			p.readiness.HTTPProxyPort = intFromAny(value)
		case "event_name", "notice_type", "type":
			p.readiness.Evidence["last_notice"] = fmt.Sprint(value)
		case "tunnels", "tunnels.count":
			p.readiness.Evidence["tunnels"] = fmt.Sprint(value)
		case "shareproxyonnetwork", "share_proxy_on_network", "lan_sharing":
			p.readiness.LANSharing = boolFromAny(value)
		case "shareproxyonnetworksocksport", "lan_socks_port":
			p.readiness.LANSOCKSPort = intFromAny(value)
		case "shareproxyonnetworkhttpport", "lan_http_proxy_port":
			p.readiness.LANHTTPProxyPort = intFromAny(value)
		case "protocolselection", "route_strategy":
			p.readiness.RouteStrategy = strings.ToLower(fmt.Sprint(value))
		case "conduitmode", "conduit_mode":
			p.readiness.ConduitMode = strings.ToLower(fmt.Sprint(value))
		case "beastmode", "beast_mode":
			p.readiness.BeastMode = boolFromAny(value)
		}
	}
	p.updatePsiphonReady()
}

func (p *PsiphonNoticeParser) applyPsiphonNoticeText(line string) {
	lower := strings.ToLower(line)
	p.readiness.Evidence["last_notice"] = truncateEvidence(line, 180)
	for _, token := range strings.FieldsFunc(line, func(r rune) bool {
		return r == ' ' || r == ',' || r == ';'
	}) {
		parts := strings.SplitN(token, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(strings.Trim(parts[0], `"'`))
		value := strings.Trim(parts[1], `"'`)
		if key == "listeningsocksproxyport" || key == "socks_port" {
			p.readiness.SOCKSPort, _ = strconv.Atoi(value)
		}
		if key == "listeninghttpproxyport" || key == "http_proxy_port" {
			p.readiness.HTTPProxyPort, _ = strconv.Atoi(value)
		}
		if key == "shareproxyonnetwork" || key == "lan_sharing" {
			p.readiness.LANSharing = strings.EqualFold(value, "true")
		}
		if key == "shareproxyonnetworksocksport" || key == "lan_socks_port" {
			p.readiness.LANSOCKSPort, _ = strconv.Atoi(value)
		}
		if key == "shareproxyonnetworkhttpport" || key == "lan_http_proxy_port" {
			p.readiness.LANHTTPProxyPort, _ = strconv.Atoi(value)
		}
	}
	if strings.Contains(lower, "conduit") {
		p.readiness.RouteStrategy = "conduit"
	}
	if strings.Contains(lower, "cdn_fronting") || strings.Contains(lower, "fronting") {
		p.readiness.FrontingPolicy = "cdn_fronting"
	}
	if strings.Contains(lower, "beast") {
		p.readiness.BeastMode = true
	}
	if strings.Contains(lower, "tunnel") || strings.Contains(lower, "listening") {
		p.updatePsiphonReady()
	}
}

func (p *PsiphonNoticeParser) updatePsiphonReady() {
	if p.readiness.SOCKSPort > 0 || p.readiness.HTTPProxyPort > 0 {
		p.readiness.ReadinessState = "proxy_listening"
		p.readiness.Status = "success"
		p.readiness.ErrorCode = ""
		return
	}
	p.readiness.ReadinessState = "starting"
	p.readiness.Status = "starting"
}

func ParsePsiphonNoticeStream(routeID string, reader io.Reader) (ProviderRouteReadiness, error) {
	parser := NewPsiphonNoticeParser(routeID)
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 4096), 1024*1024)
	var state ProviderRouteReadiness
	for scanner.Scan() {
		state = parser.ParseLine(scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return state, err
	}
	return state, nil
}

func intFromAny(value any) int {
	switch v := value.(type) {
	case float64:
		return int(v)
	case int:
		return v
	case string:
		n, _ := strconv.Atoi(v)
		return n
	default:
		return 0
	}
}

func boolFromAny(value any) bool {
	switch v := value.(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(strings.TrimSpace(v), "true")
	default:
		return false
	}
}

func truncateEvidence(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}
