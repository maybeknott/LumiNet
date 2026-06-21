package proxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// ponytail: fallback DoH resolvers for failover.
var fallbackDnsResolvers = []string{
	"https://dns.quad9.net/dns-query",
	"https://cloudflare-dns.com/dns-query",
	"https://dns.google/dns-query",
	"https://common-dns.resolve.neustar/dns-query",
}

// builtInHostsOverrides maps blocked domains to clean IPs.
var builtInHostsOverrides = map[string]string{
	"abs.twimg.com":   "104.19.229.21",
	"x.com":           "104.19.229.21",
	"ads-api.x.com":   "104.19.229.21",
	"pbs.twimg.com":   "104.19.229.21",
	"api.x.com":       "104.19.229.21",
	"www.youtube.com": "216.239.38.120",
	"youtube.com":     "216.239.38.120",
	"accounts.youtube.com": "216.239.38.120",
	"i.ytimg.com": "216.239.38.120",
	"googleads.g.doubleclick.net": "216.239.38.120",
	"yt3.ggpht.com": "216.239.38.120",
	"m.youtube.com": "216.239.38.120",
	"music.youtube.com": "216.239.38.120",
	"kids.youtube.com": "216.239.38.120",
	"studio.youtube.com": "216.239.38.120",
	"tv.youtube.com": "216.239.38.120",
	"consent.youtube.com": "216.239.38.120",
	"youtu.be": "216.239.38.120",
	"yt.be": "216.239.38.120",
	"youtube-nocookie.com": "216.239.38.120",
	"www.youtube-nocookie.com": "216.239.38.120",
	"ytimg.com": "216.239.38.120",
	"s.ytimg.com": "216.239.38.120",
	"i9.ytimg.com": "216.239.38.120",
	"ytimg.l.google.com": "216.239.38.120",
	"googlevideo.com": "216.239.38.120",
	"redirector.googlevideo.com": "216.239.38.120",
	"manifest.googlevideo.com": "216.239.38.120",
	"youtube.googleapis.com": "216.239.38.120",
	"youtubei.googleapis.com": "216.239.38.120",
	"youtubeembeddedplayer.googleapis.com": "216.239.38.120",
	"www.googleapis.com": "216.239.38.120",
	"youtube-ui.l.google.com": "216.239.38.120",
	"wide-youtube.l.google.com": "216.239.38.120",
	"yt3.googleusercontent.com": "216.239.38.120",
	"lh3.googleusercontent.com": "216.239.38.120",

	// MahsaNG Offline DNS maps to bypass DNS hijacking
	"cloudflare-dns.com":                   "203.32.120.226",
	"doh.opendns.com":                      "208.67.222.222",
	"secure.avastdns.com":                  "185.185.133.66",
	"doh.libredns.gr":                      "116.202.176.26",
	"dns.electrotm.org":                    "78.157.42.100",
	"dns.bitdefender.net":                  "34.84.232.67",
	"cluster-1.gac.edu":                    "138.236.128.101",
	"api.twitter.com":                      "104.244.42.66",
	"twitter.com":                          "104.244.42.1",
	"abs-0.twimg.com":                      "104.244.43.131",
	"video.twimg.com":                      "192.229.220.133",
	"t.co":                                 "104.244.42.69",
	"ton.local.twitter.com":                "104.244.42.1",
	"instagram.com":                        "163.70.128.174",
	"www.instagram.com":                    "163.70.128.174",
	"static.cdninstagram.com":              "163.70.132.63",
	"scontent.cdninstagram.com":            "163.70.132.63",
	"privacycenter.instagram.com":           "163.70.128.174",
	"help.instagram.com":                   "163.70.128.174",
	"l.instagram.com":                      "163.70.128.174",
	"e1.whatsapp.net":                      "163.70.128.60",
	"e2.whatsapp.net":                      "163.70.128.60",
	"e3.whatsapp.net":                      "163.70.128.60",
	"e4.whatsapp.net":                      "163.70.128.60",
	"e5.whatsapp.net":                      "163.70.128.60",
	"e6.whatsapp.net":                      "163.70.128.60",
	"e7.whatsapp.net":                      "163.70.128.60",
	"e8.whatsapp.net":                      "163.70.128.60",
	"e9.whatsapp.net":                      "163.70.128.60",
	"e10.whatsapp.net":                     "163.70.128.60",
	"e11.whatsapp.net":                     "163.70.128.60",
	"e12.whatsapp.net":                     "163.70.128.60",
	"e13.whatsapp.net":                     "163.70.128.60",
	"e14.whatsapp.net":                     "163.70.128.60",
	"e15.whatsapp.net":                     "163.70.128.60",
	"e16.whatsapp.net":                     "163.70.128.60",
	"dit.whatsapp.net":                     "185.60.219.60",
	"g.whatsapp.net":                       "185.60.218.54",
	"wa.me":                                "185.60.219.60",
	"web.whatsapp.com":                     "31.13.83.51",
	"whatsapp.net":                         "31.13.83.51",
	"whatsapp.com":                         "31.13.83.51",
	"cdn.whatsapp.net":                     "31.13.83.51",
	"snr.whatsapp.net":                     "31.13.83.51",
	"static.xx.fbcdn.net":                  "31.13.75.13",
	"scontent-mct1-1.xx.fbcdn.net":         "31.13.75.13",
	"video-mct1-1.xx.fbcdn.net":            "31.13.75.13",
	"video.fevn1-2.fna.fbcdn.net":          "185.48.241.146",
	"video.fevn1-4.fna.fbcdn.net":          "185.48.243.145",
	"scontent.xx.fbcdn.net":                "185.48.240.146",
	"scontent.fevn1-1.fna.fbcdn.net":       "185.48.240.145",
	"scontent.fevn1-2.fna.fbcdn.net":       "185.48.241.145",
	"scontent.fevn1-3.fna.fbcdn.net":       "185.48.242.146",
	"scontent.fevn1-4.fna.fbcdn.net":       "185.48.243.147",
	"connect.facebook.net":                 "31.13.84.51",
	"facebook.com":                         "31.13.65.49",
	"developers.facebook.com":              "31.13.84.8",
	"about.meta.com":                       "163.70.128.13",
	"meta.com":                             "163.70.128.13",
	"rr2---sn-vh5ouxa-hju6.googlevideo.com": "213.202.6.141",
	"rr4---sn-hju7en7k.googlevideo.com":    "74.125.167.74",
	"rr3---sn-vh5ouxa-hjuz.googlevideo.com": "134.0.218.206",
	"download.visualstudio.microsoft.com":  "68.232.34.200",
	"ocsp.pki.goog":                        "172.217.16.195",
	"rr2---sn-hju7enel.googlevideo.com":    "74.125.98.39",
	"rr3---sn-4g5lznl6.googlevideo.com":    "74.125.173.40",
	"jnn-pa.googleapis.com":                "89.58.57.45",
	"rr1---sn-hju7enll.googlevideo.com":    "74.125.98.6",
	"rr6---sn-hju7en7r.googlevideo.com":    "74.125.167.92",
	"play.google.com":                      "216.58.212.174",
	"www.gstatic.com":                      "142.250.185.99",
	"apis.google.com":                      "172.217.23.110",
	"adservice.google.com":                 "202.61.195.218",
	"mail.google.com":                      "142.250.186.37",
	"accounts.google.com":                  "172.217.16.205",
	"ssl.gstatic.com":                      "142.250.184.195",
	"fonts.gstatic.com":                    "172.217.23.99",
	"rr4---sn-hju7enll.googlevideo.com":    "74.125.98.9",
	"rr2---sn-hju7enll.googlevideo.com":    "74.125.98.7",
	"rr1---sn-hju7enel.googlevideo.com":    "74.125.98.38",
	"rr5---sn-vh5ouxa-hjuz.googlevideo.com": "134.0.218.208",
	"i1.ytimg.com":                         "172.217.18.14",
	"plos.org":                             "162.159.135.42",
	"fonts.googleapis.com":                 "89.58.57.45",
	"genweb.plos.org":                      "104.26.1.141",
	"static.ads-twitter.com":               "146.75.120.157",
	"www.google-analytics.com":             "142.250.185.174",
	"rr3---sn-hju7enel.googlevideo.com":    "74.125.98.40",
	"rr5---sn-nv47zn7y.googlevideo.com":    "173.194.15.74",
	"rr1---sn-vh5ouxa-hju6.googlevideo.com": "213.202.6.140",
	"safebrowsing.googleapis.com":          "202.61.195.218",
	"static.doubleclick.net":               "193.26.157.66",
	"rr5---sn-vh5ouxa-hju6.googlevideo.com": "213.202.6.144",
	"rr1---sn-hju7en7r.googlevideo.com":    "74.125.167.87",
	"rr4---sn-vh5ouxa-hju6.googlevideo.com": "213.202.6.143",
	"r1---sn-hju7enel.googlevideo.com":     "74.125.98.38",
	"rr1---sn-nv47zn7r.googlevideo.com":    "173.194.15.38",
	"rr2---sn-vh5ouxa-hjuz.googlevideo.com": "134.0.218.205",
	"rr4---sn-nv47zn7r.googlevideo.com":    "173.194.15.41",
	"rr4---sn-hju7en7r.googlevideo.com":    "74.125.167.90",
}

// builtInHostsWildcardOverrides holds domain suffixes for wildcard matching.
var builtInHostsWildcardOverrides = map[string]string{
	".googlevideo.com": "216.239.38.120",
	".ytimg.com": "216.239.38.120",
	".googleusercontent.com": "216.239.38.120",
	".googleapis.com": "216.239.38.120",
	".youtube.com": "216.239.38.120",
	".youtube-nocookie.com": "216.239.38.120",
	".x.com": "104.19.229.21",
	".twimg.com": "104.19.229.21",
}

// SecureResolverPresets defines a static library of secure public DoH/standard resolvers.
var SecureResolverPresets = map[string]string{
	"quad9-secure":         "https://dns.quad9.net/dns-query",
	"cloudflare":           "https://cloudflare-dns.com/dns-query",
	"cloudflare-family":    "https://family.cloudflare-dns.com/dns-query",
	"google":               "https://dns.google/dns-query",
	"adguard":              "https://dns.adguard-dns.com/dns-query",
	"cleanbrowsing-adult":  "https://doh.cleanbrowsing.org/doh/adult-filter/",
	"cleanbrowsing-family": "https://doh.cleanbrowsing.org/doh/family-filter/",
	"opendns":              "https://doh.opendns.com/dns-query",
	"nordvpn":              "https://doh.nordvpn.com/dns-query",
	// Online Gaming & Anti-Censorship DNS Presets from SOME NOTES.md
	"radar-primary":        "10.202.10.10",
	"radar-secondary":      "10.202.10.11",
	"zeus-primary":         "37.32.5.60",
	"zeus-secondary":       "37.32.5.61",
	"vanilla-primary":      "10.139.177.21",
	"vanilla-secondary":    "10.139.177.22",
	"shecan-primary":       "178.22.122.100",
	"shecan-secondary":     "185.51.200.25",
	"begzar-primary":       "185.55.226.26",
	"begzar-secondary":     "185.55.225.25",
	"electro-primary":      "78.157.42.100",
	"electro-secondary":    "78.157.42.101",
}

// GetSecureResolverURL retrieves the DoH endpoint URL for a given preset key,
// or returns the original input if it is already formatted as an http/https URL.
func GetSecureResolverURL(nameOrURL string) string {
	trimmed := strings.TrimSpace(nameOrURL)
	if url, ok := SecureResolverPresets[strings.ToLower(trimmed)]; ok {
		return url
	}
	return trimmed
}

func (m *EvasionTunnelManager) startDNSForwarder(port int, dnsResolver string, ctx context.Context) {
	addr := &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: port,
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		m.log("Failed to start UDP DNS Forwarder on 127.0.0.1:%d: %v", port, err)
		return
	}
	defer conn.Close()

	m.log("UDP DNS Forwarder listening on 127.0.0.1:%d forwarding to %s", port, dnsResolver)

	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	buf := make([]byte, 4096)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				m.log("DNS Forwarder read error: %v", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
		}

		queryData := make([]byte, n)
		copy(queryData, buf[:n])

		go func(data []byte, addr *net.UDPAddr) {
			resp, err := m.forwardDNSQuery(data, dnsResolver)
			if err != nil {
				m.log("DNS Forward query failed: %v", err)
				return
			}
			_, _ = conn.WriteToUDP(resp, addr)
		}(queryData, clientAddr)
	}
}

func (m *EvasionTunnelManager) forwardDNSQuery(query []byte, resolver string) ([]byte, error) {
	if resolver == "" {
		resolver = "https://dns.quad9.net/dns-query"
	}

	resp, err := m.forwardDNSQuerySingle(query, resolver)
	if err == nil {
		return resp, nil
	}

	m.log("Primary DNS query to %s failed: %v. Attempting secure failover...", resolver, err)

	for _, fb := range fallbackDnsResolvers {
		if fb == resolver {
			continue
		}
		resp, err = m.forwardDNSQuerySingle(query, fb)
		if err == nil {
			m.log("Failover DNS query succeeded via %s", fb)
			return resp, nil
		}
	}

	return nil, fmt.Errorf("all secure resolver attempts failed: %w", err)
}

func (m *EvasionTunnelManager) forwardDNSQuerySingle(query []byte, resolver string) ([]byte, error) {
	if strings.HasPrefix(resolver, "https://") || strings.HasPrefix(resolver, "http://") {
		client := &http.Client{Timeout: 3 * time.Second}
		req, err := http.NewRequest("POST", resolver, bytes.NewReader(query))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/dns-message")
		req.Header.Set("Accept", "application/dns-message")

		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("DoH status code %d", resp.StatusCode)
		}

		respData, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		if len(respData) >= 2 && len(query) >= 2 {
			respData[0] = query[0]
			respData[1] = query[1]
		}
		return respData, nil
	}

	dnsAddr := resolver
	if !strings.Contains(dnsAddr, ":") {
		dnsAddr = net.JoinHostPort(dnsAddr, "53")
	}

	conn, err := dialTimeoutProtected("udp", dnsAddr, 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	_, err = conn.Write(query)
	if err != nil {
		return nil, err
	}

	respBuf := make([]byte, 4096)
	rn, err := conn.Read(respBuf)
	if err != nil {
		return nil, err
	}

	respData := make([]byte, rn)
	copy(respData, respBuf[:rn])

	if len(respData) >= 2 && len(query) >= 2 {
		respData[0] = query[0]
		respData[1] = query[1]
	}
	return respData, nil
}

func resolveHostsSecurely(host string, resolver string) ([]string, error) {
	if net.ParseIP(host) != nil {
		return []string{host}, nil
	}

	mgr := GetEvasionManager()
	if mgr != nil && mgr.GetHostsOverride() {
		if ip, ok := builtInHostsOverrides[host]; ok {
			return []string{ip}, nil
		}
		for suffix, ip := range builtInHostsWildcardOverrides {
			if strings.HasSuffix(host, suffix) {
				return []string{ip}, nil
			}
		}
	}
	if mgr != nil && mgr.circularCache != nil {
		if val, found := mgr.circularCache.Get(host); found {
			if ips, ok := val.([]string); ok {
				return ips, nil
			}
		}
	}

	var resolvedIPs []string
	var err error

	if resolver != "" {
		resolvedIPs, err = resolveWithResolver(host, resolver)
		if err == nil && len(resolvedIPs) > 0 {
			if mgr != nil && mgr.circularCache != nil {
				mgr.circularCache.Set(host, resolvedIPs)
			}
			return resolvedIPs, nil
		}
		// If custom fails and it's DoH, try fallback list
		if strings.HasPrefix(resolver, "https://") || strings.HasPrefix(resolver, "http://") {
			for _, fb := range fallbackDnsResolvers {
				if fb == resolver {
					continue
				}
				resolvedIPs, err = resolveDoH(host, fb)
				if err == nil && len(resolvedIPs) > 0 {
					if mgr != nil && mgr.circularCache != nil {
						mgr.circularCache.Set(host, resolvedIPs)
					}
					return resolvedIPs, nil
				}
			}
		}
	}

	// Fallback to system resolver
	ips, err := net.LookupIP(host)
	if err == nil && len(ips) > 0 {
		var res []string
		for _, ip := range ips {
			res = append(res, ip.String())
		}
		if mgr != nil && mgr.circularCache != nil {
			mgr.circularCache.Set(host, res)
		}
		return res, nil
	}

	// Finally try the whole fallback list
	for _, fb := range fallbackDnsResolvers {
		resolvedIPs, err = resolveDoH(host, fb)
		if err == nil && len(resolvedIPs) > 0 {
			if mgr != nil && mgr.circularCache != nil {
				mgr.circularCache.Set(host, resolvedIPs)
			}
			return resolvedIPs, nil
		}
	}

	return nil, fmt.Errorf("secure DNS resolve failed for host %s", host)
}

func resolveWithResolver(host string, resolver string) ([]string, error) {
	if strings.HasPrefix(resolver, "https://") || strings.HasPrefix(resolver, "http://") {
		return resolveDoH(host, resolver)
	}

	dnsAddr := resolver
	if !strings.Contains(dnsAddr, ":") {
		dnsAddr = net.JoinHostPort(dnsAddr, "53")
	}

	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialerWithControl(2 * time.Second).DialContext(ctx, "udp", dnsAddr)
		},
	}

	ips, err := r.LookupHost(context.Background(), host)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("custom DNS resolve failed: %w", err)
	}
	return ips, nil
}

func resolveDoH(host string, resolver string) ([]string, error) {
	msg := make([]byte, 12+len(host)+2+4)
	binary.BigEndian.PutUint16(msg[0:2], 0x1234)
	binary.BigEndian.PutUint16(msg[2:4], 0x0100)
	binary.BigEndian.PutUint16(msg[4:6], 1)

	offset := 12
	parts := strings.Split(host, ".")
	for _, part := range parts {
		if len(part) == 0 {
			continue
		}
		msg[offset] = byte(len(part))
		offset++
		copy(msg[offset:offset+len(part)], part)
		offset += len(part)
	}
	msg[offset] = 0
	offset++

	binary.BigEndian.PutUint16(msg[offset:offset+2], 1)
	offset += 2
	binary.BigEndian.PutUint16(msg[offset:offset+2], 1)
	offset += 2

	queryData := msg[:offset]

	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialTimeoutProtected(network, addr, 3*time.Second)
			},
		},
	}
	req, err := http.NewRequest("POST", resolver, bytes.NewReader(queryData))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH status code %d", resp.StatusCode)
	}

	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if len(respData) < offset {
		return nil, fmt.Errorf("DoH response too short")
	}

	answersCount := binary.BigEndian.Uint16(respData[6:8])
	if answersCount == 0 {
		return nil, fmt.Errorf("no answers returned")
	}

	var ips []string
	idx := offset
	for i := 0; i < int(answersCount); i++ {
		if idx+10 > len(respData) {
			break
		}
		if respData[idx]&0xC0 == 0xC0 {
			idx += 2
		} else {
			for idx < len(respData) && respData[idx] != 0 {
				idx += int(respData[idx]) + 1
			}
			idx++
		}
		if idx+10 > len(respData) {
			break
		}
		qtype := binary.BigEndian.Uint16(respData[idx : idx+2])
		rdlength := binary.BigEndian.Uint16(respData[idx+8 : idx+10])
		idx += 10
		if idx+int(rdlength) > len(respData) {
			break
		}
		if qtype == 1 && rdlength == 4 {
			ip := net.IP(respData[idx : idx+4])
			ips = append(ips, ip.String())
		}
		idx += int(rdlength)
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no A record found")
	}
	return ips, nil
}
