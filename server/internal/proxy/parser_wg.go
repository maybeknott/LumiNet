package proxy

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
)

// parseWireGuard parses a wireguard://, wg://, awg://, amneziawg://, or warp:// URI into a ProxyConfig.
func parseWireGuard(uri string) (*ProxyConfig, error) {
	normalized := uri
	isAmnezia := false
	lowered := strings.ToLower(uri)
	isWarp := strings.HasPrefix(lowered, "warp://")
	if strings.HasPrefix(lowered, "wg://") {
		normalized = "wireguard" + uri[2:]
	} else if strings.HasPrefix(lowered, "awg://") {
		normalized = "wireguard" + uri[3:]
		isAmnezia = true
	} else if strings.HasPrefix(lowered, "amneziawg://") {
		normalized = "wireguard" + uri[9:]
		isAmnezia = true
	} else if strings.HasPrefix(lowered, "warp://") {
		normalized = "wireguard" + uri[4:]
	}

	parsed, err := url.Parse(normalized)
	if err != nil {
		return nil, err
	}

	privateKey := parsed.User.Username()
	if privateKey == "" {
		if parsed.User != nil {
			privateKey = parsed.User.String()
		}
	}
	if privateKey == "" && isWarp {
		privateKey = "aOJ4w1f/U+xY2+9f71c4J2w1f/U+xY2+9f71c4J2w1c="
	}

	port := 51820
	if parsed.Port() != "" {
		fmt.Sscanf(parsed.Port(), "%d", &port)
	}

	q := parsed.Query()

	publicKey := q.Get("publickey")
	if publicKey == "" {
		publicKey = q.Get("public_key")
	}
	if publicKey == "" && isWarp {
		publicKey = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51hJHWDZa0="
	}

	address := q.Get("address")
	if address == "" {
		address = q.Get("local_address")
	}

	var localAddr []string
	if address != "" {
		for _, x := range strings.Split(address, ",") {
			localAddr = append(localAddr, strings.TrimSpace(x))
		}
	}

	mtu := 0
	if m := q.Get("mtu"); m != "" {
		fmt.Sscanf(m, "%d", &mtu)
	}

	var reserved []int
	var reservedIsBase64 bool
	if res := q.Get("reserved"); res != "" {
		if decoded, err := base64.StdEncoding.DecodeString(res); err == nil && len(decoded) > 0 {
			reservedIsBase64 = true
			reserved = make([]int, len(decoded))
			for i, b := range decoded {
				reserved[i] = int(b)
			}
		} else {
			for _, x := range strings.Split(res, ",") {
				var val int
				if _, err := fmt.Sscanf(strings.TrimSpace(x), "%d", &val); err == nil {
					reserved = append(reserved, val)
				}
			}
		}
	}

	var jc, jmin, jmax, s1, s2, s3, s4 int
	if val := q.Get("jc"); val != "" {
		fmt.Sscanf(val, "%d", &jc)
	}
	if val := q.Get("jmin"); val != "" {
		fmt.Sscanf(val, "%d", &jmin)
	}
	if val := q.Get("jmax"); val != "" {
		fmt.Sscanf(val, "%d", &jmax)
	}
	if val := q.Get("s1"); val != "" {
		fmt.Sscanf(val, "%d", &s1)
	}
	if val := q.Get("s2"); val != "" {
		fmt.Sscanf(val, "%d", &s2)
	}
	if val := q.Get("s3"); val != "" {
		fmt.Sscanf(val, "%d", &s3)
	}
	if val := q.Get("s4"); val != "" {
		fmt.Sscanf(val, "%d", &s4)
	}
	h1 := q.Get("h1")
	h2 := q.Get("h2")
	h3 := q.Get("h3")
	h4 := q.Get("h4")
	i1 := q.Get("i1")
	i2 := q.Get("i2")
	i3 := q.Get("i3")
	i4 := q.Get("i4")
	i5 := q.Get("i5")

	wnoise := q.Get("wnoise")
	wnoisecount := q.Get("wnoisecount")
	wpayloadsize := q.Get("wpayloadsize")
	wnoisedelay := q.Get("wnoisedelay")

	fakePackets := q.Get("fake_packets")
	if fakePackets == "" {
		fakePackets = q.Get("ifp")
	}
	fakePacketsSize := q.Get("fake_packets_size")
	if fakePacketsSize == "" {
		fakePacketsSize = q.Get("ifps")
	}
	fakePacketsDelay := q.Get("fake_packets_delay")
	if fakePacketsDelay == "" {
		fakePacketsDelay = q.Get("ifpd")
	}
	fakePacketsMode := q.Get("fake_packets_mode")
	if fakePacketsMode == "" {
		fakePacketsMode = q.Get("ifpm")
	}

	if jc > 0 || jmin > 0 || jmax > 0 || s1 > 0 || s2 > 0 || s3 > 0 || s4 > 0 || h1 != "" || h2 != "" || h3 != "" || h4 != "" || i1 != "" || i2 != "" || i3 != "" || i4 != "" || i5 != "" {
		isAmnezia = true
	}

	protocol := ProtocolWireGuard
	if isAmnezia {
		protocol = ProtocolAmneziaWG
	}

	remark, _ := url.PathUnescape(parsed.Fragment)

	host := parsed.Hostname()
	if host == "" {
		return nil, fmt.Errorf("missing server address")
	}
	if privateKey == "" || publicKey == "" {
		return nil, fmt.Errorf("missing private key or public key")
	}

	return &ProxyConfig{
		Protocol:          protocol,
		Name:              remark,
		Address:           host,
		Port:              port,
		PrivateKey:        privateKey,
		PublicKey:         publicKey,
		LocalAddress:      localAddr,
		MTU:               mtu,
		Reserved:          reserved,
		WNoise:            wnoise,
		WNoiseCount:       wnoisecount,
		WPayloadSize:      wpayloadsize,
		WNoiseDelay:       wnoisedelay,
		FakePackets:       fakePackets,
		FakePacketsSize:   fakePacketsSize,
		FakePacketsDelay:  fakePacketsDelay,
		FakePacketsMode:   fakePacketsMode,
		Jc:                jc,
		Jmin:              jmin,
		Jmax:              jmax,
		S1:                s1,
		S2:                s2,
		S3:                s3,
		S4:                s4,
		H1:                h1,
		H2:                h2,
		H3:                h3,
		H4:                h4,
		I1:                i1,
		I2:                i2,
		I3:                i3,
		I4:                i4,
		I5:                i5,
		ReservedIsBase64:  reservedIsBase64,
	}, nil
}
