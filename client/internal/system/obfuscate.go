package system

import (
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"math/rand"
	"net"
	"sort"
	"time"
)

// DPIObfuscationOptions configures TCP obfuscation and desynchronization options.
type DPIObfuscationOptions struct {
	EnablePayloadSplitting bool `json:"enable_payload_splitting"`
	SplitByteBoundary      int  `json:"split_byte_boundary"`
	SplitDelayMicroseconds int  `json:"split_delay_microseconds"`
	RandomizeSplitPoint    bool `json:"randomize_split_point"`
	FragmentCount          int  `json:"fragment_count"`

	// EasySNI Desync features
	EnableDesync      bool   `json:"enable_desync"`
	DesyncMode        string `json:"desync_mode"`          // "none", "wrong_checksum", "wrong_seq"
	DesyncFakeRepeat  int    `json:"desync_fake_repeat"`   // number of fake hello injections
	DesyncFakeDelayMs int    `json:"desync_fake_delay_ms"` // delay after fake injection
	DesyncFakePreset  string `json:"desync_fake_preset"`   // "none", "firefox", "chrome", etc.
	DesyncSNIChunk    int    `json:"desync_sni_chunk"`     // SNI bytes per write (0 = whole host)
	DesyncFragDelayMs int    `json:"desync_frag_delay_ms"` // delay between split writes
}

// BypassMode selects how the fake segment is corrupted so the real server
// rejects it while the DPI still inspects it.
type BypassMode string

const (
	ModeNone          BypassMode = "none"
	ModeWrongChecksum BypassMode = "wrong_checksum"
	ModeWrongSeq      BypassMode = "wrong_seq"
)

type ObfuscatedConn struct {
	net.Conn
	Opts DPIObfuscationOptions
}

func (c *ObfuscatedConn) Write(b []byte) (int, error) {
	if c.Opts.EnableDesync && isClientHello(b) {
		mode := BypassMode(c.Opts.DesyncMode)
		if mode != ModeNone {
			la, okL := c.Conn.LocalAddr().(*net.TCPAddr)
			ra, okR := c.Conn.RemoteAddr().(*net.TCPAddr)
			if okL && okR && la.IP.To4() != nil && ra.IP.To4() != nil {
				preset := c.Opts.DesyncFakePreset
				if preset == "" {
					preset = "none"
				}
				hello := FakeClientHello(preset, ra.IP.String())
				_, _, realSNI, okSNI := FindSNI(b)
				if okSNI && realSNI != "" {
					hello = FakeClientHello(preset, realSNI)
				}

				var seed int
				var seedBuf [4]byte
				if _, err := crand.Read(seedBuf[:]); err == nil {
					seed = int(binary.BigEndian.Uint32(seedBuf[:]))
				} else {
					seed = time.Now().Nanosecond()
				}
				r := rand.New(rand.NewSource(int64(seed)))
				seq := r.Uint32()

				n := c.Opts.DesyncFakeRepeat
				if n < 1 {
					n = 1
				}
				for i := 0; i < n; i++ {
					seg := BuildFakeSegment(la.IP, ra.IP, la.Port, ra.Port, seq, 0, hello, mode)
					_ = sendRaw(ra.IP, seg)
				}
				if c.Opts.DesyncFakeDelayMs > 0 {
					time.Sleep(time.Duration(c.Opts.DesyncFakeDelayMs) * time.Millisecond)
				}
			}
		}

		if c.Opts.DesyncSNIChunk > 0 {
			chunks := FragmentWrites(b, c.Opts.DesyncSNIChunk)
			total := 0
			for i, ch := range chunks {
				n, err := c.Conn.Write(ch)
				total += n
				if err != nil {
					return total, err
				}
				if i+1 < len(chunks) && c.Opts.DesyncFragDelayMs > 0 {
					time.Sleep(time.Duration(c.Opts.DesyncFragDelayMs) * time.Millisecond)
				}
			}
			return total, nil
		}
	}

	if !c.Opts.EnablePayloadSplitting || len(b) <= 1 {
		return c.Conn.Write(b)
	}

	length := len(b)
	fc := c.Opts.FragmentCount
	if fc <= 1 {
		fc = 2 // default to 2 fragments
	}
	if fc > length {
		fc = length
	}

	// Determine split points
	var sorted []int
	if c.Opts.RandomizeSplitPoint {
		var seed int64
		var seedBuf [8]byte
		if _, err := crand.Read(seedBuf[:]); err == nil {
			seed = int64(binary.BigEndian.Uint64(seedBuf[:]))
		} else {
			seed = time.Now().UnixNano()
		}
		r := rand.New(rand.NewSource(seed))

		indices := make(map[int]bool)
		for len(indices) < fc-1 {
			idx := r.Intn(length-1) + 1
			indices[idx] = true
		}
		sorted = make([]int, 0, len(indices))
		for idx := range indices {
			sorted = append(sorted, idx)
		}
		sort.Ints(sorted)
	} else {
		if fc == 2 {
			boundary := c.Opts.SplitByteBoundary
			if boundary <= 0 || boundary >= length {
				boundary = length / 2
				if boundary == 0 {
					boundary = 1
				}
			}
			sorted = []int{boundary}
		} else {
			sorted = make([]int, 0, fc-1)
			chunkSize := length / fc
			if chunkSize == 0 {
				chunkSize = 1
			}
			for i := 1; i < fc; i++ {
				boundary := i * chunkSize
				if boundary >= length {
					break
				}
				sorted = append(sorted, boundary)
			}
		}
	}

	delay := time.Duration(c.Opts.SplitDelayMicroseconds) * time.Microsecond
	if delay == 0 {
		delay = 50 * time.Microsecond
	}

	total := 0
	last := 0
	for _, idx := range sorted {
		n, err := c.Conn.Write(b[last:idx])
		total += n
		if err != nil {
			return total, err
		}
		last = idx
		time.Sleep(delay)
	}
	n, err := c.Conn.Write(b[last:])
	total += n
	return total, err
}

func isClientHello(b []byte) bool {
	return len(b) >= 6 && b[0] == 0x16 && b[1] == 0x03 && b[5] == 0x01
}

func FindSNI(rec []byte) (start, end int, host string, ok bool) {
	if !isClientHello(rec) {
		return 0, 0, "", false
	}
	p := 5 + 4
	if p+2+32 > len(rec) {
		return 0, 0, "", false
	}
	p += 2 + 32
	if p >= len(rec) {
		return 0, 0, "", false
	}
	sid := int(rec[p])
	p += 1 + sid
	if p+2 > len(rec) {
		return 0, 0, "", false
	}
	cs := int(binary.BigEndian.Uint16(rec[p:]))
	p += 2 + cs
	if p >= len(rec) {
		return 0, 0, "", false
	}
	comp := int(rec[p])
	p += 1 + comp
	if p+2 > len(rec) {
		return 0, 0, "", false
	}
	extTotal := int(binary.BigEndian.Uint16(rec[p:]))
	p += 2
	extEnd := p + extTotal
	if extEnd > len(rec) {
		extEnd = len(rec)
	}
	for p+4 <= extEnd {
		etype := binary.BigEndian.Uint16(rec[p:])
		elen := int(binary.BigEndian.Uint16(rec[p+2:]))
		body := p + 4
		if body+elen > len(rec) {
			return 0, 0, "", false
		}
		if etype == 0x0000 { // server_name
			q := body
			if q+2 > len(rec) {
				return 0, 0, "", false
			}
			q += 2
			if q+3 > len(rec) {
				return 0, 0, "", false
			}
			nlen := int(binary.BigEndian.Uint16(rec[q+1:]))
			ns := q + 3
			ne := ns + nlen
			if ne > len(rec) {
				return 0, 0, "", false
			}
			return ns, ne, string(rec[ns:ne]), true
		}
		p = body + elen
	}
	return 0, 0, "", false
}

func FragmentWrites(rec []byte, sniChunk int) [][]byte {
	s, e, _, ok := FindSNI(rec)
	if !ok {
		if len(rec) < 2 {
			return [][]byte{rec}
		}
		mid := len(rec) / 2
		return [][]byte{rec[:mid], rec[mid:]}
	}
	bounds := map[int]struct{}{s: {}, e: {}}
	if sniChunk > 0 {
		for i := s + sniChunk; i < e; i += sniChunk {
			bounds[i] = struct{}{}
		}
	}
	cuts := []int{0, len(rec)}
	for b := range bounds {
		if b > 0 && b < len(rec) {
			cuts = append(cuts, b)
		}
	}
	sort.Ints(cuts)
	var out [][]byte
	for i := 0; i+1 < len(cuts); i++ {
		if cuts[i+1] > cuts[i] {
			out = append(out, rec[cuts[i]:cuts[i+1]])
		}
	}
	if len(out) == 0 {
		out = [][]byte{rec}
	}
	return out
}

func FakeClientHello(preset, sni string) []byte {
	if sni == "" {
		sni = "www.google.com"
	}
	ciphers := presetCiphers(preset)

	var body []byte
	body = append(body, 0x03, 0x03)
	rnd := make([]byte, 32)
	_, _ = crand.Read(rnd)
	body = append(body, rnd...)
	sid := make([]byte, 32)
	_, _ = crand.Read(sid)
	body = append(body, 32)
	body = append(body, sid...)
	cs := make([]byte, 2)
	binary.BigEndian.PutUint16(cs, uint16(len(ciphers)))
	body = append(body, cs...)
	body = append(body, ciphers...)
	body = append(body, 0x01, 0x00)
	extData := buildExtensions(sni, preset)
	el := make([]byte, 2)
	binary.BigEndian.PutUint16(el, uint16(len(extData)))
	body = append(body, el...)
	body = append(body, extData...)

	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	rec := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
	return append(rec, hs...)
}

func presetCiphers(preset string) []byte {
	common := []uint16{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035}
	switch preset {
	case "chrome", "edge", "android":
		common = append([]uint16{0x1301, 0x1303, 0x1302}, common[3:]...)
	case "safari", "ios":
		common = append([]uint16{0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b}, common[5:]...)
	case "none":
		common = []uint16{0xc02f, 0xc030, 0xc02b, 0xc02c, 0x009c, 0x009d, 0x002f, 0x0035}
	}
	out := make([]byte, 0, len(common)*2)
	b := make([]byte, 2)
	for _, c := range common {
		binary.BigEndian.PutUint16(b, c)
		out = append(out, b...)
	}
	return out
}

func ext(typ uint16, data []byte) []byte {
	h := make([]byte, 4)
	binary.BigEndian.PutUint16(h, typ)
	binary.BigEndian.PutUint16(h[2:], uint16(len(data)))
	return append(h, data...)
}

func buildExtensions(sni, preset string) []byte {
	var out []byte
	name := []byte(sni)
	sn := make([]byte, 0, len(name)+5)
	entry := append([]byte{0x00}, byte(len(name)>>8), byte(len(name)))
	entry = append(entry, name...)
	listLen := make([]byte, 2)
	binary.BigEndian.PutUint16(listLen, uint16(len(entry)))
	sn = append(sn, listLen...)
	sn = append(sn, entry...)
	out = append(out, ext(0x0000, sn)...)
	out = append(out, ext(0x000a, []byte{0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18})...)
	out = append(out, ext(0x000b, []byte{0x01, 0x00})...)
	out = append(out, ext(0x000d, []byte{0x00, 0x08, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x02, 0x01})...)
	out = append(out, ext(0x002b, []byte{0x04, 0x03, 0x04, 0x03, 0x03})...)
	if preset != "none" {
		alpn := []byte{0x00, 0x0c, 0x02, 'h', '2', 0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'}
		out = append(out, ext(0x0010, alpn)...)
	}
	return out
}

func BuildFakeSegment(src, dst net.IP, srcPort, dstPort int, seq, ack uint32, payload []byte, mode BypassMode) []byte {
	src4, dst4 := src.To4(), dst.To4()
	if src4 == nil || dst4 == nil {
		return nil
	}
	if mode == ModeWrongSeq {
		seq -= 100000
	}

	tcpLen := 20 + len(payload)
	totalLen := 20 + tcpLen

	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(totalLen))

	var seed int
	var seedBuf [4]byte
	if _, err := crand.Read(seedBuf[:]); err == nil {
		seed = int(binary.BigEndian.Uint32(seedBuf[:]))
	} else {
		seed = int(binary.BigEndian.Uint16(payload[:2]))
	}
	r := rand.New(rand.NewSource(int64(seed)))

	binary.BigEndian.PutUint16(ip[4:], uint16(r.Intn(65535)))
	ip[8] = 64
	ip[9] = 6
	copy(ip[12:16], src4)
	copy(ip[16:20], dst4)
	binary.BigEndian.PutUint16(ip[10:], ipChecksum(ip))

	tcp := make([]byte, tcpLen)
	binary.BigEndian.PutUint16(tcp[0:], uint16(srcPort))
	binary.BigEndian.PutUint16(tcp[2:], uint16(dstPort))
	binary.BigEndian.PutUint32(tcp[4:], seq)
	binary.BigEndian.PutUint32(tcp[8:], ack)
	tcp[12] = 0x50
	tcp[13] = 0x18
	tcp[14], tcp[15] = 0xff, 0xff
	copy(tcp[20:], payload)

	csum := tcpChecksum(src4, dst4, tcp)
	if mode == ModeWrongChecksum {
		csum = ^csum
		if csum == 0 {
			csum = 0xdead
		}
	}
	binary.BigEndian.PutUint16(tcp[16:], csum)

	return append(ip, tcp...)
}

func ipChecksum(h []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(h); i += 2 {
		if i == 10 {
			continue
		}
		sum += uint32(binary.BigEndian.Uint16(h[i:]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func tcpChecksum(src, dst, tcp []byte) uint16 {
	var sum uint32
	sum += uint32(binary.BigEndian.Uint16(src[0:]))
	sum += uint32(binary.BigEndian.Uint16(src[2:]))
	sum += uint32(binary.BigEndian.Uint16(dst[0:]))
	sum += uint32(binary.BigEndian.Uint16(dst[2:]))
	sum += uint32(6)
	sum += uint32(len(tcp))
	for i := 0; i+1 < len(tcp); i += 2 {
		if i == 16 {
			continue
		}
		sum += uint32(binary.BigEndian.Uint16(tcp[i:]))
	}
	if len(tcp)%2 == 1 {
		sum += uint32(tcp[len(tcp)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// DialObfuscated returns an ObfuscatedConn wrapping a socket dialed to addr.
func DialObfuscated(ctx context.Context, network, addr string, timeout time.Duration, opts DPIObfuscationOptions) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: timeout}
	rawConn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	if opts.EnablePayloadSplitting || opts.EnableDesync {
		return &ObfuscatedConn{Conn: rawConn, Opts: opts}, nil
	}
	return rawConn, nil
}
