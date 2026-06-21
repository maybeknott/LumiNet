package tcpip

func Sum(b []byte) uint32 {
	n := len(b)
	var sum uint32
	if n&1 != 0 {
		n--
		sum += uint32(b[n]) << 8
	}

	for i := 0; i < n; i += 2 {
		sum += (uint32(b[i]) << 8) | uint32(b[i+1])
	}
	return sum
}

// Checksum for Internet Protocol family headers
func Checksum(sum uint32, b []byte) (answer [2]byte) {
	sum += Sum(b)
	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16
	sum = ^sum
	answer[0] = byte(sum >> 8)
	answer[1] = byte(sum)
	return
}
