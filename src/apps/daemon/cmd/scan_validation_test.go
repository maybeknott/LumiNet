package cmd

import "testing"

func TestParsePortsRejectsInvalidValues(t *testing.T) {
	cases := []string{"0", "65536", "-1", "22-nope", "80-22", "80,,443"}
	for _, tc := range cases {
		if _, err := parsePorts(tc); err == nil {
			t.Fatalf("parsePorts(%q) unexpectedly succeeded", tc)
		}
	}
}

func TestParsePortsAcceptsValidatedRange(t *testing.T) {
	ports, err := parsePorts("22,80-82,443")
	if err != nil {
		t.Fatal(err)
	}
	want := []uint16{22, 80, 81, 82, 443}
	if len(ports) != len(want) {
		t.Fatalf("got %v want %v", ports, want)
	}
	for i := range want {
		if ports[i] != want[i] {
			t.Fatalf("got %v want %v", ports, want)
		}
	}
}

func TestParseEndpointIsIPv6Safe(t *testing.T) {
	host, port, err := parseEndpoint("2001:db8::1", 51820)
	if err != nil {
		t.Fatal(err)
	}
	if host != "2001:db8::1" || port != 51820 {
		t.Fatalf("got %q:%d", host, port)
	}

	host, port, err = parseEndpoint("[2001:db8::1]:443", 51820)
	if err != nil {
		t.Fatal(err)
	}
	if host != "2001:db8::1" || port != 443 {
		t.Fatalf("got %q:%d", host, port)
	}
}

func TestParseEndpointRejectsOutOfRangePort(t *testing.T) {
	if _, _, err := parseEndpoint("example.com:70000", 51820); err == nil {
		t.Fatal("expected invalid port error")
	}
}
