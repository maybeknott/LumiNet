package dns

import (
	"reflect"
	"testing"
)

func TestParseHostsText(t *testing.T) {
	input := `
# Sample hosts adblock file
0.0.0.0 adservice.google.com
127.0.0.1 tracker.example.net # inline comment
::1 telemetry.badsite.org
::0 metrics.evil.com
0.0.0.0 localhost
127.0.0.1 127.0.0.1
127.0.0.1 *.wildcard.com
plain-blocked-domain.com
0.0.0.0 sub1.ad.com sub2.ad.com
`

	expected := []string{
		"adservice.google.com",
		"tracker.example.net",
		"telemetry.badsite.org",
		"metrics.evil.com",
		"plain-blocked-domain.com",
		"sub1.ad.com",
		"sub2.ad.com",
	}

	got := ParseHostsText(input)
	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("ParseHostsText mismatch:\nGot:  %v\nWant: %v", got, expected)
	}
}

func TestMergeHostsBlocklists(t *testing.T) {
	l1 := []string{"domain1.com", "domain2.com"}
	l2 := []string{"domain2.com", "domain3.com", "DOMAIN1.COM"}

	merged := MergeHostsBlocklists(l1, l2)
	expected := []string{"domain1.com", "domain2.com", "domain3.com"}

	if !reflect.DeepEqual(merged, expected) {
		t.Fatalf("MergeHostsBlocklists mismatch:\nGot:  %v\nWant: %v", merged, expected)
	}
}
