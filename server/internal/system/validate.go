// Package system provides operating-system specific APIs for network adapter
// discovery, registry/proxy manipulation, and DNS modifications.
package system

import (
	"fmt"
	"net"
	"strings"
)

// maxDNSServers caps how many resolvers may be applied at once. Real adapters
// never legitimately carry more than a handful; the cap bounds command length
// and abuse.
const maxDNSServers = 8

// ValidateDNSServers verifies that every entry is a syntactically valid IP
// address (IPv4 or IPv6). It rejects empty input and any value that is not a
// bare IP. This is the primary defense that closes command/argument injection
// on platforms whose DNS backend shells out (see SetDNS on Windows): once a
// value is guaranteed to be a literal IP, it cannot contain shell metacharacters.
func ValidateDNSServers(servers []string) error {
	if len(servers) == 0 {
		return fmt.Errorf("no DNS servers provided")
	}
	if len(servers) > maxDNSServers {
		return fmt.Errorf("too many DNS servers (max %d)", maxDNSServers)
	}
	for _, s := range servers {
		trimmed := strings.TrimSpace(s)
		if trimmed == "" {
			return fmt.Errorf("empty DNS server entry")
		}
		if net.ParseIP(trimmed) == nil {
			return fmt.Errorf("invalid DNS server address: %q", s)
		}
	}
	return nil
}

// ValidateInterfaceAlias rejects interface names containing characters that
// could break out of a quoted shell or PowerShell cmdlet argument. Windows
// adapter aliases and unix interface names are free-form but never legitimately
// contain quotes, semicolons, pipes, or control characters.
func ValidateInterfaceAlias(name string) error {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return fmt.Errorf("empty interface alias")
	}
	if len(trimmed) > 256 {
		return fmt.Errorf("interface alias too long")
	}
	for _, r := range trimmed {
		if r < 0x20 || r == '\'' || r == '"' || r == '`' || r == ';' || r == '$' || r == '|' || r == '&' || r == '<' || r == '>' {
			return fmt.Errorf("invalid character in interface alias: %q", name)
		}
	}
	return nil
}
