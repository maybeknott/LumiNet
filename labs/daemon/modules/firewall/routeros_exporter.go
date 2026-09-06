package firewall

import (
	"fmt"
	"strings"
)

type RouterOsExporter struct {
	Entries []string
}

func NewRouterOsExporter() *RouterOsExporter {
	return &RouterOsExporter{Entries: make([]string, 0)}
}

func (r *RouterOsExporter) AddEntry(entry string) {
	clean := strings.TrimSpace(entry)
	if clean != "" {
		r.Entries = append(r.Entries, clean)
	}
}

func (r *RouterOsExporter) ExportAddressList(listName string) string {
	var sb strings.Builder
	sb.WriteString("/ip firewall address-list\n")
	for _, e := range r.Entries {
		sb.WriteString(fmt.Sprintf("add list=%s address=%s comment=\"LumiNet auto\"\n", listName, e))
	}
	return sb.String()
}

func (r *RouterOsExporter) ExportMangle(listName string, routingMark string) string {
	var sb strings.Builder
	sb.WriteString("/ip firewall mangle\n")
	sb.WriteString(fmt.Sprintf("add chain=prerouting dst-address-list=%s action=mark-routing new-routing-mark=%s passthrough=yes comment=\"LumiNet\"\n", listName, routingMark))
	return sb.String()
}
