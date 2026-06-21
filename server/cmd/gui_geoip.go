//go:build windows && cgo

package cmd

import (
	"fmt"
	"net/url"
	"strings"

	. "github.com/lxn/walk/declarative"
)

type geoIPInfo struct {
	Target      string  `json:"target"`
	IP          string  `json:"ip"`
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	Region      string  `json:"region"`
	City        string  `json:"city"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
}

func (s *nativeShell) geoIPPage() TabPage {
	return TabPage{
		Title:  "GeoIP Lookup",
		Layout: VBox{Margins: Margins{Left: 14, Top: 14, Right: 14, Bottom: 14}},
		Children: []Widget{
			GroupBox{
				Title:  "GeoIP Geolocation & ISP Resolver",
				Layout: Grid{Columns: 3, Spacing: 10},
				Children: []Widget{
					Label{Text: "Target Domain / IP:"},
					LineEdit{AssignTo: &s.geoIPTargetEdit},
					PushButton{Text: "Resolve Geolocation", OnClicked: s.runGeoIPAnalysis},
				},
			},
			GroupBox{
				Title:  "Geolocation Details",
				Layout: VBox{},
				Children: []Widget{
					TextEdit{AssignTo: &s.geoIPOutput, ReadOnly: true, VScroll: true, MinSize: Size{Height: 320}},
				},
			},
			VSpacer{},
		},
	}
}

func (s *nativeShell) runGeoIPAnalysis() {
	target := "8.8.8.8"
	if s.geoIPTargetEdit != nil {
		target = strings.TrimSpace(s.geoIPTargetEdit.Text())
	}
	if target == "" {
		s.setStatus("Enter target domain or IP address.")
		return
	}

	s.setStatus("Resolving geolocation...")
	if s.geoIPOutput != nil {
		s.geoIPOutput.SetText(fmt.Sprintf("GeoIP Geolocation lookup for: %s\r\n--------------------------------------------------\r\nQuerying local API GeoIP resolver...\r\n\r\n", target))
	}

	go func() {
		var info geoIPInfo
		err := s.getJSON("/api/diagnostics/geoip?target="+url.QueryEscape(target), &info)

		s.sync(func() {
			if err != nil {
				s.setStatus("GeoIP lookup failed.")
				if s.geoIPOutput != nil {
					s.geoIPOutput.AppendText(fmt.Sprintf("Lookup failed: %v\r\n", err))
				}
				return
			}

			s.setStatus("GeoIP resolution complete.")
			if s.geoIPOutput != nil {
				var sb strings.Builder
				sb.WriteString(fmt.Sprintf("GeoIP Geolocation Results for: %s\r\n", target))
				sb.WriteString("==================================================\r\n\r\n")
				sb.WriteString(fmt.Sprintf("Resolved IP Address : %s\r\n", info.IP))
				sb.WriteString(fmt.Sprintf("Country Name        : %s\r\n", info.Country))
				sb.WriteString(fmt.Sprintf("Country Code        : %s\r\n", info.CountryCode))
				sb.WriteString(fmt.Sprintf("Region/State        : %s\r\n", info.Region))
				sb.WriteString(fmt.Sprintf("City                : %s\r\n", info.City))
				sb.WriteString(fmt.Sprintf("Latitude            : %.6f\r\n", info.Latitude))
				sb.WriteString(fmt.Sprintf("Longitude           : %.6f\r\n", info.Longitude))
				sb.WriteString("\r\n--------------------------------------------------\r\n")

				// Calculate positions on a 9x19 ASCII map grid
				latRow := int((90.0 - info.Latitude) / 20.0)
				lonCol := int((info.Longitude + 180.0) / 19.0)

				if latRow < 0 {
					latRow = 0
				}
				if latRow > 8 {
					latRow = 8
				}
				if lonCol < 0 {
					lonCol = 0
				}
				if lonCol > 18 {
					lonCol = 18
				}

				grid := [9][19]rune{}
				for r := 0; r < 9; r++ {
					for c := 0; c < 19; c++ {
						if r == 4 && c == 9 {
							grid[r][c] = '+'
						} else if r == 4 {
							grid[r][c] = '-'
						} else if c == 9 {
							grid[r][c] = '|'
						} else {
							grid[r][c] = '.'
						}
					}
				}
				grid[latRow][lonCol] = 'X'

				sb.WriteString("Visual Geocoordinate Map (9x19 Grid):\r\n")
				sb.WriteString("         [W] -180°         0°         +180° [E]\r\n")
				sb.WriteString("         +-------------------------------------+\r\n")
				for r := 0; r < 9; r++ {
					var label string
					switch r {
					case 0:
						label = "   N  80°"
					case 2:
						label = "      40°"
					case 4:
						label = "   0° Eq "
					case 6:
						label = "     -40°"
					case 8:
						label = "   S -80°"
					default:
						label = "         "
					}
					sb.WriteString(label + "| ")
					for c := 0; c < 19; c++ {
						sb.WriteRune(grid[r][c])
						sb.WriteByte(' ')
					}
					sb.WriteString("|\r\n")
				}
				sb.WriteString("         +-------------------------------------+\r\n")
				sb.WriteString(fmt.Sprintf("         Current Location: ( %.4f, %.4f ) marked as 'X'\r\n", info.Latitude, info.Longitude))

				sb.WriteString("\r\n--------------------------------------------------\r\n")
				sb.WriteString("Intelligence Recommendation:\r\n")
				if info.CountryCode == "CN" || info.CountryCode == "IR" || info.CountryCode == "RU" || info.CountryCode == "TR" || info.CountryCode == "KP" {
					sb.WriteString(fmt.Sprintf("   [!] WARNING: Target country (%s) operates strict DPI filtering regim.\r\n", info.CountryCode))
					sb.WriteString("       - DNS Security: Plain UDP is highly vulnerable to poisoning. Switch to DoH/DoT resolvers.\r\n")
					sb.WriteString("       - Evasion: Set TCP segment splitting (2-byte / 5-byte offset) with a 20-50ms delay.\r\n")
					sb.WriteString("       - TLS Fingerprinting: Go/Rust standard ClientHellos may be filtered. Use browser JA3 signatures.\r\n")
					sb.WriteString("       - WireGuard: Enable standard Initiation Handshake UDP padding (MASQUE/vwarp presets).\r\n")
				} else {
					sb.WriteString("   [+] HEALTHY: Target routing path is located in a standard filtering zone.\r\n")
					sb.WriteString("       Plain connection methods (TCP/UDP) should function under default configurations.\r\n")
				}

				s.geoIPOutput.SetText(sb.String())
			}
		})
	}()
}
