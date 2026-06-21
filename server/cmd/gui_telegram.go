//go:build windows && cgo

package cmd

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
)

func (s *nativeShell) telegramPage() TabPage {
	return TabPage{
		Title:  "Telegram MTProto",
		Layout: VBox{Margins: Margins{Left: 14, Top: 14, Right: 14, Bottom: 14}},
		Children: []Widget{
			GroupBox{
				Title:  "MTProto Proxy Scraper & Tester Config",
				Layout: Grid{Columns: 4, Spacing: 10},
				Children: []Widget{
					Label{Text: "Source Channel Preset:"},
					ComboBox{
						AssignTo: &s.tgChannelPresetCombo,
						Model: []string{
							"@ProxyMTProto",
							"@MTProtoProxies",
							"@TelMTProto",
							"@Proxy_MTProto_Free",
							"@TgProxies",
							"Custom (Type below)",
						},
						OnCurrentIndexChanged: s.onTgChannelPresetChanged,
					},
					Label{Text: "Source Channel Username:"},
					LineEdit{AssignTo: &s.tgChannelEdit},

					Label{Text: "Status:"},
					Label{AssignTo: &s.tgStatusLabel, Text: "Ready"},
					Label{Text: ""},
					Label{Text: ""},
				},
			},
			Composite{
				Layout: HBox{MarginsZero: true},
				Children: []Widget{
					PushButton{Text: "Fetch & Ping Proxies", OnClicked: s.runTelegramFetch},
					PushButton{Text: "Copy Fastest Proxy", OnClicked: s.onCopyFastestTgProxy},
					PushButton{Text: "Copy All Proxies", OnClicked: s.onCopyAllTgProxies},
					HSpacer{},
				},
			},
			GroupBox{
				Title:  "Verified MTProto Proxies (Sorted by Latency)",
				Layout: VBox{},
				Children: []Widget{
					TextEdit{AssignTo: &s.tgResultEdit, ReadOnly: true, VScroll: true, MinSize: Size{Height: 320}},
				},
			},
			VSpacer{},
		},
	}
}

type mtprotoProxyResponse struct {
	Success bool `json:"success"`
	Proxies []struct {
		Host   string `json:"host"`
		Port   int    `json:"port"`
		Secret string `json:"secret"`
		PingMs int    `json:"ping_ms"`
	} `json:"proxies"`
}

func (s *nativeShell) runTelegramFetch() {
	if s.tgStatusLabel == nil || s.tgResultEdit == nil {
		return
	}

	s.tgStatusLabel.SetText("Scraping & testing...")
	s.tgResultEdit.SetText("Connecting to anti-censorship mirrors...\r\nTesting latency concurrently...\r\n\r\n")
	s.setStatus("Fetching MTProto proxies...")

	go func() {
		channel := ""
		if s.tgChannelEdit != nil {
			channel = strings.TrimSpace(s.tgChannelEdit.Text())
		}
		urlPath := "/api/telegram/mtproto"
		if channel != "" {
			urlPath += "?channel=" + url.QueryEscape(channel)
		}
		var resp mtprotoProxyResponse
		err := s.getJSON(urlPath, &resp)

		s.sync(func() {
			if err != nil {
				s.tgStatusLabel.SetText("Failed")
				s.tgResultEdit.SetText("Error: " + err.Error() + "\r\n")
				s.setStatus("MTProto fetch failed.")
				return
			}

			if len(resp.Proxies) == 0 {
				s.tgStatusLabel.SetText("No proxies found")
				s.tgResultEdit.SetText("Scraped mirrors successfully, but all tested endpoints timed out.\r\n")
				s.setStatus("No working MTProto proxies found.")
				return
			}

			s.tgStatusLabel.SetText(fmt.Sprintf("Found %d proxies", len(resp.Proxies)))
			s.setStatus("MTProto proxies updated.")
			s.lastTgProxies = resp.Proxies

			var sb strings.Builder
			sb.WriteString("Verified MTProto Proxy List:\r\n")
			sb.WriteString("============================================================\r\n\r\n")

			for i, p := range resp.Proxies {
				link := fmt.Sprintf("tg://proxy?server=%s&port=%d&secret=%s", p.Host, p.Port, p.Secret)
				sb.WriteString(fmt.Sprintf("[%d] Server:  %s:%d\r\n", i+1, p.Host, p.Port))
				sb.WriteString(fmt.Sprintf("    Latency: %d ms\r\n", p.PingMs))
				sb.WriteString(fmt.Sprintf("    Link:    %s\r\n\r\n", link))
			}

			s.tgResultEdit.SetText(sb.String())
		})
	}()
}

func (s *nativeShell) onTgChannelPresetChanged() {
	if s.tgChannelPresetCombo == nil || s.tgChannelEdit == nil {
		return
	}
	idx := s.tgChannelPresetCombo.CurrentIndex()
	if idx < 0 {
		return
	}
	channels := []string{
		"ProxyMTProto",
		"MTProtoProxies",
		"TelMTProto",
		"Proxy_MTProto_Free",
		"TgProxies",
	}
	if idx < len(channels) {
		s.tgChannelEdit.SetText(channels[idx])
	}
}

func (s *nativeShell) onCopyFastestTgProxy() {
	if len(s.lastTgProxies) == 0 {
		s.setStatus("No proxies to copy. Fetch them first.")
		return
	}
	p := s.lastTgProxies[0]
	link := fmt.Sprintf("tg://proxy?server=%s&port=%d&secret=%s", p.Host, p.Port, p.Secret)
	_ = walk.Clipboard().SetText(link)
	s.setStatus("Copied fastest proxy to clipboard!")
}

func (s *nativeShell) onCopyAllTgProxies() {
	if len(s.lastTgProxies) == 0 {
		s.setStatus("No proxies to copy. Fetch them first.")
		return
	}
	var sb strings.Builder
	for _, p := range s.lastTgProxies {
		link := fmt.Sprintf("tg://proxy?server=%s&port=%d&secret=%s", p.Host, p.Port, p.Secret)
		sb.WriteString(link + "\r\n")
	}
	_ = walk.Clipboard().SetText(sb.String())
	s.setStatus("Copied all verified proxies to clipboard!")
}
