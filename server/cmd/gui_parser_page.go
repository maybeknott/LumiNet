//go:build windows && cgo

package cmd

import (
	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
)

func (s *nativeShell) parserPage() TabPage {
	return TabPage{
		Title:  "Parser",
		Layout: VBox{MarginsZero: true, SpacingZero: true},
		Children: []Widget{
			TabWidget{
				Pages: []TabPage{
					TabPage{
						Title:  "Parse Natively",
						Layout: Grid{Columns: 2, Margins: Margins{Left: 14, Top: 14, Right: 14, Bottom: 14}, Spacing: 10},
						Children: []Widget{
							GroupBox{
								Title:  "Paste proxy URIs, base64 subscriptions, Clash YAML, or sing-box JSON",
								Layout: VBox{},
								Children: []Widget{
									TextEdit{AssignTo: &s.parserInput, VScroll: true},
									Composite{
										Layout: HBox{MarginsZero: true},
										Children: []Widget{
											PushButton{Text: "Parse natively", OnClicked: s.parseProxyInput},
											PushButton{Text: "Clear", OnClicked: func() {
												s.parserInput.SetText("")
												s.parserOutput.SetText("")
											}},
										},
									},
								},
							},
							GroupBox{
								Title:  "Safe parsed preview",
								Layout: VBox{},
								Children: []Widget{
									TextEdit{AssignTo: &s.parserOutput, ReadOnly: true, VScroll: true},
								},
							},
						},
					},
					TabPage{
						Title:  "Clean IP Mapping / Rewrite",
						Layout: Grid{Columns: 2, Margins: Margins{Left: 14, Top: 14, Right: 14, Bottom: 14}, Spacing: 10},
						Children: []Widget{
							GroupBox{
								Title:  "Template Configuration & Clean IPs",
								Layout: VBox{Spacing: 8},
								Children: []Widget{
									Label{Text: "Proxy template nodes / subscription (newline or comma-separated URIs/base64):"},
									TextEdit{AssignTo: &s.rewriteInput, VScroll: true, MinSize: Size{Height: 140}},
									Label{Text: "Clean IP addresses (comma or newline separated):"},
									TextEdit{AssignTo: &s.rewriteCleanIPs, VScroll: true, MinSize: Size{Height: 140}},
									Composite{
										Layout: Grid{Columns: 4, MarginsZero: true, Spacing: 6},
										Children: []Widget{
											Label{Text: "Port override (optional):"},
											LineEdit{AssignTo: &s.rewritePortOverride},
											Label{Text: "Name template:"},
											LineEdit{AssignTo: &s.rewriteNameTemplate},
										},
									},
									Composite{
										Layout: HBox{MarginsZero: true, Spacing: 10},
										Children: []Widget{
											PushButton{Text: "Map & Rewrite Subscription", OnClicked: s.rewriteProxySubscription},
											PushButton{Text: "Clear all", OnClicked: func() {
												s.rewriteInput.SetText("")
												s.rewriteCleanIPs.SetText("")
												s.rewritePortOverride.SetText("")
												s.rewriteNameTemplate.SetText("{name} | {ip}")
												s.rewriteOutput.SetText("")
												s.rewritePreviewOutput.SetText("")
											}},
										},
									},
								},
							},
							GroupBox{
								Title:  "Rewritten Outputs & Preview",
								Layout: VBox{Spacing: 8},
								Children: []Widget{
									Label{Text: "Rewritten Nodes (raw output):"},
									TextEdit{AssignTo: &s.rewriteOutput, ReadOnly: true, VScroll: true, MinSize: Size{Height: 140}},
									Composite{
										Layout: HBox{MarginsZero: true},
										Children: []Widget{
											PushButton{Text: "Copy all rewritten links", OnClicked: func() {
												if text := s.rewriteOutput.Text(); text != "" {
													_ = walk.Clipboard().SetText(text)
													s.setStatus("Rewritten subscription links copied to clipboard!")
												}
											}},
										},
									},
									Label{Text: "Parsed preview of rewritten nodes:"},
									TextEdit{AssignTo: &s.rewritePreviewOutput, ReadOnly: true, VScroll: true, MinSize: Size{Height: 140}},
								},
							},
						},
					},
				},
			},
		},
	}
}
