//go:build windows && cgo

package cmd

import (
	. "github.com/lxn/walk/declarative"
)

func (s *nativeShell) proxyPage() TabPage {
	return TabPage{
		Title:  "Proxy",
		Layout: VBox{MarginsZero: true, SpacingZero: true},
		Children: []Widget{
			TabWidget{
				Pages: []TabPage{
					TabPage{
						Title:  "Proxy Tester",
						Layout: Grid{Columns: 2, Margins: Margins{Left: 14, Top: 14, Right: 14, Bottom: 14}, Spacing: 10},
						Children: []Widget{
							GroupBox{
								Title:  "Proxy test queue",
								Layout: VBox{},
								Children: []Widget{
									TextEdit{AssignTo: &s.proxyTestInput, VScroll: true},
									Composite{
										Layout: Grid{Columns: 4, Spacing: 10, MarginsZero: true},
										Children: []Widget{
											Label{Text: "URL"},
											LineEdit{AssignTo: &s.proxyTestURL},
											Label{Text: "Timeout s"},
											LineEdit{AssignTo: &s.proxyTimeout},
											CheckBox{AssignTo: &s.proxySpeedTest, Text: "Speed test"},
											PushButton{Text: "Parse into tester", OnClicked: s.parseProxyTesterInput},
											PushButton{Text: "Start tests", OnClicked: s.startProxyTests},
											PushButton{Text: "Clear", OnClicked: func() {
												s.proxyTestInput.SetText("")
												s.proxyTestOutput.SetText("")
											}},
										},
									},
								},
							},
							GroupBox{
								Title:  "Safe test preview",
								Layout: VBox{},
								Children: []Widget{
									TextEdit{AssignTo: &s.proxyTestOutput, ReadOnly: true, VScroll: true},
								},
							},
						},
					},
					TabPage{
						Title:  "Proxy Directory Manager",
						Layout: Grid{Columns: 2, Margins: Margins{Left: 14, Top: 14, Right: 14, Bottom: 14}, Spacing: 10},
						Children: []Widget{
							GroupBox{
								Title:  "Register Proxy Node",
								Layout: Grid{Columns: 2, Spacing: 10},
								Children: []Widget{
									Label{Text: "Proxy Host/IP:"},
									LineEdit{AssignTo: &s.proxyRegHost},
									Label{Text: "Port:"},
									LineEdit{AssignTo: &s.proxyRegPort},
									Label{Text: "Protocol:"},
									ComboBox{
										AssignTo: &s.proxyRegType,
										Model:    []string{"HTTP", "SOCKS5", "SOCKS4", "VMESS"},
									},
									Label{Text: "Internal Notes:"},
									LineEdit{AssignTo: &s.proxyRegNotes},
									Label{Text: "Authentication:"},
									CheckBox{AssignTo: &s.proxyRegAuth, Text: "Requires Credentials", OnClicked: s.onProxyRegAuthChanged},
									Label{Text: "Username:"},
									LineEdit{AssignTo: &s.proxyRegUser, Enabled: false},
									Label{Text: "Password:"},
									LineEdit{AssignTo: &s.proxyRegPass, Enabled: false, PasswordMode: true},
									Label{Text: ""},
									Composite{
										Layout: HBox{MarginsZero: true},
										Children: []Widget{
											PushButton{Text: "Save Proxy Node", OnClicked: s.saveProxyNode},
											PushButton{Text: "Clear Form", OnClicked: s.clearProxyForm},
										},
									},
								},
							},
							GroupBox{
								Title:  "Egress Servers Matrix / Directory",
								Layout: VBox{Spacing: 10},
								Children: []Widget{
									TextEdit{AssignTo: &s.proxyDirOutput, ReadOnly: true, VScroll: true, MinSize: Size{Height: 250}},
									Composite{
										Layout: Grid{Columns: 3, Spacing: 10, MarginsZero: true},
										Children: []Widget{
											Label{Text: "Selected ID/Host:"},
											LineEdit{AssignTo: &s.proxySelectedId},
											Label{Text: ""},
											PushButton{Text: "Ping / Test Selected", OnClicked: s.testSelectedProxyNode},
											PushButton{Text: "Remove Selected", OnClicked: s.deleteSelectedProxyNode},
											PushButton{Text: "Refresh List", OnClicked: s.refreshProxyDirectory},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}
