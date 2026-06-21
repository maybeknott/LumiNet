//go:build windows && cgo

package cmd

import (
	. "github.com/lxn/walk/declarative"
)

func (s *nativeShell) maintenancePage() TabPage {
	return TabPage{
		Title:  "Maintenance",
		Layout: VBox{Margins: Margins{Left: 14, Top: 14, Right: 14, Bottom: 14}},
		Children: []Widget{
			GroupBox{
				Title:  "Startup",
				Layout: Grid{Columns: 3, Spacing: 10},
				Children: []Widget{
					CheckBox{AssignTo: &s.startupEnabled, Text: "Start LumiNet with Windows"},
					PushButton{Text: "Apply startup", OnClicked: s.applyStartup},
					PushButton{Text: "Refresh startup", OnClicked: s.refreshStartup},
				},
			},
			GroupBox{
				Title:  "Dynamic DNS",
				Layout: Grid{Columns: 4, Spacing: 10},
				Children: []Widget{
					Label{Text: "Enabled"},
					CheckBox{AssignTo: &s.ddnsEnabled, Text: "Enable DDNS"},
					Label{Text: "Provider"},
					LineEdit{AssignTo: &s.ddnsProvider},
					Label{Text: "Domain"},
					LineEdit{AssignTo: &s.ddnsDomain},
					Label{Text: "Token"},
					LineEdit{AssignTo: &s.ddnsToken, PasswordMode: true},
					Label{Text: "Interval min"},
					LineEdit{AssignTo: &s.ddnsInterval},
					PushButton{Text: "Save DDNS", OnClicked: s.saveDDNS},
					PushButton{Text: "Force update", OnClicked: s.forceDDNS},
				},
			},
			GroupBox{
				Title:  "Network profiles",
				Layout: VBox{},
				Children: []Widget{
					Composite{
						Layout: HBox{MarginsZero: true},
						Children: []Widget{
							PushButton{Text: "Refresh profiles", OnClicked: s.refreshProfiles},
							HSpacer{},
						},
					},
					TextEdit{AssignTo: &s.profilesEdit, ReadOnly: true, VScroll: true},
				},
			},
		},
	}
}

func (s *nativeShell) jobsPage() TabPage {
	return TabPage{
		Title:  "Jobs",
		Layout: VBox{Margins: Margins{Left: 14, Top: 14, Right: 14, Bottom: 14}},
		Children: []Widget{
			GroupBox{
				Title:  "Job inspector",
				Layout: Grid{Columns: 4, Spacing: 10},
				Children: []Widget{
					Label{Text: "Job ID"},
					LineEdit{AssignTo: &s.jobIDEdit},
					PushButton{Text: "Load job", OnClicked: s.loadJob},
					PushButton{Text: "Cancel job", OnClicked: s.cancelJob},
					PushButton{Text: "Load latest", OnClicked: s.loadLatestJob},
					PushButton{Text: "Refresh history", OnClicked: s.refreshHistory},
				},
			},
			GroupBox{
				Title:  "Status, config, and results",
				Layout: VBox{},
				Children: []Widget{
					TextEdit{AssignTo: &s.jobInspector, ReadOnly: true, VScroll: true},
				},
			},
		},
	}
}

func (s *nativeShell) historyPage() TabPage {
	return TabPage{
		Title:  "History",
		Layout: VBox{Margins: Margins{Left: 14, Top: 14, Right: 14, Bottom: 14}},
		Children: []Widget{
			GroupBox{
				Title:  "Recent daemon jobs",
				Layout: VBox{},
				Children: []Widget{
					Composite{
						Layout: HBox{MarginsZero: true},
						Children: []Widget{
							Label{AssignTo: &s.historyTotal, Text: "-"},
							HSpacer{},
							PushButton{Text: "Refresh history", OnClicked: s.refreshHistory},
							PushButton{Text: "Export JSON", OnClicked: func() { s.openPath("/api/export") }},
							PushButton{Text: "Clear terminal jobs", OnClicked: s.clearHistory},
						},
					},
					TextEdit{AssignTo: &s.historyEdit, ReadOnly: true, VScroll: true},
				},
			},
		},
	}
}
