//go:build windows && cgo

package cmd

import (
	. "github.com/lxn/walk/declarative"
)

func (s *nativeShell) dashboardPage() TabPage {
	return TabPage{
		Title:  "Status",
		Layout: VBox{Margins: Margins{Left: 14, Top: 14, Right: 14, Bottom: 14}},
		Children: []Widget{
			Composite{
				Layout: HBox{MarginsZero: true, Spacing: 10},
				Children: []Widget{
					GroupBox{
						Title:         "System overview",
						Layout:        VBox{},
						StretchFactor: 3,
						Children: []Widget{
							TextEdit{AssignTo: &s.overviewEdit, ReadOnly: true, VScroll: true, MinSize: Size{Height: 210}},
						},
					},
					GroupBox{
						Title:         "Quick controls",
						Layout:        VBox{},
						MinSize:       Size{Width: 220},
						StretchFactor: 1,
						Children: []Widget{
							PushButton{Text: "Refresh all", OnClicked: s.refreshAll},
							PushButton{Text: "Generate runbook", OnClicked: s.generateRunbook},
							PushButton{Text: "Load latest job", OnClicked: s.loadLatestJob},
							PushButton{Text: "API health", OnClicked: s.healthCheck},
						},
					},
				},
			},
			GroupBox{
				Title:  "Activity",
				Layout: VBox{},
				Children: []Widget{
					TextEdit{AssignTo: &s.activityLog, ReadOnly: true, VScroll: true, Text: "Native shell ready.\r\n"},
				},
			},
		},
	}
}

func (s *nativeShell) runbookPage() TabPage {
	return TabPage{
		Title:  "Runbook",
		Layout: VBox{Margins: Margins{Left: 14, Top: 14, Right: 14, Bottom: 14}},
		Children: []Widget{
			GroupBox{
				Title:  "Operator readiness snapshot",
				Layout: VBox{},
				Children: []Widget{
					Composite{
						Layout: HBox{MarginsZero: true},
						Children: []Widget{
							PushButton{Text: "Generate snapshot", OnClicked: s.generateRunbook},
							PushButton{Text: "Refresh all first", OnClicked: func() {
								s.refreshAll()
								s.generateRunbook()
							}},
							PushButton{Text: "Export history JSON", OnClicked: func() { s.openPath("/api/export") }},
							HSpacer{},
						},
					},
					TextEdit{AssignTo: &s.runbookEdit, ReadOnly: true, VScroll: true},
				},
			},
		},
	}
}

func (s *nativeShell) interfacesPage() TabPage {
	return TabPage{
		Title:  "Interfaces",
		Layout: VBox{Margins: Margins{Left: 14, Top: 14, Right: 14, Bottom: 14}},
		Children: []Widget{
			GroupBox{
				Title:  "Active network adapters",
				Layout: VBox{},
				Children: []Widget{
					Composite{
						Layout: HBox{MarginsZero: true},
						Children: []Widget{
							PushButton{Text: "Refresh interfaces", OnClicked: s.refreshInterfaces},
							PushButton{Text: "Refresh system settings", OnClicked: s.refreshSystemSettings},
							HSpacer{},
						},
					},
					TextEdit{AssignTo: &s.interfacesEdit, ReadOnly: true, VScroll: true},
				},
			},
		},
	}
}

func (s *nativeShell) operationsPage() TabPage {
	return TabPage{
		Title:  "Operations",
		Layout: Grid{Columns: 2, Margins: Margins{Left: 14, Top: 14, Right: 14, Bottom: 14}, Spacing: 10},
		Children: []Widget{
			GroupBox{
				Title:  "Capability lanes",
				Layout: VBox{},
				Children: []Widget{
					TextEdit{AssignTo: &s.capabilityEdit, ReadOnly: true, VScroll: true},
				},
			},
			GroupBox{
				Title:  "Network tools port ledger",
				Layout: VBox{},
				Children: []Widget{
					TextEdit{AssignTo: &s.toolLedgerEdit, ReadOnly: true, VScroll: true},
				},
			},
			GroupBox{
				Title:      "Safety boundary",
				Layout:     VBox{},
				ColumnSpan: 2,
				Children: []Widget{
					TextEdit{AssignTo: &s.boundaryEdit, ReadOnly: true, VScroll: true},
				},
			},
		},
	}
}
