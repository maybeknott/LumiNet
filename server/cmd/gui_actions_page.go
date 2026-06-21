//go:build windows && cgo

package cmd

import (
	. "github.com/lxn/walk/declarative"
)

func (s *nativeShell) actionsPage() TabPage {
	return TabPage{
		Title:  "Actions",
		Layout: VBox{Margins: Margins{Left: 14, Top: 14, Right: 14, Bottom: 14}},
		Children: []Widget{
			GroupBox{
				Title:  "Quick diagnostics",
				Layout: Grid{Columns: 4, Spacing: 10},
				Children: []Widget{
					Label{Text: "Target"},
					LineEdit{AssignTo: &s.targetEdit},
					ComboBox{
						AssignTo: &s.diagnosticsMode,
						Model:    []string{"ping", "dns", "tls", "http"},
					},
					PushButton{Text: "Run diagnostic", OnClicked: s.runDiagnostic},
				},
			},
			GroupBox{
				Title:  "Native capability checks",
				Layout: Grid{Columns: 3, Spacing: 10},
				Children: []Widget{
					PushButton{Text: "Refresh status", OnClicked: s.refreshStatus},
					PushButton{Text: "Refresh catalog", OnClicked: s.refreshCapabilities},
					PushButton{Text: "Health check", OnClicked: s.healthCheck},
					PushButton{Text: "Refresh history", OnClicked: s.refreshHistory},
					PushButton{Text: "Export history", OnClicked: func() { s.openPath("/api/export") }},
				},
			},
			VSpacer{},
		},
	}
}
