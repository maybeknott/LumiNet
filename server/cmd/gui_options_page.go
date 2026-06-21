//go:build windows && cgo

package cmd

import (
	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
)

func (s *nativeShell) optionsPage() TabPage {
	return TabPage{
		Title:  "Options",
		Layout: VBox{Margins: Margins{Left: 14, Top: 14, Right: 14, Bottom: 14}},
		Children: []Widget{
			GroupBox{
				Title:  "Native shell behavior",
				Layout: VBox{},
				Children: []Widget{
					CheckBox{AssignTo: &s.autoRefresh, Text: "Auto-refresh daemon status every 5 seconds"},
					CheckBox{AssignTo: &s.compactMode, Text: "Compact density for operations text panes", OnClicked: s.applyDensity},
				},
			},
			GroupBox{
				Title:  "Runtime split",
				Layout: VBox{},
				Children: []Widget{
					Label{Text: "Rust: probe primitives and scan engine"},
					Label{Text: "Go: local daemon, jobs, OS integration, native GUI"},
					Label{Text: "TypeScript: retired compatibility console and operator workflow prototypes"},
				},
			},
			GroupBox{
				Title:  "Safety policy",
				Layout: VBox{},
				Children: []Widget{
					Label{Text: "The native UI exposes diagnostics, testing, and export workflows. It does not emit tunnel relay, packet injection, or hidden interception behavior."},
				},
			},
			VSpacer{},
		},
	}
}

func (s *nativeShell) metric(title string, target **walk.Label) Widget {
	return GroupBox{
		Title:  title,
		Layout: VBox{},
		Children: []Widget{
			Label{AssignTo: target, Text: "-", Font: Font{PointSize: 20, Bold: true}},
		},
	}
}

func (s *nativeShell) infoCard(title string, target **walk.Label) Widget {
	return GroupBox{
		Title:  title,
		Layout: VBox{},
		Children: []Widget{
			Label{AssignTo: target, Text: "-", MinSize: Size{Height: 36}},
		},
	}
}
