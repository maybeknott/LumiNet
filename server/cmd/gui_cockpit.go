//go:build windows && cgo

package cmd

import (
	"fmt"
	"strings"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
)

func (s *nativeShell) cockpitPage() TabPage {
	return TabPage{
		Title:  "Cockpit",
		Layout: VBox{MarginsZero: true, SpacingZero: true},
		Children: []Widget{
			CustomWidget{
				AssignTo:            &s.cockpitWidget,
				MinSize:             Size{Width: 1180, Height: 680},
				StretchFactor:       1,
				InvalidatesOnResize: true,
				PaintMode:           PaintBuffered,
				PaintPixels:         s.paintCockpit,
			},
			Composite{
				Layout:  HBox{Margins: Margins{Left: 18, Top: 8, Right: 18, Bottom: 10}, Spacing: 10},
				MaxSize: Size{Height: 54},
				Children: []Widget{
					ComboBox{
						AssignTo: &s.cockpitScenario,
						Model: []string{
							"Diagnostic: HTTP/TLS",
							"Scan: ICMP sweep",
							"Scan: TCP ports",
							"Scan: DNS records",
							"Scan: SNI reachability",
						},
						MaxSize: Size{Width: 180},
					},
					LineEdit{AssignTo: &s.cockpitTarget, Text: "cloudflare.com", MaxSize: Size{Width: 210}},
					LineEdit{AssignTo: &s.cockpitPorts, Text: "80,443,8443", MaxSize: Size{Width: 118}},
					PushButton{Text: "Run workflow", OnClicked: s.runCockpitWorkflow},
					PushButton{Text: "Runbook", OnClicked: s.generateRunbook},
					HSpacer{},
					PushButton{Text: "Refresh", OnClicked: s.refreshAll},
					PushButton{Text: "Export history", OnClicked: func() { s.openPath("/api/export") }},
					PushButton{Text: "API health", OnClicked: s.healthCheck},
				},
			},
		},
	}
}

func (s *nativeShell) paintCockpit(canvas *walk.Canvas, _ walk.Rectangle) error {
	bounds := canvas.BoundsPixels()
	if s.cockpitWidget != nil {
		bounds = s.cockpitWidget.ClientBounds()
	}
	if bounds.Width <= 0 || bounds.Height <= 0 {
		return nil
	}

	fonts, err := newCockpitFonts()
	if err != nil {
		return err
	}
	defer fonts.dispose()

	p := cockpitPalette{
		bgTop:    walk.RGB(10, 14, 26),
		bgBottom: walk.RGB(15, 20, 37),
		rail:     walk.RGB(21, 27, 49),
		panel:    walk.RGB(26, 33, 56),
		panel2:   walk.RGB(33, 41, 70),
		border:   walk.RGB(59, 130, 246),
		muted:    walk.RGB(148, 163, 184),
		text:     walk.RGB(241, 245, 249),
		teal:     walk.RGB(6, 182, 212),
		amber:    walk.RGB(245, 158, 11),
		red:      walk.RGB(244, 63, 94),
		green:    walk.RGB(16, 185, 129),
	}

	if err := canvas.GradientFillRectanglePixels(p.bgTop, p.bgBottom, walk.Vertical, bounds); err != nil {
		return err
	}
	if err := s.paintCockpitGrain(canvas, bounds, p); err != nil {
		return err
	}

	margin := 24
	railW := 172
	if bounds.Width < 1200 {
		railW = 146
		margin = 18
	}
	railRect := walk.Rectangle{X: margin, Y: margin, Width: railW, Height: bounds.Height - margin*2}
	if err := drawRoundedPanel(canvas, railRect, p.rail, p.border, 14); err != nil {
		return err
	}
	drawText(canvas, fonts.label, p.teal, "LUMINET", insetRect(railRect, 18, 18, 18, railRect.Height-48), walk.TextSingleLine|walk.TextEndEllipsis)
	drawText(canvas, fonts.bodyBold, p.text, "Native control plane", walk.Rectangle{X: railRect.X + 18, Y: railRect.Y + 48, Width: railRect.Width - 36, Height: 48}, walk.TextWordbreak|walk.TextEndEllipsis)
	drawRailItem(canvas, fonts, p, railRect.X+16, railRect.Y+120, "LIVE", "Cockpit telemetry", true)
	drawRailItem(canvas, fonts, p, railRect.X+16, railRect.Y+174, "SCAN", "Probe launchers", false)
	drawRailItem(canvas, fonts, p, railRect.X+16, railRect.Y+228, "PROXY", "Parser and tests", false)
	drawRailItem(canvas, fonts, p, railRect.X+16, railRect.Y+282, "SYS", "DNS, proxy, DDNS", false)
	drawText(canvas, fonts.small, p.muted, "Rust probes / Go daemon / native desktop", walk.Rectangle{X: railRect.X + 18, Y: railRect.Y + railRect.Height - 70, Width: railRect.Width - 36, Height: 44}, walk.TextWordbreak|walk.TextEndEllipsis)

	contentX := railRect.X + railRect.Width + 20
	contentW := bounds.Width - contentX - margin
	if contentW < 760 {
		contentW = 760
	}
	topY := margin + 2
	drawText(canvas, fonts.hero, p.text, "Operations cockpit", walk.Rectangle{X: contentX, Y: topY, Width: contentW - 360, Height: 42}, walk.TextSingleLine|walk.TextEndEllipsis)

	statusText := "API warming up"
	statusColor := p.amber
	if !s.lastRefresh.IsZero() && s.lastStatus.APIConnected {
		statusText = "API online"
		statusColor = p.green
	} else if !s.lastRefresh.IsZero() {
		statusText = "API degraded"
		statusColor = p.red
	}
	chipX := contentX + contentW - 332
	drawStatusChip(canvas, fonts, p, chipX, topY+2, 150, statusText, statusColor)
	refreshText := "No telemetry yet"
	if !s.lastRefresh.IsZero() {
		refreshText = "Updated " + s.lastRefresh.Format("15:04:05")
	}
	drawStatusChip(canvas, fonts, p, chipX+164, topY+2, 168, refreshText, p.teal)

	subtitle := "Local daemon, native scan queue, ported LucidNet/network-tool capabilities, and Windows system controls in one operator surface."
	drawText(canvas, fonts.body, p.muted, subtitle, walk.Rectangle{X: contentX, Y: topY + 50, Width: contentW - 12, Height: 44}, walk.TextWordbreak|walk.TextEndEllipsis)

	cardY := topY + 112
	gap := 14
	cardW := (contentW - gap*3) / 4
	cardH := 118
	drawMetricCard(canvas, fonts, p, walk.Rectangle{X: contentX, Y: cardY, Width: cardW, Height: cardH}, "CPU load", fmt.Sprintf("%d%%", s.lastStatus.CPUUsage), "scheduler headroom", s.lastStatus.CPUUsage, p.teal, s.cpuHistory)
	drawMetricCard(canvas, fonts, p, walk.Rectangle{X: contentX + (cardW+gap)*1, Y: cardY, Width: cardW, Height: cardH}, "Memory", fmt.Sprintf("%d%%", s.lastStatus.RAMUsage), fmt.Sprintf("%.1f / %.1f GiB", s.lastStatus.UsedRAMGb, s.lastStatus.TotalRAMGb), s.lastStatus.RAMUsage, p.amber, s.ramHistory)
	drawMetricCard(canvas, fonts, p, walk.Rectangle{X: contentX + (cardW+gap)*2, Y: cardY, Width: cardW, Height: cardH}, "Disk", fmt.Sprintf("%d%%", s.lastStatus.DiskUsage), fmt.Sprintf("%d GiB free", s.lastStatus.DiskFreeGb), s.lastStatus.DiskUsage, p.green, nil)
	drawMetricCard(canvas, fonts, p, walk.Rectangle{X: contentX + (cardW+gap)*3, Y: cardY, Width: cardW, Height: cardH}, "Jobs", fmt.Sprintf("%d", s.lastStatus.ActiveJobs), fmt.Sprintf("%d recorded", s.lastHistory.Total), minInt(s.lastStatus.ActiveJobs*12, 100), p.teal, nil)

	panelY := cardY + cardH + 18
	leftW := (contentW*58 - gap*100) / 100
	if leftW < 440 {
		leftW = 440
	}
	rightW := contentW - leftW - gap
	panelH := bounds.Height - panelY - margin - 66
	if panelH < 320 {
		panelH = 320
	}
	networkRect := walk.Rectangle{X: contentX, Y: panelY, Width: leftW, Height: panelH}
	queueRect := walk.Rectangle{X: contentX + leftW + gap, Y: panelY, Width: rightW, Height: (panelH - gap) / 2}
	capRect := walk.Rectangle{X: queueRect.X, Y: queueRect.Y + queueRect.Height + gap, Width: rightW, Height: panelH - queueRect.Height - gap}

	drawNetworkPanel(canvas, fonts, p, networkRect, s.lastStatus)
	drawQueuePanel(canvas, fonts, p, queueRect, s.lastHistory)
	drawCapabilityPanel(canvas, fonts, p, capRect, s.lastCaps)
	return nil
}

type cockpitPalette struct {
	bgTop    walk.Color
	bgBottom walk.Color
	rail     walk.Color
	panel    walk.Color
	panel2   walk.Color
	border   walk.Color
	muted    walk.Color
	text     walk.Color
	teal     walk.Color
	amber    walk.Color
	red      walk.Color
	green    walk.Color
}

type cockpitFonts struct {
	hero     *walk.Font
	title    *walk.Font
	value    *walk.Font
	body     *walk.Font
	bodyBold *walk.Font
	label    *walk.Font
	small    *walk.Font
	mono     *walk.Font
}

func newCockpitFonts() (*cockpitFonts, error) {
	makeFont := func(family string, size int, style walk.FontStyle) (*walk.Font, error) {
		font, err := walk.NewFont(family, size, style)
		if err != nil {
			return nil, err
		}
		return font, nil
	}
	var err error
	fonts := &cockpitFonts{}
	if fonts.hero, err = makeFont("Segoe UI", 25, walk.FontBold); err != nil {
		return nil, err
	}
	if fonts.title, err = makeFont("Segoe UI", 13, walk.FontBold); err != nil {
		fonts.dispose()
		return nil, err
	}
	if fonts.value, err = makeFont("Segoe UI", 21, walk.FontBold); err != nil {
		fonts.dispose()
		return nil, err
	}
	if fonts.body, err = makeFont("Segoe UI", 10, 0); err != nil {
		fonts.dispose()
		return nil, err
	}
	if fonts.bodyBold, err = makeFont("Segoe UI", 10, walk.FontBold); err != nil {
		fonts.dispose()
		return nil, err
	}
	if fonts.label, err = makeFont("Segoe UI", 9, walk.FontBold); err != nil {
		fonts.dispose()
		return nil, err
	}
	if fonts.small, err = makeFont("Segoe UI", 8, 0); err != nil {
		fonts.dispose()
		return nil, err
	}
	if fonts.mono, err = makeFont("Cascadia Mono", 9, 0); err != nil {
		fonts.dispose()
		return nil, err
	}
	return fonts, nil
}

func (f *cockpitFonts) dispose() {
	for _, font := range []*walk.Font{f.hero, f.title, f.value, f.body, f.bodyBold, f.label, f.small, f.mono} {
		if font != nil {
			font.Dispose()
		}
	}
}

func (s *nativeShell) paintCockpitGrain(canvas *walk.Canvas, bounds walk.Rectangle, p cockpitPalette) error {
	pen, err := walk.NewCosmeticPen(walk.PenSolid, walk.RGB(24, 33, 33))
	if err != nil {
		return err
	}
	defer pen.Dispose()
	for y := bounds.Y + 18; y < bounds.Y+bounds.Height; y += 34 {
		if err := canvas.DrawLinePixels(pen, walk.Point{X: bounds.X, Y: y}, walk.Point{X: bounds.X + bounds.Width, Y: y}); err != nil {
			return err
		}
	}
	accent, err := walk.NewSolidColorBrush(p.teal)
	if err != nil {
		return err
	}
	defer accent.Dispose()
	return canvas.FillRectanglePixels(accent, walk.Rectangle{X: bounds.X, Y: bounds.Y, Width: bounds.Width, Height: 3})
}

func drawRailItem(canvas *walk.Canvas, fonts *cockpitFonts, p cockpitPalette, x, y int, key, label string, active bool) {
	bg := p.panel
	border := p.border
	if active {
		bg = walk.RGB(32, 58, 57)
		border = p.teal
	}
	rect := walk.Rectangle{X: x, Y: y, Width: 140, Height: 42}
	drawRoundedPanel(canvas, rect, bg, border, 9)
	drawText(canvas, fonts.label, p.text, key, walk.Rectangle{X: x + 12, Y: y + 7, Width: 48, Height: 18}, walk.TextSingleLine|walk.TextEndEllipsis)
	drawText(canvas, fonts.small, p.muted, label, walk.Rectangle{X: x + 12, Y: y + 23, Width: rect.Width - 22, Height: 15}, walk.TextSingleLine|walk.TextEndEllipsis)
}

func drawMetricCard(canvas *walk.Canvas, fonts *cockpitFonts, p cockpitPalette, rect walk.Rectangle, label, value, detail string, percent int, accent walk.Color, history []int) {
	drawRoundedPanel(canvas, rect, p.panel, p.border, 12)

	// Draw sparkline telemetry graph if history exists
	if len(history) >= 2 {
		fadeColor := func(c walk.Color) walk.Color {
			r := byte(c & 0xff)
			g := byte((c >> 8) & 0xff)
			b := byte((c >> 16) & 0xff)
			return walk.RGB(r/7, g/7, b/7) // Faded to ~14%
		}

		faded := fadeColor(accent)
		pen, err := walk.NewCosmeticPen(walk.PenSolid, faded)
		if err == nil {
			defer pen.Dispose()
			sparkW := rect.Width - 24
			sparkH := 24
			startX := rect.X + 12
			startY := rect.Y + rect.Height - 16 - sparkH

			stepX := float64(sparkW) / float64(len(history)-1)
			for i := 0; i < len(history)-1; i++ {
				x1 := startX + int(float64(i)*stepX)
				x2 := startX + int(float64(i+1)*stepX)
				val1 := history[i]
				val2 := history[i+1]
				y1 := startY + sparkH - int(float64(val1)/100.0*float64(sparkH-4))
				y2 := startY + sparkH - int(float64(val2)/100.0*float64(sparkH-4))
				_ = canvas.DrawLinePixels(pen, walk.Point{X: x1, Y: y1}, walk.Point{X: x2, Y: y2})
			}
		}
	}

	drawText(canvas, fonts.label, p.muted, label, walk.Rectangle{X: rect.X + 16, Y: rect.Y + 14, Width: rect.Width - 32, Height: 20}, walk.TextSingleLine|walk.TextEndEllipsis)
	drawText(canvas, fonts.value, p.text, value, walk.Rectangle{X: rect.X + 16, Y: rect.Y + 38, Width: rect.Width - 32, Height: 34}, walk.TextSingleLine|walk.TextEndEllipsis)
	drawProgress(canvas, walk.Rectangle{X: rect.X + 16, Y: rect.Y + 78, Width: rect.Width - 32, Height: 8}, percent, accent)
	drawText(canvas, fonts.small, p.muted, detail, walk.Rectangle{X: rect.X + 16, Y: rect.Y + 91, Width: rect.Width - 32, Height: 18}, walk.TextSingleLine|walk.TextEndEllipsis)
}

func drawNetworkPanel(canvas *walk.Canvas, fonts *cockpitFonts, p cockpitPalette, rect walk.Rectangle, status nativeSystemStatus) {
	drawRoundedPanel(canvas, rect, p.panel, p.border, 12)
	drawText(canvas, fonts.title, p.text, "Network posture", walk.Rectangle{X: rect.X + 18, Y: rect.Y + 16, Width: rect.Width - 36, Height: 24}, walk.TextSingleLine|walk.TextEndEllipsis)
	drawText(canvas, fonts.body, p.muted, "Public address, DNS, proxy state, and primary adapters", walk.Rectangle{X: rect.X + 18, Y: rect.Y + 42, Width: rect.Width - 36, Height: 24}, walk.TextSingleLine|walk.TextEndEllipsis)

	y := rect.Y + 78
	drawKeyValue(canvas, fonts, p, rect.X+18, y, rect.Width-36, "IPv4", emptyDash(status.PublicIPv4))
	drawKeyValue(canvas, fonts, p, rect.X+18, y+34, rect.Width-36, "IPv6", emptyDash(status.PublicIPv6))
	drawKeyValue(canvas, fonts, p, rect.X+18, y+68, rect.Width-36, "DNS", compactText(emptyDash(strings.Join(status.DNSServers, ", ")), 96))
	drawKeyValue(canvas, fonts, p, rect.X+18, y+102, rect.Width-36, "System proxy", enabledText(status.ProxyActive))
	drawKeyValue(canvas, fonts, p, rect.X+18, y+136, rect.Width-36, "Evasion tunnel", enabledText(status.EvasionActive))

	listY := y + 184
	drawText(canvas, fonts.label, p.teal, "Active interfaces", walk.Rectangle{X: rect.X + 18, Y: listY, Width: rect.Width - 36, Height: 18}, walk.TextSingleLine|walk.TextEndEllipsis)
	if len(status.Interfaces) == 0 {
		drawText(canvas, fonts.body, p.muted, "No active adapters reported yet. Refresh telemetry after the daemon finishes warming up.", walk.Rectangle{X: rect.X + 18, Y: listY + 26, Width: rect.Width - 36, Height: 44}, walk.TextWordbreak|walk.TextEndEllipsis)
		return
	}
	for i, iface := range status.Interfaces {
		if i >= 4 {
			drawText(canvas, fonts.small, p.muted, fmt.Sprintf("+%d more adapters", len(status.Interfaces)-i), walk.Rectangle{X: rect.X + 18, Y: listY + 28 + i*34, Width: rect.Width - 36, Height: 18}, walk.TextSingleLine|walk.TextEndEllipsis)
			break
		}
		name := iface.Name
		if iface.SSID != "" {
			name += " / " + iface.SSID
		}
		kind := "wired"
		if iface.IsWireless {
			kind = "wireless"
		}
		drawText(canvas, fonts.bodyBold, p.text, compactText(name, 56), walk.Rectangle{X: rect.X + 18, Y: listY + 28 + i*34, Width: rect.Width - 160, Height: 18}, walk.TextSingleLine|walk.TextEndEllipsis)
		drawText(canvas, fonts.small, p.muted, compactText(strings.Join(iface.IPs, ", "), 72), walk.Rectangle{X: rect.X + 18, Y: listY + 45 + i*34, Width: rect.Width - 36, Height: 14}, walk.TextSingleLine|walk.TextEndEllipsis)
		drawStatusChip(canvas, fonts, p, rect.X+rect.Width-128, listY+28+i*34, 92, kind, p.teal)
	}
}

func drawQueuePanel(canvas *walk.Canvas, fonts *cockpitFonts, p cockpitPalette, rect walk.Rectangle, history nativeHistoryResponse) {
	drawRoundedPanel(canvas, rect, p.panel2, p.border, 12)
	drawText(canvas, fonts.title, p.text, "Job queue", walk.Rectangle{X: rect.X + 16, Y: rect.Y + 14, Width: rect.Width - 32, Height: 24}, walk.TextSingleLine|walk.TextEndEllipsis)
	drawText(canvas, fonts.small, p.muted, fmt.Sprintf("%d recorded job(s)", history.Total), walk.Rectangle{X: rect.X + 16, Y: rect.Y + 40, Width: rect.Width - 32, Height: 18}, walk.TextSingleLine|walk.TextEndEllipsis)
	if len(history.Jobs) == 0 {
		drawText(canvas, fonts.body, p.muted, "Queue is empty. Start a scan, proxy test, or diagnostic to populate the ledger.", walk.Rectangle{X: rect.X + 16, Y: rect.Y + 72, Width: rect.Width - 32, Height: 60}, walk.TextWordbreak|walk.TextEndEllipsis)
		return
	}
	rowY := rect.Y + 70
	for i, job := range history.Jobs {
		if i >= 4 || rowY > rect.Y+rect.Height-32 {
			break
		}
		color := p.teal
		if strings.EqualFold(job.Status, "failed") {
			color = p.red
		} else if strings.EqualFold(job.Status, "completed") {
			color = p.green
		}
		drawText(canvas, fonts.bodyBold, p.text, compactText(job.Type, 28), walk.Rectangle{X: rect.X + 16, Y: rowY, Width: rect.Width - 150, Height: 18}, walk.TextSingleLine|walk.TextEndEllipsis)
		drawText(canvas, fonts.small, p.muted, compactText(job.ID, 36), walk.Rectangle{X: rect.X + 16, Y: rowY + 17, Width: rect.Width - 150, Height: 15}, walk.TextSingleLine|walk.TextEndEllipsis)
		drawStatusChip(canvas, fonts, p, rect.X+rect.Width-122, rowY, 92, fmt.Sprintf("%s %d%%", job.Status, job.Progress), color)
		rowY += 40
	}
}

func drawCapabilityPanel(canvas *walk.Canvas, fonts *cockpitFonts, p cockpitPalette, rect walk.Rectangle, caps nativeCapabilityResponse) {
	drawRoundedPanel(canvas, rect, p.panel, p.border, 12)
	core := "Core pending"
	coreColor := p.amber
	if caps.Runtime.OS != "" {
		core = fmt.Sprintf("%s/%s", caps.Runtime.OS, caps.Runtime.Arch)
		coreColor = p.green
		if caps.Runtime.MockCore {
			core = "Mock core active"
			coreColor = p.amber
		}
	}
	drawText(canvas, fonts.title, p.text, "Ported capability wall", walk.Rectangle{X: rect.X + 16, Y: rect.Y + 14, Width: rect.Width - 32, Height: 24}, walk.TextSingleLine|walk.TextEndEllipsis)
	drawStatusChip(canvas, fonts, p, rect.X+rect.Width-142, rect.Y+14, 112, core, coreColor)

	y := rect.Y + 56
	drawText(canvas, fonts.small, p.muted, fmt.Sprintf("%d LucidNet lanes / %d network-tool sources", len(caps.Catalog), len(caps.NetworkToolTemplates)), walk.Rectangle{X: rect.X + 16, Y: y, Width: rect.Width - 32, Height: 18}, walk.TextSingleLine|walk.TextEndEllipsis)
	y += 28
	if len(caps.Catalog) == 0 {
		drawText(canvas, fonts.body, p.muted, "Capability catalog is not loaded yet. Refresh telemetry to pull the native daemon catalog.", walk.Rectangle{X: rect.X + 16, Y: y, Width: rect.Width - 32, Height: 52}, walk.TextWordbreak|walk.TextEndEllipsis)
		return
	}
	for i, item := range caps.Catalog {
		if i >= 4 || y > rect.Y+rect.Height-42 {
			break
		}
		drawText(canvas, fonts.bodyBold, p.text, compactText(item.Name, 32), walk.Rectangle{X: rect.X + 16, Y: y, Width: rect.Width - 128, Height: 18}, walk.TextSingleLine|walk.TextEndEllipsis)
		drawText(canvas, fonts.small, p.muted, compactText(item.NativeRuntime+" / "+item.SafeState, 54), walk.Rectangle{X: rect.X + 16, Y: y + 17, Width: rect.Width - 32, Height: 15}, walk.TextSingleLine|walk.TextEndEllipsis)
		drawStatusChip(canvas, fonts, p, rect.X+rect.Width-112, y, 82, item.Priority, p.teal)
		y += 40
	}
}

func drawKeyValue(canvas *walk.Canvas, fonts *cockpitFonts, p cockpitPalette, x, y, width int, key, value string) {
	drawText(canvas, fonts.label, p.muted, key, walk.Rectangle{X: x, Y: y, Width: 112, Height: 20}, walk.TextSingleLine|walk.TextEndEllipsis)
	drawText(canvas, fonts.mono, p.text, value, walk.Rectangle{X: x + 122, Y: y, Width: width - 122, Height: 20}, walk.TextSingleLine|walk.TextEndEllipsis)
}

func drawStatusChip(canvas *walk.Canvas, fonts *cockpitFonts, p cockpitPalette, x, y, width int, text string, accent walk.Color) {
	rect := walk.Rectangle{X: x, Y: y, Width: width, Height: 28}
	drawRoundedPanel(canvas, rect, walk.RGB(22, 32, 32), accent, 8)
	drawText(canvas, fonts.small, accent, text, insetRect(rect, 10, 6, 10, 6), walk.TextSingleLine|walk.TextCenter|walk.TextVCenter|walk.TextEndEllipsis)
}

func drawProgress(canvas *walk.Canvas, rect walk.Rectangle, percent int, accent walk.Color) {
	track, err := walk.NewSolidColorBrush(walk.RGB(44, 57, 56))
	if err != nil {
		return
	}
	defer track.Dispose()
	fill, err := walk.NewSolidColorBrush(accent)
	if err != nil {
		return
	}
	defer fill.Dispose()
	_ = canvas.FillRoundedRectanglePixels(track, rect, walk.Size{Width: 6, Height: 6})
	fillW := rect.Width * clampPercent(percent) / 100
	if fillW < 3 && percent > 0 {
		fillW = 3
	}
	_ = canvas.FillRoundedRectanglePixels(fill, walk.Rectangle{X: rect.X, Y: rect.Y, Width: fillW, Height: rect.Height}, walk.Size{Width: 6, Height: 6})
}

func drawRoundedPanel(canvas *walk.Canvas, rect walk.Rectangle, fill, border walk.Color, radius int) error {
	brush, err := walk.NewSolidColorBrush(fill)
	if err != nil {
		return err
	}
	defer brush.Dispose()
	pen, err := walk.NewCosmeticPen(walk.PenSolid, border)
	if err != nil {
		return err
	}
	defer pen.Dispose()
	if err := canvas.FillRoundedRectanglePixels(brush, rect, walk.Size{Width: radius, Height: radius}); err != nil {
		return err
	}
	return canvas.DrawRoundedRectanglePixels(pen, rect, walk.Size{Width: radius, Height: radius})
}

func drawText(canvas *walk.Canvas, font *walk.Font, color walk.Color, text string, rect walk.Rectangle, format walk.DrawTextFormat) {
	if text == "" {
		text = "-"
	}
	_ = canvas.DrawTextPixels(text, font, color, rect, format|walk.TextNoPrefix)
}

func insetRect(rect walk.Rectangle, left, top, right, bottom int) walk.Rectangle {
	return walk.Rectangle{
		X:      rect.X + left,
		Y:      rect.Y + top,
		Width:  rect.Width - left - right,
		Height: rect.Height - top - bottom,
	}
}

func clampPercent(value int) int {
	if value < 0 {
		return 0
	}
	if value > 100 {
		return 100
	}
	return value
}
