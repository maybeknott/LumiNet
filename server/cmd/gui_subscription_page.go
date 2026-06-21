//go:build windows && cgo

package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
)

func (s *nativeShell) subscriptionPage() TabPage {
	return TabPage{
		Title:  "Subscription Center",
		Layout: VBox{MarginsZero: true, SpacingZero: true},
		Children: []Widget{
			TabWidget{
				Pages: []TabPage{
					TabPage{
						Title:  "Subscription Aggregator",
						Layout: Grid{Columns: 2, Margins: Margins{Left: 14, Top: 14, Right: 14, Bottom: 14}, Spacing: 10},
						Children: []Widget{
							GroupBox{
								Title:  "Configuration",
								Layout: VBox{Spacing: 8},
								Children: []Widget{
									Label{Text: "Source URLs / Content blocks (one per line):"},
									TextEdit{AssignTo: &s.subAggInputs, VScroll: true, MinSize: Size{Height: 160}},
									GroupBox{
										Title:  "Protocol Filters",
										Layout: HBox{Spacing: 10},
										Children: []Widget{
											CheckBox{AssignTo: &s.subAggVMess, Text: "VMess", Checked: true},
											CheckBox{AssignTo: &s.subAggVLESS, Text: "VLESS", Checked: true},
											CheckBox{AssignTo: &s.subAggTrojan, Text: "Trojan", Checked: true},
											CheckBox{AssignTo: &s.subAggSS, Text: "Shadowsocks", Checked: true},
										},
									},
									Composite{
										Layout: Grid{Columns: 4, MarginsZero: true, Spacing: 6},
										Children: []Widget{
											Label{Text: "Search keyword:"},
											LineEdit{AssignTo: &s.subAggSearch},
											Label{Text: "Min/Max port bounds:"},
											Composite{
												Layout: HBox{MarginsZero: true},
												Children: []Widget{
													LineEdit{AssignTo: &s.subAggMinPort, MaxSize: Size{Width: 50}},
													Label{Text: "-"},
													LineEdit{AssignTo: &s.subAggMaxPort, MaxSize: Size{Width: 50}},
												},
											},
										},
									},
									Composite{
										Layout: HBox{MarginsZero: true, Spacing: 10},
										Children: []Widget{
											PushButton{Text: "Compile & Aggregate", OnClicked: s.aggregateSubscriptions},
											PushButton{Text: "Clear Form", OnClicked: func() {
												s.subAggInputs.SetText("")
												s.subAggVMess.SetChecked(true)
												s.subAggVLESS.SetChecked(true)
												s.subAggTrojan.SetChecked(true)
												s.subAggSS.SetChecked(true)
												s.subAggSearch.SetText("")
												s.subAggMinPort.SetText("")
												s.subAggMaxPort.SetText("")
												s.subAggOutput.SetText("")
											}},
										},
									},
								},
							},
							GroupBox{
								Title:  "Compiled Output Pane",
								Layout: VBox{Spacing: 8},
								Children: []Widget{
									TextEdit{AssignTo: &s.subAggOutput, ReadOnly: true, VScroll: true},
									Composite{
										Layout: HBox{MarginsZero: true},
										Children: []Widget{
											PushButton{Text: "Copy aggregated URIs", OnClicked: func() {
												if text := s.subAggOutput.Text(); text != "" {
													_ = walk.Clipboard().SetText(text)
													s.setStatus("Aggregated URIs copied to clipboard!")
												}
											}},
										},
									},
								},
							},
						},
					},
					TabPage{
						Title:  "CDN IP Shaper",
						Layout: Grid{Columns: 2, Margins: Margins{Left: 14, Top: 14, Right: 14, Bottom: 14}, Spacing: 10},
						Children: []Widget{
							GroupBox{
								Title:  "Shaping Inputs",
								Layout: VBox{Spacing: 8},
								Children: []Widget{
									Label{Text: "Template proxy URI (VLESS/VMess/Trojan):"},
									TextEdit{AssignTo: &s.subShapeTemplate, VScroll: true, MinSize: Size{Height: 80}},
									Label{Text: "Clean IP list (one per line):"},
									TextEdit{AssignTo: &s.subShapeCleanIPs, VScroll: true, MinSize: Size{Height: 180}},
									Composite{
										Layout: HBox{MarginsZero: true, Spacing: 10},
										Children: []Widget{
											PushButton{Text: "CF IPv4 Presets", OnClicked: func() {
												s.subShapeCleanIPs.SetText("104.16.248.249\r\n104.17.248.249\r\n104.18.248.249\r\n104.19.248.249\r\n104.20.248.249\r\n104.21.248.249\r\n104.22.248.249\r\n104.24.248.249\r\n172.64.248.249\r\n172.67.248.249")
											}},
											PushButton{Text: "Fastly Presets", OnClicked: func() {
												s.subShapeCleanIPs.SetText("151.101.1.57\r\n151.101.65.57\r\n151.101.129.57\r\n151.101.193.57")
											}},
											Label{Text: "Name template:"},
											LineEdit{AssignTo: &s.subShapeNameTemplate, Text: "{name} | {ip}"},
										},
									},
									Composite{
										Layout: HBox{MarginsZero: true, Spacing: 10},
										Children: []Widget{
											PushButton{Text: "Shape Configurations", OnClicked: s.shapeSubscription},
											PushButton{Text: "Clear Form", OnClicked: func() {
												s.subShapeTemplate.SetText("")
												s.subShapeCleanIPs.SetText("")
												s.subShapeNameTemplate.SetText("{name} | {ip}")
												s.subShapeOutput.SetText("")
											}},
										},
									},
								},
							},
							GroupBox{
								Title:  "Shaped Outputs",
								Layout: VBox{Spacing: 8},
								Children: []Widget{
									TextEdit{AssignTo: &s.subShapeOutput, ReadOnly: true, VScroll: true},
									Composite{
										Layout: HBox{MarginsZero: true},
										Children: []Widget{
											PushButton{Text: "Copy shaped URIs", OnClicked: func() {
												if text := s.subShapeOutput.Text(); text != "" {
													_ = walk.Clipboard().SetText(text)
													s.setStatus("Shaped URIs copied to clipboard!")
												}
											}},
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

func (s *nativeShell) aggregateSubscriptions() {
	inputsRaw := s.subAggInputs.Text()
	if strings.TrimSpace(inputsRaw) == "" {
		s.subAggOutput.SetText("Enter source URLs or subscription content first.")
		return
	}

	lines := strings.Split(inputsRaw, "\n")
	var inputs []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" {
			inputs = append(inputs, l)
		}
	}

	var allowed []string
	if s.subAggVMess.Checked() {
		allowed = append(allowed, "vmess")
	}
	if s.subAggVLESS.Checked() {
		allowed = append(allowed, "vless")
	}
	if s.subAggTrojan.Checked() {
		allowed = append(allowed, "trojan")
	}
	if s.subAggSS.Checked() {
		allowed = append(allowed, "shadowsocks")
	}

	var minPort, maxPort int
	fmt.Sscanf(s.subAggMinPort.Text(), "%d", &minPort)
	fmt.Sscanf(s.subAggMaxPort.Text(), "%d", &maxPort)

	payload := map[string]interface{}{
		"inputs":          inputs,
		"allow_protocols": allowed,
		"search_query":    s.subAggSearch.Text(),
		"min_port":        minPort,
		"max_port":        maxPort,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		s.subAggOutput.SetText("Failed to build request: " + err.Error())
		return
	}

	s.setStatus("Aggregating subscriptions...")

	var resp struct {
		Count   int      `json:"count"`
		RawURIs []string `json:"raw_uris"`
	}

	err = s.postJSON("/api/subscriptions/aggregate", body, &resp)
	if err != nil {
		s.subAggOutput.SetText("Aggregation failed: " + err.Error())
		s.setStatus("Subscription aggregation failed.")
		return
	}

	output := strings.Join(resp.RawURIs, "\r\n")
	s.subAggOutput.SetText(output)
	s.setStatus(fmt.Sprintf("Aggregation completed: compiled %d nodes.", resp.Count))
}

func (s *nativeShell) shapeSubscription() {
	template := strings.TrimSpace(s.subShapeTemplate.Text())
	if template == "" {
		s.subShapeOutput.SetText("Please enter a template proxy URI.")
		return
	}

	cleanIPsRaw := s.subShapeCleanIPs.Text()
	if strings.TrimSpace(cleanIPsRaw) == "" {
		s.subShapeOutput.SetText("Please enter clean IPs.")
		return
	}

	lines := strings.Split(cleanIPsRaw, "\n")
	var cleanIPs []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" {
			cleanIPs = append(cleanIPs, l)
		}
	}

	payload := map[string]interface{}{
		"template_uri":  template,
		"clean_ips":     cleanIPs,
		"name_template": s.subShapeNameTemplate.Text(),
	}

	body, err := json.Marshal(payload)
	if err != nil {
		s.subShapeOutput.SetText("Failed to build request: " + err.Error())
		return
	}

	s.setStatus("Shaping configurations...")

	var resp struct {
		Count   int      `json:"count"`
		RawURIs []string `json:"raw_uris"`
	}

	err = s.postJSON("/api/subscriptions/shape", body, &resp)
	if err != nil {
		s.subShapeOutput.SetText("Shaping failed: " + err.Error())
		s.setStatus("CDN IP shaper failed.")
		return
	}

	output := strings.Join(resp.RawURIs, "\r\n")
	s.subShapeOutput.SetText(output)
	s.setStatus(fmt.Sprintf("Shaping completed: shaped %d nodes.", resp.Count))
}
