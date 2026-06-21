//go:build windows && cgo

package cmd

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
)

func (s *nativeShell) provisionPage() TabPage {
	var vpsIPEdit *walk.LineEdit
	var vpsUserEdit *walk.LineEdit
	var vpsPassEdit *walk.LineEdit
	var vpsKeyEdit *walk.TextEdit
	var vpsDomainEdit *walk.LineEdit
	var vpsCFTokenEdit *walk.LineEdit
	var vpsCFAcctEdit *walk.LineEdit
	var vpsLogsEdit *walk.TextEdit

	var edgeTokenEdit *walk.LineEdit
	var edgeAcctEdit *walk.LineEdit
	var edgeScriptEdit *walk.LineEdit
	var edgeHostEdit *walk.LineEdit
	var edgePortEdit *walk.LineEdit
	var edgeLogsEdit *walk.TextEdit
	var edgeTypeCombo *walk.ComboBox
	var edgeUuidEdit *walk.LineEdit
	var edgeD1BindingEdit *walk.LineEdit
	var edgeD1DbIDEdit *walk.LineEdit
	var edgeCamouflageEdit *walk.LineEdit

	return TabPage{
		Title:  "Deployment",
		Layout: VBox{MarginsZero: true, SpacingZero: true},
		Children: []Widget{
			TabWidget{
				Pages: []TabPage{
					TabPage{
						Title:  "VPS Node Provisioner",
						Layout: Grid{Columns: 2, Margins: Margins{Left: 14, Top: 14, Right: 14, Bottom: 14}, Spacing: 10},
						Children: []Widget{
							GroupBox{
								Title:  "VPS SSH & Cloudflare parameters",
								Layout: Grid{Columns: 2, Spacing: 8},
								Children: []Widget{
									Label{Text: "VPS IP Address:"},
									LineEdit{AssignTo: &vpsIPEdit, Text: ""},

									Label{Text: "SSH Username:"},
									LineEdit{AssignTo: &vpsUserEdit, Text: "root"},

									Label{Text: "SSH Password:"},
									LineEdit{AssignTo: &vpsPassEdit, PasswordMode: true},

									Label{Text: "SSH Private Key (Optional):"},
									TextEdit{AssignTo: &vpsKeyEdit, MinSize: Size{Height: 80}, VScroll: true},

									Label{Text: "Target Domain:"},
									LineEdit{AssignTo: &vpsDomainEdit, Text: ""},

									Label{Text: "Cloudflare API Token:"},
									LineEdit{AssignTo: &vpsCFTokenEdit},

									Label{Text: "Cloudflare Account ID:"},
									LineEdit{AssignTo: &vpsCFAcctEdit},

									Label{Text: ""},
									Composite{
										Layout: HBox{MarginsZero: true, Spacing: 10},
										Children: []Widget{
											PushButton{
												Text: "Start Provisioning",
												OnClicked: func() {
													vpsLogsEdit.SetText("Initiating VPS provisioning request...")
													s.setStatus("Starting VPS setup...")

													payload, _ := json.Marshal(map[string]interface{}{
														"ip":             vpsIPEdit.Text(),
														"ssh_user":       vpsUserEdit.Text(),
														"ssh_password":   vpsPassEdit.Text(),
														"ssh_key":        vpsKeyEdit.Text(),
														"domain":         vpsDomainEdit.Text(),
														"cf_token":       vpsCFTokenEdit.Text(),
														"cf_account_id":  vpsCFAcctEdit.Text(),
													})

													var resp struct {
														JobID  string `json:"job_id"`
														Status string `json:"status"`
													}
													err := s.postJSON("/api/system/provision/vps", payload, &resp)
													if err != nil {
														vpsLogsEdit.SetText("Failed to start job: " + err.Error())
														s.setStatus("VPS Provision failed.")
														return
													}

													vpsLogsEdit.SetText(vpsLogsEdit.Text() + "\r\nJob queued: " + resp.JobID + "\r\nMonitoring progress...\r\n")
													s.monitorProvisionJob(resp.JobID, vpsLogsEdit)
												},
											},
											PushButton{
												Text: "Clear Form",
												OnClicked: func() {
													vpsIPEdit.SetText("")
													vpsUserEdit.SetText("root")
													vpsPassEdit.SetText("")
													vpsKeyEdit.SetText("")
													vpsDomainEdit.SetText("")
													vpsCFTokenEdit.SetText("")
													vpsCFAcctEdit.SetText("")
													vpsLogsEdit.SetText("")
												},
											},
										},
									},
								},
							},
							GroupBox{
								Title:  "Setup progress & console output",
								Layout: VBox{},
								Children: []Widget{
									TextEdit{AssignTo: &vpsLogsEdit, ReadOnly: true, VScroll: true},
								},
							},
						},
					},
					TabPage{
						Title:  "Serverless Edge Deployer",
						Layout: Grid{Columns: 2, Margins: Margins{Left: 14, Top: 14, Right: 14, Bottom: 14}, Spacing: 10},
						Children: []Widget{
							GroupBox{
								Title:  "Cloudflare Workers parameters",
								Layout: Grid{Columns: 2, Spacing: 8},
								Children: []Widget{
									Label{Text: "Cloudflare API Token:"},
									LineEdit{AssignTo: &edgeTokenEdit},

									Label{Text: "Cloudflare Account ID:"},
									LineEdit{AssignTo: &edgeAcctEdit},

									Label{Text: "Worker Name:"},
									LineEdit{AssignTo: &edgeScriptEdit, Text: "luminet-edge-relay"},

									Label{Text: "Target SOCKS5 Egress IP:"},
									LineEdit{AssignTo: &edgeHostEdit, Text: ""},

									Label{Text: "Target Egress Port:"},
									LineEdit{AssignTo: &edgePortEdit, Text: "10888"},

									Label{Text: "Deployment Type:"},
									ComboBox{AssignTo: &edgeTypeCombo, Model: []string{"Relay (SOCKS5/Reality)", "VLESS Serverless"}},

									Label{Text: "VLESS UUID (for VLESS):"},
									LineEdit{AssignTo: &edgeUuidEdit, Text: ""},

									Label{Text: "D1 Database Binding Name:"},
									LineEdit{AssignTo: &edgeD1BindingEdit, Text: ""},

									Label{Text: "D1 Database UUID:"},
									LineEdit{AssignTo: &edgeD1DbIDEdit, Text: ""},

									Label{Text: "Camouflage Host URL:"},
									LineEdit{AssignTo: &edgeCamouflageEdit, Text: "https://ubuntu.com"},

									Label{Text: ""},
									Composite{
										Layout: HBox{MarginsZero: true, Spacing: 10},
										Children: []Widget{
											PushButton{
												Text: "Deploy Worker Proxy",
												OnClicked: func() {
													edgeLogsEdit.SetText("Initiating Edge deployment request...")
													s.setStatus("Starting edge deploy...")

													var port int
													fmt.Sscanf(edgePortEdit.Text(), "%d", &port)
													if port == 0 {
														port = 10888
													}

													edgeType := "relay"
													if edgeTypeCombo != nil && edgeTypeCombo.CurrentIndex() == 1 {
														edgeType = "vless"
													}

													payload, _ := json.Marshal(map[string]interface{}{
														"cf_token":             edgeTokenEdit.Text(),
														"cf_account_id":        edgeAcctEdit.Text(),
														"script_name":          edgeScriptEdit.Text(),
														"target_host":          edgeHostEdit.Text(),
														"target_port":          port,
														"type":                 edgeType,
														"uuid":                 edgeUuidEdit.Text(),
														"d1_database_binding": edgeD1BindingEdit.Text(),
														"d1_database_id":      edgeD1DbIDEdit.Text(),
														"camouflage_host":      edgeCamouflageEdit.Text(),
													})

													var resp struct {
														JobID  string `json:"job_id"`
														Status string `json:"status"`
													}
													err := s.postJSON("/api/system/provision/worker", payload, &resp)
													if err != nil {
														edgeLogsEdit.SetText("Failed to start job: " + err.Error())
														s.setStatus("Edge deploy failed.")
														return
													}

													edgeLogsEdit.SetText(edgeLogsEdit.Text() + "\r\nJob queued: " + resp.JobID + "\r\nMonitoring progress...\r\n")
													s.monitorProvisionJob(resp.JobID, edgeLogsEdit)
												},
											},
											PushButton{
												Text: "Clear Form",
												OnClicked: func() {
													edgeTokenEdit.SetText("")
													edgeAcctEdit.SetText("")
													edgeScriptEdit.SetText("luminet-edge-relay")
													edgeHostEdit.SetText("")
													edgePortEdit.SetText("10888")
													if edgeTypeCombo != nil {
														_ = edgeTypeCombo.SetCurrentIndex(0)
													}
													edgeUuidEdit.SetText("")
													edgeD1BindingEdit.SetText("")
													edgeD1DbIDEdit.SetText("")
													edgeCamouflageEdit.SetText("https://ubuntu.com")
													edgeLogsEdit.SetText("")
												},
											},
										},
									},
								},
							},
							GroupBox{
								Title:  "Deployment logs",
								Layout: VBox{},
								Children: []Widget{
									TextEdit{AssignTo: &edgeLogsEdit, ReadOnly: true, VScroll: true},
								},
							},
						},
					},
				},
			},
		},
	}
}

func (s *nativeShell) monitorProvisionJob(jobID string, logEdit *walk.TextEdit) {
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			var job struct {
				ID       string `json:"id"`
				Status   string `json:"status"`
				Progress int    `json:"progress"`
				Results  string `json:"results"`
				Error    string `json:"error"`
			}
			err := s.getJSON("/api/jobs/"+jobID, &job)
			if err != nil {
				s.appendLog("Failed to query job: " + err.Error())
				return
			}

			if job.Results != "" {
				var res map[string]string
				if err := json.Unmarshal([]byte(job.Results), &res); err == nil {
					if logs, ok := res["logs"]; ok {
						s.mw.Synchronize(func() {
							logEdit.SetText(logs)
						})
					}
				}
			}

			if job.Status == "completed" || job.Status == "failed" || job.Status == "cancelled" {
				s.mw.Synchronize(func() {
					if job.Status == "completed" {
						s.setStatus("Deployment job completed successfully!")
					} else if job.Status == "failed" {
						s.setStatus("Deployment job failed: " + job.Error)
						logEdit.SetText(logEdit.Text() + "\r\n[ERROR] " + job.Error)
					} else {
						s.setStatus("Deployment job cancelled.")
					}
				})
				return
			}
		}
	}()
}
