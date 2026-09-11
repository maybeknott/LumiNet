package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/integrations/provision"
	"github.com/maybeknott/luminet/internal/workflows/jobs"
)

type VpsProvisionRequest struct {
	IP               string `json:"ip" binding:"required"`
	SSHUser          string `json:"ssh_user"`
	SSHPassword      string `json:"ssh_password"`
	SSHKey           string `json:"ssh_key"`
	SSHHostKeySHA256 string `json:"ssh_host_key_sha256" binding:"required"`
	Domain           string `json:"domain"`
	CFToken          string `json:"cf_token"`
	CFAccountID      string `json:"cf_account_id"`
	ThreeXUIImage    string `json:"three_xui_image" binding:"required"`
	PostgresImage    string `json:"postgres_image" binding:"required"`
	AlpineImage      string `json:"alpine_image" binding:"required"`
	TorAPKVersion    string `json:"tor_apk_version" binding:"required"`
}

type EdgeDeployRequest struct {
	CFToken           string `json:"cf_token" binding:"required"`
	CFAccountID       string `json:"cf_account_id" binding:"required"`
	ScriptName        string `json:"script_name"`
	TargetHost        string `json:"target_host"`
	TargetPort        int    `json:"target_port"`
	UUID              string `json:"uuid"`
	Type              string `json:"type"` // "relay" or "vless"
	D1DatabaseBinding string `json:"d1_database_binding"`
	D1DatabaseID      string `json:"d1_database_id"`
	CamouflageHost    string `json:"camouflage_host"`
}

// StartVpsProvision handles POST /api/provision/vps
func (s *Server) StartVpsProvision(c *gin.Context) {
	var req VpsProvisionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	cfg := provision.VpsConfig{
		IP: req.IP, SSHUser: req.SSHUser, SSHPassword: req.SSHPassword, SSHKey: req.SSHKey,
		SSHHostKeySHA256: req.SSHHostKeySHA256, Domain: req.Domain, CFToken: req.CFToken,
		CFAccountID: req.CFAccountID, ThreeXUIImage: req.ThreeXUIImage,
		PostgresImage: req.PostgresImage, AlpineImage: req.AlpineImage, TorAPKVersion: req.TorAPKVersion,
	}
	jobID, err := s.createAndStartJob(jobs.VpsProvisionIntent{Config: cfg})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"job_id": jobID, "status": "started"})
}

// StartEdgeDeploy handles POST /api/provision/worker
func (s *Server) StartEdgeDeploy(c *gin.Context) {
	var req EdgeDeployRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Type == "" {
		req.Type = "relay"
	}
	if req.Type == "relay" {
		if req.TargetHost == "" || req.TargetPort == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "target_host and target_port are required for relay type"})
			return
		}
	} else if req.Type == "vless" {
		if req.UUID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "uuid is required for vless type"})
			return
		}
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid type, must be 'relay' or 'vless'"})
		return
	}
	cfg := provision.EdgeConfig{CFToken: req.CFToken, CFAccountID: req.CFAccountID, ScriptName: req.ScriptName, TargetHost: req.TargetHost, TargetPort: req.TargetPort, UUID: req.UUID, Type: req.Type, D1DatabaseBinding: req.D1DatabaseBinding, D1DatabaseID: req.D1DatabaseID, CamouflageHost: req.CamouflageHost}
	jobID, err := s.createAndStartJob(jobs.EdgeDeployIntent{Config: cfg})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"job_id": jobID, "status": "started"})
}

type VLESSDevcontainerRequest struct {
	UUID            string `json:"uuid" binding:"required"`
	XrayVersion     string `json:"xray_version" binding:"required"`
	BaseImage       string `json:"base_image" binding:"required"`
	XraySHA256AMD64 string `json:"xray_sha256_amd64" binding:"required"`
	XraySHA256ARM64 string `json:"xray_sha256_arm64" binding:"required"`
	Port            int    `json:"port"`
	Path            string `json:"path"`
	Mode            string `json:"mode"`
}

// GenerateVLESSDevcontainer handles a read-only deployment-template request.
// It returns files for the caller to review/export and never performs a remote
// mutation, build, or deployment.
func (s *Server) GenerateVLESSDevcontainer(c *gin.Context) {
	var req VLESSDevcontainerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	bundle, err := provision.GenerateVLESSDevcontainer(provision.VLESSDevcontainerSpec{
		UUID: req.UUID, XrayVersion: req.XrayVersion, BaseImage: req.BaseImage,
		XraySHA256AMD64: req.XraySHA256AMD64, XraySHA256ARM64: req.XraySHA256ARM64,
		Port: req.Port, Path: req.Path, Mode: req.Mode,
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, bundle)
}
