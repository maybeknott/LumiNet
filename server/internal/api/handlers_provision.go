package api

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/jobs"
	"github.com/maybeknott/luminet/internal/provision"
)

type VpsProvisionRequest struct {
	IP          string `json:"ip" binding:"required"`
	SSHUser     string `json:"ssh_user"`
	SSHPassword string `json:"ssh_password"`
	SSHKey      string `json:"ssh_key"`
	Domain      string `json:"domain"`
	CFToken     string `json:"cf_token"`
	CFAccountID string `json:"cf_account_id"`
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
		IP:          req.IP,
		SSHUser:     req.SSHUser,
		SSHPassword: req.SSHPassword,
		SSHKey:      req.SSHKey,
		Domain:      req.Domain,
		CFToken:     req.CFToken,
		CFAccountID: req.CFAccountID,
	}

	cfgBytes, _ := json.Marshal(cfg)
	jobID := s.jobManager.CreateJob(jobs.JobTypeVpsProvision, string(cfgBytes))
	if err := s.jobManager.StartJob(jobID); err != nil {
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

	cfg := provision.EdgeConfig{
		CFToken:           req.CFToken,
		CFAccountID:       req.CFAccountID,
		ScriptName:        req.ScriptName,
		TargetHost:        req.TargetHost,
		TargetPort:        req.TargetPort,
		UUID:              req.UUID,
		Type:              req.Type,
		D1DatabaseBinding: req.D1DatabaseBinding,
		D1DatabaseID:      req.D1DatabaseID,
		CamouflageHost:    req.CamouflageHost,
	}

	cfgBytes, _ := json.Marshal(cfg)
	jobID := s.jobManager.CreateJob(jobs.JobTypeEdgeDeploy, string(cfgBytes))
	if err := s.jobManager.StartJob(jobID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"job_id": jobID, "status": "started"})
}
