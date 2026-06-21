// Package jobs implements a unified job controller for all async scan/test/diagnostic tasks.
// It manages job lifecycle (create, start, cancel, complete) with thread-safe state transitions.
package jobs

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/maybeknott/luminet/internal/store"
)

// JobStatus represents the current state of a job in its lifecycle.
type JobStatus string

const (
	// JobStatusQueued indicates the job is waiting to be started.
	JobStatusQueued JobStatus = "queued"
	// JobStatusRunning indicates the job is currently executing.
	JobStatusRunning JobStatus = "running"
	// JobStatusCompleted indicates the job has finished successfully.
	JobStatusCompleted JobStatus = "completed"
	// JobStatusFailed indicates the job terminated with an error.
	JobStatusFailed JobStatus = "failed"
	// JobStatusCancelled indicates the job was cancelled by the user.
	JobStatusCancelled JobStatus = "cancelled"
)

// JobType identifies the kind of task a job performs.
type JobType string

const (
	// JobTypeIcmpScan is an ICMP ping sweep job.
	JobTypeIcmpScan JobType = "icmp_scan"
	// JobTypePortScan is a TCP port scan job.
	JobTypePortScan JobType = "port_scan"
	// JobTypeDnsScan is a DNS resolution/scan job.
	JobTypeDnsScan JobType = "dns_scan"
	// JobTypeTlsScan is a TLS handshake scan job.
	JobTypeTlsScan JobType = "tls_scan"
	// JobTypeSniScan is an SNI blocking detection job.
	JobTypeSniScan JobType = "sni_scan"
	// JobTypeProxyTest is a proxy connectivity test job.
	JobTypeProxyTest JobType = "proxy_test"
	// JobTypeDiagnostic is a 6-phase diagnostic pipeline job.
	JobTypeDiagnostic JobType = "diagnostic"
	// JobTypeSpeedTest is a speed test job.
	JobTypeSpeedTest JobType = "speed_test"
	// JobTypeWgScan is a WireGuard endpoint probe job.
	JobTypeWgScan JobType = "wg_scan"
	// JobTypeCdnScan is a CDN IP sweep job.
	JobTypeCdnScan JobType = "cdn_scan"
	// JobTypeVpsProvision is a VPS SSH setup job.
	JobTypeVpsProvision JobType = "vps_provision"
	// JobTypeEdgeDeploy is a Cloudflare Worker edge deploy job.
	JobTypeEdgeDeploy JobType = "edge_deploy"
)

// Job represents a single async task managed by the JobManager.
type Job struct {
	// ID is the unique identifier for this job (UUID).
	ID string
	// Type identifies what kind of task this job performs.
	Type JobType
	// Status is the current lifecycle state.
	Status JobStatus
	// Progress is the completion percentage (0-100).
	Progress int
	// CreatedAt is when the job was created.
	CreatedAt time.Time
	// StartedAt is when the job started executing.
	StartedAt *time.Time
	// CompletedAt is when the job finished (success, failure, or cancellation).
	CompletedAt *time.Time
	// Config is the serialized job configuration (JSON).
	Config string
	// Results is the serialized job results (JSON), populated on completion.
	Results string
	// Error is the error message if the job failed.
	Error string
	// cancel is the function to call to cancel this job.
	cancel func()
	// mu protects mutable fields.
	mu sync.RWMutex
}

// clone returns a copy of the job with a clean, uncopied mutex.
// Assumes the caller has already locked the job's mutex for reading.
func (j *Job) clone() *Job {
	return &Job{
		ID:          j.ID,
		Type:        j.Type,
		Status:      j.Status,
		Progress:    j.Progress,
		CreatedAt:   j.CreatedAt,
		StartedAt:   j.StartedAt,
		CompletedAt: j.CompletedAt,
		Config:      j.Config,
		Results:     j.Results,
		Error:       j.Error,
	}
}

// JobFilter specifies criteria for filtering jobs in list operations.
type JobFilter struct {
	// Type filters jobs by type. Empty means all types.
	Type JobType
	// Status filters jobs by status. Empty means all statuses.
	Status JobStatus
	// Limit is the maximum number of jobs to return. 0 means no limit.
	Limit int
	// Offset is the number of jobs to skip for pagination.
	Offset int
}

// JobManager is the central controller for all async jobs. It maintains a
// thread-safe registry of jobs and coordinates their lifecycle.
type JobManager struct {
	// jobs is the map of job ID to Job.
	jobs map[string]*Job
	// mu protects the jobs map.
	mu sync.RWMutex
	// broadcaster is the optional event broadcaster for WebSocket notifications.
	broadcaster *Broadcaster
	// db is the database connection for persistence.
	db *store.DB
}

func generateUUID() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// NewJobManager creates a new JobManager, associating it with a database and hydrating jobs.
func NewJobManager(db *store.DB) *JobManager {
	m := &JobManager{
		jobs:        make(map[string]*Job),
		broadcaster: NewBroadcaster(),
		db:          db,
	}

	if db != nil {
		// Load terminal and recent jobs from DB
		records, err := db.ListJobRecords(context.Background(), 1000, 0)
		if err == nil {
			for _, r := range records {
				var status JobStatus
				switch r.Status {
				case "queued", "running":
					// queued/running jobs on boot are treated as failed since the server crashed/stopped
					status = JobStatusFailed
					r.Status = string(JobStatusFailed)
					r.Error = "server restarted"
					now := time.Now()
					r.CompletedAt = &now
					_ = db.SaveJobRecord(context.Background(), r)
				case "completed":
					status = JobStatusCompleted
				case "failed":
					status = JobStatusFailed
				case "cancelled":
					status = JobStatusCancelled
				default:
					status = JobStatusFailed
				}

				m.jobs[r.ID] = &Job{
					ID:          r.ID,
					Type:        JobType(r.Type),
					Status:      status,
					Progress:    r.Progress,
					CreatedAt:   r.CreatedAt,
					StartedAt:   r.StartedAt,
					CompletedAt: r.CompletedAt,
					Config:      r.Config,
					Results:     r.Results,
					Error:       r.Error,
				}
			}
		}
	}

	return m
}

// SetBroadcaster attaches an event broadcaster for publishing job events to WebSocket clients.
func (m *JobManager) SetBroadcaster(b *Broadcaster) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.broadcaster = b
}

func (m *JobManager) persistJob(job *Job) {
	if m.db == nil {
		return
	}
	job.mu.RLock()
	jr := &store.JobRecord{
		ID:          job.ID,
		Type:        string(job.Type),
		Status:      string(job.Status),
		Progress:    job.Progress,
		CreatedAt:   job.CreatedAt,
		StartedAt:   job.StartedAt,
		CompletedAt: job.CompletedAt,
		Config:      job.Config,
		Results:     job.Results,
		Error:       job.Error,
	}
	job.mu.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = m.db.SaveJobRecord(ctx, jr)
}

// CreateJob creates a new job with the given type and configuration.
// Returns the unique job ID. The job starts in Queued status.
func (m *JobManager) CreateJob(jobType JobType, config string) string {
	m.mu.Lock()
	id := generateUUID()
	job := &Job{
		ID:        id,
		Type:      jobType,
		Status:    JobStatusQueued,
		Progress:  0,
		CreatedAt: time.Now(),
		Config:    config,
	}
	m.jobs[id] = job
	m.mu.Unlock()

	m.persistJob(job)

	if m.broadcaster != nil {
		m.broadcaster.Publish(JobEvent{
			JobID:     id,
			Type:      "status_change",
			Data:      string(JobStatusQueued),
			Timestamp: time.Now(),
		})
	}

	return id
}

// StartJob transitions a job from Queued to Running and begins execution.
// Returns an error if the job doesn't exist or is not in Queued status.
func (m *JobManager) StartJob(id string) error {
	m.mu.Lock()
	job, exists := m.jobs[id]
	if !exists && m.db != nil {
		jr, err := m.db.GetJobRecord(context.Background(), id)
		if err == nil {
			job = &Job{
				ID:        jr.ID,
				Type:      JobType(jr.Type),
				Status:    JobStatus(jr.Status),
				Progress:  jr.Progress,
				CreatedAt: jr.CreatedAt,
				Config:    jr.Config,
			}
			m.jobs[id] = job
			exists = true
		}
	}
	if !exists {
		m.mu.Unlock()
		return fmt.Errorf("job not found: %s", id)
	}

	job.mu.Lock()
	if job.Status != JobStatusQueued {
		job.mu.Unlock()
		m.mu.Unlock()
		return fmt.Errorf("job is in status %s, cannot start", job.Status)
	}

	job.Status = JobStatusRunning
	now := time.Now()
	job.StartedAt = &now
	job.mu.Unlock()
	m.mu.Unlock()

	m.persistJob(job)

	if m.broadcaster != nil {
		m.broadcaster.Publish(JobEvent{
			JobID:     id,
			Type:      "status_change",
			Data:      string(JobStatusRunning),
			Timestamp: time.Now(),
		})
	}

	ctx, cancel := context.WithCancel(context.Background())
	job.mu.Lock()
	job.cancel = cancel
	job.mu.Unlock()

	go m.runJob(ctx, job)

	return nil
}

// CancelJob cancels a running or queued job.
// Returns an error if the job doesn't exist or is already completed.
func (m *JobManager) CancelJob(id string) error {
	m.mu.Lock()
	job, exists := m.jobs[id]
	if !exists && m.db != nil {
		jr, err := m.db.GetJobRecord(context.Background(), id)
		if err == nil {
			job = &Job{
				ID:        jr.ID,
				Type:      JobType(jr.Type),
				Status:    JobStatus(jr.Status),
				Progress:  jr.Progress,
				CreatedAt: jr.CreatedAt,
				Config:    jr.Config,
			}
			m.jobs[id] = job
			exists = true
		}
	}
	if !exists {
		m.mu.Unlock()
		return fmt.Errorf("job not found: %s", id)
	}

	job.mu.Lock()
	if job.Status == JobStatusCompleted || job.Status == JobStatusFailed || job.Status == JobStatusCancelled {
		job.mu.Unlock()
		m.mu.Unlock()
		return fmt.Errorf("job already finished with status %s", job.Status)
	}

	job.Status = JobStatusCancelled
	now := time.Now()
	job.CompletedAt = &now
	if job.cancel != nil {
		job.cancel()
	}
	job.mu.Unlock()
	// Evict from in-memory map to save memory
	delete(m.jobs, id)
	m.mu.Unlock()

	m.persistJob(job)

	if m.broadcaster != nil {
		m.broadcaster.Publish(JobEvent{
			JobID:     id,
			Type:      "status_change",
			Data:      string(JobStatusCancelled),
			Timestamp: time.Now(),
		})
	}

	return nil
}

// CompleteJob marks a job as completed with the given results.
func (m *JobManager) CompleteJob(id string, results string) error {
	m.mu.Lock()
	job, exists := m.jobs[id]
	if !exists {
		m.mu.Unlock()
		return fmt.Errorf("job not found: %s", id)
	}

	job.mu.Lock()
	if job.Status != JobStatusRunning {
		job.mu.Unlock()
		m.mu.Unlock()
		return fmt.Errorf("job not running (status: %s)", job.Status)
	}

	job.Status = JobStatusCompleted
	now := time.Now()
	job.CompletedAt = &now
	job.Results = results
	job.mu.Unlock()
	// Evict from in-memory map to save memory
	delete(m.jobs, id)
	m.mu.Unlock()

	m.persistJob(job)

	if m.broadcaster != nil {
		m.broadcaster.Publish(JobEvent{
			JobID:     id,
			Type:      "status_change",
			Data:      string(JobStatusCompleted),
			Timestamp: time.Now(),
		})
		m.broadcaster.Publish(JobEvent{
			JobID:     id,
			Type:      "result",
			Data:      results,
			Timestamp: time.Now(),
		})
	}

	return nil
}

// FailJob marks a job as failed with the given error message.
func (m *JobManager) FailJob(id string, errMsg string) error {
	m.mu.Lock()
	job, exists := m.jobs[id]
	if !exists {
		m.mu.Unlock()
		return fmt.Errorf("job not found: %s", id)
	}

	job.mu.Lock()
	if job.Status != JobStatusRunning {
		job.mu.Unlock()
		m.mu.Unlock()
		return fmt.Errorf("job not running (status: %s)", job.Status)
	}

	job.Status = JobStatusFailed
	now := time.Now()
	job.CompletedAt = &now
	job.Error = errMsg
	job.mu.Unlock()
	// Evict from in-memory map to save memory
	delete(m.jobs, id)
	m.mu.Unlock()

	m.persistJob(job)

	if m.broadcaster != nil {
		m.broadcaster.Publish(JobEvent{
			JobID:     id,
			Type:      "status_change",
			Data:      string(JobStatusFailed),
			Timestamp: time.Now(),
		})
		m.broadcaster.Publish(JobEvent{
			JobID:     id,
			Type:      "error",
			Data:      errMsg,
			Timestamp: time.Now(),
		})
	}

	return nil
}

// UpdateProgress updates the progress percentage of a running job.
func (m *JobManager) UpdateProgress(id string, progress int) error {
	m.mu.RLock()
	job, exists := m.jobs[id]
	m.mu.RUnlock()
	if !exists {
		return fmt.Errorf("job not found: %s", id)
	}

	job.mu.Lock()
	if job.Status != JobStatusRunning {
		job.mu.Unlock()
		return fmt.Errorf("job not running (status: %s)", job.Status)
	}
	job.Progress = progress
	job.mu.Unlock()

	m.persistJob(job)

	if m.broadcaster != nil {
		m.broadcaster.Publish(JobEvent{
			JobID:     id,
			Type:      "job_progress",
			Data:      progress,
			Timestamp: time.Now(),
		})
	}

	return nil
}

// GetJob returns a copy of the job with the given ID.
// Returns nil and an error if the job doesn't exist.
func (m *JobManager) GetJob(id string) (*Job, error) {
	m.mu.RLock()
	job, exists := m.jobs[id]
	m.mu.RUnlock()
	if exists {
		job.mu.RLock()
		defer job.mu.RUnlock()
		return job.clone(), nil
	}

	if m.db != nil {
		jr, err := m.db.GetJobRecord(context.Background(), id)
		if err == nil {
			var status JobStatus
			switch jr.Status {
			case "queued":
				status = JobStatusQueued
			case "running":
				status = JobStatusRunning
			case "completed":
				status = JobStatusCompleted
			case "failed":
				status = JobStatusFailed
			case "cancelled":
				status = JobStatusCancelled
			default:
				status = JobStatusFailed
			}
			j := &Job{
				ID:          jr.ID,
				Type:        JobType(jr.Type),
				Status:      status,
				Progress:    jr.Progress,
				CreatedAt:   jr.CreatedAt,
				StartedAt:   jr.StartedAt,
				CompletedAt: jr.CompletedAt,
				Config:      jr.Config,
				Results:     jr.Results,
				Error:       jr.Error,
			}
			return j, nil
		}
	}

	return nil, fmt.Errorf("job not found: %s", id)
}

// ListJobs returns jobs matching the given filter criteria.
func (m *JobManager) ListJobs(filter JobFilter) []*Job {
	if m.db != nil {
		limit := filter.Limit
		if limit <= 0 {
			limit = 1000
		}
		offset := filter.Offset
		if offset < 0 {
			offset = 0
		}
		records, err := m.db.ListJobRecords(context.Background(), limit, offset)
		if err == nil {
			var list []*Job
			for _, r := range records {
				j := &Job{
					ID:          r.ID,
					Type:        JobType(r.Type),
					Status:      JobStatus(r.Status),
					Progress:    r.Progress,
					CreatedAt:   r.CreatedAt,
					StartedAt:   r.StartedAt,
					CompletedAt: r.CompletedAt,
					Config:      r.Config,
					Results:     r.Results,
					Error:       r.Error,
				}
				if filter.Type != "" && j.Type != filter.Type {
					continue
				}
				if filter.Status != "" && j.Status != filter.Status {
					continue
				}
				list = append(list, j)
			}
			return list
		}
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	var filtered []*Job
	for _, job := range m.jobs {
		job.mu.RLock()
		match := true
		if filter.Type != "" && job.Type != filter.Type {
			match = false
		}
		if filter.Status != "" && job.Status != filter.Status {
			match = false
		}
		job.mu.RUnlock()

		if match {
			job.mu.RLock()
			copied := job.clone()
			filtered = append(filtered, copied)
			job.mu.RUnlock()
		}
	}

	// Sort filtered by CreatedAt descending (newest first)
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].CreatedAt.After(filtered[j].CreatedAt)
	})

	// Apply Offset and Limit
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}
	if offset >= len(filtered) {
		return []*Job{}
	}

	limit := filter.Limit
	if limit <= 0 {
		return filtered[offset:]
	}

	end := offset + limit
	if end > len(filtered) {
		end = len(filtered)
	}

	return filtered[offset:end]
}

// ClearHistory deletes all completed, failed, and cancelled jobs from memory and SQLite database.
func (m *JobManager) ClearHistory() error {
	m.mu.Lock()
	// Clear all terminal jobs from memory
	for id, job := range m.jobs {
		job.mu.RLock()
		status := job.Status
		job.mu.RUnlock()
		if status == JobStatusCompleted || status == JobStatusFailed || status == JobStatusCancelled {
			delete(m.jobs, id)
		}
	}
	m.mu.Unlock()

	// Clear from database
	if m.db != nil {
		_, err := m.db.Conn().Exec("DELETE FROM jobs")
		return err
	}
	return nil
}

// GetActiveJobs returns all jobs currently in running or queued state.
func (m *JobManager) GetActiveJobs() []*Job {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var active []*Job
	for _, job := range m.jobs {
		job.mu.RLock()
		if job.Status == JobStatusQueued || job.Status == JobStatusRunning {
			copied := job.clone()
			active = append(active, copied)
		}
		job.mu.RUnlock()
	}
	return active
}

// GetBroadcaster returns the broadcaster attached to the job manager.
func (m *JobManager) GetBroadcaster() *Broadcaster {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.broadcaster
}

// runJob handles async background FFI calls to Rust core based on JobType
func (m *JobManager) runJob(ctx context.Context, job *Job) {
	m.UpdateProgress(job.ID, 5)

	select {
	case <-ctx.Done():
		m.CancelJob(job.ID)
		return
	default:
	}

	var results interface{}
	var err error

	switch job.Type {
	case JobTypeIcmpScan:
		results, err = m.runIcmpScan(ctx, job)
	case JobTypePortScan:
		results, err = m.runPortScan(ctx, job)
	case JobTypeDnsScan:
		results, err = m.runDnsScan(ctx, job)
	case JobTypeTlsScan:
		results, err = m.runTlsScan(ctx, job)
	case JobTypeSniScan:
		results, err = m.runSniScan(ctx, job)
	case JobTypeProxyTest:
		results, err = m.runProxyTest(ctx, job)
	case JobTypeSpeedTest:
		results, err = m.runSpeedTest(ctx, job)
	case JobTypeDiagnostic:
		results, err = m.runDiagnostic(ctx, job)
	case JobTypeWgScan:
		results, err = m.runWgScan(ctx, job)
	case JobTypeCdnScan:
		results, err = m.runCdnScan(ctx, job)
	case JobTypeVpsProvision:
		results, err = m.runVpsProvision(ctx, job)
	case JobTypeEdgeDeploy:
		results, err = m.runEdgeDeploy(ctx, job)
	default:
		err = fmt.Errorf("unsupported job type: %s", job.Type)
	}

	if err != nil {
		m.FailJob(job.ID, err.Error())
		return
	}

	resJSON, _ := json.Marshal(results)
	m.UpdateProgress(job.ID, 100)
	m.CompleteJob(job.ID, string(resJSON))
}
