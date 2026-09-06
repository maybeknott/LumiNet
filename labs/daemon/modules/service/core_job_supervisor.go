package service

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// SupervisedProcess describes a background proxy core managed by the supervisor.
type SupervisedProcess struct {
	PID       int
	Command   string
	StartTime time.Time
	Cmd       *exec.Cmd
}

// CoreJobSupervisor guarantees that all spawned child proxy processes (sing-box, Xray, etc.)
// are tracked and cleanly reaped on daemon exit, preventing orphan core leaks.
// On Windows, it integrates with Win32 Job Object limits (JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE).
// On Unix, it coordinates process group termination.
type CoreJobSupervisor struct {
	mu        sync.RWMutex
	processes map[int]*SupervisedProcess
	disposed  atomic.Bool
	jobHandle uintptr
}

// NewCoreJobSupervisor initializes a new supervisor instance.
func NewCoreJobSupervisor() *CoreJobSupervisor {
	sup := &CoreJobSupervisor{
		processes: make(map[int]*SupervisedProcess),
	}
	sup.initPlatformJob()
	return sup
}

// RegisterProcess registers a started exec.Cmd process into the supervisor.
func (s *CoreJobSupervisor) RegisterProcess(cmd *exec.Cmd) error {
	if s.disposed.Load() {
		return fmt.Errorf("core job supervisor is disposed")
	}
	if cmd == nil || cmd.Process == nil {
		return fmt.Errorf("nil process cannot be registered")
	}

	pid := cmd.Process.Pid
	proc := &SupervisedProcess{
		PID:       pid,
		Command:   cmd.Path,
		StartTime: time.Now(),
		Cmd:       cmd,
	}

	s.mu.Lock()
	s.processes[pid] = proc
	s.mu.Unlock()

	s.assignPIDToJob(pid)
	return nil
}

// RegisterPID registers an existing PID by integer.
func (s *CoreJobSupervisor) RegisterPID(pid int, commandName string) error {
	if s.disposed.Load() {
		return fmt.Errorf("core job supervisor is disposed")
	}
	if pid <= 0 {
		return fmt.Errorf("invalid pid: %d", pid)
	}

	proc := &SupervisedProcess{
		PID:       pid,
		Command:   commandName,
		StartTime: time.Now(),
	}

	s.mu.Lock()
	s.processes[pid] = proc
	s.mu.Unlock()

	s.assignPIDToJob(pid)
	return nil
}

// UnregisterPID removes a normally exited PID from tracking.
func (s *CoreJobSupervisor) UnregisterPID(pid int) {
	s.mu.Lock()
	delete(s.processes, pid)
	s.mu.Unlock()
}

// ActivePIDs returns a snapshot of currently tracked child PIDs.
func (s *CoreJobSupervisor) ActivePIDs() []int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	pids := make([]int, 0, len(s.processes))
	for pid := range s.processes {
		pids = append(pids, pid)
	}
	return pids
}

// TerminateAll stops all registered child processes gracefully, then forcefully if needed.
func (s *CoreJobSupervisor) TerminateAll(timeout time.Duration) []error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var errs []error
	for pid, proc := range s.processes {
		if proc.Cmd != nil && proc.Cmd.Process != nil {
			// Attempt graceful interrupt first
			_ = proc.Cmd.Process.Signal(os.Interrupt)
		} else {
			p, err := os.FindProcess(pid)
			if err == nil {
				_ = p.Signal(os.Interrupt)
			}
		}
	}

	// Wait briefly or force kill
	done := make(chan struct{})
	go func() {
		time.Sleep(timeout)
		close(done)
	}()

	<-done

	for pid, proc := range s.processes {
		if proc.Cmd != nil && proc.Cmd.Process != nil {
			if err := proc.Cmd.Process.Kill(); err != nil && !isProcessAlreadyTerminated(err) {
				errs = append(errs, fmt.Errorf("kill pid %d failed: %w", pid, err))
			}
		} else {
			p, err := os.FindProcess(pid)
			if err == nil {
				if err := p.Kill(); err != nil && !isProcessAlreadyTerminated(err) {
					errs = append(errs, fmt.Errorf("kill pid %d failed: %w", pid, err))
				}
			}
		}
	}

	s.processes = make(map[int]*SupervisedProcess)
	return errs
}

// Close disposes the supervisor and terminates the underlying OS job object.
func (s *CoreJobSupervisor) Close() error {
	if s.disposed.Swap(true) {
		return nil
	}
	s.TerminateAll(500 * time.Millisecond)
	s.closePlatformJob()
	return nil
}

func isProcessAlreadyTerminated(err error) bool {
	if err == nil {
		return true
	}
	return os.IsPermission(err) || err == os.ErrProcessDone || err == syscall.ESRCH
}

// Platform-specific Job Object integration
func (s *CoreJobSupervisor) initPlatformJob() {
	if runtime.GOOS != "windows" {
		return
	}
	s.initWindowsJob()
}

func (s *CoreJobSupervisor) assignPIDToJob(pid int) {
	if runtime.GOOS != "windows" || s.jobHandle == 0 {
		return
	}
	s.assignWindowsJobPID(pid)
}

func (s *CoreJobSupervisor) closePlatformJob() {
	if runtime.GOOS != "windows" || s.jobHandle == 0 {
		return
	}
	s.closeWindowsJob()
}
