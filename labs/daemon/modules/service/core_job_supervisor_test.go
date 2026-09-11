package service

import (
	"os/exec"
	"runtime"
	"testing"
	"time"
)

func TestCoreJobSupervisorLifecycle(t *testing.T) {
	sup := NewCoreJobSupervisor()
	defer sup.Close()

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd.exe", "/c", "timeout /t 5 >nul")
	} else {
		cmd = exec.Command("sleep", "5")
	}

	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start child test process: %v", err)
	}

	pid := cmd.Process.Pid
	if err := sup.RegisterProcess(cmd); err != nil {
		t.Fatalf("failed to register process: %v", err)
	}

	pids := sup.ActivePIDs()
	if len(pids) != 1 || pids[0] != pid {
		t.Fatalf("expected active pids to contain %d, got %v", pid, pids)
	}

	// Terminate all
	errs := sup.TerminateAll(100 * time.Millisecond)
	if len(errs) > 0 {
		t.Logf("termination warnings: %v", errs)
	}

	pidsAfter := sup.ActivePIDs()
	if len(pidsAfter) != 0 {
		t.Fatalf("expected 0 active pids after TerminateAll, got %v", pidsAfter)
	}
}

func TestCoreJobSupervisorRegisterPID(t *testing.T) {
	sup := NewCoreJobSupervisor()
	defer sup.Close()

	if err := sup.RegisterPID(999999, "dummy_proxy_core"); err != nil {
		t.Fatalf("unexpected error registering PID: %v", err)
	}

	pids := sup.ActivePIDs()
	if len(pids) != 1 || pids[0] != 999999 {
		t.Fatalf("expected PID 999999 in list, got %v", pids)
	}

	sup.UnregisterPID(999999)
	if len(sup.ActivePIDs()) != 0 {
		t.Fatalf("expected empty PID list after unregister, got %v", sup.ActivePIDs())
	}
}
