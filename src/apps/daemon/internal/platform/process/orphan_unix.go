//go:build !windows

package process

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// probeProcess inspects /proc on Linux. Non-Linux Unix falls back to ps.
func probeProcess(pid int) (bool, string, error) {
	cmdlineBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		if os.IsNotExist(err) {
			// /proc itself is absent on Darwin/BSD, while a missing Linux PID also
			// lands here. Probe with ps so both cases remain correct.
			return probeProcessPS(pid)
		}
		return probeProcessPS(pid)
	}
	return true, trimProcArgv(string(cmdlineBytes)), nil
}

func trimProcArgv(raw string) string {
	return strings.TrimSpace(strings.ReplaceAll(raw, "\x00", " "))
}

func runCapture(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	output, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if ctx.Err() != nil {
		return string(output), ctx.Err()
	}
	return string(output), err
}

func probeProcessPS(pid int) (bool, string, error) {
	out, err := runCapture(10*time.Second, "ps", "-p", fmt.Sprint(pid), "-o", "command=")
	if err != nil {
		if strings.Contains(strings.ToLower(out), "no process") || strings.TrimSpace(out) == "" {
			return false, "", nil
		}
		return false, "", err
	}
	if strings.TrimSpace(out) == "" {
		return false, "", nil
	}
	return true, strings.TrimSpace(out), nil
}

// killTree kills the process group when available, else the single PID.
func killTree(ctx context.Context, pid int, timeout time.Duration) error {
	done := make(chan error, 1)
	go func() {
		if pgid, pgErr := syscall.Getpgid(pid); pgErr == nil && pgid > 0 {
			if err := syscall.Kill(-pgid, syscall.SIGKILL); err == nil {
				done <- nil
				return
			}
		}
		done <- syscall.Kill(pid, syscall.SIGKILL)
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(timeout):
		return fmt.Errorf("kill timed out after %s", timeout)
	}
}
