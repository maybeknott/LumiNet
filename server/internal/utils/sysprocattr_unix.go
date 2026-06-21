//go:build !windows

package utils

import "syscall"

// GetDaemonSysProcAttr returns SysProcAttr for running background daemons on non-Windows.
func GetDaemonSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Setpgid: true,
	}
}

// GetHideWindowSysProcAttr returns SysProcAttr to execute commands on non-Windows.
func GetHideWindowSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{}
}
