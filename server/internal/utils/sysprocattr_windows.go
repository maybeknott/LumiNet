//go:build windows

package utils

import "syscall"

// GetDaemonSysProcAttr returns SysProcAttr for running background daemons on Windows.
func GetDaemonSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
	}
}

// GetHideWindowSysProcAttr returns SysProcAttr to execute commands without showing windows on Windows.
func GetHideWindowSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		HideWindow: true,
	}
}
