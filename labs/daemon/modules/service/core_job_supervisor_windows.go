//go:build windows

package service

import (
	"syscall"
	"unsafe"
)

var (
	kernel32                     = syscall.NewLazyDLL("kernel32.dll")
	procCreateJobObjectW         = kernel32.NewProc("CreateJobObjectW")
	procSetInformationJobObject  = kernel32.NewProc("SetInformationJobObject")
	procAssignProcessToJobObject = kernel32.NewProc("AssignProcessToJobObject")
	procOpenProcess              = kernel32.NewProc("OpenProcess")
	procCloseHandle              = kernel32.NewProc("CloseHandle")
)

const (
	jobObjectExtendedLimitInformation = 9
	jobObjectLimitKillOnJobClose      = 0x00002000
	processSetQuota                   = 0x0100
	processTerminate                  = 0x0001
)

type ioCounters struct {
	ReadOperationCount  uint64
	WriteOperationCount uint64
	OtherOperationCount uint64
	ReadTransferCount   uint64
	WriteTransferCount  uint64
	OtherTransferCount  uint64
}

type jobobjectBasicLimitInformation struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}

type jobobjectExtendedLimitInformation struct {
	BasicLimitInformation jobobjectBasicLimitInformation
	IoInfo                ioCounters
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryLimit uintptr
	PeakJobMemoryLimit    uintptr
}

func (s *CoreJobSupervisor) initWindowsJob() {
	handle, _, _ := procCreateJobObjectW.Call(0, 0)
	if handle == 0 {
		return
	}

	var info jobobjectExtendedLimitInformation
	info.BasicLimitInformation.LimitFlags = jobObjectLimitKillOnJobClose

	ret, _, _ := procSetInformationJobObject.Call(
		handle,
		uintptr(jobObjectExtendedLimitInformation),
		uintptr(unsafe.Pointer(&info)),
		uintptr(unsafe.Sizeof(info)),
	)

	if ret == 0 {
		procCloseHandle.Call(handle)
		return
	}

	s.jobHandle = handle
}

func (s *CoreJobSupervisor) assignWindowsJobPID(pid int) {
	if s.jobHandle == 0 {
		return
	}

	hProcess, _, _ := procOpenProcess.Call(
		uintptr(processSetQuota|processTerminate),
		0,
		uintptr(pid),
	)
	if hProcess == 0 {
		return
	}
	defer procCloseHandle.Call(hProcess)

	procAssignProcessToJobObject.Call(s.jobHandle, hProcess)
}

func (s *CoreJobSupervisor) closeWindowsJob() {
	if s.jobHandle != 0 {
		procCloseHandle.Call(s.jobHandle)
		s.jobHandle = 0
	}
}
