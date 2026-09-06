//go:build !windows

package service

func (s *CoreJobSupervisor) initWindowsJob() {}
func (s *CoreJobSupervisor) assignWindowsJobPID(pid int) {}
func (s *CoreJobSupervisor) closeWindowsJob() {}
