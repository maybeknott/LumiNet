//go:build !windows

package bridge

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func mapMemory(size int) ([]byte, error) {
	data, err := unix.Mmap(-1, 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_ANON)
	if err != nil {
		return nil, fmt.Errorf("mmap failed: %w", err)
	}
	return data, nil
}

func unmapMemory(data []byte) error {
	return unix.Munmap(data)
}
