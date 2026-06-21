//go:build windows

package system

import "io"

func createRealOrMockDevice(name string) (io.ReadWriteCloser, error) {
	return newWintunDevice(name)
}
