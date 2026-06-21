//go:build !linux && !android

package system

func setSocketMark(fd int, mark int) error {
	return nil // no-op on non-Linux platforms
}
