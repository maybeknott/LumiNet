//go:build windows

package durablefile

import "golang.org/x/sys/windows"

const (
	moveFileReplaceExisting = 0x1
	moveFileWriteThrough    = 0x8
)

func platformReplace(source, target string) error {
	from, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, moveFileReplaceExisting|moveFileWriteThrough)
}

// MoveFileEx with MOVEFILE_WRITE_THROUGH does not return until the move has
// been flushed to disk. Windows does not expose a portable directory-fsync
// analogue through os.File, so there is no second directory handle to flush.
func syncDirectory(string) error {
	return nil
}
