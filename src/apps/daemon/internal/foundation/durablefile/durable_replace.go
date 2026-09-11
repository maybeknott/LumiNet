package durablefile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Replace publishes data atomically and durably. The file data is flushed before
// publication and, on platforms that expose directory fsync, the containing
// directory is flushed after the rename so a power loss cannot resurrect the
// previous directory entry.
func Replace(path string, data []byte, mode os.FileMode) (err error) {
	dir := filepath.Dir(path)
	if dir == "" {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create parent directory: %w", err)
	}

	file, err := os.CreateTemp(dir, ".luminet-publish-*")
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	tmp := file.Name()
	published := false
	defer func() {
		if !published {
			_ = file.Close()
			_ = os.Remove(tmp)
		}
	}()

	if err := file.Chmod(mode); err != nil {
		return fmt.Errorf("set temporary file mode: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("write temporary file: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync temporary file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close temporary file: %w", err)
	}
	if err := platformReplace(tmp, path); err != nil {
		return fmt.Errorf("publish file: %w", err)
	}
	if err := syncDirectory(dir); err != nil {
		return fmt.Errorf("sync parent directory: %w", err)
	}
	published = true
	return nil
}

// Remove makes authoritative absence durable. Renaming to a same-directory
// tombstone first prevents a crash between unlink and directory flush from
// reviving an old authoritative pathname.
func Remove(path string) error {
	dir := filepath.Dir(path)
	if dir == "" {
		dir = "."
	}
	tomb, err := os.CreateTemp(dir, ".luminet-remove-*")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("create removal tombstone: %w", err)
	}
	tombPath := tomb.Name()
	if err := tomb.Close(); err != nil {
		_ = os.Remove(tombPath)
		return err
	}
	_ = os.Remove(tombPath)

	if err := platformReplace(path, tombPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("stage durable removal: %w", err)
	}
	if err := syncDirectory(dir); err != nil {
		return fmt.Errorf("sync staged removal: %w", err)
	}
	if err := os.Remove(tombPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove tombstone: %w", err)
	}
	if err := syncDirectory(dir); err != nil {
		return fmt.Errorf("sync completed removal: %w", err)
	}
	return nil
}
