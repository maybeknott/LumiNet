//go:build !windows

package durablefile

import "os"

func platformReplace(source, target string) error {
	return os.Rename(source, target)
}

func syncDirectory(dir string) error {
	file, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}
