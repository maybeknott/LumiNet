package system

import (
	"io"
	"os"
	"path/filepath"

	"golang.org/x/mobile/asset"
)

// NewFileReader checks if the requested file exists in the standard filesystem;
// if it does not, it splits the filename and loads it directly from Android assets
// using the mobile asset package. This avoids raw file write trails on mobile devices.
var NewFileReader = func(path string) (io.ReadCloser, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		_, file := filepath.Split(path)
		return asset.Open(file)
	}
	return os.Open(path)
}
