package geoip

import (
	"errors"
	"os"
	"path/filepath"
)

// GeoIPLoader checks and loads local GeoIP databases.
type GeoIPLoader struct {
	DatabasePath string
}

// NewGeoIPLoader creates a new database loader.
func NewGeoIPLoader(dbPath string) *GeoIPLoader {
	return &GeoIPLoader{DatabasePath: dbPath}
}

// VerifyDatabase checks if the local GeoIP database is present and readable.
func (l *GeoIPLoader) VerifyDatabase() error {
	if l.DatabasePath == "" {
		return errors.New("empty database path")
	}

	info, err := os.Stat(l.DatabasePath)
	if err != nil {
		return err
	}

	if info.IsDir() {
		return errors.New("path points to a directory, not a file")
	}

	if info.Size() == 0 {
		return errors.New("database file is empty")
	}

	return nil
}

// GetDatabaseType returns the database format extension (.mmdb or .dat).
func (l *GeoIPLoader) GetDatabaseType() string {
	return filepath.Ext(l.DatabasePath)
}
