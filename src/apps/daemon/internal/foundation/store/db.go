// Package store implements local SQLite schema migrations, connection bootstrapping, and persistence interfaces.
package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// DB represents a connection wrapper to the persistent SQLite instance.
type DB struct {
	conn *sql.DB
}

// Store is an alias for DB to support source compatibility.
// Deprecated: use DB.
type Store = DB

// OpenDB opens a connection to the SQLite database specified by filepath.
// Operational SQLite is not encrypted by this layer; filesystem privacy is
// therefore enforced explicitly and independently from the platform secret store.
func OpenDB(dbPath string) (*DB, error) {
	dir := filepath.Dir(dbPath)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("failed to create db directory: %w", err)
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			return nil, fmt.Errorf("failed to secure db directory: %w", err)
		}
	}

	// Pre-create (or tighten) the main DB file so its mode is not left to umask.
	file, err := os.OpenFile(dbPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("failed to create sqlite database privately: %w", err)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("failed to secure sqlite database: %w", err)
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("failed to close sqlite bootstrap file: %w", err)
	}

	conn, err := sql.Open("sqlite", dbPath+"?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	conn.SetMaxOpenConns(1)
	conn.SetMaxIdleConns(1)
	conn.SetConnMaxLifetime(time.Hour)

	return &DB{conn: conn}, nil
}

func (d *DB) Migrate() error {
	return ApplyMigrations(d.conn)
}

func (d *DB) Conn() *sql.DB {
	return d.conn
}

func (d *DB) Close() error {
	if d.conn != nil {
		return d.conn.Close()
	}
	return nil
}
