// Package store implements local SQLite schema migrations, connection bootstrapping, and persistence interfaces.
package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// DB represents a connection wrapper to the persistent SQLite instance.
type DB struct {
	conn *sql.DB
}

// Store is an alias for DB to support unified package referencing across modules.
type Store = DB

// OpenDB opens a connection to the SQLite database specified by the directory filepath.
func OpenDB(dbPath string) (*DB, error) {
	// Ensure parent directory exists
	dir := filepath.Dir(dbPath)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create db directory: %w", err)
		}
	}

	// Open connection with sqlite3 driver
	conn, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	// Configure connection pool parameters to avoid database locking/busy bugs and race conditions
	conn.SetMaxOpenConns(1) // Single writer/reader connection prevents SQLite lock contention
	conn.SetMaxIdleConns(1)
	conn.SetConnMaxLifetime(time.Hour)

	db := &DB{conn: conn}

	// Enable WAL (Write-Ahead Logging) mode for improved concurrent performance
	if _, err := conn.Exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;"); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to configure WAL mode: %w", err)
	}

	return db, nil
}

// Migrate executes standard SQL schema migrations for configuration, events, profiles, and job entries.
func (d *DB) Migrate() error {
	migrations := []string{
		// Jobs table
		`CREATE TABLE IF NOT EXISTS jobs (
			job_id TEXT PRIMARY KEY,
			type TEXT NOT NULL,
			status TEXT NOT NULL,
			progress INTEGER NOT NULL,
			created_at INTEGER NOT NULL,
			started_at INTEGER,
			completed_at INTEGER,
			config TEXT,
			results TEXT,
			error TEXT
		);`,

		// Probe results table
		`CREATE TABLE IF NOT EXISTS results (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			job_id TEXT NOT NULL,
			target TEXT NOT NULL,
			ip TEXT,
			port INTEGER,
			success INTEGER NOT NULL,
			latency_ms REAL NOT NULL,
			error TEXT,
			timestamp INTEGER NOT NULL,
			metadata TEXT,
			FOREIGN KEY(job_id) REFERENCES jobs(job_id) ON DELETE CASCADE
		);`,

		// Scan profiles table
		`CREATE TABLE IF NOT EXISTS profiles (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT UNIQUE NOT NULL,
			timeout_ms INTEGER NOT NULL,
			max_concurrent INTEGER NOT NULL,
			rate_limit_pps INTEGER NOT NULL,
			retry_count INTEGER NOT NULL,
			adaptive_rate INTEGER NOT NULL,
			ipv6 INTEGER NOT NULL,
			timestamp INTEGER NOT NULL
		);`,

		// System history/event logs table
		`CREATE TABLE IF NOT EXISTS history (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			category TEXT NOT NULL,
			message TEXT NOT NULL,
			level TEXT NOT NULL,
			timestamp INTEGER NOT NULL
		);`,

		// Covert tracking links table
		`CREATE TABLE IF NOT EXISTS covert_links (
			link_id TEXT PRIMARY KEY,
			label TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			hits INTEGER DEFAULT 0
		);`,

		// Covert tracking visits table
		`CREATE TABLE IF NOT EXISTS covert_visits (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp INTEGER NOT NULL,
			ip TEXT NOT NULL,
			country TEXT,
			country_code TEXT,
			region TEXT,
			city TEXT,
			latitude REAL,
			longitude REAL,
			isp TEXT,
			browser TEXT,
			os TEXT,
			device TEXT,
			user_agent TEXT,
			referrer TEXT,
			language TEXT,
			link_id TEXT,
			FOREIGN KEY(link_id) REFERENCES covert_links(link_id) ON DELETE SET NULL
		);`,
	}

	for _, query := range migrations {
		if _, err := d.conn.Exec(query); err != nil {
			return fmt.Errorf("migration query failed: %w", err)
		}
	}

	return nil
}

// Conn returns the raw database connection object.
func (d *DB) Conn() *sql.DB {
	return d.conn
}

// Close closes the database connection.
func (d *DB) Close() error {
	if d.conn != nil {
		return d.conn.Close()
	}
	return nil
}
