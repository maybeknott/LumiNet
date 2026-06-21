// Package history manages persistent recording, searching, and clearing of logs, diagnostics, and general system event occurrences.
package history

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// Event represents a single historical record log entry.
type Event struct {
	ID        int64     `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Category  string    `json:"category"` // e.g. "dns", "ddns", "alert", "plugin"
	Level     string    `json:"level"`    // e.g. "info", "warning", "error"
	Message   string    `json:"message"`
	Metadata  string    `json:"metadata"` // JSON field
}

// Store handles operations writing history into the local SQLite database.
type Store struct {
	db *sql.DB
}

// NewStore initializes a Store with the provided SQLite database connection.
func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

// AddRecord stores a system or application Event in the history repository.
func (s *Store) AddRecord(ctx context.Context, event *Event) error {
	query := `
		INSERT INTO history (category, message, level, timestamp)
		VALUES (?, ?, ?, ?)
	`
	_, err := s.db.ExecContext(ctx, query,
		event.Category,
		event.Message,
		event.Level,
		event.Timestamp.Unix(),
	)
	if err != nil {
		return fmt.Errorf("AddRecord: %w", err)
	}
	return nil
}

// QueryRecords fetches events matching optional criteria like category or level, with support for pagination.
func (s *Store) QueryRecords(ctx context.Context, category string, limit, offset int) ([]*Event, error) {
	var query string
	var args []interface{}

	if category != "" {
		query = `SELECT id, category, message, level, timestamp FROM history WHERE category = ? ORDER BY timestamp DESC LIMIT ? OFFSET ?`
		args = []interface{}{category, limit, offset}
	} else {
		query = `SELECT id, category, message, level, timestamp FROM history ORDER BY timestamp DESC LIMIT ? OFFSET ?`
		args = []interface{}{limit, offset}
	}

	if limit <= 0 {
		// Replace LIMIT with a large number
		if category != "" {
			query = `SELECT id, category, message, level, timestamp FROM history WHERE category = ? ORDER BY timestamp DESC`
			args = []interface{}{category}
		} else {
			query = `SELECT id, category, message, level, timestamp FROM history ORDER BY timestamp DESC`
			args = nil
		}
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("QueryRecords: %w", err)
	}
	defer rows.Close()

	var events []*Event
	for rows.Next() {
		var e Event
		var ts int64
		if err := rows.Scan(&e.ID, &e.Category, &e.Message, &e.Level, &ts); err != nil {
			continue
		}
		e.Timestamp = time.Unix(ts, 0)
		events = append(events, &e)
	}
	return events, rows.Err()
}

// ClearRecords deletes all event records before the specified timestamp cutoff.
func (s *Store) ClearRecords(ctx context.Context, before time.Time) error {
	query := `DELETE FROM history WHERE timestamp < ?`
	_, err := s.db.ExecContext(ctx, query, before.Unix())
	if err != nil {
		return fmt.Errorf("ClearRecords: %w", err)
	}
	return nil
}
