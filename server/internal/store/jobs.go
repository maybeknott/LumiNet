// Package store implements local SQLite schema migrations, connection bootstrapping, and persistence interfaces.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// JobRecord represents a database row of a background scan/test/diagnostic job.
type JobRecord struct {
	ID          string     `json:"id"`
	Type        string     `json:"type"`
	Status      string     `json:"status"`
	Progress    int        `json:"progress"`
	CreatedAt   time.Time  `json:"created_at"`
	StartedAt   *time.Time `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at"`
	Config      string     `json:"config"`
	Results     string     `json:"results"`
	Error       string     `json:"error"`
}

// SaveJobRecord upserts a job execution record in the SQLite store database.
func (d *DB) SaveJobRecord(ctx context.Context, jr *JobRecord) error {
	query := `
		INSERT INTO jobs (job_id, type, status, progress, created_at, started_at, completed_at, config, results, error)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(job_id) DO UPDATE SET
			status = excluded.status,
			progress = excluded.progress,
			started_at = excluded.started_at,
			completed_at = excluded.completed_at,
			results = excluded.results,
			error = excluded.error
	`
	var startedAtUnix, completedAtUnix interface{}
	if jr.StartedAt != nil {
		startedAtUnix = jr.StartedAt.Unix()
	}
	if jr.CompletedAt != nil {
		completedAtUnix = jr.CompletedAt.Unix()
	}

	_, err := d.conn.ExecContext(ctx, query,
		jr.ID, jr.Type, jr.Status, jr.Progress, jr.CreatedAt.Unix(),
		startedAtUnix, completedAtUnix, jr.Config, jr.Results, jr.Error,
	)
	if err != nil {
		return fmt.Errorf("SaveJobRecord: %w", err)
	}
	return nil
}

// GetJobRecord retrieves a single job record by unique ID.
func (d *DB) GetJobRecord(ctx context.Context, id string) (*JobRecord, error) {
	query := `SELECT job_id, type, status, progress, created_at, started_at, completed_at, config, results, error FROM jobs WHERE job_id = ?`
	row := d.conn.QueryRowContext(ctx, query, id)

	var jr JobRecord
	var createdAtUnix int64
	var startedAtUnix, completedAtUnix sql.NullInt64
	var configNull, resultsNull, errorNull sql.NullString

	err := row.Scan(
		&jr.ID, &jr.Type, &jr.Status, &jr.Progress, &createdAtUnix,
		&startedAtUnix, &completedAtUnix, &configNull, &resultsNull, &errorNull,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("job record not found: %s", id)
		}
		return nil, fmt.Errorf("GetJobRecord: %w", err)
	}

	jr.CreatedAt = time.Unix(createdAtUnix, 0)
	if startedAtUnix.Valid {
		t := time.Unix(startedAtUnix.Int64, 0)
		jr.StartedAt = &t
	}
	if completedAtUnix.Valid {
		t := time.Unix(completedAtUnix.Int64, 0)
		jr.CompletedAt = &t
	}
	jr.Config = configNull.String
	jr.Results = resultsNull.String
	jr.Error = errorNull.String

	return &jr, nil
}

// ListJobRecords retrieves saved job records from the database store with pagination.
func (d *DB) ListJobRecords(ctx context.Context, limit, offset int) ([]*JobRecord, error) {
	query := `SELECT job_id, type, status, progress, created_at, started_at, completed_at, config, results, error FROM jobs ORDER BY created_at DESC LIMIT ? OFFSET ?`
	rows, err := d.conn.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("ListJobRecords: %w", err)
	}
	defer rows.Close()

	var records []*JobRecord
	for rows.Next() {
		var jr JobRecord
		var createdAtUnix int64
		var startedAtUnix, completedAtUnix sql.NullInt64
		var configNull, resultsNull, errorNull sql.NullString

		err := rows.Scan(
			&jr.ID, &jr.Type, &jr.Status, &jr.Progress, &createdAtUnix,
			&startedAtUnix, &completedAtUnix, &configNull, &resultsNull, &errorNull,
		)
		if err != nil {
			continue
		}

		jr.CreatedAt = time.Unix(createdAtUnix, 0)
		if startedAtUnix.Valid {
			t := time.Unix(startedAtUnix.Int64, 0)
			jr.StartedAt = &t
		}
		if completedAtUnix.Valid {
			t := time.Unix(completedAtUnix.Int64, 0)
			jr.CompletedAt = &t
		}
		jr.Config = configNull.String
		jr.Results = resultsNull.String
		jr.Error = errorNull.String

		records = append(records, &jr)
	}
	return records, rows.Err()
}

// DeleteJobRecord removes a job record from the database.
func (d *DB) DeleteJobRecord(ctx context.Context, id string) error {
	query := `DELETE FROM jobs WHERE job_id = ?`
	result, err := d.conn.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("DeleteJobRecord: %w", err)
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("job record not found: %s", id)
	}
	return nil
}
