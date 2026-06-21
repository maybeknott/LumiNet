// Package log provides a structured, multi-level JSON logging engine.
package log

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// Level defines the verbosity threshold of the logger.
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

// Logger represents a structured logger wrapper around file/console streams.
type Logger struct {
	level  Level
	output io.Writer
}

// NewLogger constructs a structured Logger with the specified level.
func NewLogger(levelName string) *Logger {
	level := LevelInfo
	switch strings.ToLower(levelName) {
	case "debug":
		level = LevelDebug
	case "warn", "warning":
		level = LevelWarn
	case "error":
		level = LevelError
	}
	return &Logger{
		level:  level,
		output: os.Stdout,
	}
}

// SetOutput sets the output writer for the logger.
func (l *Logger) SetOutput(w io.Writer) {
	l.output = w
}

type logEntry struct {
	Time    string                 `json:"time"`
	Level   string                 `json:"level"`
	Message string                 `json:"msg"`
	Fields  map[string]interface{} `json:"fields,omitempty"`
}

func (l *Logger) log(level Level, levelName string, msg string, keysAndValues ...interface{}) {
	if level < l.level {
		return
	}
	entry := logEntry{
		Time:    time.Now().UTC().Format(time.RFC3339),
		Level:   levelName,
		Message: msg,
	}
	if len(keysAndValues) > 0 {
		fields := make(map[string]interface{})
		for i := 0; i+1 < len(keysAndValues); i += 2 {
			key := fmt.Sprintf("%v", keysAndValues[i])
			fields[key] = keysAndValues[i+1]
		}
		entry.Fields = fields
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	fmt.Fprintln(l.output, string(data))
}

// Debug outputs message and structural details at LevelDebug.
func (l *Logger) Debug(ctx context.Context, msg string, keysAndValues ...interface{}) {
	l.log(LevelDebug, "DEBUG", msg, keysAndValues...)
}

// Info outputs message and structural details at LevelInfo.
func (l *Logger) Info(ctx context.Context, msg string, keysAndValues ...interface{}) {
	l.log(LevelInfo, "INFO", msg, keysAndValues...)
}

// Warn outputs message and structural details at LevelWarn.
func (l *Logger) Warn(ctx context.Context, msg string, keysAndValues ...interface{}) {
	l.log(LevelWarn, "WARN", msg, keysAndValues...)
}

// Error outputs message and structural details at LevelError.
func (l *Logger) Error(ctx context.Context, err error, msg string, keysAndValues ...interface{}) {
	kv := append(keysAndValues, "error", err.Error())
	l.log(LevelError, "ERROR", msg, kv...)
}
