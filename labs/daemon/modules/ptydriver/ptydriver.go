// Package ptydriver drives interactive CLI engines headlessly.
//
// matches engine output lines by *suffix* (never ambiguous "[1-3]" bodies) and
// answers them on stdin; an exec-based driver feeds stdout through the table
// until the process exits. Engines that refuse to run without a real TTY need
// a ConPTY/pty backend — the Driver interface leaves that seam open.
package ptydriver

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
)

// Prompt pairs an output-line suffix with the answer to write on stdin.
type Prompt struct {
	Suffix string // matched against the trimmed line's tail
	Answer string // written verbatim plus newline when matched
}

// PromptTable answers engine prompts by suffix. Matching is suffix-only:
// engines renumber menus between versions ("Choose [1-3]" → "Choose [1-4]"),
// while header text like "Select scan mode:" is stable.
type PromptTable []Prompt

// Answer returns the response for a line, or ok=false when no entry matches.
func (t PromptTable) Answer(line string) (string, bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return "", false
	}
	for _, prompt := range t {
		if prompt.Suffix != "" && strings.HasSuffix(trimmed, prompt.Suffix) {
			return prompt.Answer, true
		}
	}
	return "", false
}

// Result captures how a driven process ended.
type Result struct {
	Output    string
	ExitErr   error
	TimedOut  bool
	Answers   int // prompts answered
}

// ExecDriver runs cmd, streams stderr+stdout through the prompt table, writes
// answers back to stdin, and buffers all output. ctx cancellation kills the
// process group.
func ExecDriver(ctx context.Context, cmd *exec.Cmd, stdin io.WriteCloser, stdout io.ReadCloser, table PromptTable) (*Result, error) {
	var buf syncBuffer
	answerCount := 0

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	errCh := make(chan error, 1)
	go func() { errCh <- cmd.Wait() }()

	driverDone := make(chan struct{})
	go func() {
		defer close(driverDone)
		for scanner.Scan() {
			line := scanner.Text()
			buf.writeLine(line)
			if stdin == nil {
				continue
			}
			if answer, ok := table.Answer(line); ok {
				fmt.Fprintln(stdin, answer)
				answerCount++
			}
		}
		// Drain any trailing bytes that lack a newline.
		if rest := scanner.Bytes(); len(rest) > 0 {
			buf.writeLine(string(rest))
		}
	}()

	select {
	case <-ctx.Done():
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		<-driverDone
		waitErr := <-errCh
		return &Result{Output: buf.String(), ExitErr: waitErr, TimedOut: true, Answers: answerCount}, nil
	case waitErr := <-errCh:
		<-driverDone
		return &Result{Output: buf.String(), ExitErr: waitErr, Answers: answerCount}, nil
	}
}

// Run is the convenience wrapper building pipes around ExecDriver.
func Run(ctx context.Context, cmd *exec.Cmd, table PromptTable) (*Result, error) {
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("ptydriver stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("ptydriver stdout pipe: %w", err)
	}
	cmd.Stderr = cmd.Stdout // merge for single-scanner simplicity
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("ptydriver start: %w", err)
	}
	return ExecDriver(ctx, cmd, stdin, stdout, table)
}

// syncBuffer is a minimal goroutine-safe line sink.
type syncBuffer struct {
	mu  sync.Mutex
	sb  strings.Builder
}

func (b *syncBuffer) writeLine(line string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sb.WriteString(line)
	b.sb.WriteByte('\n')
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sb.String()
}
