// =============================================================================
// Remote Shutdown - LAN parental control and machine management (master/agent)
// -----------------------------------------------------------------------------
// File    : agent/logging.go
// Purpose : Structured JSON logging (log/slog) to stderr and an optional size-rotated file
// Author  : Thierry Gayet <thierry.gayet@labworks.fr>
// Project : remote-shutdown (version: VERSION)
// Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
// =============================================================================

package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// logger is the process-wide structured logger.
var logger = slog.New(slog.NewJSONHandler(os.Stderr, nil))

// maxLogBytes is the size at which the log file is rotated (one backup kept: FILE.1).
const maxLogBytes = 5 << 20

// rotatingFile is an io.Writer appending to a file and rotating it by size.
type rotatingFile struct {
	mu   sync.Mutex
	path string
	f    *os.File
	size int64
}

// openRotating opens (or creates) the log file in append mode.
func openRotating(path string) (*rotatingFile, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, err
	}
	st, _ := f.Stat()
	r := &rotatingFile{path: path, f: f}
	if st != nil {
		r.size = st.Size()
	}
	return r, nil
}

// Write implements io.Writer.
func (r *rotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.size+int64(len(p)) > maxLogBytes {
		r.f.Close()
		_ = os.Rename(r.path, r.path+".1")
		f, err := os.OpenFile(r.path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
		if err != nil {
			return 0, err
		}
		r.f, r.size = f, 0
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

// Close closes the file.
func (r *rotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.f.Close()
}

// setupLogging configures the level and the destinations; it returns a close function.
func setupLogging(level, file string) func() {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	var out io.Writer = os.Stderr
	closer := func() {}
	if file != "" {
		if rf, err := openRotating(file); err == nil {
			out = io.MultiWriter(os.Stderr, rf)
			closer = func() { _ = rf.Close() }
		}
	}
	logger = slog.New(slog.NewJSONHandler(out, &slog.HandlerOptions{Level: lvl})).With("component", "rsd-agent")
	return closer
}
