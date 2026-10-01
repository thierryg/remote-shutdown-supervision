// =============================================================================
// Remote Shutdown - LAN parental control and machine management (master/agent)
// -----------------------------------------------------------------------------
// File    : agent/shutdown.go
// Purpose : Cancellable shutdown countdown, independent of the master connection
// Author  : Thierry Gayet <thierry.gayet@labworks.fr>
// Project : remote-shutdown (version: VERSION)
// Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
// =============================================================================

package main

import (
	"sync"
	"time"
)

// ShutdownManager holds at most one pending shutdown. The countdown keeps running when the
// master connection drops: a scheduled shutdown can only be cancelled by the master.
type ShutdownManager struct {
	mu       sync.Mutex
	timer    *time.Timer
	at       time.Time
	onChange func(*time.Time)
	powerOff func(force bool) error
}

// NewShutdownManager creates a manager; onChange is called with the new due time (nil when
// no shutdown is pending).
func NewShutdownManager(onChange func(*time.Time)) *ShutdownManager {
	return &ShutdownManager{onChange: onChange, powerOff: powerOff}
}

// Schedule (re)arms the countdown; a new order replaces the pending one.
func (s *ShutdownManager) Schedule(delay time.Duration, message string, force bool) {
	s.mu.Lock()
	if s.timer != nil {
		s.timer.Stop()
	}
	s.at = time.Now().Add(delay)
	at := s.at
	s.timer = time.AfterFunc(delay, func() {
		logger.Warn("powering off", "force", force)
		err := s.powerOff(force)
		if err != nil {
			logger.Error("power off failed", "error", err)
		}
		// Reached when the power-off failed or was simulated (dry run): nothing is pending any more.
		s.mu.Lock()
		s.timer, s.at = nil, time.Time{}
		s.mu.Unlock()
		s.onChange(nil)
	})
	s.mu.Unlock()
	logger.Warn("shutdown scheduled", "delay", delay.String(), "message", message, "force", force)
	s.onChange(&at)
}

// Cancel stops the countdown; it reports whether a shutdown was pending.
func (s *ShutdownManager) Cancel() bool {
	s.mu.Lock()
	pending := s.timer != nil && s.timer.Stop()
	s.timer, s.at = nil, time.Time{}
	s.mu.Unlock()
	if pending {
		logger.Info("shutdown cancelled")
		s.onChange(nil)
	}
	return pending
}

// PendingAt returns the due time of the pending shutdown, or nil.
func (s *ShutdownManager) PendingAt() *time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.timer == nil {
		return nil
	}
	at := s.at
	return &at
}
