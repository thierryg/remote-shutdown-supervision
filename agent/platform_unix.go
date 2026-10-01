// =============================================================================
// Remote Shutdown - LAN parental control and machine management (master/agent)
// -----------------------------------------------------------------------------
// File    : agent/platform_unix.go
// Purpose : Code shared by Linux and macOS: privileges, permissions, clocks, sockets, run-as-user
// Author  : Thierry Gayet <thierry.gayet@labworks.fr>
// Project : remote-shutdown (version: VERSION)
// Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
// =============================================================================

//go:build !windows

package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
	"time"
)

// processStart anchors the monotonic clock (it does not advance while the system sleeps on
// Linux, CLOCK_MONOTONIC, and on macOS, mach_absolute_time).
var processStart = time.Now()

// awakeClock returns a duration that stops increasing during sleep.
func awakeClock() time.Duration { return time.Since(processStart) }

// isWindowsService is always false outside Windows.
func isWindowsService() bool { return false }

// runWindowsService is never called outside Windows.
func runWindowsService(*Config) error { return errors.New("not a Windows service") }

// applyRegistry is a no-op outside Windows.
func applyRegistry(*Config) {}

// clearRegistryToken is a no-op outside Windows.
func clearRegistryToken() {}

// defaultLogFile: logs go to stderr (journald / launchd StandardErrorPath).
func defaultLogFile() string { return "" }

// requireAdmin fails unless running as root.
func requireAdmin() error {
	if os.Geteuid() != 0 {
		return errors.New("root privileges required (use sudo)")
	}
	return nil
}

// secureDir restricts a directory to its owner.
func secureDir(path string) error { return os.Chmod(path, 0o700) }

// enableBroadcast sets SO_BROADCAST on a UDP socket.
func enableBroadcast(conn *net.UDPConn) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	err = raw.Control(func(fd uintptr) {
		serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
	})
	if err != nil {
		return err
	}
	return serr
}

// desktopUser is a user owning a graphical session.
type desktopUser struct {
	Name string
	UID  int
	GID  int
	Home string
	Env  []string
}

// lookupDesktopUser resolves a user name to its ids and home directory.
func lookupDesktopUser(name string) (*desktopUser, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return nil, err
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	return &desktopUser{Name: u.Username, UID: uid, GID: gid, Home: u.HomeDir}, nil
}

// runAs runs a command in the session of a desktop user and returns its standard output.
// As root, the process gets the user's uid/gid; otherwise (development) it runs as is.
func runAs(ctx context.Context, du *desktopUser, name string, args ...string) (string, int, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append([]string{
		"HOME=" + du.Home, "USER=" + du.Name, "LOGNAME=" + du.Name,
		"PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
	}, du.Env...)
	cmd.Dir = du.Home
	if os.Geteuid() == 0 && du.UID != 0 {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(du.UID), Gid: uint32(du.GID)}}
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	code := 0
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code = exitErr.ExitCode()
	}
	return string(bytes.TrimRight(out.Bytes(), "\r\n")), code, err
}
