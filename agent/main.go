// =============================================================================
// Remote Shutdown - LAN parental control and machine management (master/agent)
// -----------------------------------------------------------------------------
// File    : agent/main.go
// Purpose : rsd-agent command line: run, enroll, status, unenroll, test-popup, version
// Author  : Thierry Gayet <thierry.gayet@labworks.fr>
// Project : remote-shutdown (version: VERSION)
// Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
// =============================================================================

// Command rsd-agent is the cross-platform Remote Shutdown agent (Linux, macOS, Windows).
//
// It enrolls once with the master (one-time token + pinned CA fingerprint), then keeps a
// mutual-TLS connection open to receive commands: shutdown with countdown, popup message,
// chat. It runs as a systemd service, a launchd daemon or a Windows service.
//
// Exit codes (shared with the shell scripts of the project):
//
//	0 OK, 1 runtime, 2 usage, 3 privileges, 5 configuration, 6 network, 7 state
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"
)

// version is set at build time: -ldflags "-X main.version=$(cat VERSION)".
var version = "dev"

// Exit codes.
const (
	exitOK      = 0
	exitRuntime = 1
	exitUsage   = 2
	exitPriv    = 3
	exitConfig  = 5
	exitNetwork = 6
	exitState   = 7
)

const usageText = `Usage: rsd-agent [--config FILE] <command> [options]

Commands:
  run                      run the agent (default; also used by the system service)
  enroll --token T --fingerprint F [--master HOST[:PORT]]
                           obtain a client certificate from the master
  status                   print the enrollment state and the configuration in use
  unenroll                 delete the local certificate and key
  test-popup [TEXT]        show a popup on the active desktop session
  version                  print the version

Global options:
  --config FILE            configuration file (default: ` + "%s" + `)
  --log-file FILE          also write the logs to FILE
  --log-level LEVEL        debug, info, warn, error (default info)
`

// main parses the command line and dispatches to the sub-commands.
func main() {
	os.Exit(run(os.Args[1:]))
}

// run executes the command line and returns the exit code.
func run(args []string) int {
	global := flag.NewFlagSet("rsd-agent", flag.ContinueOnError)
	global.SetOutput(io.Discard)
	configPath := global.String("config", defaultConfigPath(), "")
	logFile := global.String("log-file", "", "")
	logLevel := global.String("log-level", "", "")
	help := global.Bool("help", false, "")
	if err := global.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "rsd-agent: %v\n", err)
		fmt.Fprintf(os.Stderr, usageText, defaultConfigPath())
		return exitUsage
	}
	if *help {
		fmt.Printf(usageText, defaultConfigPath())
		return exitOK
	}
	rest := global.Args()
	command := "run"
	if len(rest) > 0 {
		command, rest = rest[0], rest[1:]
	}

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "rsd-agent: %v\n", err)
		return exitConfig
	}
	if *logLevel != "" {
		cfg.LogLevel = *logLevel
	}
	if *logFile == "" && isWindowsService() {
		*logFile = defaultLogFile()
	}
	closeLog := setupLogging(cfg.LogLevel, *logFile)
	defer closeLog()

	switch command {
	case "run":
		return cmdRun(cfg)
	case "enroll":
		return cmdEnroll(cfg, rest)
	case "status":
		return cmdStatus(cfg)
	case "unenroll":
		return cmdUnenroll(cfg)
	case "test-popup":
		note := Note{Key: "shutdown.default", Params: map[string]any{"seconds": 60}}
		if len(rest) > 0 {
			note = Note{Text: rest[0]}
		}
		if err := ShowMessage(note); err != nil {
			fmt.Fprintf(os.Stderr, "rsd-agent: %v\n", err)
			return exitState
		}
		return exitOK
	case "version":
		fmt.Printf("rsd-agent %s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
		return exitOK
	case "help":
		fmt.Printf(usageText, defaultConfigPath())
		return exitOK
	default:
		fmt.Fprintf(os.Stderr, "rsd-agent: unknown command %q\n", command)
		fmt.Fprintf(os.Stderr, usageText, defaultConfigPath())
		return exitUsage
	}
}

// cmdRun runs the agent until SIGINT/SIGTERM or a service stop request.
func cmdRun(cfg *Config) int {
	if isWindowsService() {
		if err := runWindowsService(cfg); err != nil {
			logger.Error("service failed", "error", err)
			return exitRuntime
		}
		return exitOK
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	NewAgent(cfg).Run(ctx)
	return exitOK
}

// cmdEnroll obtains a certificate from the master.
func cmdEnroll(cfg *Config, args []string) int {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	token := fs.String("token", cfg.EnrollToken, "enrollment token shown by the web console")
	fingerprint := fs.String("fingerprint", cfg.CAFingerprint, "SHA-256 fingerprint of the master CA")
	master := fs.String("master", cfg.Master, "master HOST or HOST:PORT (default: LAN discovery)")
	force := fs.Bool("force", false, "replace an existing enrollment")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *token == "" || *fingerprint == "" {
		fmt.Fprintln(os.Stderr, "rsd-agent: --token and --fingerprint are required (copy the command from the web console)")
		return exitUsage
	}
	if IsEnrolled(cfg) && !*force {
		fmt.Fprintln(os.Stderr, "rsd-agent: already enrolled (use --force to enroll again)")
		return exitState
	}
	if err := requireAdminFor(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "rsd-agent: %v\n", err)
		return exitPriv
	}
	cfg.EnrollToken, cfg.CAFingerprint, cfg.Master = *token, *fingerprint, *master
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	id, err := Enroll(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "rsd-agent: enrollment failed: %v\n", err)
		var netErr *NetworkError
		if errors.As(err, &netErr) {
			return exitNetwork
		}
		return exitRuntime
	}
	fmt.Printf("enrolled as %s; restart the service to connect (it retries by itself within a minute)\n", id)
	return exitOK
}

// cmdStatus prints the configuration and the enrollment state.
func cmdStatus(cfg *Config) int {
	fmt.Printf("version:        %s\n", version)
	fmt.Printf("config file:    %s\n", cfg.path)
	fmt.Printf("state dir:      %s\n", cfg.StateDir)
	fmt.Printf("master:         %s\n", orDefault(cfg.Master, "(discovery)"))
	if st, err := LoadState(cfg); err == nil && st.Host != "" {
		fmt.Printf("last master:    %s (agent port %d)\n", st.Host, st.AgentPort)
	}
	id, notAfter, err := CertificateInfo(cfg)
	if err != nil {
		fmt.Println("enrollment:     not enrolled")
		return exitState
	}
	fmt.Printf("agent id:       %s\n", id)
	fmt.Printf("certificate:    valid until %s\n", notAfter.Format(time.RFC3339))
	return exitOK
}

// cmdUnenroll deletes the local credentials.
func cmdUnenroll(cfg *Config) int {
	if err := requireAdminFor(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "rsd-agent: %v\n", err)
		return exitPriv
	}
	if err := RemoveCredentials(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "rsd-agent: %v\n", err)
		return exitRuntime
	}
	fmt.Println("local certificate removed; delete the machine in the web console as well")
	return exitOK
}

// requireAdminFor demands administrator rights when the system state directory is used (a
// custom state_dir, e.g. for development, only needs write access to that directory).
func requireAdminFor(cfg *Config) error {
	if cfg.StateDir != defaultStateDir() {
		return nil
	}
	return requireAdmin()
}

// orDefault returns value, or fallback when value is empty.
func orDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
