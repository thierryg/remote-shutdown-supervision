// =============================================================================
// Remote Shutdown - LAN parental control and machine management (master/agent)
// -----------------------------------------------------------------------------
// File    : agent/config.go
// Purpose : Agent configuration (JSON file + environment + Windows registry) and persistent state
// Author  : Thierry Gayet <thierry.gayet@labworks.fr>
// Project : remote-shutdown (version: VERSION)
// Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
// =============================================================================

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Config is the agent configuration. Precedence, highest first: command-line flags >
// environment (RSD_*) > Windows registry (HKLM\SOFTWARE\rsd-agent, written by the MSI) >
// JSON file > defaults.
type Config struct {
	// Master is the master host name or IP, optionally with the web port (HOST:PORT).
	// Empty means LAN discovery.
	Master string `json:"master"`
	// WebPort is the HTTPS port used for enrollment.
	WebPort int `json:"web_port"`
	// AgentPort is the mutual-TLS port of the agent hub.
	AgentPort int `json:"agent_port"`
	// DiscoveryPort is the UDP port of the discovery broadcast (0 disables discovery).
	DiscoveryPort int `json:"discovery_port"`
	// CAFingerprint is the SHA-256 fingerprint of the master CA, pinned at enrollment.
	CAFingerprint string `json:"ca_fingerprint"`
	// EnrollToken is a one-time token for unattended enrollment (cleared after use).
	EnrollToken string `json:"enroll_token"`
	// LogLevel is debug, info, warn or error.
	LogLevel string `json:"log_level"`
	// StateDir holds the key, the certificates and state.json (default per OS).
	StateDir string `json:"state_dir"`
	// DryRun logs the power-off instead of executing it (containers, demonstrations).
	DryRun bool `json:"dry_run"`

	path string
}

// State is what the agent remembers between runs (state.json in StateDir).
type State struct {
	// Host is the master address that answered last (enrollment or discovery).
	Host string `json:"host"`
	// WebPort is the master web port.
	WebPort int `json:"web_port"`
	// AgentPort is the master agent port.
	AgentPort int `json:"agent_port"`
}

// defaults returns a configuration with the built-in default values.
func defaults() *Config {
	return &Config{WebPort: 8443, AgentPort: 8444, DiscoveryPort: 50000, LogLevel: "info", StateDir: defaultStateDir()}
}

// LoadConfig reads the JSON file (a missing file is not an error) and applies the overrides.
func LoadConfig(path string) (*Config, error) {
	cfg := defaults()
	cfg.path = path
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := json.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("invalid configuration %s: %w", path, err)
		}
	case errors.Is(err, os.ErrNotExist):
	default:
		return nil, fmt.Errorf("cannot read %s: %w", path, err)
	}
	applyRegistry(cfg)
	applyEnv(cfg)
	if cfg.StateDir == "" {
		cfg.StateDir = defaultStateDir()
	}
	cfg.CAFingerprint = normalizeFingerprint(cfg.CAFingerprint)
	return cfg, nil
}

// applyEnv applies the RSD_* environment variables.
func applyEnv(cfg *Config) {
	setString := func(name string, dst *string) {
		if v, ok := os.LookupEnv(name); ok && v != "" {
			*dst = v
		}
	}
	setInt := func(name string, dst *int) {
		if v, ok := os.LookupEnv(name); ok {
			if n, err := strconv.Atoi(v); err == nil {
				*dst = n
			}
		}
	}
	setString("RSD_MASTER", &cfg.Master)
	setString("RSD_ENROLL_TOKEN", &cfg.EnrollToken)
	setString("RSD_CA_FINGERPRINT", &cfg.CAFingerprint)
	setString("RSD_LOG_LEVEL", &cfg.LogLevel)
	setString("RSD_STATE_DIR", &cfg.StateDir)
	setInt("RSD_WEB_PORT", &cfg.WebPort)
	setInt("RSD_AGENT_PORT", &cfg.AgentPort)
	setInt("RSD_DISCOVERY_PORT", &cfg.DiscoveryPort)
	if v, ok := os.LookupEnv("RSD_DRY_RUN"); ok {
		cfg.DryRun = v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
	}
}

// normalizeFingerprint lowercases a fingerprint and removes ':' and spaces.
func normalizeFingerprint(fp string) string {
	return strings.ToLower(strings.NewReplacer(":", "", " ", "", "-", "").Replace(strings.TrimSpace(fp)))
}

// SplitMaster returns the host and web port of cfg.Master (the port defaults to WebPort).
func (c *Config) SplitMaster() (string, int) {
	host := c.Master
	port := c.WebPort
	if h, p, ok := strings.Cut(host, "]:"); ok && strings.HasPrefix(h, "[") { // [IPv6]:port
		host = strings.TrimPrefix(h, "[")
		if n, err := strconv.Atoi(p); err == nil {
			port = n
		}
	} else if strings.Count(host, ":") == 1 {
		h, p, _ := strings.Cut(host, ":")
		if n, err := strconv.Atoi(p); err == nil {
			host, port = h, n
		}
	}
	return strings.Trim(host, "[]"), port
}

// ClearEnrollToken removes a consumed token from the configuration file and the registry.
func (c *Config) ClearEnrollToken() {
	c.EnrollToken = ""
	clearRegistryToken()
	data, err := os.ReadFile(c.path)
	if err != nil {
		return
	}
	var raw map[string]any
	if json.Unmarshal(data, &raw) != nil {
		return
	}
	// Rewrite only when a token is really stored: an untouched file stays identical to the
	// packaged one (no .rpmsave / dpkg conffile prompt on upgrade or removal).
	if token, _ := raw["enroll_token"].(string); token == "" {
		return
	}
	raw["enroll_token"] = ""
	if out, err := json.MarshalIndent(raw, "", "  "); err == nil {
		_ = os.WriteFile(c.path, append(out, '\n'), 0o600)
	}
}

// statePath returns the path of a file of the state directory.
func (c *Config) statePath(name string) string {
	return filepath.Join(c.StateDir, name)
}

// LoadState reads state.json.
func LoadState(cfg *Config) (*State, error) {
	data, err := os.ReadFile(cfg.statePath("state.json"))
	if err != nil {
		return &State{}, err
	}
	st := &State{}
	if err := json.Unmarshal(data, st); err != nil {
		return &State{}, err
	}
	return st, nil
}

// SaveState writes state.json atomically.
func SaveState(cfg *Config, st *State) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(cfg.statePath("state.json"), append(data, '\n'), 0o600)
}

// writeFileAtomic writes a file through a temporary file and a rename.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
