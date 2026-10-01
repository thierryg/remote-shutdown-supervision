// =============================================================================
// Remote Shutdown - LAN parental control and machine management (master/agent)
// -----------------------------------------------------------------------------
// File    : agent/enroll.go
// Purpose : Automatic PKI enrollment: CSR + one-time token sent to the pinned master over HTTPS
// Author  : Thierry Gayet <thierry.gayet@labworks.fr>
// Project : remote-shutdown (version: VERSION)
// Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
// =============================================================================

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"
)

// NetworkError marks a failure to reach the master (exit code 6).
type NetworkError struct{ Err error }

// Error implements error.
func (e *NetworkError) Error() string { return e.Err.Error() }

// Unwrap returns the wrapped error.
func (e *NetworkError) Unwrap() error { return e.Err }

type enrollRequest struct {
	Token    string `json:"token"`
	CSR      string `json:"csr"`
	Hostname string `json:"hostname"`
}

type enrollResponse struct {
	AgentID   string `json:"agent_id"`
	Cert      string `json:"cert"`
	CA        string `json:"ca"`
	AgentPort int    `json:"agent_port"`
	Detail    string `json:"detail"`
}

// resolveMaster returns the master host and ports: configuration first, then discovery.
func resolveMaster(ctx context.Context, cfg *Config) (string, int, int, error) {
	if cfg.Master != "" {
		host, port := cfg.SplitMaster()
		return host, port, cfg.AgentPort, nil
	}
	if cfg.DiscoveryPort == 0 {
		return "", 0, 0, errors.New("no master configured and discovery disabled")
	}
	found, err := Discover(ctx, cfg.DiscoveryPort, 3*time.Second)
	if err != nil {
		return "", 0, 0, &NetworkError{err}
	}
	if cfg.CAFingerprint != "" && found.CAFingerprint != cfg.CAFingerprint {
		// Only a hint: the TLS pinning below is the real check.
		logger.Warn("discovered master announces another CA fingerprint", "host", found.Host)
	}
	return found.Host, found.WebPort, found.AgentPort, nil
}

// Enroll obtains a client certificate and stores it; it returns the agent id.
func Enroll(ctx context.Context, cfg *Config) (string, error) {
	if cfg.EnrollToken == "" || len(cfg.CAFingerprint) != 64 {
		return "", errors.New("an enrollment token and the 64-hex-digit CA fingerprint are required")
	}
	host, webPort, agentPort, err := resolveMaster(ctx, cfg)
	if err != nil {
		return "", err
	}
	hostname, _ := os.Hostname()
	key, csr, err := newKeyAndCSR(hostname)
	if err != nil {
		return "", err
	}
	body, _ := json.Marshal(enrollRequest{Token: cfg.EnrollToken, CSR: string(csr), Hostname: hostname})
	url := "https://" + net.JoinHostPort(host, strconv.Itoa(webPort)) + "/api/enroll"
	client := &http.Client{
		Timeout:   20 * time.Second,
		Transport: &http.Transport{TLSClientConfig: pinnedTLSConfig(cfg.CAFingerprint), Proxy: nil},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	logger.Info("enrolling", "url", url)
	resp, err := client.Do(req)
	if err != nil {
		return "", &NetworkError{err}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var out enrollResponse
	_ = json.Unmarshal(raw, &out)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("master answered %d %s", resp.StatusCode, out.Detail)
	}
	ca, err := parseCertPEM([]byte(out.CA))
	if err != nil || certFingerprint(ca) != cfg.CAFingerprint {
		return "", errors.New("the CA returned by the master does not match the pinned fingerprint")
	}
	cert, err := parseCertPEM([]byte(out.Cert))
	if err != nil || cert.Subject.CommonName != out.AgentID || cert.CheckSignatureFrom(ca) != nil {
		return "", errors.New("invalid certificate returned by the master")
	}
	if err := saveCredentials(cfg, key, []byte(out.Cert), []byte(out.CA)); err != nil {
		return "", err
	}
	if out.AgentPort != 0 {
		agentPort = out.AgentPort
	}
	if err := SaveState(cfg, &State{Host: host, WebPort: webPort, AgentPort: agentPort}); err != nil {
		logger.Warn("cannot save state", "error", err)
	}
	cfg.ClearEnrollToken()
	logger.Info("enrolled", "agent_id", out.AgentID, "master", host)
	return out.AgentID, nil
}
