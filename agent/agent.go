// =============================================================================
// Remote Shutdown - LAN parental control and machine management (master/agent)
// -----------------------------------------------------------------------------
// File    : agent/agent.go
// Purpose : Agent runtime: enrollment wait, mutual-TLS connection loop, protocol messages
// Author  : Thierry Gayet <thierry.gayet@labworks.fr>
// Project : remote-shutdown (version: VERSION)
// Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
// =============================================================================

package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"encoding/json"
	"errors"
	"math/rand"
	"net"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"sync"
	"time"
)

// Protocol constants (see docs/PROTOCOL.md).
const (
	maxLineBytes        = 64 * 1024
	defaultKeepalive    = 10 * time.Second
	interfacesPeriod    = 30 * time.Second
	maxBackoff          = 60 * time.Second
	refusedBackoff      = 5 * time.Minute
	enrollRetryInterval = 30 * time.Second
	failuresBeforeScan  = 3
)

// Message is the envelope of every protocol line (only the relevant fields are set).
type Message struct {
	Type              string         `json:"type"`
	Ref               string         `json:"ref,omitempty"`
	AgentID           string         `json:"agent_id,omitempty"`
	KeepaliveInterval float64        `json:"keepalive_interval,omitempty"`
	Delay             *int           `json:"delay,omitempty"`
	Force             bool           `json:"force,omitempty"`
	Message           string         `json:"message,omitempty"`
	Title             string         `json:"title,omitempty"`
	Text              string         `json:"text,omitempty"`
	Author            string         `json:"author,omitempty"`
	Key               string         `json:"key,omitempty"`
	Params            map[string]any `json:"params,omitempty"`
	Cert              string         `json:"cert,omitempty"`
	CA                string         `json:"ca,omitempty"`
	Error             string         `json:"error,omitempty"`
	Fatal             bool           `json:"fatal,omitempty"`
}

// errRefused means the master rejected the certificate (deleted or superseded agent).
var errRefused = errors.New("certificate refused by the master")

// errRenewed asks the loop to reconnect with the renewed certificate.
var errRenewed = errors.New("certificate renewed")

// Agent is the long-running agent.
type Agent struct {
	cfg      *Config
	shutdown *ShutdownManager
	popups   chan struct{}

	mu        sync.Mutex
	conn      *tls.Conn
	pendingKy *ecdsa.PrivateKey
}

// NewAgent creates an agent from its configuration.
func NewAgent(cfg *Config) *Agent {
	a := &Agent{cfg: cfg, popups: make(chan struct{}, 3)}
	a.shutdown = NewShutdownManager(a.reportShutdownState)
	if cfg.DryRun {
		a.shutdown.powerOff = func(force bool) error {
			logger.Warn("dry run: power off skipped", "force", force)
			return nil
		}
	}
	return a
}

// Run waits for the enrollment, then keeps the master connection alive until ctx ends.
func (a *Agent) Run(ctx context.Context) {
	logger.Info("agent starting", "version", version, "os", runtime.GOOS, "arch", runtime.GOARCH)
	for !IsEnrolled(a.cfg) {
		if a.cfg.EnrollToken != "" && a.cfg.CAFingerprint != "" {
			enrollCtx, cancel := context.WithTimeout(ctx, time.Minute)
			_, err := Enroll(enrollCtx, a.cfg)
			cancel()
			if err == nil {
				break
			}
			logger.Error("unattended enrollment failed", "error", err)
		} else {
			logger.Warn("not enrolled: run 'rsd-agent enroll --token ... --fingerprint ...' (command shown by the web console)")
		}
		if !sleepCtx(ctx, enrollRetryInterval) {
			return
		}
		if reloaded, err := LoadConfig(a.cfg.path); err == nil {
			a.cfg = reloaded
		}
	}
	backoff := time.Second
	failures := 0
	for ctx.Err() == nil {
		started := time.Now()
		err := a.session(ctx)
		if ctx.Err() != nil {
			break
		}
		switch {
		case errors.Is(err, errRenewed):
			backoff = time.Second
			continue
		case errors.Is(err, errRefused):
			logger.Error("the master refused this agent: enroll it again", "retry_in", refusedBackoff.String())
			if !sleepCtx(ctx, refusedBackoff) {
				return
			}
			continue
		}
		if time.Since(started) > time.Minute {
			backoff, failures = time.Second, 0
		}
		failures++
		if failures%failuresBeforeScan == 0 {
			a.rediscover(ctx)
		}
		wait := backoff + time.Duration(rand.Int63n(int64(backoff/2)+1)) // #nosec G404 - jitter only
		logger.Warn("master connection lost", "error", errString(err), "retry_in", wait.Round(time.Second).String())
		if !sleepCtx(ctx, wait) {
			break
		}
		if backoff *= 2; backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
	logger.Info("agent stopped")
}

// rediscover looks for the master again when the configured address does not answer.
func (a *Agent) rediscover(ctx context.Context) {
	if a.cfg.Master != "" || a.cfg.DiscoveryPort == 0 {
		return
	}
	found, err := Discover(ctx, a.cfg.DiscoveryPort, 3*time.Second)
	if err != nil {
		logger.Debug("rediscovery failed", "error", err)
		return
	}
	_ = SaveState(a.cfg, &State{Host: found.Host, WebPort: found.WebPort, AgentPort: found.AgentPort})
}

// target returns the agent-hub address: the configured master host (or the one remembered
// from the enrollment / last discovery) and the agent port announced by the master.
func (a *Agent) target() (string, error) {
	st, _ := LoadState(a.cfg)
	host := st.Host
	if a.cfg.Master != "" {
		host, _ = a.cfg.SplitMaster()
	}
	if host == "" {
		return "", errors.New("master address unknown (no configuration, no discovery answer yet)")
	}
	port := a.cfg.AgentPort
	if st.AgentPort != 0 {
		port = st.AgentPort
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

// session runs one connection until it fails.
func (a *Agent) session(ctx context.Context) error {
	addr, err := a.target()
	if err != nil {
		return err
	}
	tlsCfg, err := mutualTLSConfig(a.cfg)
	if err != nil {
		return err
	}
	dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}, Config: tlsCfg}
	raw, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	conn := raw.(*tls.Conn)
	a.mu.Lock()
	a.conn = conn
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		a.conn = nil
		a.mu.Unlock()
		conn.Close()
	}()
	logger.Info("connected to master", "addr", addr)

	sessCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { <-sessCtx.Done(); conn.Close() }()

	if err := a.send(a.declare()); err != nil {
		return err
	}
	a.reportShutdownState(a.shutdown.PendingAt())
	a.maybeRenew()

	keepalive := defaultKeepalive
	reader := bufio.NewReaderSize(conn, 4096)
	var once sync.Once
	for {
		_ = conn.SetReadDeadline(time.Now().Add(3*keepalive + 5*time.Second))
		line, err := readLine(reader)
		if err != nil {
			return err
		}
		var msg Message
		if err := json.Unmarshal(line, &msg); err != nil {
			logger.Warn("invalid line from master", "error", err)
			continue
		}
		if msg.Type == "WELCOME" {
			if msg.KeepaliveInterval > 0 {
				keepalive = time.Duration(msg.KeepaliveInterval * float64(time.Second))
			}
			once.Do(func() { go a.periodic(sessCtx, keepalive) })
			continue
		}
		if err := a.handle(msg); err != nil {
			return err
		}
	}
}

// readLine reads one line, refusing lines longer than maxLineBytes.
func readLine(r *bufio.Reader) ([]byte, error) {
	var buf []byte
	for {
		chunk, isPrefix, err := r.ReadLine()
		if err != nil {
			return nil, err
		}
		buf = append(buf, chunk...)
		if len(buf) > maxLineBytes {
			return nil, errors.New("line too long")
		}
		if !isPrefix {
			return buf, nil
		}
	}
}

// periodic sends KEEPALIVE frames and UPDATE when the interfaces change.
func (a *Agent) periodic(ctx context.Context, keepalive time.Duration) {
	ka := time.NewTicker(keepalive)
	defer ka.Stop()
	ifTick := time.NewTicker(interfacesPeriod)
	defer ifTick.Stop()
	last := Interfaces()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ka.C:
			if a.send(map[string]any{"type": "KEEPALIVE", "timestamp": time.Now().Unix(),
				"uptime": int64(Uptime().Seconds())}) != nil {
				return
			}
		case <-ifTick.C:
			current := Interfaces()
			if !reflect.DeepEqual(current, last) {
				last = current
				logger.Info("network interfaces changed")
				_ = a.send(map[string]any{"type": "UPDATE", "interfaces": current})
			}
		}
	}
}

// declare builds the DECLARE message.
func (a *Agent) declare() map[string]any {
	hostname, _ := os.Hostname()
	return map[string]any{
		"type":       "DECLARE",
		"hostname":   hostname,
		"os":         osDescription(),
		"arch":       runtime.GOARCH,
		"version":    version,
		"boot_time":  time.Now().Add(-Uptime()).Unix(),
		"interfaces": Interfaces(),
	}
}

// send writes one JSON line on the current connection.
func (a *Agent) send(v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.conn == nil {
		return errors.New("not connected")
	}
	_ = a.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err = a.conn.Write(append(data, '\n'))
	return err
}

// ack acknowledges a command.
func (a *Agent) ack(ref string, err error) {
	msg := map[string]any{"type": "ACK", "ref": ref, "ok": err == nil}
	if err != nil {
		msg["error"] = err.Error()
	}
	_ = a.send(msg)
}

// reportShutdownState tells the master whether a shutdown is pending.
func (a *Agent) reportShutdownState(at *time.Time) {
	msg := map[string]any{"type": "STATE", "shutdown_at": nil}
	if at != nil {
		msg["shutdown_at"] = at.Unix()
	}
	_ = a.send(msg)
}

// handle processes one message from the master.
func (a *Agent) handle(msg Message) error {
	switch msg.Type {
	case "PONG":
	case "SHUTDOWN":
		delay := 60
		if msg.Delay != nil && *msg.Delay >= 0 {
			delay = *msg.Delay
		}
		a.shutdown.Schedule(time.Duration(delay)*time.Second, msg.Message, msg.Force)
		a.popup(Note{Key: msg.Key, Params: msg.Params, Text: msg.Message})
		a.ack(msg.Ref, nil)
	case "CANCEL_SHUTDOWN":
		if a.shutdown.Cancel() {
			a.popup(Note{Key: "shutdown.cancelled"})
		}
		a.ack(msg.Ref, nil)
	case "MESSAGE":
		a.popup(Note{Key: msg.Key, Params: msg.Params, Text: msg.Text})
		a.ack(msg.Ref, nil)
	case "CHAT":
		a.chat(msg)
		a.ack(msg.Ref, nil)
	case "RENEWED":
		return a.storeRenewed(msg)
	case "ERROR":
		logger.Error("master error", "error", msg.Error)
		if msg.Fatal {
			return errRefused
		}
	default:
		logger.Warn("unknown message type", "type", msg.Type)
	}
	return nil
}

// popup shows a message without blocking the connection (at most 3 at once), in the language
// of each desktop user.
func (a *Agent) popup(note Note) {
	if note.Text == "" && note.Key == "" {
		return
	}
	select {
	case a.popups <- struct{}{}:
	default:
		logger.Warn("too many popups open, message dropped", "text", note.Text, "key", note.Key)
		return
	}
	go func() {
		defer func() { <-a.popups }()
		if err := ShowMessage(note); err != nil {
			logger.Warn("popup failed", "error", err)
		}
	}()
}

// chat shows a chat message and sends back the reply typed by the user, if any.
func (a *Agent) chat(msg Message) {
	select {
	case a.popups <- struct{}{}:
	default:
		logger.Warn("too many popups open, chat message dropped")
		return
	}
	go func() {
		defer func() { <-a.popups }()
		reply, user, err := AskReply(Note{Text: msg.Text, TitleKey: "chat.from",
			TitleParams: map[string]any{"author": orDefault(msg.Author, "admin")}})
		if err != nil {
			logger.Warn("chat popup failed", "error", err)
			return
		}
		if reply != "" {
			_ = a.send(map[string]any{"type": "CHAT", "text": reply, "user": user})
		}
	}()
}

// maybeRenew asks for a new certificate when the current one expires soon.
func (a *Agent) maybeRenew() {
	_, notAfter, err := CertificateInfo(a.cfg)
	if err != nil || time.Until(notAfter) > renewBefore {
		return
	}
	hostname, _ := os.Hostname()
	key, csr, err := newKeyAndCSR(hostname)
	if err != nil {
		logger.Error("cannot create the renewal request", "error", err)
		return
	}
	a.mu.Lock()
	a.pendingKy = key
	a.mu.Unlock()
	logger.Info("certificate expires soon, requesting renewal", "not_after", notAfter.Format(time.RFC3339))
	_ = a.send(map[string]any{"type": "RENEW", "csr": string(csr)})
}

// storeRenewed saves a renewed certificate and asks for a reconnection.
func (a *Agent) storeRenewed(msg Message) error {
	a.mu.Lock()
	key := a.pendingKy
	a.pendingKy = nil
	a.mu.Unlock()
	if key == nil {
		logger.Warn("unexpected RENEWED message")
		return nil
	}
	cert, err := parseCertPEM([]byte(msg.Cert))
	if err != nil || !publicKeyMatches(cert, key) {
		logger.Error("invalid renewed certificate")
		return nil
	}
	if err := saveCredentials(a.cfg, key, []byte(msg.Cert), []byte(msg.CA)); err != nil {
		logger.Error("cannot store the renewed certificate", "error", err)
		return nil
	}
	logger.Info("certificate renewed", "not_after", cert.NotAfter.Format(time.RFC3339))
	return errRenewed
}

// sleepCtx sleeps for d; it returns false when ctx ended first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// errString formats a possibly nil error.
func errString(err error) string {
	if err == nil {
		return "closed by the master"
	}
	return err.Error()
}
