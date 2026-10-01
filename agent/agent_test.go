// =============================================================================
// Remote Shutdown - LAN parental control and machine management (master/agent)
// -----------------------------------------------------------------------------
// File    : agent/agent_test.go
// Purpose : Unit tests: configuration, CA pinning, chain verification, framing, shutdown timer
// Author  : Thierry Gayet <thierry.gayet@labworks.fr>
// Project : remote-shutdown (version: VERSION)
// Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
// =============================================================================

package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// testCA creates a CA and returns it with a leaf issued for the given usage.
func testCA(t *testing.T, usage x509.ExtKeyUsage) (*x509.Certificate, *x509.Certificate) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{usage}, KeyUsage: x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(leafDER)
	return ca, leaf
}

func TestSplitMaster(t *testing.T) {
	cases := map[string]struct {
		host string
		port int
	}{
		"192.168.1.10":       {"192.168.1.10", 8443},
		"master.lan:9443":    {"master.lan", 9443},
		"[fd00::1]:7443":     {"fd00::1", 7443},
		"fd00::1":            {"fd00::1", 8443},
		"host.example:wrong": {"host.example:wrong", 8443},
	}
	for in, want := range cases {
		cfg := defaults()
		cfg.Master = in
		host, port := cfg.SplitMaster()
		if host != want.host || port != want.port {
			t.Errorf("%s: got %s %d, want %s %d", in, host, port, want.host, want.port)
		}
	}
}

func TestNormalizeFingerprint(t *testing.T) {
	if got := normalizeFingerprint(" AB:cd-EF 01 "); got != "abcdef01" {
		t.Fatalf("got %q", got)
	}
}

func TestLoadConfigAndEnvironment(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.json")
	if err := os.WriteFile(path, []byte(`{"master":"10.0.0.1","agent_port":9444,"enroll_token":"tok"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RSD_MASTER", "10.0.0.2")
	t.Setenv("RSD_CA_FINGERPRINT", "AA:BB")
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Master != "10.0.0.2" || cfg.AgentPort != 9444 || cfg.CAFingerprint != "aabb" || cfg.WebPort != 8443 {
		t.Fatalf("unexpected config %+v", cfg)
	}
	cfg.ClearEnrollToken()
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), `"tok"`) {
		t.Fatal("token not cleared from the file")
	}
	// A file without token is left untouched (packaged configuration file).
	pristine := filepath.Join(dir, "pristine.json")
	original := []byte("{\n  \"enroll_token\": \"\",\n  \"master\": \"\"\n}\n")
	if err := os.WriteFile(pristine, original, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg2, _ := LoadConfig(pristine)
	cfg2.ClearEnrollToken()
	if after, _ := os.ReadFile(pristine); string(after) != string(original) {
		t.Fatal("a configuration without token was rewritten")
	}
	if _, err := LoadConfig(filepath.Join(dir, "missing.json")); err != nil {
		t.Fatal("a missing file must not be an error")
	}
}

func TestPinnedAndChainVerification(t *testing.T) {
	ca, server := testCA(t, x509.ExtKeyUsageServerAuth)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	ok := tls.ConnectionState{PeerCertificates: []*x509.Certificate{server, ca}}
	if err := verifyMasterChain(ok, pool); err != nil {
		t.Fatalf("valid chain refused: %v", err)
	}
	if err := pinnedTLSConfig(certFingerprint(ca)).VerifyConnection(ok); err != nil {
		t.Fatalf("pinned CA refused: %v", err)
	}
	if err := pinnedTLSConfig(strings.Repeat("0", 64)).VerifyConnection(ok); err == nil {
		t.Fatal("wrong fingerprint accepted")
	}
	// An agent (clientAuth) certificate must never be accepted as the master.
	ca2, client := testCA(t, x509.ExtKeyUsageClientAuth)
	pool2 := x509.NewCertPool()
	pool2.AddCert(ca2)
	if err := verifyMasterChain(tls.ConnectionState{PeerCertificates: []*x509.Certificate{client}}, pool2); err == nil {
		t.Fatal("clientAuth certificate accepted as master")
	}
	// A server certificate of another CA is refused.
	if err := verifyMasterChain(ok, pool2); err == nil {
		t.Fatal("foreign CA accepted")
	}
}

func TestCredentialsRoundTrip(t *testing.T) {
	cfg := defaults()
	cfg.StateDir = t.TempDir()
	key, csr, err := newKeyAndCSR("pc")
	if err != nil || !strings.Contains(string(csr), "CERTIFICATE REQUEST") {
		t.Fatalf("CSR: %v", err)
	}
	if IsEnrolled(cfg) {
		t.Fatal("enrolled before saving")
	}
	if err := saveCredentials(cfg, key, []byte("cert"), []byte("ca")); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(cfg.statePath(keyFile))
	if runtime.GOOS != "windows" && st.Mode().Perm()&0o077 != 0 { // Windows: ACL, not mode bits
		t.Fatalf("key permissions too open: %v", st.Mode())
	}
	if !IsEnrolled(cfg) || RemoveCredentials(cfg) != nil || IsEnrolled(cfg) {
		t.Fatal("enrollment state not tracked")
	}
}

func TestReadLineLimit(t *testing.T) {
	r := bufio.NewReaderSize(strings.NewReader("{\"type\":\"PONG\"}\n"+strings.Repeat("x", maxLineBytes+10)+"\n"), 16)
	if line, err := readLine(r); err != nil || string(line) != `{"type":"PONG"}` {
		t.Fatalf("got %q %v", line, err)
	}
	if _, err := readLine(r); err == nil {
		t.Fatal("oversized line accepted")
	}
}

func TestShutdownManager(t *testing.T) {
	var mu sync.Mutex
	var states []bool
	fired := make(chan bool, 1)
	m := NewShutdownManager(func(at *time.Time) {
		mu.Lock()
		states = append(states, at != nil)
		mu.Unlock()
	})
	m.powerOff = func(force bool) error { fired <- force; return nil }

	m.Schedule(time.Hour, "later", false)
	if m.PendingAt() == nil || !m.Cancel() || m.PendingAt() != nil || m.Cancel() {
		t.Fatal("cancel semantics")
	}
	m.Schedule(10*time.Millisecond, "now", true)
	select {
	case force := <-fired:
		if !force {
			t.Fatal("force flag lost")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("power off not called")
	}
	mu.Lock()
	defer mu.Unlock()
	deadline := time.Now().Add(2 * time.Second)
	for len(states) < 4 && time.Now().Before(deadline) {
		mu.Unlock()
		time.Sleep(5 * time.Millisecond)
		mu.Lock()
	}
	if len(states) != 4 || !states[0] || states[1] || !states[2] || states[3] {
		t.Fatalf("state notifications %v", states)
	}
}

func TestUptimeAndInterfaces(t *testing.T) {
	if Uptime() <= 0 {
		t.Fatal("uptime not positive")
	}
	for _, i := range Interfaces() {
		if i.Name == "" || (len(i.IPv4)+len(i.IPv6)) == 0 {
			t.Fatalf("bad interface %+v", i)
		}
	}
	if len(broadcastAddresses()) == 0 {
		t.Fatal("no broadcast address")
	}
}
