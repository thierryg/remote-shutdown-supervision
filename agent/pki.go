// =============================================================================
// Remote Shutdown - LAN parental control and machine management (master/agent)
// -----------------------------------------------------------------------------
// File    : agent/pki.go
// Purpose : Agent credentials: key/CSR generation, storage, mutual-TLS configuration, CA pinning
// Author  : Thierry Gayet <thierry.gayet@labworks.fr>
// Project : remote-shutdown (version: VERSION)
// Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
// =============================================================================

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"
)

// File names in the state directory.
const (
	keyFile  = "client.key"
	certFile = "client.crt"
	caFile   = "ca.crt"
)

// renewBefore is how long before expiry the agent asks for a new certificate.
const renewBefore = 30 * 24 * time.Hour

// newKeyAndCSR generates an ECDSA P-256 key and a CSR (the master chooses the subject).
func newKeyAndCSR(hostname string) (*ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: hostname},
	}, key)
	if err != nil {
		return nil, nil, err
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// publicKeyMatches reports whether a certificate carries the public key of key.
func publicKeyMatches(cert *x509.Certificate, key *ecdsa.PrivateKey) bool {
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	return ok && pub.Equal(&key.PublicKey)
}

// keyPEM encodes a private key as PKCS#8 PEM.
func keyPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// parseCertPEM decodes the first certificate of a PEM document.
func parseCertPEM(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("no PEM certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

// certFingerprint returns the SHA-256 fingerprint (lowercase hex) of a certificate.
func certFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// saveCredentials stores the key, the client certificate and the CA (key and cert 0600).
func saveCredentials(cfg *Config, key *ecdsa.PrivateKey, certPEM, caPEM []byte) error {
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return err
	}
	if err := secureDir(cfg.StateDir); err != nil {
		logger.Warn("cannot restrict the state directory permissions", "dir", cfg.StateDir, "error", err)
	}
	kp, err := keyPEM(key)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(cfg.statePath(keyFile), kp, 0o600); err != nil {
		return err
	}
	if err := writeFileAtomic(cfg.statePath(certFile), certPEM, 0o600); err != nil {
		return err
	}
	return writeFileAtomic(cfg.statePath(caFile), caPEM, 0o644)
}

// IsEnrolled reports whether a key and a certificate are present.
func IsEnrolled(cfg *Config) bool {
	for _, name := range []string{keyFile, certFile, caFile} {
		if _, err := os.Stat(cfg.statePath(name)); err != nil {
			return false
		}
	}
	return true
}

// CertificateInfo returns the agent id (certificate CN) and the expiry of the certificate.
func CertificateInfo(cfg *Config) (string, time.Time, error) {
	data, err := os.ReadFile(cfg.statePath(certFile))
	if err != nil {
		return "", time.Time{}, err
	}
	cert, err := parseCertPEM(data)
	if err != nil {
		return "", time.Time{}, err
	}
	return cert.Subject.CommonName, cert.NotAfter, nil
}

// RemoveCredentials deletes the key, the certificates and the state file.
func RemoveCredentials(cfg *Config) error {
	for _, name := range []string{keyFile, certFile, caFile, "state.json"} {
		if err := os.Remove(cfg.statePath(name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

// loadCAPool reads the stored CA certificate.
func loadCAPool(cfg *Config) (*x509.CertPool, *x509.Certificate, error) {
	data, err := os.ReadFile(cfg.statePath(caFile))
	if err != nil {
		return nil, nil, err
	}
	ca, err := parseCertPEM(data)
	if err != nil {
		return nil, nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return pool, ca, nil
}

// verifyMasterChain checks that the peer chain is issued by the trusted CA for server use.
//
// The host name is deliberately not checked: the CA is private and dedicated, and only the
// master holds a certificate with the serverAuth usage (agents get clientAuth only), so the
// chain alone identifies the master even when its DHCP address changes.
func verifyMasterChain(cs tls.ConnectionState, roots *x509.CertPool) error {
	if len(cs.PeerCertificates) == 0 {
		return errors.New("no server certificate")
	}
	inter := x509.NewCertPool()
	for _, c := range cs.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		return fmt.Errorf("master certificate not trusted: %w", err)
	}
	return nil
}

// pinnedTLSConfig trusts only a master whose chain contains the CA with the given fingerprint
// (used for enrollment, before the CA is stored locally).
func pinnedTLSConfig(fingerprint string) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // replaced by the pinning check below  #nosec G402
		VerifyConnection: func(cs tls.ConnectionState) error {
			for _, c := range cs.PeerCertificates {
				if c.IsCA && certFingerprint(c) == fingerprint {
					pool := x509.NewCertPool()
					pool.AddCert(c)
					return verifyMasterChain(cs, pool)
				}
			}
			return errors.New("the master CA does not match the pinned fingerprint")
		},
	}
}

// mutualTLSConfig returns the client configuration for the agent hub connection.
func mutualTLSConfig(cfg *Config) (*tls.Config, error) {
	pool, _, err := loadCAPool(cfg)
	if err != nil {
		return nil, err
	}
	pair, err := tls.LoadX509KeyPair(cfg.statePath(certFile), cfg.statePath(keyFile))
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		Certificates:       []tls.Certificate{pair},
		InsecureSkipVerify: true, // replaced by verifyMasterChain (no host name check)  #nosec G402
		VerifyConnection: func(cs tls.ConnectionState) error {
			return verifyMasterChain(cs, pool)
		},
	}, nil
}

// webTLSConfig trusts the stored CA for HTTPS calls to the master (no client certificate).
func webTLSConfig(cfg *Config) (*tls.Config, error) {
	pool, _, err := loadCAPool(cfg)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // replaced by verifyMasterChain  #nosec G402
		VerifyConnection: func(cs tls.ConnectionState) error {
			return verifyMasterChain(cs, pool)
		},
	}, nil
}
