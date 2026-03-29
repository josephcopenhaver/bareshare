package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

func keyDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "."+cmdName)
}

// generateEphemeralKey creates a new P-384 key pair in memory without persisting it.
func generateEphemeralKey() (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral P-384 key: %w", err)
	}
	return key, nil
}

// loadKeyFromFile loads a P-384 private key from the given PEM file.
func loadKeyFromFile(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file %s: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM in %s", path)
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

// loadOrCreateKey loads the P-384 private key from ~/.bareshare/key.pem,
// generating a new one if it doesn't exist.
func loadOrCreateKey() (*ecdsa.PrivateKey, error) {
	dir := keyDir()
	path := filepath.Join(dir, "key.pem")

	if data, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("invalid PEM in %s", path)
		}
		return x509.ParseECPrivateKey(block.Bytes)
	}

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate P-384 key: %w", err)
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}

	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}

	pemData := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, pemData, 0600); err != nil {
		return nil, err
	}

	fmt.Fprintf(os.Stderr, "Generated new P-384 key pair in %s\n", path)
	return key, nil
}

// rotateKey generates a new P-384 key pair, replacing the existing one.
// Returns the new key and the old fingerprint (empty if there was no prior key).
func rotateKey() (newKey *ecdsa.PrivateKey, oldFP string, err error) {
	dir := keyDir()
	path := filepath.Join(dir, "key.pem")

	// Load existing key to capture old fingerprint.
	if data, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(data)
		if block != nil {
			if old, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
				oldFP = fingerprint(&old.PublicKey)
			}
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("generate P-384 key: %w", err)
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, "", err
	}

	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, "", err
	}

	pemData := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, pemData, 0600); err != nil {
		return nil, "", err
	}

	return key, oldFP, nil
}

// fingerprint returns the base64 (standard, no padding) encoded SHA-256
// digest of the SPKI-encoded public key.
func fingerprint(pub *ecdsa.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		panic(fmt.Errorf("marshal public key: %w", err))
	}
	hash := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// makeTLSCert creates an ephemeral self-signed certificate from the EC key.
func makeTLSCert(key *ecdsa.PrivateKey) (tls.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("marshal private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return tls.X509KeyPair(certPEM, keyPEM)
}

// verifyPeerFingerprint checks that the peer's certificate contains the expected
// public key by comparing SHA-256 fingerprints of the SPKI encoding.
func verifyPeerFingerprint(rawCerts [][]byte, expectedFP string) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("peer presented no certificate")
	}

	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("parse peer certificate: %w", err)
	}

	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("peer key is not ECDSA P-384")
	}
	if pub.Curve != elliptic.P384() {
		return fmt.Errorf("peer key is ECDSA but not P-384: got curve %s", pub.Curve.Params().Name)
	}

	fp := fingerprint(pub)
	if fp != expectedFP {
		return fmt.Errorf("peer fingerprint MISMATCH\n  expected: %s\n  got:      %s", expectedFP, fp)
	}

	return nil
}
