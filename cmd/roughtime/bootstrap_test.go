// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

//go:build unix

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/mldsa"
	"github.com/tannerryan/roughtime/protocol"
)

// withSeedFile writes an Ed25519 seed with permissions no broader than 0600.
func withSeedFile(t *testing.T) (string, ed25519.PublicKey) {
	t.Helper()
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	seed := sk.Seed()
	path := filepath.Join(t.TempDir(), "seed.hex")
	if err := os.WriteFile(path, []byte(hex.EncodeToString(seed)+"\n"), 0600); err != nil {
		t.Fatalf("write seed: %v", err)
	}
	return path, pk
}

// withPQSeedFile writes a headered ML-DSA-44 seed with permissions no broader
// than 0600.
func withPQSeedFile(t *testing.T) (string, []byte) {
	t.Helper()
	sk, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("mldsa gen: %v", err)
	}
	path := filepath.Join(t.TempDir(), "pq.hex")
	raw := []byte(mldsa44SeedHeader + "\n" + hex.EncodeToString(sk.Bytes()) + "\n")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatalf("write PQ seed: %v", err)
	}
	return path, sk.PublicKey().Bytes()
}

// setRootKeyPath swaps *rootKeySeedHexFile for the test and restores on
// cleanup.
func setRootKeyPath(t *testing.T, path string) {
	t.Helper()
	prev := *rootKeySeedHexFile
	*rootKeySeedHexFile = path
	t.Cleanup(func() { *rootKeySeedHexFile = prev })
}

// setPQRootKeyPath swaps *pqRootKeySeedHexFile for the test and restores on
// cleanup.
func setPQRootKeyPath(t *testing.T, path string) {
	t.Helper()
	prev := *pqRootKeySeedHexFile
	*pqRootKeySeedHexFile = path
	t.Cleanup(func() { *pqRootKeySeedHexFile = prev })
}

// TestValidateFlagsRejects covers invalid required and range settings.
func TestValidateFlagsRejects(t *testing.T) {
	// Cases cover invalid required and range settings.
	cases := []struct {
		name string
		mut  func(t *testing.T)
		want string
	}{
		{"missing root-key-file", func(t *testing.T) { setRootKeyPath(t, "") }, "usage:"},
		{"port too low", func(t *testing.T) {
			setRootKeyPath(t, "/x")
			prev := *port
			*port = 0
			t.Cleanup(func() { *port = prev })
		}, "-port"},
		{"port too high", func(t *testing.T) {
			setRootKeyPath(t, "/x")
			prev := *port
			*port = 70000
			t.Cleanup(func() { *port = prev })
		}, "-port"},
		{"grease rate negative", func(t *testing.T) {
			setRootKeyPath(t, "/x")
			prev := *greaseRate
			*greaseRate = -0.1
			t.Cleanup(func() { *greaseRate = prev })
		}, "-grease-rate"},
		{"grease rate over one", func(t *testing.T) {
			setRootKeyPath(t, "/x")
			prev := *greaseRate
			*greaseRate = 1.5
			t.Cleanup(func() { *greaseRate = prev })
		}, "-grease-rate"},
		{"stats interval zero", func(t *testing.T) {
			setRootKeyPath(t, "/x")
			prev := *statsInterval
			*statsInterval = 0
			t.Cleanup(func() { *statsInterval = prev })
		}, "-stats-interval"},
		{"stats interval negative", func(t *testing.T) {
			setRootKeyPath(t, "/x")
			prev := *statsInterval
			*statsInterval = -time.Second
			t.Cleanup(func() { *statsInterval = prev })
		}, "-stats-interval"},
		{"stats interval below floor", func(t *testing.T) {
			setRootKeyPath(t, "/x")
			prev := *statsInterval
			*statsInterval = 500 * time.Millisecond
			t.Cleanup(func() { *statsInterval = prev })
		}, "-stats-interval"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.mut(t)
			err := validateFlags()
			if err == nil {
				t.Fatalf("validateFlags() want error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("validateFlags() err=%q, want contains %q", err, tc.want)
			}
		})
	}
}

// TestGenerateKeypairSuccess covers Ed25519 seed generation.
func TestGenerateKeypairSuccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "new.hex")
	if err := generateKeypair(path); err != nil {
		t.Fatalf("generateKeypair: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0600 {
		t.Fatalf("mode=%#o want 0600", mode)
	}
	raw, _ := os.ReadFile(path)
	if !strings.HasPrefix(strings.TrimSpace(string(raw)), ed25519SeedHeader) {
		t.Fatalf("seed file missing header %q", ed25519SeedHeader)
	}
	hexPart := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(raw)), ed25519SeedHeader))
	seed, err := hex.DecodeString(hexPart)
	if err != nil {
		t.Fatalf("seed decode: %v", err)
	}
	if len(seed) != ed25519.SeedSize {
		t.Fatalf("seed size=%d want %d", len(seed), ed25519.SeedSize)
	}
}

// TestGenerateKeypairRefusesOverwrite covers existing seed paths.
func TestGenerateKeypairRefusesOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "exists.hex")
	if err := os.WriteFile(path, []byte("placeholder"), 0600); err != nil {
		t.Fatalf("pre-write: %v", err)
	}
	err := generateKeypair(path)
	if err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("generateKeypair want refusing-to-overwrite error, got %v", err)
	}
}

// TestGeneratePQKeypairSuccess covers ML-DSA-44 seed generation.
func TestGeneratePQKeypairSuccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pq.hex")
	if err := generateMLDSA44Keypair(path); err != nil {
		t.Fatalf("generateMLDSA44Keypair: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0600 {
		t.Fatalf("mode=%#o want 0600", mode)
	}
	raw, _ := os.ReadFile(path)
	if !strings.HasPrefix(strings.TrimSpace(string(raw)), mldsa44SeedHeader) {
		t.Fatalf("PQ seed file missing %q header", mldsa44SeedHeader)
	}
	hexPart := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(raw)), mldsa44SeedHeader))
	seed, err := hex.DecodeString(hexPart)
	if err != nil {
		t.Fatalf("seed decode: %v", err)
	}
	if len(seed) != mldsa.PrivateKeySize {
		t.Fatalf("seed size=%d want %d", len(seed), mldsa.PrivateKeySize)
	}
}

// TestDerivePublicKeySuccess covers valid Ed25519 seed loading.
func TestDerivePublicKeySuccess(t *testing.T) {
	path, _ := withSeedFile(t)
	if err := derivePublicKey(path); err != nil {
		t.Fatalf("derivePublicKey: %v", err)
	}
}

// TestDerivePublicKeyRejectsInsecureMode covers group/world-readable seeds.
func TestDerivePublicKeyRejectsInsecureMode(t *testing.T) {
	path, _ := withSeedFile(t)
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	err := derivePublicKey(path)
	if err == nil || !strings.Contains(err.Error(), "insecure mode") {
		t.Fatalf("derivePublicKey want insecure-mode error, got %v", err)
	}
}

// TestDerivePQPublicKeySuccess covers valid ML-DSA-44 seed loading.
func TestDerivePQPublicKeySuccess(t *testing.T) {
	path, _ := withPQSeedFile(t)
	if err := deriveMLDSA44PublicKey(path); err != nil {
		t.Fatalf("deriveMLDSA44PublicKey: %v", err)
	}
}

// TestProvisionCertificateKeySuccess covers Ed25519 delegation provisioning.
func TestProvisionCertificateKeySuccess(t *testing.T) {
	path, wantPK := withSeedFile(t)
	setRootKeyPath(t, path)

	cert, onlinePK, rootPK, expiry, err := provisionCertificateKey()
	if err != nil {
		t.Fatalf("provisionCertificateKey: %v", err)
	}
	if cert == nil {
		t.Fatal("cert is nil")
	}
	if len(onlinePK) != ed25519.PublicKeySize {
		t.Fatalf("online pk size=%d", len(onlinePK))
	}
	if string(rootPK) != string(wantPK) {
		t.Fatalf("rootPK mismatch")
	}
	if remaining := time.Until(expiry); remaining < certEndOffset-time.Minute {
		t.Fatalf("expiry too soon: %s", remaining)
	}
}

// TestProvisionPQCertificateKeySuccess covers ML-DSA-44 provisioning.
func TestProvisionPQCertificateKeySuccess(t *testing.T) {
	path, wantPK := withPQSeedFile(t)
	setPQRootKeyPath(t, path)

	cert, onlinePK, rootPK, expiry, err := provisionMLDSA44CertificateKey()
	if err != nil {
		t.Fatalf("provisionMLDSA44CertificateKey: %v", err)
	}
	if cert == nil {
		t.Fatal("cert is nil")
	}
	if len(onlinePK) != mldsa.MLDSA44PublicKeySize {
		t.Fatalf("online pk size=%d want %d", len(onlinePK), mldsa.MLDSA44PublicKeySize)
	}
	if !bytes.Equal(rootPK, wantPK) {
		t.Fatal("rootPK mismatch")
	}
	if remaining := time.Until(expiry); remaining < certEndOffset-time.Minute {
		t.Fatalf("expiry too soon: %s", remaining)
	}
}

// TestTryRefreshCertSuccess covers Ed25519 certificate refresh.
func TestTryRefreshCertSuccess(t *testing.T) {
	path, pk := withSeedFile(t)
	setRootKeyPath(t, path)

	newState, newOnlinePK, err := tryRefreshCert(pk)
	if err != nil {
		t.Fatalf("tryRefreshCert: %v", err)
	}
	if newState == nil || newState.cert == nil {
		t.Fatal("newState or cert nil")
	}
	if len(newOnlinePK) != ed25519.PublicKeySize {
		t.Fatal("online pk wrong size")
	}
	if got, want := newState.srvHash, protocol.ComputeSRV(pk); string(got) != string(want) {
		t.Fatal("srvHash does not match rootPK")
	}
}

// TestTryRefreshCertRejectsChangedRoot covers root identity changes.
func TestTryRefreshCertRejectsChangedRoot(t *testing.T) {
	path, _ := withSeedFile(t)
	setRootKeyPath(t, path)

	otherPK, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen other: %v", err)
	}
	_, _, err = tryRefreshCert(otherPK)
	if err == nil || !strings.Contains(err.Error(), "root public key on disk has changed") {
		t.Fatalf("tryRefreshCert want identity error, got %v", err)
	}
}

// TestParseSeedAcceptsHeader covers headered seed parsing.
func TestParseSeedAcceptsHeader(t *testing.T) {
	seed := bytes.Repeat([]byte{0x77}, mldsa.PrivateKeySize)
	raw := []byte(mldsa44SeedHeader + "\n" + hex.EncodeToString(seed))
	got, err := parseSeed(raw, "headered.hex", mldsa44SeedHeader, "PQ", mldsa.PrivateKeySize, false)
	if err != nil {
		t.Fatalf("parseSeed: %v", err)
	}
	if !bytes.Equal(got, seed) {
		t.Fatal("parseSeed returned wrong bytes")
	}
}

// TestParseSeedRejectsCrossScheme covers scheme-bound seed headers.
func TestParseSeedRejectsCrossScheme(t *testing.T) {
	seed := bytes.Repeat([]byte{0xaa}, 32)
	raw := []byte(ed25519SeedHeader + "\n" + hex.EncodeToString(seed))
	_, err := parseSeed(raw, "cross.hex", mldsa44SeedHeader, "PQ", mldsa.PrivateKeySize, false)
	if err == nil {
		t.Fatal("parseSeed accepted a cross-scheme file")
	}
}
