// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

//go:build unix

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/mldsa"
	"github.com/tannerryan/roughtime/protocol"
	"go.uber.org/zap"
)

// withSeedFile writes a fresh Ed25519 seed at 0600 and returns its path and
// public key.
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

// withPQSeedFile writes a fresh headered ML-DSA-44 seed at 0600.
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

// withInterval swaps a duration variable for the test and restores on cleanup.
func withInterval(t *testing.T, v *time.Duration, d time.Duration) {
	t.Helper()
	prev := *v
	*v = d
	t.Cleanup(func() { *v = prev })
}

// TestValidateFlagsAccepts verifies validateFlags accepts a configuration with
// only an Ed25519 key path.
func TestValidateFlagsAccepts(t *testing.T) {
	setRootKeyPath(t, "/nonexistent")
	if err := validateFlags(); err != nil {
		t.Fatalf("validateFlags() err=%v, want nil", err)
	}
}

// TestValidateFlagsAcceptsPQOnly verifies validateFlags accepts a PQ-only
// configuration.
func TestValidateFlagsAcceptsPQOnly(t *testing.T) {
	setRootKeyPath(t, "")
	setPQRootKeyPath(t, "/nonexistent/pq")
	if err := validateFlags(); err != nil {
		t.Fatalf("validateFlags() err=%v, want nil", err)
	}
}

// TestValidateFlagsRejectsBothEmpty verifies validateFlags rejects when neither
// key flag is set.
func TestValidateFlagsRejectsBothEmpty(t *testing.T) {
	setRootKeyPath(t, "")
	setPQRootKeyPath(t, "")
	err := validateFlags()
	if err == nil || !strings.Contains(err.Error(), "usage:") {
		t.Fatalf("validateFlags() err=%v, want usage error", err)
	}
}

// TestValidateFlagsRejects verifies validateFlags rejects each invalid flag
// combination.
func TestValidateFlagsRejects(t *testing.T) {
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

// TestGenerateKeypairSuccess verifies generateKeypair writes a 0600 file with
// the Ed25519 scheme header.
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

// TestGenerateKeypairRefusesOverwrite verifies generateKeypair refuses to
// overwrite an existing file.
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

// TestGeneratePQKeypairSuccess verifies generateMLDSA44Keypair writes a 0600
// headered seed file.
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

// TestGeneratePQKeypairRefusesOverwrite verifies generateMLDSA44Keypair refuses
// to overwrite an existing file.
func TestGeneratePQKeypairRefusesOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pq.hex")
	if err := os.WriteFile(path, []byte("placeholder"), 0600); err != nil {
		t.Fatalf("pre-write: %v", err)
	}
	err := generateMLDSA44Keypair(path)
	if err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("generateMLDSA44Keypair want refusing-to-overwrite error, got %v", err)
	}
}

// TestDerivePublicKeySuccess verifies derivePublicKey accepts a valid Ed25519
// seed file.
func TestDerivePublicKeySuccess(t *testing.T) {
	path, _ := withSeedFile(t)
	if err := derivePublicKey(path); err != nil {
		t.Fatalf("derivePublicKey: %v", err)
	}
}

// TestDerivePublicKeyMissingFile verifies derivePublicKey reports
// fs.ErrNotExist for a missing file.
func TestDerivePublicKeyMissingFile(t *testing.T) {
	err := derivePublicKey(filepath.Join(t.TempDir(), "nope.hex"))
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("derivePublicKey want fs.ErrNotExist, got %v", err)
	}
}

// TestDerivePublicKeyBadSeed verifies derivePublicKey rejects non-hex content.
func TestDerivePublicKeyBadSeed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.hex")
	if err := os.WriteFile(path, []byte("not-hex-!@#"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	err := derivePublicKey(path)
	if err == nil || !strings.Contains(err.Error(), "decoding seed") {
		t.Fatalf("derivePublicKey want decode error, got %v", err)
	}
}

// TestDerivePublicKeyWrongSize verifies derivePublicKey rejects a seed with the
// wrong byte length.
func TestDerivePublicKeyWrongSize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "short.hex")
	if err := os.WriteFile(path, []byte(hex.EncodeToString([]byte{1, 2, 3})), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	err := derivePublicKey(path)
	if err == nil || !strings.Contains(err.Error(), "bytes, want") {
		t.Fatalf("derivePublicKey want size error, got %v", err)
	}
}

// TestDerivePublicKeyRejectsInsecureMode verifies derivePublicKey rejects a
// seed file with permissive mode.
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

// TestDerivePublicKeyRejectsSymlink verifies derivePublicKey refuses to follow
// a symlink.
func TestDerivePublicKeyRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target, _ := withSeedFile(t)
	link := filepath.Join(dir, "link.hex")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	err := derivePublicKey(link)
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("derivePublicKey want symlink error, got %v", err)
	}
}

// TestDerivePQPublicKeySuccess verifies deriveMLDSA44PublicKey accepts a valid
// headered seed.
func TestDerivePQPublicKeySuccess(t *testing.T) {
	path, _ := withPQSeedFile(t)
	if err := deriveMLDSA44PublicKey(path); err != nil {
		t.Fatalf("deriveMLDSA44PublicKey: %v", err)
	}
}

// TestDerivePQPublicKeyMissingFile verifies deriveMLDSA44PublicKey reports
// fs.ErrNotExist for a missing file.
func TestDerivePQPublicKeyMissingFile(t *testing.T) {
	err := deriveMLDSA44PublicKey(filepath.Join(t.TempDir(), "nope.hex"))
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("deriveMLDSA44PublicKey want fs.ErrNotExist, got %v", err)
	}
}

// TestDerivePQPublicKeyRejectsBareHex verifies deriveMLDSA44PublicKey rejects
// bare hex without the scheme header.
func TestDerivePQPublicKeyRejectsBareHex(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bare.hex")
	seed := bytes.Repeat([]byte{0x41}, mldsa.PrivateKeySize)
	if err := os.WriteFile(path, []byte(hex.EncodeToString(seed)), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	err := deriveMLDSA44PublicKey(path)
	if err == nil || !strings.Contains(err.Error(), "missing") || !strings.Contains(err.Error(), "header") {
		t.Fatalf("deriveMLDSA44PublicKey want header-missing error, got %v", err)
	}
}

// TestDerivePQPublicKeyRejectsInsecureMode verifies deriveMLDSA44PublicKey
// rejects a seed file with permissive mode.
func TestDerivePQPublicKeyRejectsInsecureMode(t *testing.T) {
	path, _ := withPQSeedFile(t)
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	err := deriveMLDSA44PublicKey(path)
	if err == nil || !strings.Contains(err.Error(), "insecure mode") {
		t.Fatalf("deriveMLDSA44PublicKey want insecure-mode error, got %v", err)
	}
}

// TestDerivePQPublicKeyRejectsSymlink verifies deriveMLDSA44PublicKey refuses
// to follow a symlink.
func TestDerivePQPublicKeyRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target, _ := withPQSeedFile(t)
	link := filepath.Join(dir, "link.hex")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	err := deriveMLDSA44PublicKey(link)
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("deriveMLDSA44PublicKey want symlink error, got %v", err)
	}
}

// TestProvisionCertificateKeySuccess verifies provisionCertificateKey returns a
// fresh cert and matching root key.
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

// TestProvisionCertificateKeyRejectsInsecureMode verifies
// provisionCertificateKey rejects a seed file with permissive mode.
func TestProvisionCertificateKeyRejectsInsecureMode(t *testing.T) {
	path, _ := withSeedFile(t)
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	setRootKeyPath(t, path)
	_, _, _, _, err := provisionCertificateKey()
	if err == nil || !strings.Contains(err.Error(), "insecure mode") {
		t.Fatalf("provisionCertificateKey want insecure-mode error, got %v", err)
	}
}

// TestProvisionCertificateKeyRejectsMissing verifies provisionCertificateKey
// reports a stat error for a missing file.
func TestProvisionCertificateKeyRejectsMissing(t *testing.T) {
	setRootKeyPath(t, filepath.Join(t.TempDir(), "nope.hex"))
	_, _, _, _, err := provisionCertificateKey()
	if err == nil || !strings.Contains(err.Error(), "stat root key file") {
		t.Fatalf("provisionCertificateKey want stat error, got %v", err)
	}
}

// TestProvisionCertificateKeyRejectsBadSeed verifies provisionCertificateKey
// rejects non-hex content.
func TestProvisionCertificateKeyRejectsBadSeed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.hex")
	if err := os.WriteFile(path, []byte("not-hex-!@#"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	setRootKeyPath(t, path)
	_, _, _, _, err := provisionCertificateKey()
	if err == nil || !strings.Contains(err.Error(), "decoding") {
		t.Fatalf("provisionCertificateKey want decode error, got %v", err)
	}
}

// TestProvisionCertificateKeyRejectsWrongSize verifies provisionCertificateKey
// rejects a seed of the wrong byte length.
func TestProvisionCertificateKeyRejectsWrongSize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "short.hex")
	if err := os.WriteFile(path, []byte(hex.EncodeToString([]byte{1, 2, 3})), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	setRootKeyPath(t, path)
	_, _, _, _, err := provisionCertificateKey()
	if err == nil || !strings.Contains(err.Error(), "bytes, want") {
		t.Fatalf("provisionCertificateKey want size error, got %v", err)
	}
}

// TestProvisionCertificateKeyRejectsSymlink verifies provisionCertificateKey
// refuses to follow a symlink.
func TestProvisionCertificateKeyRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target, _ := withSeedFile(t)
	link := filepath.Join(dir, "link.hex")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	setRootKeyPath(t, link)
	_, _, _, _, err := provisionCertificateKey()
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("provisionCertificateKey want symlink error, got %v", err)
	}
}

// TestProvisionPQCertificateKeySuccess verifies provisionMLDSA44CertificateKey
// returns a fresh cert and matching root key.
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

// TestProvisionPQCertificateKeyRejectsInsecureMode verifies
// provisionMLDSA44CertificateKey rejects a seed file with permissive mode.
func TestProvisionPQCertificateKeyRejectsInsecureMode(t *testing.T) {
	path, _ := withPQSeedFile(t)
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	setPQRootKeyPath(t, path)
	_, _, _, _, err := provisionMLDSA44CertificateKey()
	if err == nil || !strings.Contains(err.Error(), "insecure mode") {
		t.Fatalf("provisionMLDSA44CertificateKey want insecure-mode error, got %v", err)
	}
}

// TestProvisionPQCertificateKeyRejectsMissing verifies
// provisionMLDSA44CertificateKey reports a stat error for a missing file.
func TestProvisionPQCertificateKeyRejectsMissing(t *testing.T) {
	setPQRootKeyPath(t, filepath.Join(t.TempDir(), "nope.hex"))
	_, _, _, _, err := provisionMLDSA44CertificateKey()
	if err == nil || !strings.Contains(err.Error(), "stat PQ root key file") {
		t.Fatalf("provisionMLDSA44CertificateKey want stat error, got %v", err)
	}
}

// TestProvisionPQCertificateKeyRejectsBareHex verifies
// provisionMLDSA44CertificateKey rejects bare hex without the scheme header.
func TestProvisionPQCertificateKeyRejectsBareHex(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bare.hex")
	seed := bytes.Repeat([]byte{0x5a}, mldsa.PrivateKeySize)
	if err := os.WriteFile(path, []byte(hex.EncodeToString(seed)), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	setPQRootKeyPath(t, path)
	_, _, _, _, err := provisionMLDSA44CertificateKey()
	if err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("provisionMLDSA44CertificateKey want missing-header error, got %v", err)
	}
}

// TestProvisionPQCertificateKeyRejectsWrongSize verifies
// provisionMLDSA44CertificateKey rejects a seed of the wrong byte length.
func TestProvisionPQCertificateKeyRejectsWrongSize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "short.hex")
	raw := []byte(mldsa44SeedHeader + "\n" + hex.EncodeToString([]byte{1, 2, 3}) + "\n")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	setPQRootKeyPath(t, path)
	_, _, _, _, err := provisionMLDSA44CertificateKey()
	if err == nil || !strings.Contains(err.Error(), "bytes, want") {
		t.Fatalf("provisionMLDSA44CertificateKey want size error, got %v", err)
	}
}

// TestTryRefreshCertSuccess verifies tryRefreshCert returns a fresh certState
// and online public key.
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

// TestTryRefreshCertRejectsChangedRoot verifies tryRefreshCert rejects a
// refresh when the on-disk root key has changed.
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

// TestTryRefreshCertPropagatesProvisionErr verifies tryRefreshCert surfaces
// provisioning errors verbatim.
func TestTryRefreshCertPropagatesProvisionErr(t *testing.T) {
	setRootKeyPath(t, filepath.Join(t.TempDir(), "nope.hex"))
	pk, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	_, _, err = tryRefreshCert(pk)
	if err == nil || !strings.Contains(err.Error(), "stat root key file") {
		t.Fatalf("tryRefreshCert want provision error, got %v", err)
	}
}

// TestTryRefreshCertPQSuccess verifies tryRefreshCertMLDSA44 returns a fresh
// certState and online public key.
func TestTryRefreshCertPQSuccess(t *testing.T) {
	path, pk := withPQSeedFile(t)
	setPQRootKeyPath(t, path)

	newState, newOnlinePK, err := tryRefreshCertMLDSA44(pk)
	if err != nil {
		t.Fatalf("tryRefreshCertMLDSA44: %v", err)
	}
	if newState == nil || newState.cert == nil {
		t.Fatal("newState or cert nil")
	}
	if len(newOnlinePK) != mldsa.MLDSA44PublicKeySize {
		t.Fatal("online pk wrong size")
	}
	if got, want := newState.srvHash, protocol.ComputeSRV(pk); !bytes.Equal(got, want) {
		t.Fatal("srvHash does not match rootPK")
	}
}

// TestTryRefreshCertPQRejectsChangedRoot verifies tryRefreshCertMLDSA44 rejects
// a refresh when the on-disk root key has changed.
func TestTryRefreshCertPQRejectsChangedRoot(t *testing.T) {
	path, _ := withPQSeedFile(t)
	setPQRootKeyPath(t, path)

	other, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("gen other: %v", err)
	}
	_, _, err = tryRefreshCertMLDSA44(other.PublicKey().Bytes())
	if err == nil || !strings.Contains(err.Error(), "PQ root public key on disk has changed") {
		t.Fatalf("tryRefreshCertMLDSA44 want identity error, got %v", err)
	}
}

// TestTryRefreshCertPQPropagatesProvisionErr verifies tryRefreshCertMLDSA44
// surfaces provisioning errors verbatim.
func TestTryRefreshCertPQPropagatesProvisionErr(t *testing.T) {
	setPQRootKeyPath(t, filepath.Join(t.TempDir(), "nope.hex"))
	other, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	if _, _, err := tryRefreshCertMLDSA44(other.PublicKey().Bytes()); err == nil ||
		!strings.Contains(err.Error(), "stat PQ root key file") {
		t.Fatalf("tryRefreshCertMLDSA44 want provision error, got %v", err)
	}
}

// TestProvisionCertificateKeyRejectsDirectory verifies provisionCertificateKey
// rejects a directory path.
func TestProvisionCertificateKeyRejectsDirectory(t *testing.T) {
	setRootKeyPath(t, t.TempDir())
	_, _, _, _, err := provisionCertificateKey()
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("provisionCertificateKey: %v; want not-a-regular-file error", err)
	}
}

// TestRefreshLoopRefreshesNearExpiry verifies refreshLoop swaps in a new
// certState once expiry crosses the threshold.
func TestRefreshLoopRefreshesNearExpiry(t *testing.T) {
	withInterval(t, &certCheckInterval, 5*time.Millisecond)
	withInterval(t, &certRefreshThreshold, time.Hour)
	withInterval(t, &refreshRetryCooldown, time.Millisecond)

	path, pk := withSeedFile(t)
	setRootKeyPath(t, path)

	// expiry below threshold triggers refresh on first tick
	_, stSeed := newUnitCertState(t)
	stSeed.expiry = time.Now().Add(time.Minute)
	statePtr := &atomic.Pointer[certState]{}
	statePtr.Store(stSeed)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	refreshLoop(ctx, zap.NewNop(), statePtr, pk)

	got := statePtr.Load()
	if got == stSeed {
		t.Fatal("refreshLoop did not replace certState")
	}
	if remaining := time.Until(got.expiry); remaining < time.Hour {
		t.Fatalf("post-refresh expiry too soon: %s", remaining)
	}
}

// TestRefreshLoopLogsErrorOnIdentityChange verifies refreshLoop preserves the
// prior certState when the root identity changes.
func TestRefreshLoopLogsErrorOnIdentityChange(t *testing.T) {
	withInterval(t, &certCheckInterval, 5*time.Millisecond)
	withInterval(t, &certRefreshThreshold, time.Hour)
	withInterval(t, &refreshRetryCooldown, time.Millisecond)

	path, _ := withSeedFile(t)
	setRootKeyPath(t, path)

	otherPK, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen other: %v", err)
	}

	_, stSeed := newUnitCertState(t)
	stSeed.expiry = time.Now().Add(time.Minute)
	statePtr := &atomic.Pointer[certState]{}
	statePtr.Store(stSeed)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	refreshLoop(ctx, zap.NewNop(), statePtr, otherPK)

	if statePtr.Load() != stSeed {
		t.Fatal("refreshLoop replaced certState despite identity mismatch")
	}
}

// TestRefreshLoopSkipsWhenNotNearExpiry verifies refreshLoop leaves the
// certState alone when expiry is healthy.
func TestRefreshLoopSkipsWhenNotNearExpiry(t *testing.T) {
	withInterval(t, &certCheckInterval, 5*time.Millisecond)
	withInterval(t, &certRefreshThreshold, time.Minute)
	withInterval(t, &refreshRetryCooldown, time.Millisecond)

	path, pk := withSeedFile(t)
	setRootKeyPath(t, path)

	_, stSeed := newUnitCertState(t)
	stSeed.expiry = time.Now().Add(time.Hour)
	statePtr := &atomic.Pointer[certState]{}
	statePtr.Store(stSeed)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	refreshLoop(ctx, zap.NewNop(), statePtr, pk)

	if statePtr.Load() != stSeed {
		t.Fatal("refreshLoop refreshed despite healthy expiry")
	}
}

// TestRefreshLoopPQRefreshesNearExpiry verifies refreshLoopMLDSA44 swaps in a
// new certState once expiry crosses the threshold.
func TestRefreshLoopPQRefreshesNearExpiry(t *testing.T) {
	withInterval(t, &certCheckInterval, 5*time.Millisecond)
	withInterval(t, &certRefreshThreshold, time.Hour)
	withInterval(t, &refreshRetryCooldown, time.Millisecond)

	path, pk := withPQSeedFile(t)
	setPQRootKeyPath(t, path)

	// seed state with an arbitrary cert; refresh path overwrites it
	_, stSeed := newUnitCertState(t)
	stSeed.expiry = time.Now().Add(time.Minute)
	statePtr := &atomic.Pointer[certState]{}
	statePtr.Store(stSeed)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	refreshLoopMLDSA44(ctx, zap.NewNop(), statePtr, pk)

	got := statePtr.Load()
	if got == stSeed {
		t.Fatal("refreshLoopMLDSA44 did not replace certState")
	}
	if remaining := time.Until(got.expiry); remaining < time.Hour {
		t.Fatalf("post-refresh expiry too soon: %s", remaining)
	}
}

// TestRefreshLoopPQLogsErrorOnIdentityChange verifies refreshLoopMLDSA44
// preserves the prior certState when the root identity changes.
func TestRefreshLoopPQLogsErrorOnIdentityChange(t *testing.T) {
	withInterval(t, &certCheckInterval, 5*time.Millisecond)
	withInterval(t, &certRefreshThreshold, time.Hour)
	withInterval(t, &refreshRetryCooldown, time.Millisecond)

	path, _ := withPQSeedFile(t)
	setPQRootKeyPath(t, path)

	other, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("gen other: %v", err)
	}

	_, stSeed := newUnitCertState(t)
	stSeed.expiry = time.Now().Add(time.Minute)
	statePtr := &atomic.Pointer[certState]{}
	statePtr.Store(stSeed)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	refreshLoopMLDSA44(ctx, zap.NewNop(), statePtr, other.PublicKey().Bytes())

	if statePtr.Load() != stSeed {
		t.Fatal("refreshLoopMLDSA44 replaced certState despite identity mismatch")
	}
}

// TestParseSeedAcceptsBareHex verifies parseSeed accepts bare hex when
// acceptBareHex is true.
func TestParseSeedAcceptsBareHex(t *testing.T) {
	seed := bytes.Repeat([]byte{0x33}, 32)
	raw := []byte(hex.EncodeToString(seed) + "\n")
	got, err := parseSeed(raw, "bare.hex", ed25519SeedHeader, "", 32, true)
	if err != nil {
		t.Fatalf("parseSeed: %v", err)
	}
	if !bytes.Equal(got, seed) {
		t.Fatal("parseSeed returned wrong bytes")
	}
}

// TestParseSeedAcceptsHeader verifies parseSeed accepts a seed prefixed with
// the scheme header.
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

// TestParseSeedRejectsCrossScheme verifies parseSeed rejects a seed file
// headered for a different scheme.
func TestParseSeedRejectsCrossScheme(t *testing.T) {
	seed := bytes.Repeat([]byte{0xaa}, 32)
	raw := []byte(ed25519SeedHeader + "\n" + hex.EncodeToString(seed))
	_, err := parseSeed(raw, "cross.hex", mldsa44SeedHeader, "PQ", mldsa.PrivateKeySize, false)
	if err == nil {
		t.Fatal("parseSeed accepted a cross-scheme file")
	}
}

// TestParseSeedRejectsHeaderWithoutBoundary verifies parseSeed requires a
// whitespace boundary between header and payload.
func TestParseSeedRejectsHeaderWithoutBoundary(t *testing.T) {
	seed := bytes.Repeat([]byte{0x55}, 32)
	raw := []byte(ed25519SeedHeader + "0" + hex.EncodeToString(seed))
	_, err := parseSeed(raw, "noboundary.hex", ed25519SeedHeader, "", 32, false)
	if err == nil {
		t.Fatal("parseSeed accepted a header with no whitespace boundary")
	}
}

// TestParseSeedRejectsBadHexPostHeader verifies parseSeed rejects non-hex
// payload following a valid header.
func TestParseSeedRejectsBadHexPostHeader(t *testing.T) {
	raw := []byte(ed25519SeedHeader + "\nNOT-HEX-CONTENT")
	_, err := parseSeed(raw, "badhex.hex", ed25519SeedHeader, "", 32, false)
	if err == nil {
		t.Fatal("parseSeed accepted non-hex content after header")
	}
}

// TestParseSeedHeaderTabSeparator verifies parseSeed accepts a tab between
// header and payload.
func TestParseSeedHeaderTabSeparator(t *testing.T) {
	seed := bytes.Repeat([]byte{0x66}, 32)
	raw := []byte(ed25519SeedHeader + "\t" + hex.EncodeToString(seed))
	got, err := parseSeed(raw, "tab.hex", ed25519SeedHeader, "", 32, false)
	if err != nil {
		t.Fatalf("parseSeed rejected tab separator: %v", err)
	}
	if !bytes.Equal(got, seed) {
		t.Fatal("parseSeed returned wrong bytes")
	}
}

// TestParseSeedRejectsEmpty verifies parseSeed rejects empty input.
func TestParseSeedRejectsEmpty(t *testing.T) {
	_, err := parseSeed(nil, "empty.hex", ed25519SeedHeader, "", 32, true)
	if err == nil {
		t.Fatal("parseSeed accepted empty input")
	}
}
