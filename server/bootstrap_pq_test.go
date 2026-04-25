// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"encoding/hex"
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

// setPQRootKeyPath swaps *pqRootKeySeedHexFile for the test's duration.
func setPQRootKeyPath(t *testing.T, path string) {
	t.Helper()
	prev := *pqRootKeySeedHexFile
	*pqRootKeySeedHexFile = path
	t.Cleanup(func() { *pqRootKeySeedHexFile = prev })
}

// TestValidateFlagsAcceptsPQOnly verifies a PQ-only config validates.
func TestValidateFlagsAcceptsPQOnly(t *testing.T) {
	setRootKeyPath(t, "")
	setPQRootKeyPath(t, "/nonexistent/pq")
	if err := validateFlags(); err != nil {
		t.Fatalf("validateFlags() err=%v, want nil", err)
	}
}

// TestValidateFlagsRejectsBothEmpty verifies missing both keys returns a usage
// error.
func TestValidateFlagsRejectsBothEmpty(t *testing.T) {
	setRootKeyPath(t, "")
	setPQRootKeyPath(t, "")
	err := validateFlags()
	if err == nil || !strings.Contains(err.Error(), "usage:") {
		t.Fatalf("validateFlags() err=%v, want usage error", err)
	}
}

// TestGeneratePQKeypairSuccess verifies a headered PQ seed is written at 0600.
func TestGeneratePQKeypairSuccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pq.hex")
	if err := generatePQKeypair(path); err != nil {
		t.Fatalf("generatePQKeypair: %v", err)
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

// TestGeneratePQKeypairRefusesOverwrite verifies an existing file is not
// clobbered.
func TestGeneratePQKeypairRefusesOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pq.hex")
	if err := os.WriteFile(path, []byte("placeholder"), 0600); err != nil {
		t.Fatalf("pre-write: %v", err)
	}
	err := generatePQKeypair(path)
	if err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("generatePQKeypair want refusing-to-overwrite error, got %v", err)
	}
}

// TestDerivePQPublicKeySuccess verifies a valid headered PQ seed derives a
// public key.
func TestDerivePQPublicKeySuccess(t *testing.T) {
	path, _ := withPQSeedFile(t)
	if err := derivePQPublicKey(path); err != nil {
		t.Fatalf("derivePQPublicKey: %v", err)
	}
}

// TestDerivePQPublicKeyMissingFile verifies a missing file surfaces a read
// error.
func TestDerivePQPublicKeyMissingFile(t *testing.T) {
	err := derivePQPublicKey(filepath.Join(t.TempDir(), "nope.hex"))
	if err == nil || !strings.Contains(err.Error(), "reading") {
		t.Fatalf("derivePQPublicKey want read error, got %v", err)
	}
}

// TestDerivePQPublicKeyRejectsBareHex verifies PQ refuses bare-hex content.
func TestDerivePQPublicKeyRejectsBareHex(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bare.hex")
	seed := bytes.Repeat([]byte{0x41}, mldsa.PrivateKeySize)
	if err := os.WriteFile(path, []byte(hex.EncodeToString(seed)), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	err := derivePQPublicKey(path)
	if err == nil || !strings.Contains(err.Error(), "missing") || !strings.Contains(err.Error(), "header") {
		t.Fatalf("derivePQPublicKey want header-missing error, got %v", err)
	}
}

// TestProvisionPQCertificateKeySuccess verifies PQ provisioning returns
// populated keys and cert.
func TestProvisionPQCertificateKeySuccess(t *testing.T) {
	path, wantPK := withPQSeedFile(t)
	setPQRootKeyPath(t, path)

	cert, onlinePK, rootPK, expiry, err := provisionPQCertificateKey()
	if err != nil {
		t.Fatalf("provisionPQCertificateKey: %v", err)
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

// TestProvisionPQCertificateKeyRejectsInsecureMode verifies group/other
// permission bits are refused.
func TestProvisionPQCertificateKeyRejectsInsecureMode(t *testing.T) {
	path, _ := withPQSeedFile(t)
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	setPQRootKeyPath(t, path)
	_, _, _, _, err := provisionPQCertificateKey()
	if err == nil || !strings.Contains(err.Error(), "insecure mode") {
		t.Fatalf("provisionPQCertificateKey want insecure-mode error, got %v", err)
	}
}

// TestProvisionPQCertificateKeyRejectsMissing verifies a missing seed surfaces
// a stat error.
func TestProvisionPQCertificateKeyRejectsMissing(t *testing.T) {
	setPQRootKeyPath(t, filepath.Join(t.TempDir(), "nope.hex"))
	_, _, _, _, err := provisionPQCertificateKey()
	if err == nil || !strings.Contains(err.Error(), "stat PQ root key file") {
		t.Fatalf("provisionPQCertificateKey want stat error, got %v", err)
	}
}

// TestProvisionPQCertificateKeyRejectsBareHex verifies PQ provisioning rejects
// bare-hex files.
func TestProvisionPQCertificateKeyRejectsBareHex(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bare.hex")
	seed := bytes.Repeat([]byte{0x5a}, mldsa.PrivateKeySize)
	if err := os.WriteFile(path, []byte(hex.EncodeToString(seed)), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	setPQRootKeyPath(t, path)
	_, _, _, _, err := provisionPQCertificateKey()
	if err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("provisionPQCertificateKey want missing-header error, got %v", err)
	}
}

// TestProvisionPQCertificateKeyRejectsWrongSize verifies a wrong-length seed is
// rejected.
func TestProvisionPQCertificateKeyRejectsWrongSize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "short.hex")
	raw := []byte(mldsa44SeedHeader + "\n" + hex.EncodeToString([]byte{1, 2, 3}) + "\n")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	setPQRootKeyPath(t, path)
	_, _, _, _, err := provisionPQCertificateKey()
	if err == nil || !strings.Contains(err.Error(), "bytes, want") {
		t.Fatalf("provisionPQCertificateKey want size error, got %v", err)
	}
}

// TestTryRefreshCertPQSuccess verifies refresh returns a populated certState
// whose srvHash matches the root key.
func TestTryRefreshCertPQSuccess(t *testing.T) {
	path, pk := withPQSeedFile(t)
	setPQRootKeyPath(t, path)

	newState, newOnlinePK, err := tryRefreshCertPQ(pk)
	if err != nil {
		t.Fatalf("tryRefreshCertPQ: %v", err)
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

// TestTryRefreshCertPQRejectsChangedRoot verifies a rotated PQ seed aborts
// refresh with an identity error.
func TestTryRefreshCertPQRejectsChangedRoot(t *testing.T) {
	path, _ := withPQSeedFile(t)
	setPQRootKeyPath(t, path)

	other, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("gen other: %v", err)
	}
	_, _, err = tryRefreshCertPQ(other.PublicKey().Bytes())
	if err == nil || !strings.Contains(err.Error(), "PQ root public key on disk has changed") {
		t.Fatalf("tryRefreshCertPQ want identity error, got %v", err)
	}
}

// TestRefreshLoopPQRefreshesNearExpiry verifies a near-expired cert is
// atomically replaced.
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
	refreshLoopPQ(ctx, zap.NewNop(), statePtr, pk)

	got := statePtr.Load()
	if got == stSeed {
		t.Fatal("refreshLoopPQ did not replace certState")
	}
	if remaining := time.Until(got.expiry); remaining < time.Hour {
		t.Fatalf("post-refresh expiry too soon: %s", remaining)
	}
}

// TestRefreshLoopPQLogsErrorOnIdentityChange verifies state is not replaced
// when the in-memory key differs from disk.
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
	refreshLoopPQ(ctx, zap.NewNop(), statePtr, other.PublicKey().Bytes())

	if statePtr.Load() != stSeed {
		t.Fatal("refreshLoopPQ replaced certState despite identity mismatch")
	}
}

// TestParseSeedAcceptsBareHex verifies the Ed25519 path accepts bare hex for
// legacy compatibility.
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

// TestParseSeedAcceptsHeader verifies a headered payload is stripped and
// decoded.
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

// TestParseSeedRejectsCrossScheme verifies an Ed25519-headered file cannot
// satisfy a PQ expectation.
func TestParseSeedRejectsCrossScheme(t *testing.T) {
	seed := bytes.Repeat([]byte{0xaa}, 32)
	raw := []byte(ed25519SeedHeader + "\n" + hex.EncodeToString(seed))
	_, err := parseSeed(raw, "cross.hex", mldsa44SeedHeader, "PQ", mldsa.PrivateKeySize, false)
	if err == nil {
		t.Fatal("parseSeed accepted a cross-scheme file")
	}
}

// TestParseSeedRejectsHeaderWithoutBoundary verifies a header followed by
// non-whitespace bytes is rejected.
func TestParseSeedRejectsHeaderWithoutBoundary(t *testing.T) {
	seed := bytes.Repeat([]byte{0x55}, 32)
	raw := []byte(ed25519SeedHeader + "0" + hex.EncodeToString(seed))
	_, err := parseSeed(raw, "noboundary.hex", ed25519SeedHeader, "", 32, false)
	if err == nil {
		t.Fatal("parseSeed accepted a header with no whitespace boundary")
	}
}

// TestParseSeedRejectsBadHexPostHeader verifies non-hex bytes after a valid
// header surface a decode error.
func TestParseSeedRejectsBadHexPostHeader(t *testing.T) {
	raw := []byte(ed25519SeedHeader + "\nNOT-HEX-CONTENT")
	_, err := parseSeed(raw, "badhex.hex", ed25519SeedHeader, "", 32, false)
	if err == nil {
		t.Fatal("parseSeed accepted non-hex content after header")
	}
}

// TestParseSeedHeaderTabSeparator verifies a tab is accepted as the
// header/payload separator.
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

// TestParseSeedRejectsEmpty verifies an empty file surfaces a length error
// under acceptBareHex.
func TestParseSeedRejectsEmpty(t *testing.T) {
	_, err := parseSeed(nil, "empty.hex", ed25519SeedHeader, "", 32, true)
	if err == nil {
		t.Fatal("parseSeed accepted empty input")
	}
}
