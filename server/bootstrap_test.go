// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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

// setRootKeyPath swaps *rootKeySeedHexFile for the test and restores on
// cleanup.
func setRootKeyPath(t *testing.T, path string) {
	t.Helper()
	prev := *rootKeySeedHexFile
	*rootKeySeedHexFile = path
	t.Cleanup(func() { *rootKeySeedHexFile = prev })
}

// TestValidateFlagsAccepts verifies validateFlags returns nil for in-range
// flags.
func TestValidateFlagsAccepts(t *testing.T) {
	setRootKeyPath(t, "/nonexistent")
	if err := validateFlags(); err != nil {
		t.Fatalf("validateFlags() err=%v, want nil", err)
	}
}

// TestValidateFlagsRejects verifies out-of-range flags produce a naming error.
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

// TestGenerateKeypairSuccess verifies generateKeypair writes a headered seed at
// 0600; the header binds the file to Ed25519 so it cannot be mistaken for a PQ
// key.
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

// TestGenerateKeypairRefusesOverwrite verifies an existing seed file is not
// clobbered.
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

// TestDerivePublicKeySuccess verifies a valid seed file derives a public key.
func TestDerivePublicKeySuccess(t *testing.T) {
	path, _ := withSeedFile(t)
	if err := derivePublicKey(path); err != nil {
		t.Fatalf("derivePublicKey: %v", err)
	}
}

// TestDerivePublicKeyMissingFile verifies a missing seed file surfaces a read
// error.
func TestDerivePublicKeyMissingFile(t *testing.T) {
	err := derivePublicKey(filepath.Join(t.TempDir(), "nope.hex"))
	if err == nil || !strings.Contains(err.Error(), "reading") {
		t.Fatalf("derivePublicKey want read error, got %v", err)
	}
}

// TestDerivePublicKeyBadSeed verifies non-hex seed content is rejected.
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

// TestDerivePublicKeyWrongSize verifies a short hex payload is rejected.
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

// TestProvisionCertificateKeySuccess verifies a valid seed produces a
// delegation cert whose returned keys match the on-disk seed.
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

// TestProvisionCertificateKeyRejectsInsecureMode verifies seeds with any
// group/other bits are refused.
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

// TestProvisionCertificateKeyRejectsMissing verifies a missing seed surfaces a
// stat error.
func TestProvisionCertificateKeyRejectsMissing(t *testing.T) {
	setRootKeyPath(t, filepath.Join(t.TempDir(), "nope.hex"))
	_, _, _, _, err := provisionCertificateKey()
	if err == nil || !strings.Contains(err.Error(), "stat root key file") {
		t.Fatalf("provisionCertificateKey want stat error, got %v", err)
	}
}

// TestProvisionCertificateKeyRejectsBadSeed verifies non-hex seed content fails
// decoding.
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

// TestProvisionCertificateKeyRejectsWrongSize verifies a short seed is
// rejected.
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

// TestProvisionCertificateKeyRejectsSymlink verifies a symlink is refused even
// when its target is valid.
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

// TestTryRefreshCertSuccess verifies the returned certState is populated and
// srvHash matches the on-disk root key.
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

// TestTryRefreshCertRejectsChangedRoot verifies a rotated seed aborts refresh
// with an identity-change error.
func TestTryRefreshCertRejectsChangedRoot(t *testing.T) {
	path, _ := withSeedFile(t)
	setRootKeyPath(t, path)

	// key differs from disk
	otherPK, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen other: %v", err)
	}
	_, _, err = tryRefreshCert(otherPK)
	if err == nil || !strings.Contains(err.Error(), "root public key on disk has changed") {
		t.Fatalf("tryRefreshCert want identity error, got %v", err)
	}
}

// TestTryRefreshCertPropagatesProvisionErr verifies provisioning errors are
// returned verbatim.
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

// TestStatsLoopExitsOnCtxCancel verifies the loop returns immediately on a
// cancelled ctx.
func TestStatsLoopExitsOnCtxCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, st := newUnitCertState(t)
	statePtr := &atomic.Pointer[certState]{}
	statePtr.Store(st)

	done := make(chan struct{})
	go func() {
		statsLoop(ctx, zap.NewNop(), statePtr, nil)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("statsLoop did not return on cancelled ctx")
	}
}

// withInterval swaps a duration variable for the test and restores on cleanup.
func withInterval(t *testing.T, v *time.Duration, d time.Duration) {
	t.Helper()
	prev := *v
	*v = d
	t.Cleanup(func() { *v = prev })
}

// TestStatsLoopTicks verifies the tick body executes with a non-zero batch
// count.
func TestStatsLoopTicks(t *testing.T) {
	withInterval(t, &statsInterval, 5*time.Millisecond)
	_, st := newUnitCertState(t)
	statePtr := &atomic.Pointer[certState]{}
	statePtr.Store(st)

	// prime counter so tick takes avg_batch_size path
	statsBatches.Add(1)
	statsBatchedReqs.Add(4)
	t.Cleanup(func() { statsBatches.Store(0); statsBatchedReqs.Store(0) })

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	statsLoop(ctx, zap.NewNop(), statePtr, nil)
}

// TestRefreshLoopRefreshesNearExpiry verifies a near-expired cert is atomically
// replaced.
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

// TestRefreshLoopLogsErrorOnIdentityChange verifies state is never replaced
// when the key differs from disk.
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

// TestRefreshLoopSkipsWhenNotNearExpiry verifies the loop is a no-op while
// validity exceeds the threshold.
func TestRefreshLoopSkipsWhenNotNearExpiry(t *testing.T) {
	withInterval(t, &certCheckInterval, 5*time.Millisecond)
	withInterval(t, &certRefreshThreshold, time.Minute)
	withInterval(t, &refreshRetryCooldown, time.Millisecond)

	path, pk := withSeedFile(t)
	setRootKeyPath(t, path)

	// expiry far beyond threshold
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
