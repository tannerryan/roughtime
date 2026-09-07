// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

//go:build unix

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/tannerryan/roughtime/protocol"
	"go.uber.org/zap"
)

// Seed-file headers bind a seed to its scheme. Ed25519 still accepts legacy
// bare hex while PQ files must carry the header.
const (
	// ed25519SeedHeader identifies an Ed25519 seed file.
	ed25519SeedHeader = "roughtime-ed25519-seed-v1"
	// mldsa44SeedHeader identifies an ML-DSA-44 seed file.
	mldsa44SeedHeader = "roughtime-mldsa44-seed-v1"
)

// Certificate validity window relative to now.
const (
	// certStartOffset sets delegation validity before provisioning.
	certStartOffset = -6 * time.Hour
	// certEndOffset sets delegation expiry after provisioning.
	certEndOffset = 18 * time.Hour
)

// Certificate refresh schedule.
const (
	// certRefreshThreshold is the remaining-validity window that triggers a
	// refresh attempt.
	certRefreshThreshold = 3 * time.Hour
	// certCheckInterval is the cadence at which the refresh loop wakes to check
	// expiry.
	certCheckInterval = 15 * time.Minute
	// certValidityCheckInterval bounds detection of wall-clock corrections that
	// move the active delegation outside its validity window.
	certValidityCheckInterval = time.Second
)

// certState holds the current online certificate, its expiry, and the
// precomputed SRV hash of the long-term root key.
type certState struct {
	// mu prevents retirement from wiping cert while a response is signing.
	mu        sync.RWMutex
	retired   bool
	cert      *protocol.Certificate
	notBefore time.Time
	expiry    time.Time
	srvHash   []byte
}

// acquire retains s for one signing operation. The caller must call release
// after a successful acquire.
func (s *certState) acquire() bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	if s.retired {
		s.mu.RUnlock()
		return false
	}
	return true
}

// release ends a signing operation begun by acquire.
func (s *certState) release() {
	s.mu.RUnlock()
}

// acquireCurrent retains the certificate currently published in state. If a
// rotation races the retain operation, it releases the replaced certificate and
// retries the newly published state.
func acquireCurrent(state *atomic.Pointer[certState]) *certState {
	if state == nil {
		return nil
	}
	for {
		current := state.Load()
		if current == nil {
			return nil
		}
		if !current.acquire() {
			if state.Load() != current {
				continue
			}
			return nil
		}
		if state.Load() == current {
			return current
		}
		current.release()
	}
}

// retire prevents new signing operations and wipes the online signing key after
// every operation already using the state has completed.
func (s *certState) retire() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.retired {
		return
	}
	s.retired = true
	if s.cert != nil {
		s.cert.Wipe()
	}
}

// retireCurrent atomically detaches and retires the current certificate.
func retireCurrent(state *atomic.Pointer[certState]) {
	if state == nil {
		return
	}
	state.Swap(nil).retire()
}

// writeSeedFile creates a seed file with permissions no broader than 0600 and
// never replaces an existing path.
func writeSeedFile(path, header string, seed []byte) error {
	encoded := make([]byte, len(header)+2+hex.EncodedLen(len(seed)))
	copy(encoded, header)
	encoded[len(header)] = '\n'
	hex.Encode(encoded[len(header)+1:], seed)
	encoded[len(encoded)-1] = '\n'
	defer clear(encoded)

	path = filepath.Clean(path)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s already exists (refusing to overwrite)", path)
		}
		return fmt.Errorf("creating seed file %s: %w", path, err)
	}
	failed := true
	defer func() {
		_ = f.Close()
		if failed {
			_ = os.Remove(path)
		}
	}()
	if _, err := f.Write(encoded); err != nil {
		return fmt.Errorf("writing seed file %s: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("syncing seed file %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("closing seed file %s: %w", path, err)
	}
	failed = false
	return nil
}

// generateKeypair generates an Ed25519 root key pair, writes the headered seed
// to path, and prints the public key.
func generateKeypair(path string) error {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return fmt.Errorf("reading entropy: %w", err)
	}
	defer clear(seed)

	sk := ed25519.NewKeyFromSeed(seed)
	defer clear(sk)
	pk := sk.Public().(ed25519.PublicKey)

	if err := writeSeedFile(path, ed25519SeedHeader, seed); err != nil {
		return err
	}
	fmt.Printf("Seed written to: %s\nPublic key (hex):    %s\nPublic key (base64): %s\n",
		path, hex.EncodeToString(pk), base64.StdEncoding.EncodeToString(pk))
	return nil
}

// generateMLDSA44Keypair generates an ML-DSA-44 root key pair, writes the
// headered seed to path, and prints the public key.
func generateMLDSA44Keypair(path string) error {
	sk, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		return fmt.Errorf("generating ML-DSA-44 key: %w", err)
	}
	seed := sk.Bytes()
	defer clear(seed)
	pk := sk.PublicKey().Bytes()

	if err := writeSeedFile(path, mldsa44SeedHeader, seed); err != nil {
		return err
	}
	fmt.Printf("Seed written to: %s\nPublic key (hex):    %s\nPublic key (base64): %s\n",
		path, hex.EncodeToString(pk), base64.StdEncoding.EncodeToString(pk))
	return nil
}

// derivePublicKey reads an Ed25519 root seed and prints the public key,
// accepting headered or legacy bare-hex format.
func derivePublicKey(path string) error {
	path = filepath.Clean(path)
	raw, err := readPrivateKeyFile(path, "root")
	if err != nil {
		return err
	}
	defer clear(raw)

	seed, err := parseSeed(raw, path, ed25519SeedHeader, "", ed25519.SeedSize, true)
	if err != nil {
		return err
	}
	defer clear(seed)

	sk := ed25519.NewKeyFromSeed(seed)
	defer clear(sk)
	pk := sk.Public().(ed25519.PublicKey)

	fmt.Printf("Public key (hex):    %s\nPublic key (base64): %s\n",
		hex.EncodeToString(pk), base64.StdEncoding.EncodeToString(pk))
	return nil
}

// deriveMLDSA44PublicKey reads an ML-DSA-44 root seed and prints the public
// key. The header is required.
func deriveMLDSA44PublicKey(path string) error {
	path = filepath.Clean(path)
	raw, err := readPrivateKeyFile(path, "PQ root")
	if err != nil {
		return err
	}
	defer clear(raw)

	seed, err := parseSeed(raw, path, mldsa44SeedHeader, "PQ", mldsa.PrivateKeySize, false)
	if err != nil {
		return err
	}
	defer clear(seed)

	sk, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), seed)
	if err != nil {
		return fmt.Errorf("loading ML-DSA-44 key: %w", err)
	}
	pk := sk.PublicKey().Bytes()

	fmt.Printf("Public key (hex):    %s\nPublic key (base64): %s\n",
		hex.EncodeToString(pk), base64.StdEncoding.EncodeToString(pk))
	return nil
}

// readPrivateKeyFile reads a regular seed file with no group or other
// permissions under O_NOFOLLOW.
func readPrivateKeyFile(path, role string) ([]byte, error) {
	// O_NOFOLLOW refuses a symlink, then validate the opened descriptor so the
	// checks can't race a swap between stat and open. O_NONBLOCK prevents a
	// FIFO from blocking before the regular-file check.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("%s key file %s is a symlink (refusing to follow)", role, path)
		}
		return nil, fmt.Errorf("open %s key file: %w", role, err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat %s key file: %w", role, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s key file %s is not a regular file", role, path)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return nil, fmt.Errorf("%s key file %s has insecure mode %#o (must be 0600 or stricter)", role, path, mode)
	}
	raw, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("reading %s signing key file: %w", role, err)
	}
	return raw, nil
}

// parseSeed extracts a hex-encoded seed from raw, optionally accepting legacy
// bare hex when acceptBareHex is true.
func parseSeed(raw []byte, path, header, label string, wantLen int, acceptBareHex bool) ([]byte, error) {
	noun := "seed"
	if label != "" {
		noun = label + " seed"
	}
	trimmed := bytes.TrimSpace(raw)
	// require whitespace/EOF after header so v10 doesn't accept v1
	hasHeader := false
	var afterHeader []byte
	if bytes.HasPrefix(trimmed, []byte(header)) {
		rest := trimmed[len(header):]
		if len(rest) == 0 || rest[0] == ' ' || rest[0] == '\t' || rest[0] == '\n' || rest[0] == '\r' {
			hasHeader = true
			afterHeader = rest
		}
	}
	var hexPart []byte
	switch {
	case hasHeader:
		hexPart = bytes.TrimSpace(afterHeader)
	case acceptBareHex:
		hexPart = trimmed
	default:
		return nil, fmt.Errorf("%s file %s missing %q header", noun, path, header)
	}
	if len(hexPart)%2 != 0 {
		return nil, fmt.Errorf("decoding %s in %s: odd length hex string", noun, path)
	}
	seed := make([]byte, hex.DecodedLen(len(hexPart)))
	if _, err := hex.Decode(seed, hexPart); err != nil {
		clear(seed)
		return nil, fmt.Errorf("decoding %s in %s: %w", noun, path, err)
	}
	if len(seed) != wantLen {
		clear(seed)
		return nil, fmt.Errorf("%s in %s has %d bytes, want %d", noun, path, len(seed), wantLen)
	}
	return seed, nil
}

// provisionCertificateKey reads the Ed25519 root seed and signs a fresh online
// delegation.
func provisionCertificateKey() (*protocol.Certificate, ed25519.PublicKey, ed25519.PublicKey, time.Time, error) {
	path := filepath.Clean(*rootKeySeedHexFile)

	raw, err := readPrivateKeyFile(path, "root")
	if err != nil {
		return nil, nil, nil, time.Time{}, err
	}
	defer clear(raw)

	rootKeySeed, err := parseSeed(raw, path, ed25519SeedHeader, "root signing key", ed25519.SeedSize, true)
	if err != nil {
		return nil, nil, nil, time.Time{}, err
	}
	defer clear(rootKeySeed)

	rootSK := ed25519.NewKeyFromSeed(rootKeySeed)
	defer clear(rootSK)
	rootPK := rootSK.Public().(ed25519.PublicKey)

	onlinePK, onlineSK, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, time.Time{}, fmt.Errorf("generating online signing key: %w", err)
	}
	defer clear(onlineSK)

	now := wallClockNow()
	expiry := now.Add(certEndOffset)
	cert, err := protocol.NewCertificate(now.Add(certStartOffset), expiry, onlineSK, rootSK)
	if err != nil {
		return nil, nil, nil, time.Time{}, fmt.Errorf("generating online certificate: %w", err)
	}
	return cert, onlinePK, rootPK, expiry, nil
}

// provisionMLDSA44CertificateKey reads the ML-DSA-44 root seed and signs a
// fresh online delegation.
func provisionMLDSA44CertificateKey() (*protocol.Certificate, []byte, []byte, time.Time, error) {
	path := filepath.Clean(*pqRootKeySeedHexFile)

	raw, err := readPrivateKeyFile(path, "PQ root")
	if err != nil {
		return nil, nil, nil, time.Time{}, err
	}
	defer clear(raw)

	rootKeySeed, err := parseSeed(raw, path, mldsa44SeedHeader, "PQ root signing key", mldsa.PrivateKeySize, false)
	if err != nil {
		return nil, nil, nil, time.Time{}, err
	}
	defer clear(rootKeySeed)

	rootSK, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), rootKeySeed)
	if err != nil {
		return nil, nil, nil, time.Time{}, fmt.Errorf("loading PQ root signing key: %w", err)
	}
	rootPK := rootSK.PublicKey().Bytes()

	onlineSK, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		return nil, nil, nil, time.Time{}, fmt.Errorf("generating PQ online signing key: %w", err)
	}
	onlinePK := onlineSK.PublicKey().Bytes()

	now := wallClockNow()
	expiry := now.Add(certEndOffset)
	cert, err := protocol.NewCertificateMLDSA44(now.Add(certStartOffset), expiry, onlineSK, rootSK)
	if err != nil {
		return nil, nil, nil, time.Time{}, fmt.Errorf("generating PQ online certificate: %w", err)
	}
	return cert, onlinePK, rootPK, expiry, nil
}

// wallClockNow deliberately strips the monotonic reading. Delegation validity
// is expressed in UTC timestamps, so refresh decisions must follow civil-clock
// corrections instead of measuring only process elapsed time.
func wallClockNow() time.Time { return time.Now().Round(0) }

// certRemaining returns wall-clock validity remaining for expiry.
func certRemaining(expiry time.Time) time.Duration {
	return expiry.Sub(wallClockNow())
}

// certNotBefore derives the delegation start generated alongside expiry.
func certNotBefore(expiry time.Time) time.Time {
	return expiry.Add(certStartOffset - certEndOffset)
}

// offlineExpiryCheckInterval rechecks the civil clock so a forward wall-clock
// correction cannot leave read-once mode serving an expired delegation.
const offlineExpiryCheckInterval = time.Second

// monitorOfflineDelegation stops serving when offline delegation state is
// unavailable or outside its validity window. Signing paths repeat the check to
// cover scheduling jitter.
func monitorOfflineDelegation(ctx context.Context, scheme string, state *atomic.Pointer[certState]) error {
	ticker := time.NewTicker(offlineExpiryCheckInterval)
	defer ticker.Stop()
	for {
		if state == nil {
			return fmt.Errorf("%s offline delegation state unavailable", scheme)
		}
		current := state.Load()
		if current == nil {
			return fmt.Errorf("%s offline delegation state unavailable", scheme)
		}
		now := wallClockNow()
		if now.Before(current.notBefore) {
			return fmt.Errorf("%s offline delegation is not yet valid after a backward clock correction. Restart with a fresh delegation", scheme)
		}
		if !now.Before(current.expiry) {
			return fmt.Errorf("%s offline delegation expired. Restart with a fresh delegation", scheme)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// refreshLoop replaces the Ed25519 certificate near expiry, rejecting refresh
// if the root key on disk has changed.
func refreshLoop(ctx context.Context, log *zap.Logger, state *atomic.Pointer[certState], initialRootPK ed25519.PublicKey) error {
	return runRefreshLoop(ctx, log, "Ed25519", schemeEd25519, initialRootPK, state, func() (*certState, []byte, error) {
		return tryRefreshCert(initialRootPK)
	})
}

// refreshLoopMLDSA44 is the ML-DSA-44 counterpart of refreshLoop, gated by the
// encoded root public key captured at startup.
func refreshLoopMLDSA44(ctx context.Context, log *zap.Logger, state *atomic.Pointer[certState], initialRootPK []byte) error {
	return runRefreshLoop(ctx, log, "ML-DSA-44", schemeMLDSA44, initialRootPK, state, func() (*certState, []byte, error) {
		return tryRefreshCertMLDSA44(initialRootPK)
	})
}

// runRefreshLoop is the scheme-agnostic refresh driver invoked by refreshLoop
// and refreshLoopMLDSA44.
func runRefreshLoop(ctx context.Context, log *zap.Logger, schemeName, schemeMetric string, rootPK []byte, state *atomic.Pointer[certState], refresh func() (*certState, []byte, error)) error {
	refreshTicker := time.NewTicker(certCheckInterval)
	defer refreshTicker.Stop()
	validityTicker := time.NewTicker(certValidityCheckInterval)
	defer validityTicker.Stop()
	log.Info("certificate refresh loop started",
		zap.String("scheme", schemeName),
		zap.Duration("check_interval", certCheckInterval),
		zap.Duration("validity_check_interval", certValidityCheckInterval),
		zap.Duration("refresh_threshold", certRefreshThreshold),
	)
	return runRefreshChecks(ctx, log, schemeName, schemeMetric, rootPK, state,
		refreshTicker.C, validityTicker.C, wallClockNow, refresh)
}

// runRefreshChecks handles routine refresh checks and short validity-only
// checks. The latter reread the root key only after a wall-clock correction
// moves the active delegation outside its validity window.
func runRefreshChecks(ctx context.Context, log *zap.Logger, schemeName, schemeMetric string, rootPK []byte, state *atomic.Pointer[certState], refreshTicks, validityTicks <-chan time.Time, now func() time.Time, refresh func() (*certState, []byte, error)) error {
	for {
		validityOnly := false
		select {
		case <-ctx.Done():
			return nil
		case <-refreshTicks:
		case <-validityTicks:
			validityOnly = true
		}

		if state == nil {
			return fmt.Errorf("%s certificate state unavailable", schemeName)
		}
		cur := state.Load()
		if cur == nil {
			return fmt.Errorf("%s certificate state unavailable", schemeName)
		}
		checkTime := now()
		invalid := checkTime.Before(cur.notBefore) || !checkTime.Before(cur.expiry)
		if validityOnly && !invalid {
			continue
		}
		if !invalid && cur.expiry.Sub(checkTime) > certRefreshThreshold {
			continue
		}
		log.Info("attempting certificate refresh",
			zap.String("scheme", schemeName),
			zap.Time("current_expiry", cur.expiry),
			zap.Duration("remaining", cur.expiry.Sub(checkTime)),
		)
		newState, newOnlinePK, err := refresh()
		if err != nil {
			failureTime := now()
			remaining := cur.expiry.Sub(failureTime)
			if failureTime.Before(cur.notBefore) {
				return fmt.Errorf("%s certificate refresh failed while the current certificate is not yet valid: %w", schemeName, err)
			}
			// Leave one check interval plus retry margin. Otherwise the next
			// scheduled attempt can begin at or after certificate expiry.
			if refreshFailureTerminal(remaining) {
				return fmt.Errorf("%s certificate refresh failed with %s remaining: %w", schemeName, remaining, err)
			}
			if ce := log.Check(zap.ErrorLevel, "certificate refresh failed"); ce != nil {
				ce.Write(
					zap.String("scheme", schemeName),
					zap.Error(err),
					zap.Time("current_expiry", cur.expiry),
					zap.Duration("remaining", remaining),
				)
			}
			continue
		}
		retired := state.Swap(newState)
		retired.retire()
		provisioned := now()
		noteCertProvisioned(schemeMetric, newOnlinePK, rootPK, newState.expiry, provisioned)
		noteCertRotation(schemeMetric)
		log.Info("certificate refreshed",
			zap.String("scheme", schemeName),
			zap.String("online_pubkey", hex.EncodeToString(newOnlinePK)),
			zap.Time("previous_expiry", cur.expiry),
			zap.Time("expiry", newState.expiry),
			zap.Duration("validity", newState.expiry.Sub(provisioned)),
		)
	}
}

// refreshFailureTerminal reports whether another scheduled refresh plus a
// one-minute retry margin would reach expiry.
func refreshFailureTerminal(remaining time.Duration) bool {
	return remaining <= certCheckInterval+time.Minute
}

// tryRefreshCert reads the Ed25519 root key, rejects any change against
// initialRootPK, and returns a fresh certState plus the new online public key.
func tryRefreshCert(initialRootPK ed25519.PublicKey) (*certState, ed25519.PublicKey, error) {
	newCert, newOnlinePK, newRootPK, newExpiry, err := provisionCertificateKey()
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(newRootPK, initialRootPK) {
		newCert.Wipe()
		return nil, nil, fmt.Errorf("root public key on disk has changed since startup (want %s, got %s). Restart required",
			hex.EncodeToString(initialRootPK), hex.EncodeToString(newRootPK))
	}
	return &certState{cert: newCert, notBefore: certNotBefore(newExpiry), expiry: newExpiry, srvHash: protocol.ComputeSRV(newRootPK)}, newOnlinePK, nil
}

// tryRefreshCertMLDSA44 reads the ML-DSA-44 root key, rejects any change
// against initialRootPK, and returns a fresh certState plus the new online
// public key.
func tryRefreshCertMLDSA44(initialRootPK []byte) (*certState, []byte, error) {
	newCert, newOnlinePK, newRootPK, newExpiry, err := provisionMLDSA44CertificateKey()
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(newRootPK, initialRootPK) {
		newCert.Wipe()
		return nil, nil, fmt.Errorf("PQ root public key on disk has changed since startup (want %s, got %s). Restart required",
			hex.EncodeToString(initialRootPK), hex.EncodeToString(newRootPK))
	}
	return &certState{cert: newCert, notBefore: certNotBefore(newExpiry), expiry: newExpiry, srvHash: protocol.ComputeSRV(newRootPK)}, newOnlinePK, nil
}
