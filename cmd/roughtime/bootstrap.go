// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

//go:build unix

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"

	"filippo.io/mldsa"
	"github.com/tannerryan/roughtime/protocol"
	"go.uber.org/zap"
)

// Seed-file headers bind a seed to its scheme; Ed25519 still accepts legacy
// bare hex while PQ files must carry the header.
const (
	ed25519SeedHeader = "roughtime-ed25519-seed-v1"
	mldsa44SeedHeader = "roughtime-mldsa44-seed-v1"
)

// Certificate validity window relative to now.
const (
	certStartOffset = -6 * time.Hour
	certEndOffset   = 18 * time.Hour
)

// Cert refresh tunables; var so tests can shrink them.
var (
	// certRefreshThreshold is the remaining-validity window that triggers a
	// refresh attempt.
	certRefreshThreshold = 3 * time.Hour
	// certCheckInterval is the cadence at which the refresh loop wakes to check
	// expiry.
	certCheckInterval = 15 * time.Minute
	// refreshRetryCooldown is the minimum gap between successive refresh
	// attempts after a failure.
	refreshRetryCooldown = 5 * time.Minute
	// certWipeGrace delays zeroing a rotated-out online signing key so
	// in-flight signers can finish.
	certWipeGrace = 5 * time.Second
)

// certState holds the current online certificate, its expiry, and the
// precomputed SRV hash of the long-term root key.
type certState struct {
	// cert is the active online delegation certificate.
	cert *protocol.Certificate
	// expiry is the wall-clock time at which cert ceases to be valid.
	expiry time.Time
	// srvHash is the precomputed SRV hash of the long-term root public key.
	srvHash []byte
}

// writeSeedFile writes header plus hex-encoded seed to path at mode 0600,
// refusing existing files and symlink races.
func writeSeedFile(path, header string, seed []byte) error {
	encoded := []byte(header + "\n" + hex.EncodeToString(seed) + "\n")
	defer clear(encoded)

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s already exists (refusing to overwrite)", path)
		}
		return fmt.Errorf("creating seed file %s: %w", path, err)
	}
	if _, err := f.Write(encoded); err != nil {
		_ = f.Close()
		return fmt.Errorf("writing seed to %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("closing seed file %s: %w", path, err)
	}
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

	fmt.Printf("Seed written to: %s\n", path)
	fmt.Printf("Public key (hex):    %s\n", hex.EncodeToString(pk))
	fmt.Printf("Public key (base64): %s\n", base64.StdEncoding.EncodeToString(pk))
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

	fmt.Printf("Seed written to: %s\n", path)
	fmt.Printf("Public key (hex):    %s\n", hex.EncodeToString(pk))
	fmt.Printf("Public key (base64): %s\n", base64.StdEncoding.EncodeToString(pk))
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

	fmt.Printf("Public key (hex):    %s\n", hex.EncodeToString(pk))
	fmt.Printf("Public key (base64): %s\n", base64.StdEncoding.EncodeToString(pk))
	return nil
}

// deriveMLDSA44PublicKey reads an ML-DSA-44 root seed and prints the public
// key; the header is required.
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

	fmt.Printf("Public key (hex):    %s\n", hex.EncodeToString(pk))
	fmt.Printf("Public key (base64): %s\n", base64.StdEncoding.EncodeToString(pk))
	return nil
}

// readPrivateKeyFile reads a 0600-or-stricter seed file under O_NOFOLLOW, using
// role to label error messages.
func readPrivateKeyFile(path, role string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %s key file: %w", role, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s key file %s is a symlink (refusing to follow)", role, path)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s key file %s is not a regular file", role, path)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return nil, fmt.Errorf("%s key file %s has insecure mode %#o (must be 0600 or stricter)", role, path, mode)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("opening %s signing key file: %w", role, err)
	}
	raw, err := io.ReadAll(f)
	_ = f.Close()
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
	seed, err := hex.DecodeString(string(hexPart))
	if err != nil {
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

	now := time.Now()
	cert, err := protocol.NewCertificate(now.Add(certStartOffset), now.Add(certEndOffset), onlineSK, rootSK)
	if err != nil {
		return nil, nil, nil, time.Time{}, fmt.Errorf("generating online certificate: %w", err)
	}
	return cert, onlinePK, rootPK, now.Add(certEndOffset), nil
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

	now := time.Now()
	cert, err := protocol.NewCertificateMLDSA44(now.Add(certStartOffset), now.Add(certEndOffset), onlineSK, rootSK)
	if err != nil {
		return nil, nil, nil, time.Time{}, fmt.Errorf("generating PQ online certificate: %w", err)
	}
	return cert, onlinePK, rootPK, now.Add(certEndOffset), nil
}

// refreshLoop replaces the Ed25519 certificate near expiry, rejecting refresh
// if the root key on disk has changed.
func refreshLoop(ctx context.Context, log *zap.Logger, state *atomic.Pointer[certState], initialRootPK ed25519.PublicKey) {
	runRefreshLoop(ctx, log, "Ed25519", schemeEd25519, initialRootPK, state, func() (*certState, []byte, error) {
		return tryRefreshCert(initialRootPK)
	})
}

// refreshLoopMLDSA44 is the ML-DSA-44 counterpart of refreshLoop, gated by the
// encoded root public key captured at startup.
func refreshLoopMLDSA44(ctx context.Context, log *zap.Logger, state *atomic.Pointer[certState], initialRootPK []byte) {
	runRefreshLoop(ctx, log, "ML-DSA-44", schemeMLDSA44, initialRootPK, state, func() (*certState, []byte, error) {
		return tryRefreshCertMLDSA44(initialRootPK)
	})
}

// runRefreshLoop is the scheme-agnostic refresh driver invoked by refreshLoop
// and refreshLoopMLDSA44.
func runRefreshLoop(ctx context.Context, log *zap.Logger, schemeName, schemeMetric string, rootPK []byte, state *atomic.Pointer[certState], refresh func() (*certState, []byte, error)) {
	ticker := time.NewTicker(certCheckInterval)
	defer ticker.Stop()
	var lastAttempt time.Time

	log.Info("certificate refresh loop started",
		zap.String("scheme", schemeName),
		zap.Duration("check_interval", certCheckInterval),
		zap.Duration("refresh_threshold", certRefreshThreshold),
		zap.Duration("retry_cooldown", refreshRetryCooldown),
	)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		cur := state.Load()
		if time.Until(cur.expiry) > certRefreshThreshold {
			continue
		}
		now := time.Now()
		if now.Sub(lastAttempt) < refreshRetryCooldown {
			continue
		}
		lastAttempt = now

		log.Info("attempting certificate refresh",
			zap.String("scheme", schemeName),
			zap.Time("current_expiry", cur.expiry),
			zap.Duration("remaining", time.Until(cur.expiry)),
		)
		newState, newOnlinePK, err := refresh()
		if err != nil {
			remaining := time.Until(cur.expiry)
			// below 2x cooldown the next attempt may miss expiry; fail so the
			// supervisor restarts rather than serving an expiring cert
			if remaining < 2*refreshRetryCooldown {
				log.Fatal("certificate refresh failed near expiry; restart required",
					zap.String("scheme", schemeName),
					zap.Error(err),
					zap.Time("current_expiry", cur.expiry),
					zap.Duration("remaining", remaining),
					zap.Duration("retry_cooldown", refreshRetryCooldown),
				)
			}
			if ce := log.Check(zap.ErrorLevel, "certificate refresh failed"); ce != nil {
				ce.Write(
					zap.String("scheme", schemeName),
					zap.Error(err),
					zap.Time("current_expiry", cur.expiry),
					zap.Duration("remaining", remaining),
					zap.Duration("retry_cooldown", refreshRetryCooldown),
				)
			}
			continue
		}
		state.Store(newState)
		noteCertProvisioned(schemeMetric, newOnlinePK, rootPK, newState.expiry, time.Now())
		noteCertRotation(schemeMetric)
		oldCert := cur.cert
		time.AfterFunc(certWipeGrace, oldCert.Wipe)
		log.Info("certificate refreshed",
			zap.String("scheme", schemeName),
			zap.String("online_pubkey", hex.EncodeToString(newOnlinePK)),
			zap.Time("previous_expiry", cur.expiry),
			zap.Time("expiry", newState.expiry),
			zap.Duration("validity", time.Until(newState.expiry)),
		)
	}
}

// tryRefreshCert reads the Ed25519 root key, rejects any change against
// initialRootPK, and returns a fresh certState plus the new online public key.
func tryRefreshCert(initialRootPK ed25519.PublicKey) (*certState, ed25519.PublicKey, error) {
	newCert, newOnlinePK, newRootPK, newExpiry, err := provisionCertificateKey()
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(newRootPK, initialRootPK) {
		return nil, nil, fmt.Errorf("root public key on disk has changed since startup (want %s, got %s); restart required",
			hex.EncodeToString(initialRootPK), hex.EncodeToString(newRootPK))
	}
	return &certState{cert: newCert, expiry: newExpiry, srvHash: protocol.ComputeSRV(newRootPK)}, newOnlinePK, nil
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
		return nil, nil, fmt.Errorf("PQ root public key on disk has changed since startup (want %s, got %s); restart required",
			hex.EncodeToString(initialRootPK), hex.EncodeToString(newRootPK))
	}
	return &certState{cert: newCert, expiry: newExpiry, srvHash: protocol.ComputeSRV(newRootPK)}, newOnlinePK, nil
}
