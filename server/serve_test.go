// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

//go:build unix

package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// withFlagGlobals snapshots the server flag globals, applies overrides, and
// restores originals via t.Cleanup.
func withFlagGlobals(t *testing.T, edKey, pqKey, level string, p int, grease float64) {
	t.Helper()
	origPort := *port
	origEd := *rootKeySeedHexFile
	origPQ := *pqRootKeySeedHexFile
	origLevel := *logLevel
	origGrease := *greaseRate
	origShowVersion := *showVersion
	origKeygen := *keygen
	origPubkey := *pubkey
	origPQKeygen := *pqKeygen
	origPQPubkey := *pqPubkey
	t.Cleanup(func() {
		*port = origPort
		*rootKeySeedHexFile = origEd
		*pqRootKeySeedHexFile = origPQ
		*logLevel = origLevel
		*greaseRate = origGrease
		*showVersion = origShowVersion
		*keygen = origKeygen
		*pubkey = origPubkey
		*pqKeygen = origPQKeygen
		*pqPubkey = origPQPubkey
	})
	*port = p
	*rootKeySeedHexFile = edKey
	*pqRootKeySeedHexFile = pqKey
	*logLevel = level
	*greaseRate = grease
	*showVersion = false
	*keygen = ""
	*pubkey = ""
	*pqKeygen = ""
	*pqPubkey = ""
}

// pickEphemeralPort binds :0 to discover a free port; close it before reuse.
// Race-prone in theory, fine in practice for short-lived tests.
func pickEphemeralPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ephemeral listen: %v", err)
	}
	chosen := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return chosen
}

// TestServeDualStack runs serve with both Ed25519 and ML-DSA-44 keys, then
// cancels. Exercises both certificate-provisioning branches and the listener
// shutdown path.
func TestServeDualStack(t *testing.T) {
	dir := t.TempDir()
	edPath := filepath.Join(dir, "ed.key")
	if err := generateKeypair(edPath); err != nil {
		t.Fatalf("generateKeypair: %v", err)
	}
	pqPath := filepath.Join(dir, "pq.key")
	if err := generateMLDSA44Keypair(pqPath); err != nil {
		t.Fatalf("generateMLDSA44Keypair: %v", err)
	}
	withFlagGlobals(t, edPath, pqPath, "error", pickEphemeralPort(t), 0)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serve(ctx) }()

	time.Sleep(200 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not return after cancel")
	}
}

// TestServeRejectsBadLogLevel covers the [zapcore.ParseLevel] error path.
func TestServeRejectsBadLogLevel(t *testing.T) {
	dir := t.TempDir()
	edPath := filepath.Join(dir, "ed.key")
	if err := generateKeypair(edPath); err != nil {
		t.Fatalf("generateKeypair: %v", err)
	}
	withFlagGlobals(t, edPath, "", "not-a-level", pickEphemeralPort(t), 0)

	err := serve(context.Background())
	if err == nil || !strings.Contains(err.Error(), "log-level") {
		t.Fatalf("serve: %v; want log-level error", err)
	}
}

// TestServeRejectsBadEd25519Key covers the Ed25519 provisioning error path.
func TestServeRejectsBadEd25519Key(t *testing.T) {
	dir := t.TempDir()
	edPath := filepath.Join(dir, "bad.key")
	if err := os.WriteFile(edPath, []byte("not a valid seed file"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	withFlagGlobals(t, edPath, "", "error", pickEphemeralPort(t), 0)

	err := serve(context.Background())
	if err == nil || !strings.Contains(err.Error(), "Ed25519") {
		t.Fatalf("serve: %v; want Ed25519 provisioning error", err)
	}
}

// TestServeRejectsBadPQKey covers the ML-DSA-44 provisioning error path.
func TestServeRejectsBadPQKey(t *testing.T) {
	dir := t.TempDir()
	edPath := filepath.Join(dir, "ed.key")
	if err := generateKeypair(edPath); err != nil {
		t.Fatalf("generateKeypair: %v", err)
	}
	pqPath := filepath.Join(dir, "bad.pq.key")
	if err := os.WriteFile(pqPath, []byte("not valid"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	withFlagGlobals(t, edPath, pqPath, "error", pickEphemeralPort(t), 0)

	err := serve(context.Background())
	if err == nil || !strings.Contains(err.Error(), "ML-DSA-44") {
		t.Fatalf("serve: %v; want ML-DSA-44 provisioning error", err)
	}
}

// TestDispatchVersion covers the -version subcommand branch.
func TestDispatchVersion(t *testing.T) {
	withFlagGlobals(t, "", "", "info", 2002, 0.01)
	*showVersion = true
	if err := dispatch(); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
}

// TestDispatchKeygen covers the -keygen subcommand branch.
func TestDispatchKeygen(t *testing.T) {
	withFlagGlobals(t, "", "", "info", 2002, 0.01)
	*keygen = filepath.Join(t.TempDir(), "ed.key")
	if err := dispatch(); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
}

// TestDispatchPQKeygen covers the -pq-keygen subcommand branch.
func TestDispatchPQKeygen(t *testing.T) {
	withFlagGlobals(t, "", "", "info", 2002, 0.01)
	*pqKeygen = filepath.Join(t.TempDir(), "pq.key")
	if err := dispatch(); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
}

// TestDispatchPubkey covers the -pubkey subcommand branch.
func TestDispatchPubkey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ed.key")
	if err := generateKeypair(path); err != nil {
		t.Fatalf("generateKeypair: %v", err)
	}
	withFlagGlobals(t, "", "", "info", 2002, 0.01)
	*pubkey = path
	if err := dispatch(); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
}

// TestDispatchPQPubkey covers the -pq-pubkey subcommand branch.
func TestDispatchPQPubkey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pq.key")
	if err := generateMLDSA44Keypair(path); err != nil {
		t.Fatalf("generateMLDSA44Keypair: %v", err)
	}
	withFlagGlobals(t, "", "", "info", 2002, 0.01)
	*pqPubkey = path
	if err := dispatch(); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
}

// TestDispatchValidateFlagsFails covers the validateFlags error branch.
func TestDispatchValidateFlagsFails(t *testing.T) {
	withFlagGlobals(t, "", "", "info", 2002, 0.01)
	if err := dispatch(); err == nil || !strings.Contains(err.Error(), "usage:") {
		t.Fatalf("dispatch: %v; want usage error", err)
	}
}

// TestDispatchKeygenFails covers a generateKeypair-error path through dispatch.
func TestDispatchKeygenFails(t *testing.T) {
	withFlagGlobals(t, "", "", "info", 2002, 0.01)
	*keygen = filepath.Join(t.TempDir(), "no", "such", "dir", "ed.key")
	if err := dispatch(); err == nil || !strings.Contains(err.Error(), "keygen") {
		t.Fatalf("dispatch: %v; want keygen error", err)
	}
}

// TestDispatchPQKeygenFails covers a generateMLDSA44Keypair-error path through
// dispatch.
func TestDispatchPQKeygenFails(t *testing.T) {
	withFlagGlobals(t, "", "", "info", 2002, 0.01)
	*pqKeygen = filepath.Join(t.TempDir(), "no", "such", "dir", "pq.key")
	if err := dispatch(); err == nil || !strings.Contains(err.Error(), "pq-keygen") {
		t.Fatalf("dispatch: %v; want pq-keygen error", err)
	}
}

// TestDispatchPubkeyFails covers a derivePublicKey-error path through dispatch.
func TestDispatchPubkeyFails(t *testing.T) {
	withFlagGlobals(t, "", "", "info", 2002, 0.01)
	*pubkey = filepath.Join(t.TempDir(), "missing.key")
	if err := dispatch(); err == nil || !strings.Contains(err.Error(), "pubkey") {
		t.Fatalf("dispatch: %v; want pubkey error", err)
	}
}

// TestDispatchPQPubkeyFails covers a deriveMLDSA44PublicKey-error path through
// dispatch.
func TestDispatchPQPubkeyFails(t *testing.T) {
	withFlagGlobals(t, "", "", "info", 2002, 0.01)
	*pqPubkey = filepath.Join(t.TempDir(), "missing.pq.key")
	if err := dispatch(); err == nil || !strings.Contains(err.Error(), "pq-pubkey") {
		t.Fatalf("dispatch: %v; want pq-pubkey error", err)
	}
}
