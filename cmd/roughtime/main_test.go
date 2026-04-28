// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

//go:build unix

package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
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

// TestServeDualStack verifies serve starts and stops cleanly with both Ed25519
// and ML-DSA-44 configured.
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
	withFlagGlobals(t, edPath, pqPath, "error", pickFreeTCPPort(t), 0)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serve(ctx) }()

	// poll until the TCP listener accepts so cancel does not race startup
	waitForTCPReady(t, *port, 2*time.Second)
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

// waitForTCPReady polls until a TCP dial to [::1]:port succeeds or timeout
// elapses.
func waitForTCPReady(t *testing.T, port int, timeout time.Duration) {
	t.Helper()
	addr := net.JoinHostPort("::1", strconv.Itoa(port))
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("TCP listener on %s not ready within %s", addr, timeout)
}

// TestServeRejectsBadLogLevel verifies serve reports an error for an
// unparseable log-level flag.
func TestServeRejectsBadLogLevel(t *testing.T) {
	dir := t.TempDir()
	edPath := filepath.Join(dir, "ed.key")
	if err := generateKeypair(edPath); err != nil {
		t.Fatalf("generateKeypair: %v", err)
	}
	withFlagGlobals(t, edPath, "", "not-a-level", pickFreeTCPPort(t), 0)

	err := serve(context.Background())
	if err == nil || !strings.Contains(err.Error(), "log-level") {
		t.Fatalf("serve: %v; want log-level error", err)
	}
}

// TestServeRejectsBadEd25519Key verifies serve reports an error when Ed25519
// provisioning fails.
func TestServeRejectsBadEd25519Key(t *testing.T) {
	dir := t.TempDir()
	edPath := filepath.Join(dir, "bad.key")
	if err := os.WriteFile(edPath, []byte("not a valid seed file"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	withFlagGlobals(t, edPath, "", "error", pickFreeTCPPort(t), 0)

	err := serve(context.Background())
	if err == nil || !strings.Contains(err.Error(), "Ed25519") {
		t.Fatalf("serve: %v; want Ed25519 provisioning error", err)
	}
}

// TestServeRejectsBadPQKey verifies serve reports an error when ML-DSA-44
// provisioning fails.
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
	withFlagGlobals(t, edPath, pqPath, "error", pickFreeTCPPort(t), 0)

	err := serve(context.Background())
	if err == nil || !strings.Contains(err.Error(), "ML-DSA-44") {
		t.Fatalf("serve: %v; want ML-DSA-44 provisioning error", err)
	}
}

// TestDispatchVersion verifies dispatch handles the -version subcommand.
func TestDispatchVersion(t *testing.T) {
	withFlagGlobals(t, "", "", "info", 2002, 0.01)
	*showVersion = true
	if err := dispatch(); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
}

// TestDispatchKeygen verifies dispatch handles the -keygen subcommand.
func TestDispatchKeygen(t *testing.T) {
	withFlagGlobals(t, "", "", "info", 2002, 0.01)
	*keygen = filepath.Join(t.TempDir(), "ed.key")
	if err := dispatch(); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
}

// TestDispatchPQKeygen verifies dispatch handles the -pq-keygen subcommand.
func TestDispatchPQKeygen(t *testing.T) {
	withFlagGlobals(t, "", "", "info", 2002, 0.01)
	*pqKeygen = filepath.Join(t.TempDir(), "pq.key")
	if err := dispatch(); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
}

// TestDispatchPubkey verifies dispatch handles the -pubkey subcommand.
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

// TestDispatchPQPubkey verifies dispatch handles the -pq-pubkey subcommand.
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

// TestDispatchValidateFlagsFails verifies dispatch surfaces the usage error
// from validateFlags.
func TestDispatchValidateFlagsFails(t *testing.T) {
	withFlagGlobals(t, "", "", "info", 2002, 0.01)
	if err := dispatch(); err == nil || !strings.Contains(err.Error(), "usage:") {
		t.Fatalf("dispatch: %v; want usage error", err)
	}
}

// TestDispatchKeygenFails verifies dispatch surfaces an error when -keygen
// cannot write its output.
func TestDispatchKeygenFails(t *testing.T) {
	withFlagGlobals(t, "", "", "info", 2002, 0.01)
	*keygen = filepath.Join(t.TempDir(), "no", "such", "dir", "ed.key")
	if err := dispatch(); err == nil || !strings.Contains(err.Error(), "keygen") {
		t.Fatalf("dispatch: %v; want keygen error", err)
	}
}

// TestDispatchPQKeygenFails verifies dispatch surfaces an error when -pq-keygen
// cannot write its output.
func TestDispatchPQKeygenFails(t *testing.T) {
	withFlagGlobals(t, "", "", "info", 2002, 0.01)
	*pqKeygen = filepath.Join(t.TempDir(), "no", "such", "dir", "pq.key")
	if err := dispatch(); err == nil || !strings.Contains(err.Error(), "pq-keygen") {
		t.Fatalf("dispatch: %v; want pq-keygen error", err)
	}
}

// TestDispatchPubkeyFails verifies dispatch surfaces an error when -pubkey
// cannot read its input.
func TestDispatchPubkeyFails(t *testing.T) {
	withFlagGlobals(t, "", "", "info", 2002, 0.01)
	*pubkey = filepath.Join(t.TempDir(), "missing.key")
	if err := dispatch(); err == nil || !strings.Contains(err.Error(), "pubkey") {
		t.Fatalf("dispatch: %v; want pubkey error", err)
	}
}

// TestDispatchPQPubkeyFails verifies dispatch surfaces an error when -pq-pubkey
// cannot read its input.
func TestDispatchPQPubkeyFails(t *testing.T) {
	withFlagGlobals(t, "", "", "info", 2002, 0.01)
	*pqPubkey = filepath.Join(t.TempDir(), "missing.pq.key")
	if err := dispatch(); err == nil || !strings.Contains(err.Error(), "pq-pubkey") {
		t.Fatalf("dispatch: %v; want pq-pubkey error", err)
	}
}
