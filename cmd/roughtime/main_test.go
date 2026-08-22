// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

//go:build unix

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tannerryan/roughtime/protocol"
)

// withFlagGlobals snapshots the server flag globals, applies overrides, and
// restores originals via t.Cleanup.
func withFlagGlobals(t *testing.T, edKey, pqKey, level string, p int, grease float64) {
	t.Helper()
	origPort := *port
	origListenAddress := *listenAddress
	origEd := *rootKeySeedHexFile
	origPQ := *pqRootKeySeedHexFile
	origLevel := *logLevel
	origGrease := *greaseRate
	origShowVersion := *showVersion
	origKeygen := *keygen
	origPubkey := *pubkey
	origPQKeygen := *pqKeygen
	origPQPubkey := *pqPubkey
	origMetrics := *metricsAddr
	origStatsInterval := *statsInterval
	t.Cleanup(func() {
		*port = origPort
		*listenAddress = origListenAddress
		*rootKeySeedHexFile = origEd
		*pqRootKeySeedHexFile = origPQ
		*logLevel = origLevel
		*greaseRate = origGrease
		*showVersion = origShowVersion
		*keygen = origKeygen
		*pubkey = origPubkey
		*pqKeygen = origPQKeygen
		*pqPubkey = origPQPubkey
		*metricsAddr = origMetrics
		*statsInterval = origStatsInterval
	})
	*port = p
	*listenAddress = ""
	*rootKeySeedHexFile = edKey
	*pqRootKeySeedHexFile = pqKey
	*logLevel = level
	*greaseRate = grease
	*showVersion = false
	*keygen = ""
	*pubkey = ""
	*pqKeygen = ""
	*pqPubkey = ""
	*metricsAddr = ""
}

// TestServeDualStack covers combined Ed25519 and ML-DSA-44 serving.
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
	edCert, _, edRootPK, _, err := provisionCertificateKey()
	if err != nil {
		t.Fatalf("provision Ed25519: %v", err)
	}
	defer edCert.Wipe()
	pqCert, _, pqRootPK, _, err := provisionMLDSA44CertificateKey()
	if err != nil {
		t.Fatalf("provision ML-DSA-44: %v", err)
	}
	defer pqCert.Wipe()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serve(ctx) }()

	// Poll until the TCP listener is bound so cancellation does not race
	// startup.
	waitForTCPReady(t, *port, 2*time.Second)
	// Cases cover both configured signing schemes.
	for _, test := range []struct {
		version protocol.Version
		rootPK  []byte
	}{
		{protocol.VersionDraft12, edRootPK},
		{protocol.VersionMLDSA44, pqRootPK},
	} {
		srv := protocol.ComputeSRV(test.rootPK)
		nonce, request, err := protocol.CreateRequest([]protocol.Version{test.version}, rand.Reader, srv)
		if err != nil {
			t.Fatalf("CreateRequest(%s): %v", test.version, err)
		}
		conn := dialTCP(t, *port)
		reply := tcpRoundTrip(t, conn, request)
		_ = conn.Close()
		if _, _, err := protocol.VerifyReply([]protocol.Version{test.version}, reply, test.rootPK, nonce, request); err != nil {
			t.Fatalf("VerifyReply(%s): %v", test.version, err)
		}
	}
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
	waitForTCPDialReady(t, net.JoinHostPort("::1", strconv.Itoa(port)), timeout)
}

// waitForTCPDialReady polls a literal host:port until a TCP dial succeeds or
// timeout elapses.
func waitForTCPDialReady(t *testing.T, addr string, timeout time.Duration) {
	t.Helper()
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

// TestServeWithMetricsAddr covers the configured metrics listener.
func TestServeWithMetricsAddr(t *testing.T) {
	dir := t.TempDir()
	edPath := filepath.Join(dir, "ed.key")
	if err := generateKeypair(edPath); err != nil {
		t.Fatalf("generateKeypair: %v", err)
	}
	metricsPort := pickFreeTCPPort(t)
	metricsHostPort := net.JoinHostPort("127.0.0.1", strconv.Itoa(metricsPort))

	withFlagGlobals(t, edPath, "", "error", pickFreeTCPPort(t), 0)
	*metricsAddr = metricsHostPort

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serve(ctx) }()

	waitForTCPReady(t, *port, 2*time.Second)
	waitForTCPDialReady(t, metricsHostPort, 2*time.Second)

	resp, err := http.Get("http://" + metricsHostPort + "/metrics")
	if err != nil {
		cancel()
		<-done
		t.Fatalf("scrape: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		cancel()
		<-done
		t.Fatalf("scrape status=%d body=%s", resp.StatusCode, body)
	}
	if !bytes.Contains(body, []byte("roughtime_build_info")) {
		cancel()
		<-done
		t.Fatalf("scrape missing build_info:\n%s", body)
	}

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

// TestServePreCanceled treats shutdown during listener startup as clean.
func TestServePreCanceled(t *testing.T) {
	edPath := filepath.Join(t.TempDir(), "ed.key")
	if err := generateKeypair(edPath); err != nil {
		t.Fatalf("generateKeypair: %v", err)
	}
	withFlagGlobals(t, edPath, "", "error", pickFreeTCPPort(t), 0)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := serve(ctx); err != nil {
		t.Fatalf("serve with canceled context: %v", err)
	}
}

// TestServeRejectsBadEd25519Key covers an invalid Ed25519 seed.
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

// TestServeRejectsBadPQKey covers an invalid ML-DSA-44 seed.
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
