// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

//go:build unix

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tannerryan/roughtime/protocol"
)

// withFlagGlobals snapshots the server flag globals, applies overrides, and
// restores originals via t.Cleanup.
func withFlagGlobals(t *testing.T, edKey, pqKey, level string, p int, grease float64) {
	t.Helper()
	origPort := *port
	origFlexPort := *flexPort
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
	origOfflineDelegation := *offlineDelegation
	t.Cleanup(func() {
		*port = origPort
		*flexPort = origFlexPort
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
		*offlineDelegation = origOfflineDelegation
	})
	*port = p
	*flexPort = 0
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
	*offlineDelegation = false
}

// TestDispatchVersion exercises version output without starting listeners.
func TestDispatchVersion(t *testing.T) {
	withFlagGlobals(t, "", "", "error", 2002, 0)
	output, err := os.Create(filepath.Join(t.TempDir(), "stdout"))
	if err != nil {
		t.Fatal(err)
	}
	originalStdout := os.Stdout
	t.Cleanup(func() {
		os.Stdout = originalStdout
		_ = output.Close()
	})
	os.Stdout = output
	*showVersion = true
	if err := dispatch(); err != nil {
		t.Fatalf("dispatch version: %v", err)
	}
	if _, err := output.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(output)
	if err != nil || !bytes.Contains(data, []byte("github.com/tannerryan/roughtime")) {
		t.Fatalf("version output=%q, error=%v", data, err)
	}
}

// TestValidateActionFlagsAllowsSingles preserves every existing one-shot
// command while checking their shared mutual-exclusion gate.
func TestValidateActionFlagsAllowsSingles(t *testing.T) {
	cases := []struct {
		name string
		set  func()
	}{
		{name: "none", set: func() {}},
		{name: "version", set: func() { *showVersion = true }},
		{name: "keygen", set: func() { *keygen = "ed.key" }},
		{name: "pq-keygen", set: func() { *pqKeygen = "pq.key" }},
		{name: "pubkey", set: func() { *pubkey = "ed.key" }},
		{name: "pq-pubkey", set: func() { *pqPubkey = "pq.key" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withFlagGlobals(t, "", "", "error", 2002, 0)
			tc.set()
			if err := validateActionFlags(); err != nil {
				t.Fatalf("validateActionFlags: %v", err)
			}
		})
	}
}

// TestValidateActionFlagsRejectsConflicts covers conflicts across version, key
// generation, and public-key derivation actions.
func TestValidateActionFlagsRejectsConflicts(t *testing.T) {
	cases := []struct {
		name string
		set  func()
	}{
		{name: "version and keygen", set: func() { *showVersion, *keygen = true, "ed.key" }},
		{name: "both keygens", set: func() { *keygen, *pqKeygen = "ed.key", "pq.key" }},
		{name: "both pubkeys", set: func() { *pubkey, *pqPubkey = "ed.key", "pq.key" }},
		{name: "keygen and pubkey", set: func() { *pqKeygen, *pubkey = "pq.key", "ed.key" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withFlagGlobals(t, "", "", "error", 2002, 0)
			tc.set()
			if err := validateActionFlags(); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
				t.Fatalf("validateActionFlags conflict error=%v", err)
			}
		})
	}
}

// TestDispatchRejectsConflictingActionsBeforeExecution ensures a successful
// first action cannot hide an ignored second action.
func TestDispatchRejectsConflictingActionsBeforeExecution(t *testing.T) {
	withFlagGlobals(t, "", "", "error", 2002, 0)
	edPath := filepath.Join(t.TempDir(), "ed.key")
	pqPath := filepath.Join(t.TempDir(), "pq.key")
	*keygen = edPath
	*pqKeygen = pqPath

	err := dispatch()
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") ||
		!strings.Contains(err.Error(), "-keygen") || !strings.Contains(err.Error(), "-pq-keygen") {
		t.Fatalf("dispatch conflict error=%v", err)
	}
	for _, path := range []string{edPath, pqPath} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("conflicting dispatch modified %s: stat err=%v", path, err)
		}
	}
}

// startServeForTest retries the full server fixture if another process claims
// either selected port before serve binds it.
func startServeForTest(t *testing.T) (chan error, context.CancelFunc, string) {
	t.Helper()
	const maxAttempts = 5
	var lastErr error
attempts:
	for range maxAttempts {
		*port = pickFreeTCPPort(t)
		if *flexPort != 0 {
			*flexPort = pickFreeTCPPort(t)
			if *flexPort == *port {
				continue
			}
		}
		metricsPort := pickFreeTCPPort(t)
		if metricsPort == *port || metricsPort == *flexPort {
			continue
		}
		metricsHostPort := net.JoinHostPort("127.0.0.1", strconv.Itoa(metricsPort))
		*metricsAddr = metricsHostPort

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			defer close(done)
			done <- serve(ctx)
		}()
		t.Cleanup(func() {
			cancel()
			if err := awaitTest(t, done, 5*time.Second, "full server cleanup"); err != nil {
				t.Errorf("serve cleanup: %v", err)
			}
		})

		addresses := []string{
			net.JoinHostPort("::1", strconv.Itoa(*port)),
			metricsHostPort,
		}
		if *flexPort != 0 {
			addresses = append(addresses, net.JoinHostPort("::1", strconv.Itoa(*flexPort)))
		}
		ready := make([]bool, len(addresses))
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			select {
			case err := <-done:
				if !errors.Is(err, syscall.EADDRINUSE) {
					t.Fatalf("serve startup: %v", err)
				}
				lastErr = err
				cancel()
				continue attempts
			default:
			}
			for i, addr := range addresses {
				if ready[i] {
					continue
				}
				conn, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
				if err == nil {
					ready[i] = true
					_ = conn.Close()
				}
			}
			allReady := true
			for _, listening := range ready {
				allReady = allReady && listening
			}
			if allReady {
				return done, cancel, metricsHostPort
			}
			time.Sleep(10 * time.Millisecond)
		}
		cancel()
		lastErr = awaitTest(t, done, 5*time.Second, "failed full server attempt")
		t.Fatalf("server did not become ready, serve returned: %v", lastErr)
	}
	t.Fatalf("server did not start after %d attempts, last error: %v", maxAttempts, lastErr)
	return nil, nil, ""
}

// TestServeDualStack checks both ports, signature schemes, metrics, and
// shutdown.
func TestServeDualStack(t *testing.T) {
	edPath, edRootPK := withSeedFile(t)
	pqPath, pqRootPK := withPQSeedFile(t)
	withFlagGlobals(t, edPath, pqPath, "error", 2002, 0)
	*flexPort = 2002
	done, cancel, metricsHostPort := startServeForTest(t)

	for _, listenPort := range []int{*port, *flexPort} {
		waitForServerReady(t, listenPort, edRootPK)
		for _, ver := range protocol.SupportedWithMode(protocol.Flex) {
			rootPK := edRootPK
			if ver == protocol.VersionMLDSA44 {
				rootPK = pqRootPK
			}
			offer := []protocol.Version{ver}
			if ver == protocol.Version1 {
				offer = append(offer, protocol.VersionDraft12)
			}
			nonce, request, err := protocol.CreateRequestWithOptions(offer, rand.Reader,
				protocol.ComputeSRV(rootPK), protocol.RequestOptions{Mode: protocol.Flex})
			if err != nil {
				t.Fatal(err)
			}
			for _, network := range []string{"udp", "tcp"} {
				if network == "udp" && ver == protocol.VersionMLDSA44 || network == "tcp" && ver == protocol.VersionGoogle {
					continue
				}
				addr := net.JoinHostPort("::1", strconv.Itoa(listenPort))
				accept := isFlexPort(listenPort) || ver == protocol.Version1 || ver == protocol.VersionMLDSA44
				var reply []byte
				if network == "udp" {
					timeout := time.Second
					if !accept {
						timeout = 50 * time.Millisecond
					}
					reply, _, _, err = protocol.RoundTripUDP(context.Background(), addr, request, timeout)
				} else {
					reply, _, _, err = protocol.RoundTripTCP(context.Background(), addr, request, time.Second)
				}
				if !accept {
					if network == "udp" {
						var timeout net.Error
						if !errors.As(err, &timeout) || !timeout.Timeout() {
							t.Fatalf("primary UDP %s: expected silence, got %v", ver, err)
						}
					} else if !errors.Is(err, protocol.ErrPeerClosedNoReply) {
						t.Fatalf("primary TCP %s: expected rejection, got %v", ver, err)
					}
					continue
				}
				if err != nil {
					t.Fatalf("%s port %d, %s: %v", network, listenPort, ver, err)
				}
				if _, _, err := protocol.VerifyReplyWithOptions([]protocol.Version{ver}, reply, rootPK, nonce, request,
					protocol.VerifyOptions{Mode: protocol.Flex}); err != nil {
					t.Fatalf("%s port %d, %s: %v", network, listenPort, ver, err)
				}
				if ver == protocol.Version1 {
					checkListenerVERS(t, reply, !isFlexPort(listenPort))
				}
			}
		}
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://" + metricsHostPort + "/metrics")
	if err != nil {
		t.Fatalf("scrape: %v", err)
	}
	body, readErr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if readErr != nil {
		t.Fatalf("read scrape: %v", readErr)
	}
	if resp.StatusCode != http.StatusOK || !bytes.Contains(body, []byte("roughtime_build_info")) {
		t.Fatalf("scrape status=%d body=%s", resp.StatusCode, body)
	}
	cancel()
	if err := awaitTest(t, done, 5*time.Second, "dual-stack server shutdown"); err != nil {
		t.Fatalf("serve: %v", err)
	}
	for _, listenPort := range []int{*port, *flexPort} {
		for _, network := range []string{"tcp", "udp"} {
			addr := net.JoinHostPort("::1", strconv.Itoa(listenPort))
			if network == "tcp" {
				conn, err := net.Listen(network, addr)
				if err != nil {
					t.Fatalf("TCP port %d retained after shutdown: %v", listenPort, err)
				}
				_ = conn.Close()
			} else {
				conn, err := net.ListenPacket(network, addr)
				if err != nil {
					t.Fatalf("UDP port %d retained after shutdown: %v", listenPort, err)
				}
				_ = conn.Close()
			}
		}
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
		t.Fatalf("serve: %v, want Ed25519 provisioning error", err)
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
		t.Fatalf("serve: %v, want ML-DSA-44 provisioning error", err)
	}
}

// checkListenerVERS checks the advertised profiles after the reply is
// authenticated.
func checkListenerVERS(t *testing.T, reply []byte, rfcOnly bool) {
	t.Helper()
	msg, err := protocol.Decode(reply[protocol.PacketHeaderSize:])
	if err != nil {
		t.Fatal(err)
	}
	srep, err := protocol.Decode(msg[protocol.TagSREP])
	if err != nil {
		t.Fatal(err)
	}
	versions := srep[protocol.TagVERS]
	if rfcOnly {
		if !bytes.Equal(versions, []byte{1, 0, 0, 0}) {
			t.Fatalf("primary RFC VERS = %x, want version 1 only", versions)
		}
	} else if len(versions) != 4*(len(protocol.ServerPreferenceEd25519)-1) {
		// Google has no signed VERS entry.
		t.Fatalf("compatibility RFC VERS = %x, want all Ed25519 versions", versions)
	}
}
