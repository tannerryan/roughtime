// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

//go:build unix

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tannerryan/roughtime/protocol"
	"go.uber.org/zap"
)

// TestCertificateRotationWaitsForActiveSigner checks that rotation publishes
// the replacement before waiting to wipe a certificate still used for signing.
func TestCertificateRotationWaitsForActiveSigner(t *testing.T) {
	rootPK, rootSK, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("root key: %v", err)
	}
	base := time.Now().Round(0)
	makeState := func(expiry time.Time) (*certState, []byte) {
		_, onlineSK, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("online key: %v", err)
		}
		cert, err := protocol.NewCertificate(base.Add(-time.Hour), expiry, onlineSK, rootSK)
		if err != nil {
			t.Fatalf("NewCertificate: %v", err)
		}
		return &certState{
			cert:      cert,
			notBefore: base.Add(-time.Hour),
			expiry:    expiry,
			srvHash:   protocol.ComputeSRV(rootPK),
		}, onlineSK.Public().(ed25519.PublicKey)
	}

	oldState, _ := makeState(base.Add(2 * time.Hour))
	newState, newOnlinePK := makeState(base.Add(18 * time.Hour))
	var current atomic.Pointer[certState]
	current.Store(oldState)

	if !oldState.acquire() {
		t.Fatal("failed to retain current certificate")
	}
	oldHeld := true
	refreshTicks := make(chan time.Time)
	validityTicks := make(chan time.Time)
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan struct{})
	var loopErr error
	go func() {
		loopErr = runRefreshChecks(ctx, zap.NewNop(), "test", schemeEd25519,
			rootPK, &current, refreshTicks, validityTicks, func() time.Time { return base },
			func() (*certState, []byte, error) { return newState, newOnlinePK, nil })
		close(finished)
	}()
	t.Cleanup(func() {
		if oldHeld {
			oldState.release()
		}
		cancel()
		select {
		case <-finished:
		case <-time.After(time.Second):
		}
	})

	select {
	case refreshTicks <- base:
	case <-time.After(time.Second):
		t.Fatal("refresh loop did not receive tick")
	}
	deadline := time.Now().Add(time.Second)
	for current.Load() != newState && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	if current.Load() != newState {
		t.Fatal("rotation did not publish replacement state")
	}

	nonce, request, err := protocol.CreateRequest(
		[]protocol.Version{protocol.VersionDraft12}, rand.Reader, oldState.srvHash)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	parsed, err := protocol.ParseRequest(request)
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}
	replies, err := protocol.CreateReplies(protocol.VersionDraft12,
		[]protocol.Request{*parsed}, base, time.Second, oldState.cert)
	if err != nil {
		t.Fatalf("sign with retained certificate: %v", err)
	}
	if _, _, err := protocol.VerifyReply([]protocol.Version{protocol.VersionDraft12},
		replies[0], rootPK, nonce, request); err != nil {
		t.Fatalf("VerifyReply: %v", err)
	}
	if got := acquireCurrent(&current); got != newState {
		if got != nil {
			got.release()
		}
		t.Fatalf("acquireCurrent()=%p want replacement %p", got, newState)
	} else {
		got.release()
	}

	oldState.release()
	oldHeld = false
	cancel()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("refresh loop did not finish retirement")
	}
	if loopErr != nil {
		t.Fatalf("runRefreshChecks: %v", loopErr)
	}
	oldState.mu.RLock()
	retired := oldState.retired
	oldState.mu.RUnlock()
	if !retired {
		t.Fatal("replaced certificate was not retired")
	}
	if oldState.acquire() {
		oldState.release()
		t.Fatal("retired certificate accepted a new signer")
	}
}
