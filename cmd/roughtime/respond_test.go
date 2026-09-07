// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

//go:build unix

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tannerryan/roughtime/protocol"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

// TestValidateRequestAcceptsValidDraft12 covers parsing and negotiation.
func TestValidateRequestAcceptsValidDraft12(t *testing.T) {
	rootPK, st := newUnitCertState(t)
	srv := protocol.ComputeSRV(rootPK)
	_, req, err := protocol.CreateRequest([]protocol.Version{protocol.VersionDraft12}, rand.Reader, srv)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	peer := &net.UDPAddr{IP: net.IPv6loopback, Port: 0}
	vr, reason, ok := validateRequest(zap.NewNop(), req, peer, len(req), nil, st)
	if !ok {
		t.Fatal("validateRequest rejected a well-formed request")
	}
	if reason != dropNone {
		t.Fatalf("reason=%q want empty on success", reason)
	}
	if vr.version != protocol.VersionDraft12 {
		t.Fatalf("version=%s want Draft12", vr.version)
	}
	if vr.requestSize != len(req) {
		t.Fatalf("requestSize=%d want %d", vr.requestSize, len(req))
	}
}

// TestValidateRequestRejectsSRVMismatch covers server-binding rejection.
func TestValidateRequestRejectsSRVMismatch(t *testing.T) {
	_, st := newUnitCertState(t)

	otherPK, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen other: %v", err)
	}
	badSRV := protocol.ComputeSRV(otherPK)

	_, req, err := protocol.CreateRequest([]protocol.Version{protocol.VersionDraft12}, rand.Reader, badSRV)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	peer := &net.UDPAddr{IP: net.IPv6loopback, Port: 0}
	if _, reason, ok := validateRequest(zaptest.NewLogger(t), req, peer, len(req), nil, st); ok || reason != dropSRV {
		t.Fatalf("validateRequest SRV mismatch: ok=%v reason=%q want ok=false reason=%q", ok, reason, dropSRV)
	}
}

// TestRejectUDPBatchAccountsForEveryRequest covers the shared fail-closed batch
// rejection path.
func TestRejectUDPBatchAccountsForEveryRequest(t *testing.T) {
	startBatches := statsBatchErrs.Load()
	startDropped := droppedFor(transportUDP, dropBatchErr)
	items := make([]validatedRequest, 3)
	if replies := rejectUDPBatch(zap.NewNop(), protocol.VersionDraft12, items, "test rejection"); replies != nil {
		t.Fatalf("rejectUDPBatch replies=%v want nil", replies)
	}
	if got := statsBatchErrs.Load(); got != startBatches+1 {
		t.Fatalf("batch errors=%d want %d", got, startBatches+1)
	}
	if got := droppedFor(transportUDP, dropBatchErr); got != startDropped+uint64(len(items)) {
		t.Fatalf("batch drops=%d want %d", got, startDropped+uint64(len(items)))
	}
}

// TestSignAndBuildRepliesRejectsInvalidCertificate covers unavailable,
// not-yet-valid, and expired signing states without producing a reply.
func TestSignAndBuildRepliesRejectsInvalidCertificate(t *testing.T) {
	now := wallClockNow()
	_, notYetValid := newCertState(t)
	notYetValid.Load().notBefore = now.Add(time.Hour)
	_, expired := newCertState(t)
	expired.Load().expiry = now.Add(-time.Hour)
	cases := []struct {
		name  string
		state *atomic.Pointer[certState]
	}{
		{name: "unavailable", state: &atomic.Pointer[certState]{}},
		{name: "not yet valid", state: notYetValid},
		{name: "expired", state: expired},
	}

	items := []validatedRequest{{}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if replies := signAndBuildRepliesCurrent(zap.NewNop(), tc.state, protocol.VersionDraft12, items); replies != nil {
				t.Fatalf("signAndBuildRepliesCurrent replies=%v want nil", replies)
			}
		})
	}
}

// FuzzValidateRequest exercises arbitrary UDP requests.
func FuzzValidateRequest(f *testing.F) {
	rootPK, rootSK, _ := ed25519.GenerateKey(rand.Reader)
	_, onlineSK, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	cert, _ := protocol.NewCertificate(now.Add(-time.Hour), now.Add(time.Hour), onlineSK, rootSK)
	st := &certState{cert: cert, expiry: now.Add(time.Hour), srvHash: protocol.ComputeSRV(rootPK)}

	srv := protocol.ComputeSRV(rootPK)
	_, googleReq, _ := protocol.CreateRequest([]protocol.Version{protocol.VersionGoogle}, rand.Reader, nil)
	_, draft01Req, _ := protocol.CreateRequest([]protocol.Version{protocol.VersionDraft01}, rand.Reader, srv)
	_, draft12Req, _ := protocol.CreateRequest([]protocol.Version{protocol.VersionDraft12}, rand.Reader, srv)
	f.Add(googleReq)
	f.Add(draft01Req)
	f.Add(draft12Req)
	f.Add([]byte{})
	f.Add([]byte{0})
	f.Add(make([]byte, 1024))

	peer := &net.UDPAddr{IP: net.IPv6loopback, Port: 0}
	f.Fuzz(func(_ *testing.T, data []byte) {
		validateRequest(zap.NewNop(), data, peer, len(data), nil, st)
	})
}
