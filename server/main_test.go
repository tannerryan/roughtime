// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package main

import (
	"context"
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

// newUnitCertState builds an in-memory certState for unit tests without
// touching disk. Returns the root public key so tests can forge mismatched SRV
// values and verify replies.
func newUnitCertState(t *testing.T) (ed25519.PublicKey, *certState) {
	t.Helper()
	rootPK, rootSK, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen root: %v", err)
	}
	_, onlineSK, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen online: %v", err)
	}
	now := time.Now()
	cert, err := protocol.NewCertificate(now.Add(-time.Hour), now.Add(time.Hour), onlineSK, rootSK)
	if err != nil {
		t.Fatalf("NewCertificate: %v", err)
	}
	return rootPK, &certState{cert: cert, expiry: now.Add(time.Hour), srvHash: protocol.ComputeSRV(rootPK)}
}

// TestRecoverGoroutineAbsorbsPanic verifies that `defer recoverGoroutine(...)`
// absorbs a panic and increments statsPanics. recover() only works when called
// directly from a deferred function, so the production call site must be `defer
// recoverGoroutine(...)` rather than wrapped in another closure.
func TestRecoverGoroutineAbsorbsPanic(t *testing.T) {
	before := statsPanics.Load()
	func() {
		defer recoverGoroutine(zap.NewNop(), "unit")
		panic("boom")
	}()
	if got := statsPanics.Load(); got != before+1 {
		t.Fatalf("statsPanics delta=%d, want 1", got-before)
	}
}

// TestRecoverGoroutineNoPanicNoOp verifies that deferring recoverGoroutine on a
// function that exits normally leaves statsPanics untouched.
func TestRecoverGoroutineNoPanicNoOp(t *testing.T) {
	before := statsPanics.Load()
	func() {
		defer recoverGoroutine(zap.NewNop(), "unit")
	}()
	if got := statsPanics.Load(); got != before {
		t.Fatalf("statsPanics changed without panic: %d", got-before)
	}
}

// TestSuperviseLoopRestartsOnPanic injects panics from the supervised function
// and asserts the loop absorbs them and keeps restarting until ctx is done.
func TestSuperviseLoopRestartsOnPanic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var runs atomic.Int32
	done := make(chan struct{})
	go func() {
		superviseLoop(ctx, zap.NewNop(), "unit", func() {
			n := runs.Add(1)
			if n < 3 {
				panic("induced")
			}
			// Third iteration: clean exit so the loop keeps restarting until
			// ctx cancellation terminates it.
		})
		close(done)
	}()

	// Wait for at least three runs to occur, then cancel.
	deadline := time.Now().Add(2 * time.Second)
	for runs.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if runs.Load() < 3 {
		t.Fatalf("superviseLoop did not reach 3 runs (got %d)", runs.Load())
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("superviseLoop did not exit after cancel")
	}
}

// TestSuperviseLoopExitsOnCtxCancel asserts that a pre-cancelled ctx causes
// superviseLoop to return immediately without invoking the supervised fn.
func TestSuperviseLoopExitsOnCtxCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before starting

	done := make(chan struct{})
	var ran atomic.Bool
	go func() {
		superviseLoop(ctx, zap.NewNop(), "unit", func() {
			ran.Store(true)
		})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("superviseLoop did not return on pre-cancelled ctx")
	}
	if ran.Load() {
		t.Fatal("fn ran when ctx was already cancelled")
	}
}

// TestValidateRequestAcceptsValidDraft12 is the happy-path assertion for an
// IETF draft-12 request with matching SRV.
func TestValidateRequestAcceptsValidDraft12(t *testing.T) {
	rootPK, st := newUnitCertState(t)
	srv := protocol.ComputeSRV(rootPK)
	_, req, err := protocol.CreateRequest([]protocol.Version{protocol.VersionDraft12}, rand.Reader, srv)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	peer := &net.UDPAddr{IP: net.IPv6loopback, Port: 0}
	vr, ok := validateRequest(zap.NewNop(), req, peer, len(req), nil, st)
	if !ok {
		t.Fatal("validateRequest rejected a well-formed request")
	}
	if vr.version != protocol.VersionDraft12 {
		t.Fatalf("version=%s want Draft12", vr.version)
	}
	if vr.requestSize != len(req) {
		t.Fatalf("requestSize=%d want %d", vr.requestSize, len(req))
	}
}

// TestValidateRequestAcceptsGoogle asserts Google-Roughtime requests (no VER
// tag, no SRV) are accepted and surface VersionGoogle as the negotiated wire.
func TestValidateRequestAcceptsGoogle(t *testing.T) {
	_, st := newUnitCertState(t)
	_, req, err := protocol.CreateRequest([]protocol.Version{protocol.VersionGoogle}, rand.Reader, nil)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	peer := &net.UDPAddr{IP: net.IPv6loopback, Port: 0}
	vr, ok := validateRequest(zap.NewNop(), req, peer, len(req), nil, st)
	if !ok {
		t.Fatal("validateRequest rejected Google request")
	}
	if vr.version != protocol.VersionGoogle {
		t.Fatalf("version=%s want Google", vr.version)
	}
}

// TestValidateRequestRejectsParseError feeds junk bytes through validation and
// asserts it rejects them without panicking.
func TestValidateRequestRejectsParseError(t *testing.T) {
	_, st := newUnitCertState(t)
	peer := &net.UDPAddr{IP: net.IPv6loopback, Port: 0}

	// All-zero 1024 bytes: valid size, but ParseRequest fails (no ROUGHTIM
	// header, no valid tag structure). Uses a debug logger so the parse-failure
	// log branch is also exercised.
	junk := make([]byte, 1024)
	if _, ok := validateRequest(zaptest.NewLogger(t), junk, peer, 1024, nil, st); ok {
		t.Fatal("validateRequest accepted all-zero bytes")
	}
}

// TestValidateRequestRejectsSRVMismatch covers the drafts 10+ §5.1 MUST: a
// request whose SRV hash does not address this server's key is dropped.
func TestValidateRequestRejectsSRVMismatch(t *testing.T) {
	_, st := newUnitCertState(t)

	// Forge SRV with a different root key.
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
	if _, ok := validateRequest(zaptest.NewLogger(t), req, peer, len(req), nil, st); ok {
		t.Fatal("validateRequest accepted request with wrong SRV")
	}
}

// TestValidateRequestAcceptsAbsentSRV asserts pre-draft-10 requests (which do
// not include SRV) are still served.
func TestValidateRequestAcceptsAbsentSRV(t *testing.T) {
	// Pre-draft-10 versions do not require SRV; server must still serve them.
	_, st := newUnitCertState(t)
	_, req, err := protocol.CreateRequest([]protocol.Version{protocol.VersionDraft09}, rand.Reader, nil)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	peer := &net.UDPAddr{IP: net.IPv6loopback, Port: 0}
	if _, ok := validateRequest(zap.NewNop(), req, peer, len(req), nil, st); !ok {
		t.Fatal("validateRequest rejected draft-09 request without SRV")
	}
}

// TestValidateRequestRejectsUnsupportedVersion exercises the SelectVersion
// failure branch: a client advertising only a version this server does not
// implement must be dropped.
func TestValidateRequestRejectsUnsupportedVersion(t *testing.T) {
	rootPK, st := newUnitCertState(t)
	srv := protocol.ComputeSRV(rootPK)
	// 0xdeadbeef is not in the server's version preference list. The wire group
	// defaults to groupD14 so CreateRequest still produces a parseable packet;
	// SelectVersion then rejects it with "no mutually supported".
	_, req, err := protocol.CreateRequest([]protocol.Version{protocol.Version(0xdeadbeef)}, rand.Reader, srv)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	peer := &net.UDPAddr{IP: net.IPv6loopback, Port: 0}
	if _, ok := validateRequest(zaptest.NewLogger(t), req, peer, len(req), nil, st); ok {
		t.Fatal("validateRequest accepted request with unsupported version")
	}
}

// TestValidateRequestStoresBufPtr asserts the pooled-read buffer pointer is
// round-tripped so listen_other.go can return it after signing.
func TestValidateRequestStoresBufPtr(t *testing.T) {
	rootPK, st := newUnitCertState(t)
	srv := protocol.ComputeSRV(rootPK)
	_, req, _ := protocol.CreateRequest([]protocol.Version{protocol.VersionDraft12}, rand.Reader, srv)
	peer := &net.UDPAddr{IP: net.IPv6loopback, Port: 0}
	buf := make([]byte, len(req))
	copy(buf, req)
	vr, ok := validateRequest(zap.NewNop(), buf, peer, len(req), &buf, st)
	if !ok {
		t.Fatal("validateRequest rejected valid request")
	}
	if vr.bufPtr != &buf {
		t.Fatal("validateRequest did not preserve bufPtr")
	}
}

// TestSignAndBuildRepliesSingle signs a one-item batch and verifies the reply
// parses cleanly against the root key.
func TestSignAndBuildRepliesSingle(t *testing.T) {
	rootPK, st := newUnitCertState(t)
	srv := protocol.ComputeSRV(rootPK)
	peer := &net.UDPAddr{IP: net.IPv6loopback, Port: 12345}

	prevGrease := *greaseRate
	*greaseRate = 0
	t.Cleanup(func() { *greaseRate = prevGrease })

	nonce, req, _ := protocol.CreateRequest([]protocol.Version{protocol.VersionDraft12}, rand.Reader, srv)
	parsed, _ := protocol.ParseRequest(req)
	items := []validatedRequest{{req: *parsed, peer: peer, requestSize: len(req), version: protocol.VersionDraft12}}

	replies := signAndBuildReplies(zap.NewNop(), st, protocol.VersionDraft12, items)
	if len(replies) != 1 {
		t.Fatalf("replies=%d want 1", len(replies))
	}
	if len(replies[0].bytes) > len(req) {
		t.Fatalf("amplification: reply=%d request=%d", len(replies[0].bytes), len(req))
	}
	if _, _, err := protocol.VerifyReply([]protocol.Version{protocol.VersionDraft12}, replies[0].bytes, rootPK, nonce, req); err != nil {
		t.Fatalf("VerifyReply: %v", err)
	}
}

// TestSignAndBuildRepliesBatch exercises the bulk-signing path with eight
// peers, asserting reply/peer order is preserved and each reply verifies.
func TestSignAndBuildRepliesBatch(t *testing.T) {
	rootPK, st := newUnitCertState(t)
	srv := protocol.ComputeSRV(rootPK)

	prevGrease := *greaseRate
	*greaseRate = 0
	t.Cleanup(func() { *greaseRate = prevGrease })

	const n = 8
	nonces := make([][]byte, n)
	reqs := make([][]byte, n)
	items := make([]validatedRequest, n)
	for i := range items {
		nonce, req, _ := protocol.CreateRequest([]protocol.Version{protocol.VersionDraft12}, rand.Reader, srv)
		parsed, _ := protocol.ParseRequest(req)
		nonces[i], reqs[i] = nonce, req
		items[i] = validatedRequest{
			req:         *parsed,
			peer:        &net.UDPAddr{IP: net.IPv6loopback, Port: 10000 + i},
			requestSize: len(req),
			version:     protocol.VersionDraft12,
		}
	}

	replies := signAndBuildReplies(zap.NewNop(), st, protocol.VersionDraft12, items)
	if len(replies) != n {
		t.Fatalf("replies=%d want %d", len(replies), n)
	}
	for i, r := range replies {
		if r.peer.Port != 10000+i {
			t.Errorf("reply %d: peer port=%d want %d", i, r.peer.Port, 10000+i)
		}
		if _, _, err := protocol.VerifyReply([]protocol.Version{protocol.VersionDraft12}, r.bytes, rootPK, nonces[i], reqs[i]); err != nil {
			t.Errorf("reply %d VerifyReply: %v", i, err)
		}
	}
}

// TestSignAndBuildRepliesAmplificationDrop forces reply > requestSize and
// asserts the amplification guard suppresses the outgoing reply.
func TestSignAndBuildRepliesAmplificationDrop(t *testing.T) {
	// Shrink the effective "request size" so the reply MUST exceed it.
	rootPK, st := newUnitCertState(t)
	srv := protocol.ComputeSRV(rootPK)
	_, req, _ := protocol.CreateRequest([]protocol.Version{protocol.VersionDraft12}, rand.Reader, srv)
	parsed, _ := protocol.ParseRequest(req)

	prevGrease := *greaseRate
	*greaseRate = 0
	t.Cleanup(func() { *greaseRate = prevGrease })

	items := []validatedRequest{{
		req:         *parsed,
		peer:        &net.UDPAddr{IP: net.IPv6loopback, Port: 1},
		requestSize: 64, // impossibly small — reply will exceed
		version:     protocol.VersionDraft12,
	}}
	replies := signAndBuildReplies(zap.NewNop(), st, protocol.VersionDraft12, items)
	if len(replies) != 0 {
		t.Fatalf("amplification: got %d replies, want 0", len(replies))
	}
}

// TestSignAndBuildRepliesEmpty asserts a nil items slice returns nil rather
// than attempting to sign a zero-item batch.
func TestSignAndBuildRepliesEmpty(t *testing.T) {
	_, st := newUnitCertState(t)
	replies := signAndBuildReplies(zap.NewNop(), st, protocol.VersionDraft12, nil)
	if replies != nil {
		t.Fatalf("nil items: got %d replies", len(replies))
	}
}

// FuzzValidateRequest pumps arbitrary UDP payloads through the server's hot
// validation path and asserts it never panics. This mirrors FuzzParseRequest at
// the protocol layer but exercises the server's additional SRV/version checks
// and the cert-state interaction.
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
		// Must not panic on any input.
		validateRequest(zap.NewNop(), data, peer, len(data), nil, st)
	})
}

// FuzzServeOnce exercises the full server request-to-reply pipeline:
// validateRequest followed by signAndBuildReplies on any accepted input. This
// catches panics that could only surface when validation accepts a payload the
// signer then mishandles.
func FuzzServeOnce(f *testing.F) {
	rootPK, rootSK, _ := ed25519.GenerateKey(rand.Reader)
	_, onlineSK, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	cert, _ := protocol.NewCertificate(now.Add(-time.Hour), now.Add(time.Hour), onlineSK, rootSK)
	st := &certState{cert: cert, expiry: now.Add(time.Hour), srvHash: protocol.ComputeSRV(rootPK)}

	srv := protocol.ComputeSRV(rootPK)
	for _, v := range []protocol.Version{
		protocol.VersionGoogle,
		protocol.VersionDraft01,
		protocol.VersionDraft08,
		protocol.VersionDraft12,
	} {
		var s []byte
		if v != protocol.VersionGoogle {
			s = srv
		}
		if _, req, err := protocol.CreateRequest([]protocol.Version{v}, rand.Reader, s); err == nil {
			f.Add(req)
		}
	}
	f.Add(make([]byte, 1024))

	peer := &net.UDPAddr{IP: net.IPv6loopback, Port: 0}
	f.Fuzz(func(_ *testing.T, data []byte) {
		vr, ok := validateRequest(zap.NewNop(), data, peer, len(data), nil, st)
		if !ok {
			return
		}
		// signAndBuildReplies must tolerate any payload validateRequest
		// accepts, including replies it chooses to drop (amplification cap).
		signAndBuildReplies(zap.NewNop(), st, vr.version, []validatedRequest{vr})
	})
}
