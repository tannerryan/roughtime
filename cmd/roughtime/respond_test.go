// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

//go:build unix

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"github.com/tannerryan/roughtime/protocol"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

// TestValidateRequestAcceptsValidDraft12 verifies validateRequest accepts a
// well-formed Draft12 request.
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

// TestValidateRequestAcceptsGoogle verifies validateRequest accepts a
// Google-Roughtime request.
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

// TestValidateRequestRejectsParseError verifies validateRequest rejects
// all-zero bytes.
func TestValidateRequestRejectsParseError(t *testing.T) {
	_, st := newUnitCertState(t)
	peer := &net.UDPAddr{IP: net.IPv6loopback, Port: 0}

	// debug logger exercises parse-failure branch
	junk := make([]byte, 1024)
	if _, ok := validateRequest(zaptest.NewLogger(t), junk, peer, 1024, nil, st); ok {
		t.Fatal("validateRequest accepted all-zero bytes")
	}
}

// TestValidateRequestRejectsSRVMismatch verifies validateRequest rejects a
// request whose SRV addresses a different root.
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
	if _, ok := validateRequest(zaptest.NewLogger(t), req, peer, len(req), nil, st); ok {
		t.Fatal("validateRequest accepted request with wrong SRV")
	}
}

// TestValidateRequestAcceptsAbsentSRV verifies validateRequest accepts a
// draft-09 request with no SRV tag.
func TestValidateRequestAcceptsAbsentSRV(t *testing.T) {
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

// TestValidateRequestRejectsUnsupportedVersion verifies validateRequest rejects
// an unrecognised wire version.
func TestValidateRequestRejectsUnsupportedVersion(t *testing.T) {
	rootPK, st := newUnitCertState(t)
	srv := protocol.ComputeSRV(rootPK)
	_, req, err := protocol.CreateRequest([]protocol.Version{protocol.Version(0xdeadbeef)}, rand.Reader, srv)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	peer := &net.UDPAddr{IP: net.IPv6loopback, Port: 0}
	if _, ok := validateRequest(zaptest.NewLogger(t), req, peer, len(req), nil, st); ok {
		t.Fatal("validateRequest accepted request with unsupported version")
	}
}

// TestValidateRequestStoresBufPtr verifies validateRequest preserves the
// caller's buffer pointer for pool return.
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

// TestSignAndBuildRepliesSingle verifies signAndBuildReplies returns a
// verifiable reply for a single request.
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

// TestSignAndBuildRepliesBatch verifies signAndBuildReplies returns one
// verifiable reply per item, in order.
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

// TestSignAndBuildRepliesAmplificationDrop verifies signAndBuildReplies drops a
// reply that would exceed the request size.
func TestSignAndBuildRepliesAmplificationDrop(t *testing.T) {
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
		requestSize: 64, // forces reply to exceed request
		version:     protocol.VersionDraft12,
	}}
	replies := signAndBuildReplies(zap.NewNop(), st, protocol.VersionDraft12, items)
	if len(replies) != 0 {
		t.Fatalf("amplification: got %d replies, want 0", len(replies))
	}
}

// TestSignAndBuildRepliesEmpty verifies signAndBuildReplies returns nil for an
// empty batch.
func TestSignAndBuildRepliesEmpty(t *testing.T) {
	_, st := newUnitCertState(t)
	replies := signAndBuildReplies(zap.NewNop(), st, protocol.VersionDraft12, nil)
	if replies != nil {
		t.Fatalf("nil items: got %d replies", len(replies))
	}
}

// FuzzValidateRequest verifies validateRequest never panics on arbitrary input.
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

// FuzzServeOnce verifies the validate-and-sign pipeline never panics on
// arbitrary input.
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
		signAndBuildReplies(zap.NewNop(), st, vr.version, []validatedRequest{vr})
	})
}
