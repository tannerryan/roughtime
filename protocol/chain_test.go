// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"
	"testing"
	"time"
)

// chainServer is a test fixture for serving Roughtime replies in chain tests.
type chainServer struct {
	rootSK ed25519.PrivateKey
	rootPK ed25519.PublicKey
	cert   *Certificate
	ver    Version
}

// newChainServer constructs a chainServer with a fresh certificate.
func newChainServer(t *testing.T, ver Version) chainServer {
	t.Helper()
	rootSK, onlineSK := testKeys(t)
	now := time.Now()
	cert, err := NewCertificate(now.Add(-time.Hour), now.Add(time.Hour), onlineSK, rootSK)
	if err != nil {
		t.Fatal(err)
	}
	return chainServer{
		rootSK: rootSK,
		rootPK: rootSK.Public().(ed25519.PublicKey),
		cert:   cert,
		ver:    ver,
	}
}

// respond builds a signed reply for a single request.
func (s chainServer) respond(t *testing.T, request []byte) []byte {
	t.Helper()
	parsed, err := ParseRequest(request)
	if err != nil {
		t.Fatalf("parse request: %v", err)
	}
	replies, err := CreateReplies(s.ver, []Request{*parsed}, time.Now(), time.Second, s.cert)
	if err != nil || len(replies) != 1 {
		t.Fatalf("create reply: %v", err)
	}
	return replies[0]
}

// buildChain creates a chain of n verified links against fresh chainServers.
func buildChain(t *testing.T, ver Version, n int) (*Chain, []chainServer) {
	t.Helper()
	servers := make([]chainServer, n)
	for i := range n {
		servers[i] = newChainServer(t, ver)
	}

	var c Chain
	for _, srv := range servers {
		link, err := c.NextRequest([]Version{ver}, srv.rootPK, rand.Reader)
		if err != nil {
			t.Fatalf("next request: %v", err)
		}
		link.Response = srv.respond(t, link.Request)
		c.Append(link)
	}
	return &c, servers
}

// errReader is an io.Reader that always returns its err.
type errReader struct{ err error }

// Read returns the configured error.
func (r errReader) Read([]byte) (int, error) { return 0, r.err }

// TestChainNonceFirst verifies ChainNonce returns nil rand and a sized nonce
// for the first link.
func TestChainNonceFirst(t *testing.T) {
	nonce, blind, err := ChainNonce(nil, rand.Reader, []Version{VersionDraft12})
	if err != nil {
		t.Fatal(err)
	}
	if blind != nil {
		t.Fatal("first link should have nil rand")
	}
	if len(nonce) != 32 {
		t.Fatalf("nonce length = %d, want 32", len(nonce))
	}
}

// TestChainNonceGoogle verifies ChainNonce derivation for Google-Roughtime
// (64-byte nonce).
func TestChainNonceGoogle(t *testing.T) {
	prevResp := randBytes(t, 128)
	nonce, blind, err := ChainNonce(prevResp, rand.Reader, []Version{VersionGoogle})
	if err != nil {
		t.Fatal(err)
	}
	if len(blind) != 64 {
		t.Fatalf("Google blind length = %d, want 64", len(blind))
	}
	if len(nonce) != 64 {
		t.Fatalf("Google nonce length = %d, want 64", len(nonce))
	}

	h := sha512.New()
	h.Write(prevResp)
	h.Write(blind)
	want := h.Sum(nil)[:64]
	if !bytes.Equal(nonce, want) {
		t.Fatal("Google chain nonce mismatch")
	}
}

// TestChainNonceDerived verifies ChainNonce produces H(prevResp || rand) for
// derived links.
func TestChainNonceDerived(t *testing.T) {
	prevResp := randBytes(t, 128)
	nonce, blind, err := ChainNonce(prevResp, rand.Reader, []Version{VersionDraft12})
	if err != nil {
		t.Fatal(err)
	}
	if len(blind) != 32 {
		t.Fatalf("rand length = %d, want 32", len(blind))
	}
	if len(nonce) != 32 {
		t.Fatalf("nonce length = %d, want 32", len(nonce))
	}

	h := sha512.New()
	h.Write(prevResp)
	h.Write(blind)
	want := h.Sum(nil)[:32]
	if !bytes.Equal(nonce, want) {
		t.Fatal("derived nonce does not match H(resp || rand)")
	}
}

// TestChainNonceDraft01 verifies ChainNonce derivation for draft-01 (64-byte
// nonce).
func TestChainNonceDraft01(t *testing.T) {
	prevResp := randBytes(t, 128)
	nonce, blind, err := ChainNonce(prevResp, rand.Reader, []Version{VersionDraft01})
	if err != nil {
		t.Fatal(err)
	}
	if len(blind) != 64 {
		t.Fatalf("draft-01 blind length = %d, want 64", len(blind))
	}
	if len(nonce) != 64 {
		t.Fatalf("draft-01 nonce length = %d, want 64", len(nonce))
	}
	h := sha512.New()
	h.Write(prevResp)
	h.Write(blind)
	want := h.Sum(nil)[:64]
	if !bytes.Equal(nonce, want) {
		t.Fatal("draft-01 chain nonce mismatch")
	}
}

// TestChainNonceDraft02 verifies ChainNonce derivation for draft-02.
func TestChainNonceDraft02(t *testing.T) {
	prevResp := randBytes(t, 128)
	nonce, blind, err := ChainNonce(prevResp, rand.Reader, []Version{VersionDraft02})
	if err != nil {
		t.Fatal(err)
	}
	if len(blind) != 64 {
		t.Fatalf("draft-02 blind length = %d, want 64", len(blind))
	}
	if len(nonce) != 64 {
		t.Fatalf("draft-02 nonce length = %d, want 64", len(nonce))
	}
	h := sha512.New()
	h.Write(prevResp)
	h.Write(blind)
	want := h.Sum(nil)[:64]
	if !bytes.Equal(nonce, want) {
		t.Fatal("draft-02 chain nonce mismatch")
	}
}

// TestChainNonceDraft05 verifies ChainNonce derivation for draft-05.
func TestChainNonceDraft05(t *testing.T) {
	prevResp := randBytes(t, 128)
	nonce, blind, err := ChainNonce(prevResp, rand.Reader, []Version{VersionDraft05})
	if err != nil {
		t.Fatal(err)
	}
	if len(blind) != 32 {
		t.Fatalf("draft-05 blind length = %d, want 32", len(blind))
	}
	if len(nonce) != 32 {
		t.Fatalf("draft-05 nonce length = %d, want 32", len(nonce))
	}
	h := sha512.New()
	h.Write(prevResp)
	h.Write(blind)
	want := h.Sum(nil)[:32]
	if !bytes.Equal(nonce, want) {
		t.Fatal("draft-05 chain nonce mismatch")
	}
}

// TestChainNonceDraft07 verifies ChainNonce derivation for draft-07.
func TestChainNonceDraft07(t *testing.T) {
	prevResp := randBytes(t, 128)
	nonce, blind, err := ChainNonce(prevResp, rand.Reader, []Version{VersionDraft07})
	if err != nil {
		t.Fatal(err)
	}
	if len(blind) != 32 {
		t.Fatalf("draft-07 blind length = %d, want 32", len(blind))
	}
	if len(nonce) != 32 {
		t.Fatalf("draft-07 nonce length = %d, want 32", len(nonce))
	}
	h := sha512.New()
	h.Write(prevResp)
	h.Write(blind)
	want := h.Sum(nil)[:32]
	if !bytes.Equal(nonce, want) {
		t.Fatal("draft-07 chain nonce mismatch")
	}
}

// TestChainNonceDraft10 verifies ChainNonce derivation for draft-10.
func TestChainNonceDraft10(t *testing.T) {
	prevResp := randBytes(t, 128)
	nonce, blind, err := ChainNonce(prevResp, rand.Reader, []Version{VersionDraft10})
	if err != nil {
		t.Fatal(err)
	}
	if len(blind) != 32 {
		t.Fatalf("draft-10 blind length = %d, want 32", len(blind))
	}
	if len(nonce) != 32 {
		t.Fatalf("draft-10 nonce length = %d, want 32", len(nonce))
	}
	h := sha512.New()
	h.Write(prevResp)
	h.Write(blind)
	want := h.Sum(nil)[:32]
	if !bytes.Equal(nonce, want) {
		t.Fatal("draft-10 chain nonce mismatch")
	}
}

// TestChainNonceDraft12 verifies ChainNonce derivation for draft-12.
func TestChainNonceDraft12(t *testing.T) {
	prevResp := randBytes(t, 128)
	nonce, blind, err := ChainNonce(prevResp, rand.Reader, []Version{VersionDraft12})
	if err != nil {
		t.Fatal(err)
	}
	if len(blind) != 32 {
		t.Fatalf("draft-12 blind length = %d, want 32", len(blind))
	}
	if len(nonce) != 32 {
		t.Fatalf("draft-12 nonce length = %d, want 32", len(nonce))
	}
	h := sha512.New()
	h.Write(prevResp)
	h.Write(blind)
	want := h.Sum(nil)[:32]
	if !bytes.Equal(nonce, want) {
		t.Fatal("draft-12 chain nonce mismatch")
	}
}

// TestChainNonceDeterministic verifies ChainNonce is deterministic for the same
// entropy and inputs.
func TestChainNonceDeterministic(t *testing.T) {
	prevResp := randBytes(t, 128)
	ver := []Version{VersionDraft12}
	entropy := bytes.NewReader(bytes.Repeat([]byte{0x42}, 32))
	nonce1, rand1, err := ChainNonce(prevResp, entropy, ver)
	if err != nil {
		t.Fatal(err)
	}

	entropy = bytes.NewReader(bytes.Repeat([]byte{0x42}, 32))
	nonce2, rand2, err := ChainNonce(prevResp, entropy, ver)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(nonce1, nonce2) || !bytes.Equal(rand1, rand2) {
		t.Fatal("same entropy should produce same nonce and rand")
	}
}

// TestChainNonceRejectsEmptyVersions verifies ChainNonce rejects an empty
// versions list.
func TestChainNonceRejectsEmptyVersions(t *testing.T) {
	if _, _, err := ChainNonce(nil, rand.Reader, nil); err == nil {
		t.Fatal("expected error for empty versions")
	}
}

// TestChainNonceFirstReadError verifies ChainNonce wraps entropy errors on the
// first link.
func TestChainNonceFirstReadError(t *testing.T) {
	want := errors.New("entropy boom")
	_, _, err := ChainNonce(nil, errReader{want}, []Version{VersionDraft12})
	if err == nil || !errors.Is(err, want) {
		t.Fatalf("expected wrapped %v, got %v", want, err)
	}
}

// TestChainNonceDerivedReadError verifies ChainNonce wraps entropy errors on
// derived links.
func TestChainNonceDerivedReadError(t *testing.T) {
	want := errors.New("entropy boom")
	prev := []byte("previous response")
	_, _, err := ChainNonce(prev, errReader{want}, []Version{VersionDraft12})
	if err == nil || !errors.Is(err, want) {
		t.Fatalf("expected wrapped %v, got %v", want, err)
	}
}

// TestNextRequestFirstLink verifies the first link's Rand is nil and Request is
// parseable.
func TestNextRequestFirstLink(t *testing.T) {
	srv := newChainServer(t, VersionDraft12)
	var c Chain
	link, err := c.NextRequest([]Version{VersionDraft12}, srv.rootPK, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if link.Rand != nil {
		t.Fatal("first link should have nil Rand")
	}
	if !bytes.Equal(link.PublicKey, srv.rootPK) {
		t.Fatal("PublicKey mismatch")
	}
	if len(link.Request) == 0 {
		t.Fatal("empty request")
	}
	if _, err := ParseRequest(link.Request); err != nil {
		t.Fatalf("parse request: %v", err)
	}
}

// TestNextRequestChained verifies a chained second link derives its nonce from
// the previous response.
func TestNextRequestChained(t *testing.T) {
	srv1 := newChainServer(t, VersionDraft12)
	srv2 := newChainServer(t, VersionDraft12)
	ver := []Version{VersionDraft12}

	var c Chain
	link1, err := c.NextRequest(ver, srv1.rootPK, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	link1.Response = srv1.respond(t, link1.Request)
	c.Append(link1)

	link2, err := c.NextRequest(ver, srv2.rootPK, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if link2.Rand == nil || len(link2.Rand) != 32 {
		t.Fatal("second link should have 32-byte Rand")
	}

	req2, err := ParseRequest(link2.Request)
	if err != nil {
		t.Fatal(err)
	}
	h := sha512.New()
	h.Write(link1.Response)
	h.Write(link2.Rand)
	want := h.Sum(nil)[:32]
	if !bytes.Equal(req2.Nonce, want) {
		t.Fatal("chained nonce mismatch")
	}
}

// TestNextRequestRejectsMissingResponse verifies NextRequest errors when the
// previous link lacks a response.
func TestNextRequestRejectsMissingResponse(t *testing.T) {
	srv := newChainServer(t, VersionDraft12)
	c := Chain{Links: []ChainLink{{Request: []byte("dummy")}}}
	if _, err := c.NextRequest([]Version{VersionDraft12}, srv.rootPK, rand.Reader); err == nil {
		t.Fatal("expected error for missing response")
	}
}

// TestNextRequestWithNonceFirstLink verifies NextRequestWithNonce uses the
// supplied nonce on the first link.
func TestNextRequestWithNonceFirstLink(t *testing.T) {
	srv := newChainServer(t, VersionDraft12)
	seed := bytes.Repeat([]byte{0x42}, 32)
	var c Chain
	link, err := c.NextRequestWithNonce([]Version{VersionDraft12}, srv.rootPK, seed)
	if err != nil {
		t.Fatalf("NextRequestWithNonce: %v", err)
	}
	if !bytes.Equal(link.Nonce, seed) {
		t.Fatalf("link.Nonce = %x, want seed %x", link.Nonce, seed)
	}
	if link.Rand != nil {
		t.Fatalf("link.Rand = %x, want nil for first link", link.Rand)
	}
}

// TestNextRequestWithNonceRejectsNonFirst verifies NextRequestWithNonce errors
// on a non-empty chain.
func TestNextRequestWithNonceRejectsNonFirst(t *testing.T) {
	srv := newChainServer(t, VersionDraft12)
	c := Chain{Links: []ChainLink{{Request: []byte("dummy"), Response: []byte("dummy-reply")}}}
	if _, err := c.NextRequestWithNonce([]Version{VersionDraft12}, srv.rootPK, bytes.Repeat([]byte{0x42}, 32)); err == nil {
		t.Fatal("expected error when chain is non-empty")
	}
}

// TestNextRequestWithNonceRejectsBadLength verifies NextRequestWithNonce
// rejects a wrong-length nonce.
func TestNextRequestWithNonceRejectsBadLength(t *testing.T) {
	srv := newChainServer(t, VersionDraft12)
	var c Chain
	if _, err := c.NextRequestWithNonce([]Version{VersionDraft12}, srv.rootPK, []byte{1, 2, 3}); err == nil {
		t.Fatal("expected length error for 3-byte nonce")
	}
}

// TestNextRequestRejectsEmptyVersions verifies NextRequest errors on an empty
// versions list.
func TestNextRequestRejectsEmptyVersions(t *testing.T) {
	rootSK, _ := testKeys(t)
	rootPK := rootSK.Public().(ed25519.PublicKey)
	var c Chain
	if _, err := c.NextRequest(nil, rootPK, rand.Reader); err == nil {
		t.Fatal("expected error for empty versions")
	}
}

// TestNextRequestEntropyError verifies NextRequest surfaces entropy read
// failures.
func TestNextRequestEntropyError(t *testing.T) {
	rootSK, _ := testKeys(t)
	rootPK := rootSK.Public().(ed25519.PublicKey)
	var c Chain
	_, err := c.NextRequest([]Version{VersionDraft12}, rootPK, errReader{errors.New("no entropy")})
	if err == nil {
		t.Fatal("expected entropy error")
	}
}

// TestNextRequestPopulatesNonce verifies ChainLink.Nonce matches the framed
// Request's nonce.
func TestNextRequestPopulatesNonce(t *testing.T) {
	rootSK, _ := testKeys(t)
	rootPK := rootSK.Public().(ed25519.PublicKey)
	var c Chain
	link, err := c.NextRequest([]Version{VersionDraft12}, rootPK, rand.Reader)
	if err != nil {
		t.Fatalf("NextRequest: %v", err)
	}
	if len(link.Nonce) == 0 {
		t.Fatal("link.Nonce not populated")
	}
	parsed, err := ParseRequest(link.Request)
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}
	if !bytes.Equal(parsed.Nonce, link.Nonce) {
		t.Fatalf("link.Nonce != ParseRequest(link.Request).Nonce: %x vs %x", link.Nonce, parsed.Nonce)
	}
}

// TestVerifyValidChain verifies Chain.Verify accepts valid chains of varying
// length.
func TestVerifyValidChain(t *testing.T) {
	for _, n := range []int{1, 2, 3, 5} {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			c, _ := buildChain(t, VersionDraft12, n)
			if err := c.Verify(); err != nil {
				t.Fatalf("valid chain should verify: %v", err)
			}
		})
	}
}

// TestVerifyEmpty verifies Chain.Verify rejects an empty chain.
func TestVerifyEmpty(t *testing.T) {
	var c Chain
	if err := c.Verify(); err == nil {
		t.Fatal("expected error for empty chain")
	}
}

// TestVerifyBadNonce verifies Chain.Verify wraps ErrChainNonce on a corrupted
// blind.
func TestVerifyBadNonce(t *testing.T) {
	c, _ := buildChain(t, VersionDraft12, 3)

	c.Links[1].Rand[0] ^= 0xff

	err := c.Verify()
	if err == nil {
		t.Fatal("expected nonce mismatch error")
	}
	if !errors.Is(err, ErrChainNonce) {
		t.Fatalf("expected ErrChainNonce, got: %v", err)
	}
}

// TestVerifyBadSignature verifies a wrong public key surfaces as a signature
// failure.
func TestVerifyBadSignature(t *testing.T) {
	c, _ := buildChain(t, VersionDraft12, 2)

	_, badSK, _ := ed25519.GenerateKey(rand.Reader)
	c.Links[1].PublicKey = badSK.Public().(ed25519.PublicKey)

	err := c.Verify()
	if err == nil {
		t.Fatal("expected signature error")
	}
	if errors.Is(err, ErrCausalOrder) {
		t.Fatal("wrong error type: got ErrCausalOrder for bad signature")
	}
}

// TestPQChainVerify verifies Chain.Verify accepts an ML-DSA-44 chain.
func TestPQChainVerify(t *testing.T) {
	cert, rootPK := testPQCert(t)
	versions := []Version{VersionMLDSA44}

	var chain Chain
	for i := range 2 {
		link, err := chain.NextRequest(versions, rootPK, rand.Reader)
		if err != nil {
			t.Fatalf("NextRequest %d: %v", i, err)
		}
		parsed, err := ParseRequest(link.Request)
		if err != nil {
			t.Fatalf("ParseRequest %d: %v", i, err)
		}
		replies, err := CreateReplies(VersionMLDSA44, []Request{*parsed}, time.Now().Add(time.Duration(i)*time.Second), time.Second, cert)
		if err != nil {
			t.Fatalf("CreateReplies %d: %v", i, err)
		}
		link.Response = replies[0]
		chain.Append(link)
	}
	if err := chain.Verify(); err != nil {
		t.Fatalf("Chain.Verify: %v", err)
	}
}

// TestPQChainNonce verifies ChainNonce sizes for VersionMLDSA44.
func TestPQChainNonce(t *testing.T) {
	prevResp := randBytes(t, 128)
	nonce, blind, err := ChainNonce(prevResp, rand.Reader, []Version{VersionMLDSA44})
	if err != nil {
		t.Fatalf("ChainNonce: %v", err)
	}
	if len(blind) != 32 || len(nonce) != 32 {
		t.Fatalf("PQ chain nonce/blind lengths = %d/%d, want 32/32", len(nonce), len(blind))
	}
}

// TestVerifyBadRandLength verifies Chain.Verify wraps ErrChainNonce when Rand
// is the wrong length.
func TestVerifyBadRandLength(t *testing.T) {
	c, _ := buildChain(t, VersionDraft12, 2)

	c.Links[1].Rand = c.Links[1].Rand[:16]

	err := c.Verify()
	if err == nil {
		t.Fatal("expected error for bad rand length")
	}
	if !errors.Is(err, ErrChainNonce) {
		t.Fatalf("expected ErrChainNonce, got: %v", err)
	}
}

// TestVerifyCorruptedResponse verifies Chain.Verify rejects a chain with a
// tampered response.
func TestVerifyCorruptedResponse(t *testing.T) {
	c, _ := buildChain(t, VersionDraft12, 2)

	c.Links[0].Response[len(c.Links[0].Response)-1] ^= 0xff

	if err := c.Verify(); err == nil {
		t.Fatal("expected error for corrupted response")
	}
}

// TestVerifyCausalOrder verifies non-monotonic midpoints trigger
// ErrCausalOrder.
func TestVerifyCausalOrder(t *testing.T) {
	ver := VersionDraft12
	versions := []Version{ver}

	srv1 := newChainServer(t, ver)
	srv2 := newChainServer(t, ver)
	srv3 := newChainServer(t, ver)

	now := time.Now()
	past := now.Add(-10 * time.Minute)
	future := now.Add(10 * time.Minute)

	var c Chain
	link1, _ := c.NextRequest(versions, srv1.rootPK, rand.Reader)
	req1, _ := ParseRequest(link1.Request)
	replies1, _ := CreateReplies(ver, []Request{*req1}, past, time.Second, srv1.cert)
	link1.Response = replies1[0]
	c.Append(link1)

	link2, _ := c.NextRequest(versions, srv2.rootPK, rand.Reader)
	req2, _ := ParseRequest(link2.Request)
	replies2, _ := CreateReplies(ver, []Request{*req2}, now, time.Second, srv2.cert)
	link2.Response = replies2[0]
	c.Append(link2)

	link3, _ := c.NextRequest(versions, srv3.rootPK, rand.Reader)
	req3, _ := ParseRequest(link3.Request)
	replies3, _ := CreateReplies(ver, []Request{*req3}, future, time.Second, srv3.cert)
	link3.Response = replies3[0]
	c.Append(link3)

	if err := c.Verify(); err != nil {
		t.Fatalf("baseline chain should verify: %v", err)
	}

	// link 2 claims future, link 3 claims past — preserves nonce linkage,
	// violates causal ordering
	var bad Chain
	blink1, _ := bad.NextRequest(versions, srv1.rootPK, rand.Reader)
	breq1, _ := ParseRequest(blink1.Request)
	breplies1, _ := CreateReplies(ver, []Request{*breq1}, now, time.Second, srv1.cert)
	blink1.Response = breplies1[0]
	bad.Append(blink1)

	blink2, _ := bad.NextRequest(versions, srv2.rootPK, rand.Reader)
	breq2, _ := ParseRequest(blink2.Request)
	breplies2, _ := CreateReplies(ver, []Request{*breq2}, future, time.Second, srv2.cert)
	blink2.Response = breplies2[0]
	bad.Append(blink2)

	blink3, _ := bad.NextRequest(versions, srv3.rootPK, rand.Reader)
	breq3, _ := ParseRequest(blink3.Request)
	breplies3, _ := CreateReplies(ver, []Request{*breq3}, past, time.Second, srv3.cert)
	blink3.Response = breplies3[0]
	bad.Append(blink3)

	err := bad.Verify()
	if err == nil {
		t.Fatal("expected causal ordering error")
	}
	if !errors.Is(err, ErrCausalOrder) {
		t.Fatalf("expected ErrCausalOrder, got: %v", err)
	}
}

// TestVerifyCausalOrderFiveLinks verifies the running-max algorithm catches
// non-adjacent ordering violations.
func TestVerifyCausalOrderFiveLinks(t *testing.T) {
	ver := VersionDraft12
	versions := []Version{ver}

	servers := make([]chainServer, 5)
	for i := range servers {
		servers[i] = newChainServer(t, ver)
	}

	// link 2 is the peak; link 4 drops below it, violating running max
	base := time.Now().Truncate(time.Second)
	midpoints := []time.Time{
		base.Add(-10 * time.Minute),
		base.Add(-5 * time.Minute),
		base.Add(30 * time.Minute),
		base.Add(10 * time.Minute),
		base.Add(-15 * time.Minute),
	}

	var c Chain
	for i, srv := range servers {
		link, err := c.NextRequest(versions, srv.rootPK, rand.Reader)
		if err != nil {
			t.Fatalf("next request %d: %v", i, err)
		}
		req, err := ParseRequest(link.Request)
		if err != nil {
			t.Fatalf("parse %d: %v", i, err)
		}
		replies, err := CreateReplies(ver, []Request{*req}, midpoints[i], time.Second, srv.cert)
		if err != nil {
			t.Fatalf("create reply %d: %v", i, err)
		}
		link.Response = replies[0]
		c.Append(link)
	}

	err := c.Verify()
	if err == nil {
		t.Fatal("expected causal ordering error")
	}
	if !errors.Is(err, ErrCausalOrder) {
		t.Fatalf("expected ErrCausalOrder, got: %v", err)
	}
}

// TestVerifyRejectsTooManyLinks verifies Chain.Verify rejects chains exceeding
// maxChainLinks.
func TestVerifyRejectsTooManyLinks(t *testing.T) {
	c := &Chain{Links: make([]ChainLink, maxChainLinks+1)}
	err := c.Verify()
	if err == nil {
		t.Fatal("expected error for chain length > maxChainLinks")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("max")) {
		t.Fatalf("error should mention max link count, got: %v", err)
	}
}

// TestVerifyMultipleVersions verifies Chain.Verify accepts chains across drafts
// 08, 10, 12.
func TestVerifyMultipleVersions(t *testing.T) {
	versions := []Version{VersionDraft08, VersionDraft10, VersionDraft12}
	for _, ver := range versions {
		t.Run(ver.ShortString(), func(t *testing.T) {
			c, _ := buildChain(t, ver, 3)
			if err := c.Verify(); err != nil {
				t.Fatalf("chain with %s should verify: %v", ver, err)
			}
		})
	}
}

// TestVerifyMultipleVersionsExtended verifies Chain.Verify across every Ed25519
// wire group.
func TestVerifyMultipleVersionsExtended(t *testing.T) {
	versions := []Version{
		VersionGoogle,
		VersionDraft01,
		VersionDraft02,
		VersionDraft03,
		VersionDraft04,
		VersionDraft05,
		VersionDraft07,
		VersionDraft08,
		VersionDraft10,
		VersionDraft12,
	}
	for _, ver := range versions {
		t.Run(ver.ShortString(), func(t *testing.T) {
			c, _ := buildChain(t, ver, 3)
			if err := c.Verify(); err != nil {
				t.Fatalf("chain with %s should verify: %v", ver, err)
			}
		})
	}
}

// TestVerifyMultipleVersionsWithDraft12TYPE verifies Chain.Verify on the
// groupD14 path via draft-12 with TYPE.
func TestVerifyMultipleVersionsWithDraft12TYPE(t *testing.T) {
	c, _ := buildChain(t, VersionDraft12, 3)
	if err := c.Verify(); err != nil {
		t.Fatalf("chain with draft-12+TYPE should verify: %v", err)
	}
}

// TestVerifyChainDraft10 verifies Chain.Verify on a draft-10 chain.
func TestVerifyChainDraft10(t *testing.T) {
	c, _ := buildChain(t, VersionDraft10, 3)
	if err := c.Verify(); err != nil {
		t.Fatalf("draft-10 chain should verify: %v", err)
	}
}

// TestVerifyChainDraft11 verifies Chain.Verify on a draft-11 chain.
func TestVerifyChainDraft11(t *testing.T) {
	c, _ := buildChain(t, VersionDraft11, 3)
	if err := c.Verify(); err != nil {
		t.Fatalf("draft-11 chain should verify: %v", err)
	}
}

// TestChainMixedVersions verifies Chain.Verify on a chain whose links span
// drafts 08, 10, 12.
func TestChainMixedVersions(t *testing.T) {
	versions := []Version{VersionDraft08, VersionDraft10, VersionDraft12}
	servers := make([]chainServer, len(versions))
	for i, ver := range versions {
		servers[i] = newChainServer(t, ver)
	}

	var c Chain
	for i, srv := range servers {
		ver := versions[i]
		link, err := c.NextRequest([]Version{ver}, srv.rootPK, rand.Reader)
		if err != nil {
			t.Fatalf("next request %d: %v", i, err)
		}
		link.Response = srv.respond(t, link.Request)
		c.Append(link)
	}

	if err := c.Verify(); err != nil {
		t.Fatalf("mixed-version chain should verify: %v", err)
	}
}

// FuzzChainNonce fuzzes ChainNonce length and truncation invariants across wire
// groups.
func FuzzChainNonce(f *testing.F) {
	f.Add([]byte{}, byte(0))
	f.Add(make([]byte, 128), byte(1))
	f.Add(make([]byte, 1024), byte(5))
	f.Add(make([]byte, 65535), byte(0x0c))

	versions := []Version{
		VersionGoogle, VersionDraft01, VersionDraft02, VersionDraft05,
		VersionDraft07, VersionDraft08, VersionDraft12,
	}

	f.Fuzz(func(t *testing.T, prevResp []byte, verHint byte) {
		idx := int(verHint) % len(versions)
		ver := versions[idx]

		nonce, blind, err := ChainNonce(prevResp, rand.Reader, []Version{ver})
		if err != nil {
			return
		}

		_, g, _ := clientVersionPreference([]Version{ver})
		ns := nonceSize(g)
		if len(nonce) != ns {
			t.Fatalf("nonce length = %d, want %d for %s", len(nonce), ns, ver)
		}
		if prevResp != nil && len(blind) != ns {
			t.Fatalf("blind length = %d, want %d for %s", len(blind), ns, ver)
		}

		if prevResp != nil {
			h := sha512.New()
			h.Write(prevResp)
			h.Write(blind)
			want := h.Sum(nil)[:ns]
			if !bytes.Equal(nonce, want) {
				t.Fatal("chain nonce derivation mismatch")
			}
		}
	})
}

// FuzzChainVerify fuzzes ParseMalfeasanceReport and Chain.Verify for
// panic-safety.
func FuzzChainVerify(f *testing.F) {
	chain, _ := buildChain(&testing.T{}, VersionDraft12, 2)
	seed, _ := chain.MalfeasanceReport()
	f.Add(seed)
	f.Add([]byte(`{"responses":[]}`))
	f.Add([]byte(`{"nonces":[""],"responses":[""]}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := ParseMalfeasanceReport(data)
		if err != nil {
			return
		}
		_ = c.Verify()
	})
}
