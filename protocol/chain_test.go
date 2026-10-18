// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"strings"
	"testing"
	"time"
)

// chainServer is a test fixture for serving Roughtime replies in chain tests.
type chainServer struct {
	rootPK ed25519.PublicKey
	cert   *Certificate
	ver    Version
}

// newChainServer constructs a chainServer with a fresh certificate.
func newChainServer(t *testing.T, ver Version) chainServer {
	t.Helper()
	rootSK, onlineSK := testKeys(t)
	now := time.Now()
	cert, err := NewCertificateWithVersions(now.Add(-time.Hour), now.Add(time.Hour), onlineSK, rootSK, ServerPreferenceEd25519)
	if err != nil {
		t.Fatal(err)
	}
	return chainServer{
		rootPK: rootSK.Public().(ed25519.PublicKey),
		cert:   cert,
		ver:    ver,
	}
}

// respond builds a signed reply for a single request.
func (s chainServer) respond(t *testing.T, request []byte) []byte {
	t.Helper()
	parsed, err := ParseRequestWithMode(request, Flex)
	if err != nil {
		t.Fatalf("parse request: %v", err)
	}
	replies, err := CreateRepliesWithOptions(s.ver, []Request{*parsed}, time.Now(), time.Second, s.cert, ReplyOptions{Mode: Flex})
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

	c := Chain{Mode: Flex}
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

// TestChainNonce covers first and subsequent chain nonces.
func TestChainNonce(t *testing.T) {
	previous := randBytes(t, 128)
	for _, tc := range []struct {
		version Version
		size    int
		double  bool
	}{
		{VersionGoogle, 64, true},
		{VersionDraft01, 64, true},
		{VersionDraft12, 32, false},
	} {
		t.Run(tc.version.ShortString(), func(t *testing.T) {
			nonce, blind, err := ChainNonce(previous, rand.Reader, []Version{tc.version})
			if err != nil {
				t.Fatal(err)
			}
			input := previous
			if tc.double {
				digest := sha512.Sum512(previous)
				input = digest[:]
			}
			h := sha512.New()
			_, _ = h.Write(input)
			_, _ = h.Write(blind)
			if len(blind) != tc.size || len(nonce) != tc.size || !bytes.Equal(nonce, h.Sum(nil)[:tc.size]) {
				t.Fatal("unexpected chain nonce")
			}
		})
	}
}

// TestChainRejectsMixedNonceDerivations rejects offers that can negotiate an
// incompatible draft-01 linkage, including chains built outside NextRequest.
func TestChainRejectsMixedNonceDerivations(t *testing.T) {
	srv := newChainServer(t, VersionDraft01)
	t.Cleanup(srv.cert.Wipe)
	chain := Chain{Mode: Flex}
	first, err := chain.NextRequest([]Version{VersionDraft01}, srv.rootPK, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	first.Response = srv.respond(t, first.Request)
	chain.Append(first)

	for _, other := range []Version{VersionDraft02, VersionDraft03, VersionDraft04} {
		t.Run(other.ShortString(), func(t *testing.T) {
			versions := []Version{VersionDraft01, other}
			if _, _, err := ChainNonce(nil, rand.Reader, versions); err == nil {
				t.Fatal("accepted incompatible chain offer")
			}
			if _, err := chain.NextRequest(versions, srv.rootPK, rand.Reader); err == nil {
				t.Fatal("constructed request with incompatible chain offer")
			}

			// Recreate the old single-hash linkage and authenticate it as draft
			// 01.
			blind := bytes.Repeat([]byte{0x42}, 64)
			nonce := sha512.Sum512(append(bytes.Clone(first.Response), blind...))
			request, err := CreateRequestWithNonceOptions(versions, nonce[:], nil, RequestOptions{Mode: Flex})
			if err != nil {
				t.Fatal(err)
			}
			second := ChainLink{
				Rand: blind, PublicKey: srv.rootPK, Nonce: nonce[:],
				Request: request, Response: srv.respond(t, request),
			}
			imported := Chain{Mode: Flex, Links: []ChainLink{first, second}}
			if err := imported.Verify(); err == nil || !strings.Contains(err.Error(), "nonce derivations") {
				t.Fatalf("mixed chain verification = %v", err)
			}
		})
	}

	// Offers that retain one derivation after nonce-size filtering remain
	// valid.
	for _, versions := range [][]Version{
		{VersionDraft02, VersionDraft03, VersionDraft04},
		{VersionDraft01, VersionDraft12},
		{VersionDraft01, Version1},
	} {
		if _, _, err := ChainNonce(first.Response, rand.Reader, versions); err != nil {
			t.Fatalf("compatible offer %v: %v", versions, err)
		}
	}
}

// TestNextRequestWithNonceFirstLink covers caller-supplied first nonces.
func TestNextRequestWithNonceFirstLink(t *testing.T) {
	srv := newChainServer(t, VersionDraft12)
	seed := bytes.Repeat([]byte{0x42}, 32)
	c := Chain{Mode: Flex}
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

// TestVerifyValidChain covers a valid causal chain.
func TestVerifyValidChain(t *testing.T) {
	c, _ := buildChain(t, VersionDraft12, 3)
	if err := c.Verify(); err != nil {
		t.Fatalf("valid chain should verify: %v", err)
	}
}

// TestPQChainVerify covers an ML-DSA-44 chain.
func TestPQChainVerify(t *testing.T) {
	cert, rootPK := testPQCert(t)
	versions := []Version{VersionMLDSA44}

	chain := Chain{Mode: Flex}
	for i := range 2 {
		link, err := chain.NextRequest(versions, rootPK, rand.Reader)
		if err != nil {
			t.Fatalf("NextRequest %d: %v", i, err)
		}
		parsed, err := ParseRequestWithMode(link.Request, Flex)
		if err != nil {
			t.Fatalf("ParseRequest %d: %v", i, err)
		}
		replies, err := CreateRepliesWithOptions(VersionMLDSA44, []Request{*parsed}, time.Now().Add(time.Duration(i)*time.Second), time.Second, cert, ReplyOptions{Mode: Flex})
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

// TestVerifyCausalOrderFiveLinks covers nonadjacent causal ordering.
func TestVerifyCausalOrderFiveLinks(t *testing.T) {
	ver := VersionDraft12
	versions := []Version{ver}

	servers := make([]chainServer, 5)
	for i := range servers {
		servers[i] = newChainServer(t, ver)
	}

	// Link 3's wide interval permits both adjacent pairs. Link 4 contradicts
	// link 2, so checking adjacent links alone would miss the violation.
	base := time.Now().Truncate(time.Second)
	midpoints := []time.Time{
		base.Add(-10 * time.Minute),
		base.Add(-5 * time.Minute),
		base.Add(30 * time.Minute),
		base.Add(10 * time.Minute),
		base.Add(-15 * time.Minute),
	}
	radii := []time.Duration{time.Second, time.Second, time.Second, 30 * time.Minute, time.Second}

	c := Chain{Mode: Flex}
	for i, srv := range servers {
		link, err := c.NextRequest(versions, srv.rootPK, rand.Reader)
		if err != nil {
			t.Fatalf("next request %d: %v", i, err)
		}
		req, err := ParseRequestWithMode(link.Request, Flex)
		if err != nil {
			t.Fatalf("parse %d: %v", i, err)
		}
		replies, err := CreateRepliesWithOptions(ver, []Request{*req}, midpoints[i], radii[i], srv.cert, ReplyOptions{Mode: Flex})
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

// TestVerifyBoundsReturnsPerLinkBounds covers verified bound extraction.
func TestVerifyBoundsReturnsPerLinkBounds(t *testing.T) {
	c, _ := buildChain(t, VersionDraft12, 3)
	bounds, err := c.VerifyBounds()
	if err != nil {
		t.Fatalf("VerifyBounds: %v", err)
	}
	if len(bounds) != len(c.Links) {
		t.Fatalf("got %d bounds, want %d", len(bounds), len(c.Links))
	}
	for i, b := range bounds {
		if b.Midpoint.IsZero() {
			t.Errorf("link %d: zero midpoint", i)
		}
		if b.Radius <= 0 {
			t.Errorf("link %d: non-positive radius %v", i, b.Radius)
		}
	}
	over := &Chain{Mode: Flex, Links: make([]ChainLink, MaxChainLinks+1)}
	if _, err := over.VerifyBounds(); err == nil {
		t.Fatal("expected error for chain length > MaxChainLinks")
	}
}

// TestChainMixedVersions covers a chain spanning wire versions.
func TestChainMixedVersions(t *testing.T) {
	versions := []Version{VersionDraft08, VersionDraft10, VersionDraft12}
	servers := make([]chainServer, len(versions))
	for i, ver := range versions {
		servers[i] = newChainServer(t, ver)
	}

	c := Chain{Mode: Flex}
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
