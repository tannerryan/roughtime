// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"
)

// chainServer is a test helper that holds a server's keys and certificate for
// building chain links.
type chainServer struct {
	rootSK ed25519.PrivateKey
	rootPK ed25519.PublicKey
	cert   *Certificate
	ver    Version
}

// newChainServer creates a server with a certificate valid for ±1 hour.
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

// respond generates a server reply for a request packet.
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

// buildChain creates a valid chain of n links using distinct servers, all at
// the given version. Returns the chain and the servers used.
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

// TestChainNonceFirst verifies that the first nonce is random with nil rand.
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

// TestChainNonceGoogle verifies that Google-Roughtime chain nonces use 64-byte
// nonces and blinds.
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

// TestChainNonceDerived verifies the derived nonce matches H(resp || rand).
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

// TestChainNonceDraft02 verifies that draft-02 chain nonces use SHA-512 (not
// SHA-512/256, which would panic because its 32-byte output is shorter than the
// 64-byte nonce size for drafts 01–04).
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

// TestChainNonceDraft07 verifies that draft-07 chain nonces use SHA-512 with
// 32-byte nonces.
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

// TestChainNonceDeterministic verifies that fixed entropy produces a
// deterministic nonce.
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

// TestNextRequestFirstLink verifies that the first link has nil Rand and a
// valid request.
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
	// Request should be parseable.
	if _, err := ParseRequest(link.Request); err != nil {
		t.Fatalf("parse request: %v", err)
	}
}

// TestNextRequestChained verifies that the second link's nonce is correctly
// derived from the first link's response.
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

	// Verify the nonce in link2's request matches H(link1.Response ||
	// link2.Rand).
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

// TestNextRequestRejectsMissingResponse verifies that NextRequest fails when
// the previous link has no response.
func TestNextRequestRejectsMissingResponse(t *testing.T) {
	srv := newChainServer(t, VersionDraft12)
	c := Chain{Links: []ChainLink{{Request: []byte("dummy")}}}
	if _, err := c.NextRequest([]Version{VersionDraft12}, srv.rootPK, rand.Reader); err == nil {
		t.Fatal("expected error for missing response")
	}
}

// TestVerifyValidChain verifies that a correctly constructed chain passes
// verification.
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

// TestVerifyEmpty verifies that an empty chain is rejected.
func TestVerifyEmpty(t *testing.T) {
	var c Chain
	if err := c.Verify(); err == nil {
		t.Fatal("expected error for empty chain")
	}
}

// TestVerifyBadNonce verifies that a corrupted rand is detected.
func TestVerifyBadNonce(t *testing.T) {
	c, _ := buildChain(t, VersionDraft12, 3)

	// Corrupt the second link's rand.
	c.Links[1].Rand[0] ^= 0xff

	err := c.Verify()
	if err == nil {
		t.Fatal("expected nonce mismatch error")
	}
	if !errors.Is(err, ErrChainNonce) {
		t.Fatalf("expected ErrChainNonce, got: %v", err)
	}
}

// TestVerifyBadSignature verifies that a wrong public key is detected as a
// signature failure (not a causal ordering error).
func TestVerifyBadSignature(t *testing.T) {
	c, _ := buildChain(t, VersionDraft12, 2)

	// Replace the second link's public key with a random one.
	_, badSK, _ := ed25519.GenerateKey(rand.Reader)
	c.Links[1].PublicKey = badSK.Public().(ed25519.PublicKey)

	err := c.Verify()
	if err == nil {
		t.Fatal("expected signature error")
	}
	// Should NOT be a causal ordering error.
	if errors.Is(err, ErrCausalOrder) {
		t.Fatal("wrong error type: got ErrCausalOrder for bad signature")
	}
}

// TestVerifyCausalOrder verifies that swapping two responses triggers a causal
// ordering violation.
func TestVerifyCausalOrder(t *testing.T) {
	// Build a chain of 3 with timestamps that increase over time (each server
	// responds to a sequential request, so midpoints naturally increase). Then
	// swap responses 0 and 2, which will have enough separation for the radius
	// windows to not overlap, creating a causal ordering violation.
	//
	// We need to build this manually to control timing and ensure separation.
	ver := VersionDraft12
	versions := []Version{ver}

	srv1 := newChainServer(t, ver)
	srv2 := newChainServer(t, ver)
	srv3 := newChainServer(t, ver)

	// Create three legitimate chain links with increasing midpoints. To
	// guarantee causal ordering violation after swap, use servers with large
	// time offsets.
	now := time.Now()
	past := now.Add(-10 * time.Minute)
	future := now.Add(10 * time.Minute)

	// Build link 1 (response with "past" midpoint).
	var c Chain
	link1, _ := c.NextRequest(versions, srv1.rootPK, rand.Reader)
	req1, _ := ParseRequest(link1.Request)
	replies1, _ := CreateReplies(ver, []Request{*req1}, past, time.Second, srv1.cert)
	link1.Response = replies1[0]
	c.Append(link1)

	// Build link 2 (response with "now" midpoint).
	link2, _ := c.NextRequest(versions, srv2.rootPK, rand.Reader)
	req2, _ := ParseRequest(link2.Request)
	replies2, _ := CreateReplies(ver, []Request{*req2}, now, time.Second, srv2.cert)
	link2.Response = replies2[0]
	c.Append(link2)

	// Build link 3 (response with "future" midpoint).
	link3, _ := c.NextRequest(versions, srv3.rootPK, rand.Reader)
	req3, _ := ParseRequest(link3.Request)
	replies3, _ := CreateReplies(ver, []Request{*req3}, future, time.Second, srv3.cert)
	link3.Response = replies3[0]
	c.Append(link3)

	// Sanity: this chain should verify (timestamps increase).
	if err := c.Verify(); err != nil {
		t.Fatalf("baseline chain should verify: %v", err)
	}

	// Now build a new chain where the second server claims "future" time and
	// the third claims "past" time. This violates causal ordering since link 2
	// was received before link 3, but future - 1s > past + 1s. We need to
	// rebuild because nonce linkage must still be valid.
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

// TestMalfeasanceReportRoundTrip verifies that a chain survives serialization
// and deserialization, and that the deserialized chain still verifies.
func TestMalfeasanceReportRoundTrip(t *testing.T) {
	c, _ := buildChain(t, VersionDraft12, 3)

	data, err := c.MalfeasanceReport()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	parsed, err := ParseMalfeasanceReport(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if len(parsed.Links) != len(c.Links) {
		t.Fatalf("link count = %d, want %d", len(parsed.Links), len(c.Links))
	}
	for i := range c.Links {
		if !bytes.Equal(parsed.Links[i].Rand, c.Links[i].Rand) {
			t.Fatalf("link %d: rand mismatch", i)
		}
		if !bytes.Equal(parsed.Links[i].PublicKey, c.Links[i].PublicKey) {
			t.Fatalf("link %d: publicKey mismatch", i)
		}
		if !bytes.Equal(parsed.Links[i].Request, c.Links[i].Request) {
			t.Fatalf("link %d: request mismatch", i)
		}
		if !bytes.Equal(parsed.Links[i].Response, c.Links[i].Response) {
			t.Fatalf("link %d: response mismatch", i)
		}
	}

	// The deserialized chain should still verify.
	if err := parsed.Verify(); err != nil {
		t.Fatalf("deserialized chain should verify: %v", err)
	}
}

// TestMalfeasanceReportFirstLinkNoRand verifies that the first link's rand is
// omitted from the JSON output.
func TestMalfeasanceReportFirstLinkNoRand(t *testing.T) {
	c, _ := buildChain(t, VersionDraft12, 2)

	data, err := c.MalfeasanceReport()
	if err != nil {
		t.Fatal(err)
	}

	var raw struct {
		Responses []map[string]any `json:"responses"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}

	// First link should not have "rand".
	if _, ok := raw.Responses[0]["rand"]; ok {
		t.Fatal("first link should not have rand in JSON")
	}
	// Second link should have "rand".
	if _, ok := raw.Responses[1]["rand"]; !ok {
		t.Fatal("second link should have rand in JSON")
	}
}

// TestMalfeasanceReportFields verifies the JSON structure matches Section
// 8.4.1.
func TestMalfeasanceReportFields(t *testing.T) {
	c, _ := buildChain(t, VersionDraft12, 2)

	data, err := c.MalfeasanceReport()
	if err != nil {
		t.Fatal(err)
	}

	var report struct {
		Responses []struct {
			Rand      string `json:"rand"`
			PublicKey string `json:"publicKey"`
			Request   string `json:"request"`
			Response  string `json:"response"`
		} `json:"responses"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}

	for i, r := range report.Responses {
		if r.PublicKey == "" {
			t.Fatalf("link %d: missing publicKey", i)
		}
		if r.Request == "" {
			t.Fatalf("link %d: missing request", i)
		}
		if r.Response == "" {
			t.Fatalf("link %d: missing response", i)
		}
		// Verify base64 is valid.
		for _, field := range []string{r.PublicKey, r.Request, r.Response} {
			if _, err := base64.StdEncoding.DecodeString(field); err != nil {
				t.Fatalf("link %d: invalid base64: %v", i, err)
			}
		}
	}
}

// TestParseMalfeasanceReportRejectsEmpty verifies that an empty report is
// rejected.
func TestParseMalfeasanceReportRejectsEmpty(t *testing.T) {
	if _, err := ParseMalfeasanceReport([]byte(`{"responses":[]}`)); err == nil {
		t.Fatal("expected error for empty responses")
	}
}

// TestParseMalfeasanceReportRejectsMalformed verifies that invalid JSON is
// rejected.
func TestParseMalfeasanceReportRejectsMalformed(t *testing.T) {
	if _, err := ParseMalfeasanceReport([]byte(`not json`)); err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

// TestParseMalfeasanceReportRejectsBadBase64 verifies that invalid base64 in
// any field is rejected.
func TestParseMalfeasanceReportRejectsBadBase64(t *testing.T) {
	valid := base64.StdEncoding.EncodeToString([]byte("test"))
	for _, field := range []string{"publicKey", "request", "response"} {
		t.Run(field, func(t *testing.T) {
			entry := map[string]string{
				"publicKey": valid,
				"request":   valid,
				"response":  valid,
			}
			entry[field] = "!!!not-base64!!!"
			data, _ := json.Marshal(map[string]any{"responses": []any{entry}})
			if _, err := ParseMalfeasanceReport(data); err == nil {
				t.Fatalf("expected error for bad %s", field)
			}
		})
	}
}

// TestMalfeasanceReportEmpty verifies that MalfeasanceReport rejects an empty
// chain.
func TestMalfeasanceReportEmpty(t *testing.T) {
	var c Chain
	if _, err := c.MalfeasanceReport(); err == nil {
		t.Fatal("expected error for empty chain")
	}
}

// TestVerifyMultipleVersions verifies that chains work across different IETF
// draft versions (all using 32-byte nonces).
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

// TestVerifyBadRandLength verifies that a rand of wrong length is detected.
func TestVerifyBadRandLength(t *testing.T) {
	c, _ := buildChain(t, VersionDraft12, 2)

	// Truncate the second link's rand.
	c.Links[1].Rand = c.Links[1].Rand[:16]

	err := c.Verify()
	if err == nil {
		t.Fatal("expected error for bad rand length")
	}
	if !errors.Is(err, ErrChainNonce) {
		t.Fatalf("expected ErrChainNonce, got: %v", err)
	}
}

// TestVerifyCorruptedResponse verifies that a corrupted response (which breaks
// signature verification) is detected.
func TestVerifyCorruptedResponse(t *testing.T) {
	c, _ := buildChain(t, VersionDraft12, 2)

	// Corrupt a byte in the first link's response.
	c.Links[0].Response[len(c.Links[0].Response)-1] ^= 0xff

	if err := c.Verify(); err == nil {
		t.Fatal("expected error for corrupted response")
	}
}

// TestVerifyMultipleVersionsExtended extends TestVerifyMultipleVersions to
// include Google-Roughtime (64-byte nonces), MJD-microsecond versions (drafts
// 01, 05), and SHA-512/256 versions (draft-02).
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

// TestChainNonceDraft01 verifies that draft-01 chain nonces use SHA-512 with
// 64-byte nonces (same as Google and draft-02).
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

// TestChainNonceDraft05 verifies that draft-05 chain nonces use SHA-512 with
// 32-byte nonces (MJD-microsecond timestamp version).
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

// TestVerifyMultipleVersionsWithDraft12TYPE extends the multi-version chain
// test to include VersionDraft12 which exercises the groupD14 path (TYPE tag).
func TestVerifyMultipleVersionsWithDraft12TYPE(t *testing.T) {
	// VersionDraft12 with TYPE exercises groupD14 path.
	c, _ := buildChain(t, VersionDraft12, 3)
	if err := c.Verify(); err != nil {
		t.Fatalf("chain with draft-12+TYPE should verify: %v", err)
	}
}

// TestChainMixedVersions verifies that a chain mixing different draft versions
// across links can be built and verified.
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

// TestMalfeasanceReportRoundTripDraft14 verifies that a chain built with
// TYPE-aware requests (groupD14) produces a valid malfeasance report that
// survives round-trip serialization.
func TestMalfeasanceReportRoundTripDraft14(t *testing.T) {
	c, servers := buildChain(t, VersionDraft12, 3) // exercises groupD14 via TYPE

	data, err := c.MalfeasanceReport()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseMalfeasanceReport(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Links) != len(c.Links) {
		t.Fatalf("link count = %d, want %d", len(parsed.Links), len(c.Links))
	}
	for i, link := range parsed.Links {
		if !bytes.Equal(link.PublicKey, c.Links[i].PublicKey) {
			t.Fatalf("link %d: public key mismatch", i)
		}
		if !bytes.Equal(link.Request, c.Links[i].Request) {
			t.Fatalf("link %d: request mismatch", i)
		}
		if !bytes.Equal(link.Response, c.Links[i].Response) {
			t.Fatalf("link %d: response mismatch", i)
		}
	}
	// Verify the round-tripped chain.
	_ = servers // servers needed for building, chain verifies with embedded keys
	if err := parsed.Verify(); err != nil {
		t.Fatalf("round-tripped draft-14 chain should verify: %v", err)
	}
}

// TestChainNonceDraft12 verifies that draft-12 chain nonces use SHA-512
// truncated to 32 bytes.
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

// FuzzParseMalfeasanceReport exercises JSON malfeasance report parsing with
// arbitrary input. This is an untrusted-input parser and must not panic.
func FuzzParseMalfeasanceReport(f *testing.F) {
	// Seed with a valid report.
	validReport, _ := json.Marshal(struct {
		Responses []struct {
			Rand      string `json:"rand,omitempty"`
			PublicKey string `json:"publicKey"`
			Request   string `json:"request"`
			Response  string `json:"response"`
		} `json:"responses"`
	}{
		Responses: []struct {
			Rand      string `json:"rand,omitempty"`
			PublicKey string `json:"publicKey"`
			Request   string `json:"request"`
			Response  string `json:"response"`
		}{
			{
				PublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32)),
				Request:   base64.StdEncoding.EncodeToString(make([]byte, 64)),
				Response:  base64.StdEncoding.EncodeToString(make([]byte, 128)),
			},
			{
				Rand:      base64.StdEncoding.EncodeToString(make([]byte, 32)),
				PublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32)),
				Request:   base64.StdEncoding.EncodeToString(make([]byte, 64)),
				Response:  base64.StdEncoding.EncodeToString(make([]byte, 128)),
			},
		},
	})
	f.Add(validReport)

	// Seed with degenerate inputs.
	f.Add([]byte("{}"))
	f.Add([]byte(`{"responses":[]}`))
	f.Add([]byte(`{"responses":[{}]}`))
	f.Add([]byte(""))
	f.Add([]byte("null"))
	f.Add([]byte(`{"responses":[{"publicKey":"!!!","request":"!!!","response":"!!!"}]}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic. Errors are expected for most inputs.
		chain, err := ParseMalfeasanceReport(data)
		if err != nil {
			return
		}
		// If parsing succeeds, round-trip through MalfeasanceReport must not
		// panic.
		out, err := chain.MalfeasanceReport()
		if err != nil {
			return
		}
		// Re-parse the round-tripped output.
		chain2, err := ParseMalfeasanceReport(out)
		if err != nil {
			t.Fatalf("round-trip failed: %v", err)
		}
		if len(chain2.Links) != len(chain.Links) {
			t.Fatalf("link count mismatch: %d vs %d", len(chain2.Links), len(chain.Links))
		}
		for i := range chain.Links {
			if !bytes.Equal(chain.Links[i].Rand, chain2.Links[i].Rand) {
				t.Fatalf("link %d rand mismatch", i)
			}
			if !bytes.Equal(chain.Links[i].PublicKey, chain2.Links[i].PublicKey) {
				t.Fatalf("link %d publicKey mismatch", i)
			}
			if !bytes.Equal(chain.Links[i].Request, chain2.Links[i].Request) {
				t.Fatalf("link %d request mismatch", i)
			}
			if !bytes.Equal(chain.Links[i].Response, chain2.Links[i].Response) {
				t.Fatalf("link %d response mismatch", i)
			}
		}
	})
}

// FuzzChainNonce exercises chain nonce derivation with arbitrary previous
// responses across all wire groups. Must not panic.
func FuzzChainNonce(f *testing.F) {
	// Seed with various response sizes.
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

		// Must not panic.
		nonce, blind, err := ChainNonce(prevResp, rand.Reader, []Version{ver})
		if err != nil {
			return
		}

		// Verify output sizes match the version's nonce size.
		_, g, _ := clientVersionPreference([]Version{ver})
		ns := nonceSize(g)
		if len(nonce) != ns {
			t.Fatalf("nonce length = %d, want %d for %s", len(nonce), ns, ver)
		}
		if prevResp != nil && len(blind) != ns {
			t.Fatalf("blind length = %d, want %d for %s", len(blind), ns, ver)
		}

		// Verify hash derivation when prevResp is non-nil.
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

// TestParseMalfeasanceReportLegacy verifies that a drafts 10–11 malfeasance
// report ({nonces, responses} parallel arrays) is parsed successfully.
func TestParseMalfeasanceReportLegacy(t *testing.T) {
	legacy := []byte(`{"nonces":["","` +
		base64.StdEncoding.EncodeToString(make([]byte, 32)) +
		`"],"responses":["` +
		base64.StdEncoding.EncodeToString([]byte("resp1")) +
		`","` +
		base64.StdEncoding.EncodeToString([]byte("resp2")) +
		`"]}`)
	chain, err := ParseMalfeasanceReport(legacy)
	if err != nil {
		t.Fatalf("parse legacy report: %v", err)
	}
	if len(chain.Links) != 2 {
		t.Fatalf("expected 2 links, got %d", len(chain.Links))
	}
	if chain.Links[0].Rand != nil {
		t.Error("first link rand should be nil")
	}
	if len(chain.Links[1].Rand) != 32 {
		t.Errorf("second link rand length = %d, want 32", len(chain.Links[1].Rand))
	}
	if !bytes.Equal(chain.Links[0].Response, []byte("resp1")) {
		t.Error("first response mismatch")
	}
	if !bytes.Equal(chain.Links[1].Response, []byte("resp2")) {
		t.Error("second response mismatch")
	}
	// Legacy format has no request or publicKey.
	if chain.Links[0].Request != nil || chain.Links[0].PublicKey != nil {
		t.Error("legacy link should have nil Request and PublicKey")
	}
}

// TestParseMalfeasanceReportLegacyLengthMismatch verifies the legacy parser
// rejects a report where the nonces and responses arrays differ in length.
func TestParseMalfeasanceReportLegacyLengthMismatch(t *testing.T) {
	legacy := []byte(`{"nonces":["",""],"responses":["` +
		base64.StdEncoding.EncodeToString([]byte("x")) + `"]}`)
	if _, err := ParseMalfeasanceReport(legacy); err == nil {
		t.Fatal("expected length mismatch error")
	}
}

// FuzzChainVerify exercises Chain.Verify with arbitrary parsed reports. Must
// not panic on any input.
func FuzzChainVerify(f *testing.F) {
	// Seed with a valid two-link chain built normally.
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
		// Verify is expected to fail on most inputs; it must not panic.
		_ = c.Verify()
	})
}

// errReader is an io.Reader that always returns the configured error.
type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }

// TestChainNonceRejectsEmptyVersions verifies that ChainNonce surfaces the
// "empty version list" error from clientVersionPreference instead of panicking.
func TestChainNonceRejectsEmptyVersions(t *testing.T) {
	if _, _, err := ChainNonce(nil, rand.Reader, nil); err == nil {
		t.Fatal("expected error for empty versions")
	}
}

// TestChainNonceFirstReadError verifies that an entropy reader failure on the
// first link is wrapped with a useful message.
func TestChainNonceFirstReadError(t *testing.T) {
	want := errors.New("entropy boom")
	_, _, err := ChainNonce(nil, errReader{want}, []Version{VersionDraft12})
	if err == nil || !errors.Is(err, want) {
		t.Fatalf("expected wrapped %v, got %v", want, err)
	}
}

// TestChainNonceDerivedReadError verifies that an entropy reader failure on a
// derived link is wrapped with a useful message.
func TestChainNonceDerivedReadError(t *testing.T) {
	want := errors.New("entropy boom")
	prev := []byte("previous response")
	_, _, err := ChainNonce(prev, errReader{want}, []Version{VersionDraft12})
	if err == nil || !errors.Is(err, want) {
		t.Fatalf("expected wrapped %v, got %v", want, err)
	}
}

// TestNextRequestRejectsEmptyVersions verifies that NextRequest surfaces the
// version preference error.
func TestNextRequestRejectsEmptyVersions(t *testing.T) {
	rootSK, _ := testKeys(t)
	rootPK := rootSK.Public().(ed25519.PublicKey)
	var c Chain
	if _, err := c.NextRequest(nil, rootPK, rand.Reader); err == nil {
		t.Fatal("expected error for empty versions")
	}
}

// TestNextRequestEntropyError verifies that an entropy failure during
// NextRequest is propagated.
func TestNextRequestEntropyError(t *testing.T) {
	rootSK, _ := testKeys(t)
	rootPK := rootSK.Public().(ed25519.PublicKey)
	var c Chain
	_, err := c.NextRequest([]Version{VersionDraft12}, rootPK, errReader{errors.New("no entropy")})
	if err == nil {
		t.Fatal("expected entropy error")
	}
}

// TestParseMalfeasanceReportRejectsTooManyLinks verifies that the parser caps
// the number of links to prevent unbounded allocation.
func TestParseMalfeasanceReportRejectsTooManyLinks(t *testing.T) {
	const n = 1025
	entries := make([]string, n)
	for i := range entries {
		entries[i] = `""`
	}
	data := []byte(`{"nonces":[` + joinStrings(entries) + `],"responses":[` + joinStrings(entries) + `]}`)
	if _, err := ParseMalfeasanceReport(data); err == nil {
		t.Fatal("expected error for too many links")
	}
}

// joinStrings is a tiny helper to avoid pulling in strings just for one call.
func joinStrings(parts []string) string {
	var b []byte
	for i, p := range parts {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, p...)
	}
	return string(b)
}

// TestParseMalfeasanceReportLegacyBadBase64 verifies that bad base64 in either
// the nonces or responses array of a legacy report is rejected.
func TestParseMalfeasanceReportLegacyBadBase64(t *testing.T) {
	good := base64.StdEncoding.EncodeToString([]byte("ok"))
	t.Run("nonce", func(t *testing.T) {
		data := []byte(`{"nonces":["!!!"],"responses":["` + good + `"]}`)
		if _, err := ParseMalfeasanceReport(data); err == nil {
			t.Fatal("expected error for bad legacy nonce")
		}
	})
	t.Run("response", func(t *testing.T) {
		data := []byte(`{"nonces":["` + good + `"],"responses":["!!!"]}`)
		if _, err := ParseMalfeasanceReport(data); err == nil {
			t.Fatal("expected error for bad legacy response")
		}
	})
}

// TestParseMalfeasanceReportRejectsBadRand verifies that an invalid base64 rand
// in a drafts 12+ report is rejected.
func TestParseMalfeasanceReportRejectsBadRand(t *testing.T) {
	good := base64.StdEncoding.EncodeToString([]byte("ok"))
	entry := map[string]string{
		"rand":      "!!!not-base64!!!",
		"publicKey": good,
		"request":   good,
		"response":  good,
	}
	data, _ := json.Marshal(map[string]any{"responses": []any{entry}})
	if _, err := ParseMalfeasanceReport(data); err == nil {
		t.Fatal("expected error for bad rand")
	}
}
