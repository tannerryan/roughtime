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

// chainServer holds keys and a certificate for building chain links.
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

// buildChain creates a valid n-link chain with distinct servers.
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

// TestChainNonceFirst verifies the first link returns a random nonce and nil
// blind.
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

// TestChainNonceGoogle verifies Google-Roughtime uses 64-byte nonces and
// blinds.
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

// TestChainNonceDraft02 verifies draft-02 uses SHA-512; SHA-512/256's 32-byte
// output is too short for the 64-byte nonce of drafts 01–04.
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

// TestChainNonceDraft07 verifies draft-07 uses SHA-512 with 32-byte nonces.
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

// TestChainNonceDeterministic verifies fixed entropy produces a deterministic
// nonce.
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

// TestNextRequestFirstLink verifies the first link has nil Rand and a valid
// request.
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

// TestNextRequestChained verifies link 2's nonce derives from link 1's
// response.
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

// TestNextRequestRejectsMissingResponse verifies NextRequest fails when the
// prior link has no response.
func TestNextRequestRejectsMissingResponse(t *testing.T) {
	srv := newChainServer(t, VersionDraft12)
	c := Chain{Links: []ChainLink{{Request: []byte("dummy")}}}
	if _, err := c.NextRequest([]Version{VersionDraft12}, srv.rootPK, rand.Reader); err == nil {
		t.Fatal("expected error for missing response")
	}
}

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

func TestVerifyEmpty(t *testing.T) {
	var c Chain
	if err := c.Verify(); err == nil {
		t.Fatal("expected error for empty chain")
	}
}

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
// failure, not a causal ordering error.
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

// TestVerifyCausalOrder verifies non-monotonic midpoints (with non-overlapping
// radius windows) trigger a causal ordering violation.
func TestVerifyCausalOrder(t *testing.T) {
	ver := VersionDraft12
	versions := []Version{ver}

	srv1 := newChainServer(t, ver)
	srv2 := newChainServer(t, ver)
	srv3 := newChainServer(t, ver)

	now := time.Now()
	past := now.Add(-10 * time.Minute)
	future := now.Add(10 * time.Minute)

	// baseline: increasing midpoints
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

	// link 2 claims future, link 3 claims past: preserves nonce linkage but
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

// TestMalfeasanceReportRoundTrip verifies a chain round-trips through
// serialization and the deserialized chain still verifies.
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

	if err := parsed.Verify(); err != nil {
		t.Fatalf("deserialized chain should verify: %v", err)
	}
}

// TestMalfeasanceReportFirstLinkNoRand verifies the first link's rand is
// omitted from JSON.
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

	if _, ok := raw.Responses[0]["rand"]; ok {
		t.Fatal("first link should not have rand in JSON")
	}
	if _, ok := raw.Responses[1]["rand"]; !ok {
		t.Fatal("second link should have rand in JSON")
	}
}

// TestMalfeasanceReportFields verifies the drafts-12+ report JSON structure.
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
		for _, field := range []string{r.PublicKey, r.Request, r.Response} {
			if _, err := base64.StdEncoding.DecodeString(field); err != nil {
				t.Fatalf("link %d: invalid base64: %v", i, err)
			}
		}
	}
}

func TestParseMalfeasanceReportRejectsEmpty(t *testing.T) {
	if _, err := ParseMalfeasanceReport([]byte(`{"responses":[]}`)); err == nil {
		t.Fatal("expected error for empty responses")
	}
}

func TestParseMalfeasanceReportRejectsMalformed(t *testing.T) {
	if _, err := ParseMalfeasanceReport([]byte(`not json`)); err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

// TestParseMalfeasanceReportRejectsBadBase64 verifies invalid base64 in any
// field is rejected.
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

func TestMalfeasanceReportEmpty(t *testing.T) {
	var c Chain
	if _, err := c.MalfeasanceReport(); err == nil {
		t.Fatal("expected error for empty chain")
	}
}

// TestVerifyMultipleVersions verifies chains work across 32-byte-nonce draft
// versions.
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

// TestVerifyChainDraft10 exercises the groupD10 path.
func TestVerifyChainDraft10(t *testing.T) {
	c, _ := buildChain(t, VersionDraft10, 3)
	if err := c.Verify(); err != nil {
		t.Fatalf("draft-10 chain should verify: %v", err)
	}
}

// TestVerifyChainDraft11 exercises the groupD10 path for draft-11.
func TestVerifyChainDraft11(t *testing.T) {
	c, _ := buildChain(t, VersionDraft11, 3)
	if err := c.Verify(); err != nil {
		t.Fatalf("draft-11 chain should verify: %v", err)
	}
}

// TestMalfeasanceReportRoundTripDraft10 verifies a draft-10 chain emits the
// legacy format (parallel nonces/responses, no request/publicKey) and
// round-trips Rand + Response bytewise. Parsed chain is not Verify()-able since
// legacy omits Request.
func TestMalfeasanceReportRoundTripDraft10(t *testing.T) {
	c, _ := buildChain(t, VersionDraft10, 3)

	data, err := c.MalfeasanceReport()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// drafts 10-11 emit legacy {"nonces":[...],"responses":[...]}
	var probe struct {
		Nonces    []string `json:"nonces"`
		Responses []string `json:"responses"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		t.Fatalf("legacy format unmarshal: %v", err)
	}
	if len(probe.Nonces) != len(c.Links) || len(probe.Responses) != len(c.Links) {
		t.Fatalf("legacy arrays length mismatch: nonces=%d responses=%d want=%d",
			len(probe.Nonces), len(probe.Responses), len(c.Links))
	}
	parsed, err := ParseMalfeasanceReport(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(parsed.Links) != len(c.Links) {
		t.Fatalf("link count = %d, want %d", len(parsed.Links), len(c.Links))
	}
	for i, link := range parsed.Links {
		if !bytes.Equal(link.Rand, c.Links[i].Rand) {
			t.Fatalf("link %d: rand mismatch", i)
		}
		if !bytes.Equal(link.Response, c.Links[i].Response) {
			t.Fatalf("link %d: response mismatch", i)
		}
		if link.Request != nil || link.PublicKey != nil {
			t.Fatalf("link %d: legacy format should drop Request/PublicKey", i)
		}
	}
}

// TestMalfeasanceReportRoundTripDraft12 verifies a draft-12 chain round-trips
// and Verify()s after deserialization.
func TestMalfeasanceReportRoundTripDraft12(t *testing.T) {
	c, _ := buildChain(t, VersionDraft12, 3)

	data, err := c.MalfeasanceReport()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	parsed, err := ParseMalfeasanceReport(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := parsed.Verify(); err != nil {
		t.Fatalf("deserialized draft-12 chain should verify: %v", err)
	}
}

// TestParseMalfeasanceReportLegacyFromChain verifies the legacy
// {nonces,responses} format parses from a real draft-10 chain.
func TestParseMalfeasanceReportLegacyFromChain(t *testing.T) {
	c, _ := buildChain(t, VersionDraft10, 3)

	nonces := make([]string, len(c.Links))
	responses := make([]string, len(c.Links))
	for i, link := range c.Links {
		if link.Rand != nil {
			nonces[i] = base64.StdEncoding.EncodeToString(link.Rand)
		}
		responses[i] = base64.StdEncoding.EncodeToString(link.Response)
	}
	data, err := json.Marshal(struct {
		Nonces    []string `json:"nonces"`
		Responses []string `json:"responses"`
	}{Nonces: nonces, Responses: responses})
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := ParseMalfeasanceReport(data)
	if err != nil {
		t.Fatalf("parse legacy report: %v", err)
	}
	if len(parsed.Links) != len(c.Links) {
		t.Fatalf("link count = %d, want %d", len(parsed.Links), len(c.Links))
	}
	for i, link := range parsed.Links {
		if !bytes.Equal(link.Rand, c.Links[i].Rand) {
			t.Fatalf("link %d: rand mismatch", i)
		}
		if !bytes.Equal(link.Response, c.Links[i].Response) {
			t.Fatalf("link %d: response mismatch", i)
		}
	}
}

// TestChainNonceDraft10 verifies draft-10 uses SHA-512 with 32-byte nonces.
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

// TestVerifyCorruptedResponse verifies a corrupted response is detected.
func TestVerifyCorruptedResponse(t *testing.T) {
	c, _ := buildChain(t, VersionDraft12, 2)

	c.Links[0].Response[len(c.Links[0].Response)-1] ^= 0xff

	if err := c.Verify(); err == nil {
		t.Fatal("expected error for corrupted response")
	}
}

// TestVerifyMultipleVersionsExtended covers all supported versions.
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

// TestChainNonceDraft01 verifies draft-01 uses SHA-512 with 64-byte nonces.
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

// TestChainNonceDraft05 verifies draft-05 uses SHA-512 with 32-byte nonces.
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

// TestVerifyMultipleVersionsWithDraft12TYPE exercises the groupD14 (TYPE tag)
// path via draft-12.
func TestVerifyMultipleVersionsWithDraft12TYPE(t *testing.T) {
	c, _ := buildChain(t, VersionDraft12, 3)
	if err := c.Verify(); err != nil {
		t.Fatalf("chain with draft-12+TYPE should verify: %v", err)
	}
}

// TestChainMixedVersions verifies a chain mixing draft versions across links
// verifies.
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

// TestMalfeasanceReportRoundTripDraft14 verifies a groupD14 chain round-trips.
func TestMalfeasanceReportRoundTripDraft14(t *testing.T) {
	c, servers := buildChain(t, VersionDraft12, 3)

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
	_ = servers
	if err := parsed.Verify(); err != nil {
		t.Fatalf("round-tripped draft-14 chain should verify: %v", err)
	}
}

// TestChainNonceDraft12 verifies draft-12 uses SHA-512 truncated to 32 bytes.
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

// FuzzParseMalfeasanceReport ensures the parser never panics on arbitrary JSON.
func FuzzParseMalfeasanceReport(f *testing.F) {
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

	f.Add([]byte("{}"))
	f.Add([]byte(`{"responses":[]}`))
	f.Add([]byte(`{"responses":[{}]}`))
	f.Add([]byte(""))
	f.Add([]byte("null"))
	f.Add([]byte(`{"responses":[{"publicKey":"!!!","request":"!!!","response":"!!!"}]}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		chain, err := ParseMalfeasanceReport(data)
		if err != nil {
			return
		}
		out, err := chain.MalfeasanceReport()
		if err != nil {
			return
		}
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

// FuzzChainNonce ensures nonce derivation never panics across wire groups.
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

// TestParseMalfeasanceReportLegacy verifies the drafts 10–11 {nonces,responses}
// format parses.
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
	if chain.Links[0].Request != nil || chain.Links[0].PublicKey != nil {
		t.Error("legacy link should have nil Request and PublicKey")
	}
}

// TestParseMalfeasanceReportLegacyLengthMismatch verifies legacy parser rejects
// mismatched array lengths.
func TestParseMalfeasanceReportLegacyLengthMismatch(t *testing.T) {
	legacy := []byte(`{"nonces":["",""],"responses":["` +
		base64.StdEncoding.EncodeToString([]byte("x")) + `"]}`)
	if _, err := ParseMalfeasanceReport(legacy); err == nil {
		t.Fatal("expected length mismatch error")
	}
}

// FuzzChainVerify ensures Chain.Verify never panics on arbitrary parsed
// reports.
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

// errReader is an io.Reader that always returns its configured error.
type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }

// TestChainNonceRejectsEmptyVersions verifies ChainNonce surfaces the
// empty-versions error.
func TestChainNonceRejectsEmptyVersions(t *testing.T) {
	if _, _, err := ChainNonce(nil, rand.Reader, nil); err == nil {
		t.Fatal("expected error for empty versions")
	}
}

// TestChainNonceFirstReadError verifies an entropy failure on the first link is
// wrapped.
func TestChainNonceFirstReadError(t *testing.T) {
	want := errors.New("entropy boom")
	_, _, err := ChainNonce(nil, errReader{want}, []Version{VersionDraft12})
	if err == nil || !errors.Is(err, want) {
		t.Fatalf("expected wrapped %v, got %v", want, err)
	}
}

// TestChainNonceDerivedReadError verifies an entropy failure on a derived link
// is wrapped.
func TestChainNonceDerivedReadError(t *testing.T) {
	want := errors.New("entropy boom")
	prev := []byte("previous response")
	_, _, err := ChainNonce(prev, errReader{want}, []Version{VersionDraft12})
	if err == nil || !errors.Is(err, want) {
		t.Fatalf("expected wrapped %v, got %v", want, err)
	}
}

// TestNextRequestRejectsEmptyVersions verifies NextRequest surfaces the
// version-preference error.
func TestNextRequestRejectsEmptyVersions(t *testing.T) {
	rootSK, _ := testKeys(t)
	rootPK := rootSK.Public().(ed25519.PublicKey)
	var c Chain
	if _, err := c.NextRequest(nil, rootPK, rand.Reader); err == nil {
		t.Fatal("expected error for empty versions")
	}
}

// TestNextRequestEntropyError verifies an entropy failure in NextRequest is
// propagated.
func TestNextRequestEntropyError(t *testing.T) {
	rootSK, _ := testKeys(t)
	rootPK := rootSK.Public().(ed25519.PublicKey)
	var c Chain
	_, err := c.NextRequest([]Version{VersionDraft12}, rootPK, errReader{errors.New("no entropy")})
	if err == nil {
		t.Fatal("expected entropy error")
	}
}

// TestParseMalfeasanceReportRejectsTooManyLinks verifies the parser caps link
// count.
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

// joinStrings concatenates parts with ',' separators.
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

// TestParseMalfeasanceReportLegacyBadBase64 verifies bad base64 in legacy
// nonces or responses is rejected.
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

// TestParseMalfeasanceReportRejectsBadRand verifies bad base64 in the rand
// field is rejected.
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

// TestVerifyRejectsTooManyLinks verifies Verify rejects chains longer than
// [maxChainLinks].
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

// TestVerifyCausalOrderFiveLinks exercises the running-max algorithm where the
// violating link's midpoint precedes an older (non-adjacent) link's upper
// bound.
func TestVerifyCausalOrderFiveLinks(t *testing.T) {
	ver := VersionDraft12
	versions := []Version{ver}

	servers := make([]chainServer, 5)
	for i := range servers {
		servers[i] = newChainServer(t, ver)
	}

	// link 2 is the peak; link 4 drops below it, violating running max even
	// though link 3 (immediate predecessor) does not
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

// TestNextRequestPopulatesNonce confirms ChainLink.Nonce matches the nonce in
// the framed Request, so callers can verify replies without re-parsing.
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
