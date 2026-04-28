// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package roughtime_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/tannerryan/roughtime"
	"github.com/tannerryan/roughtime/protocol"
)

// makeProof builds a Proof from an n-link chain against a fresh fakeServer.
func makeProof(t *testing.T, n int) *roughtime.Proof {
	t.Helper()
	f := newFakeServer(t)
	t.Cleanup(f.Close)
	s := f.server()
	servers := make([]roughtime.Server, n)
	for i := range servers {
		servers[i] = s
	}
	var c roughtime.Client
	cr, err := c.QueryChain(context.Background(), servers)
	if err != nil {
		t.Fatalf("QueryChain: %v", err)
	}
	proof, err := cr.Proof()
	if err != nil {
		t.Fatalf("cr.Proof: %v", err)
	}
	return proof
}

// gzipReport returns data wrapped in a gzip stream.
func gzipReport(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(data); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

// tamperResponse flips a byte in link[idx]'s response and re-gzips the report.
func tamperResponse(t *testing.T, marshaled []byte, idx int) []byte {
	t.Helper()
	gr, err := gzip.NewReader(bytes.NewReader(marshaled))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	raw, err := io.ReadAll(gr)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	_ = gr.Close()
	var report struct {
		Responses []map[string]string `json:"responses"`
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	resp, err := base64.StdEncoding.DecodeString(report.Responses[idx]["response"])
	if err != nil {
		t.Fatalf("b64: %v", err)
	}
	resp[len(resp)-1] ^= 0x01
	report.Responses[idx]["response"] = base64.StdEncoding.EncodeToString(resp)
	out, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return gzipReport(t, out)
}

// makeGoogleProof builds a 2-link VersionGoogle chain and marshals it as
// gzipped malfeasance JSON.
func makeGoogleProof(t *testing.T) []byte {
	t.Helper()
	build := func() *protocol.Chain {
		_, rootSK, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("ed25519 root: %v", err)
		}
		_, onlineSK, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("ed25519 online: %v", err)
		}
		now := time.Now()
		cert, err := protocol.NewCertificate(now.Add(-time.Hour), now.Add(time.Hour), onlineSK, rootSK)
		if err != nil {
			t.Fatalf("NewCertificate: %v", err)
		}
		rootPK := rootSK.Public().(ed25519.PublicKey)
		var c protocol.Chain
		for i := range 2 {
			link, err := c.NextRequest([]protocol.Version{protocol.VersionGoogle}, rootPK, rand.Reader)
			if err != nil {
				t.Fatalf("NextRequest: %v", err)
			}
			req, err := protocol.ParseRequest(link.Request)
			if err != nil {
				t.Fatalf("ParseRequest: %v", err)
			}
			replies, err := protocol.CreateReplies(protocol.VersionGoogle, []protocol.Request{*req}, now.Add(time.Duration(i)*time.Second), time.Second, cert)
			if err != nil {
				t.Fatalf("CreateReplies: %v", err)
			}
			link.Response = replies[0]
			c.Append(link)
		}
		return &c
	}
	chain := build()
	report, err := chain.MalfeasanceReport()
	if err != nil {
		t.Fatalf("MalfeasanceReport: %v", err)
	}
	return gzipReport(t, report)
}

// TestProofLinksGoogleChain verifies Proof.Links handles VER-less Google
// requests via the same fallback as protocol.Chain.Verify.
func TestProofLinksGoogleChain(t *testing.T) {
	p, err := roughtime.ParseProof(makeGoogleProof(t))
	if err != nil {
		t.Fatalf("ParseProof: %v", err)
	}
	if err := p.Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	links, err := p.Links()
	if err != nil {
		t.Fatalf("Links: %v", err)
	}
	if len(links) != 2 {
		t.Fatalf("got %d links, want 2", len(links))
	}
	for i, l := range links {
		if l.Version != protocol.VersionGoogle {
			t.Errorf("link %d: Version = %v, want VersionGoogle", i, l.Version)
		}
	}
	if _, _, err := p.AttestationBound(); err != nil {
		t.Fatalf("AttestationBound: %v", err)
	}
}

// craftBadRequestProof returns malfeasance-report JSON whose request bytes will
// not parse.
func craftBadRequestProof(t *testing.T) []byte {
	t.Helper()
	report := map[string]any{
		"responses": []map[string]string{
			{
				"publicKey": base64.StdEncoding.EncodeToString(make([]byte, 32)),
				"request":   base64.StdEncoding.EncodeToString([]byte("garbage1")),
				"response":  base64.StdEncoding.EncodeToString(make([]byte, 32)),
			},
		},
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return data
}

// TestChainResultProof verifies a chained query yields a Proof that round-trips
// through MarshalGzip and ParseProof.
func TestChainResultProof(t *testing.T) {
	f1 := newFakeServer(t)
	defer f1.Close()
	f2 := newFakeServer(t)
	defer f2.Close()

	var c roughtime.Client
	cr, err := c.QueryChain(context.Background(), []roughtime.Server{f1.server(), f2.server()})
	if err != nil {
		t.Fatalf("QueryChain: %v", err)
	}
	proof, err := cr.Proof()
	if err != nil {
		t.Fatalf("Proof: %v", err)
	}
	if proof.Len() != 2 {
		t.Fatalf("Len = %d, want 2", proof.Len())
	}
	if err := proof.Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	data, err := proof.MarshalGzip()
	if err != nil {
		t.Fatalf("MarshalGzip: %v", err)
	}
	if !bytes.HasPrefix(data, []byte{0x1f, 0x8b}) {
		t.Fatalf("MarshalGzip output not gzipped")
	}
	parsed, err := roughtime.ParseProof(data)
	if err != nil {
		t.Fatalf("ParseProof: %v", err)
	}
	if parsed.Len() != proof.Len() {
		t.Fatalf("round-trip Len: got %d want %d", parsed.Len(), proof.Len())
	}
}

// TestChainResultProofNil verifies ChainResult.Proof errors on a nil receiver
// and a nil chain.
func TestChainResultProofNil(t *testing.T) {
	var cr *roughtime.ChainResult
	if _, err := cr.Proof(); err == nil {
		t.Fatal("nil receiver should error")
	}
	cr = &roughtime.ChainResult{}
	if _, err := cr.Proof(); err == nil {
		t.Fatal("nil chain should error")
	}
}

// TestChainResultProofEmpty verifies ChainResult.Proof errors when no link
// succeeded.
func TestChainResultProofEmpty(t *testing.T) {
	f := newFakeServer(t)
	defer f.Close()
	f.dropNext(1_000_000)
	c := roughtime.Client{Timeout: 10 * time.Millisecond, MaxAttempts: 1}
	cr, err := c.QueryChain(context.Background(), []roughtime.Server{f.server(), f.server()})
	if err != nil {
		t.Fatalf("QueryChain: %v", err)
	}
	if _, err := cr.Proof(); err == nil || !strings.Contains(err.Error(), "empty chain") {
		t.Fatalf("Proof: %v; want 'empty chain' error", err)
	}
}

// TestProofMarshalGzipRoundTrip verifies MarshalGzip output parses back and
// re-verifies.
func TestProofMarshalGzipRoundTrip(t *testing.T) {
	proof := makeProof(t, 3)
	data, err := proof.MarshalGzip()
	if err != nil {
		t.Fatalf("MarshalGzip: %v", err)
	}
	if !bytes.HasPrefix(data, []byte{0x1f, 0x8b}) {
		t.Fatal("MarshalGzip output not gzipped")
	}
	out, err := roughtime.ParseProof(data)
	if err != nil {
		t.Fatalf("ParseProof: %v", err)
	}
	if out.Len() != 3 {
		t.Fatalf("Len = %d, want 3", out.Len())
	}
	if err := out.Verify(); err != nil {
		t.Fatalf("Verify after round-trip: %v", err)
	}
}

// TestProofMarshalGzipNil verifies Proof.MarshalGzip errors on a nil receiver.
func TestProofMarshalGzipNil(t *testing.T) {
	var p *roughtime.Proof
	if _, err := p.MarshalGzip(); err == nil {
		t.Fatal("nil receiver should error")
	}
}

// TestProofMarshalJSON verifies Proof.MarshalJSON emits malfeasance JSON and is
// invoked by encoding/json.
func TestProofMarshalJSON(t *testing.T) {
	proof := makeProof(t, 2)
	raw, err := proof.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	if !bytes.Contains(raw, []byte(`"responses"`)) {
		t.Fatalf("MarshalJSON output missing 'responses' field")
	}
	out, err := roughtime.ParseProof(raw)
	if err != nil {
		t.Fatalf("ParseProof(raw): %v", err)
	}
	if out.Len() != proof.Len() {
		t.Fatalf("round-trip Len: got %d want %d", out.Len(), proof.Len())
	}
	// json.Marshal should call our MarshalJSON
	via, err := json.Marshal(proof)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if !bytes.Equal(via, raw) {
		t.Fatal("json.Marshal output did not match MarshalJSON")
	}
}

// TestProofMarshalJSONNil verifies Proof.MarshalJSON errors on a nil receiver.
func TestProofMarshalJSONNil(t *testing.T) {
	var p *roughtime.Proof
	if _, err := p.MarshalJSON(); err == nil {
		t.Fatal("nil receiver should error")
	}
}

// TestProofVerify verifies a freshly built Proof passes Verify.
func TestProofVerify(t *testing.T) {
	if err := makeProof(t, 3).Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// TestProofVerifyNil verifies Proof.Verify errors on a nil receiver.
func TestProofVerifyNil(t *testing.T) {
	var p *roughtime.Proof
	if err := p.Verify(); err == nil {
		t.Fatal("nil receiver should error")
	}
}

// TestProofVerifyTampered verifies Proof.Verify rejects a chain with a flipped
// reply byte.
func TestProofVerifyTampered(t *testing.T) {
	proof := makeProof(t, 2)
	data, _ := proof.MarshalGzip()
	tampered := tamperResponse(t, data, 0)
	p2, err := roughtime.ParseProof(tampered)
	if err != nil {
		t.Fatalf("ParseProof: %v", err)
	}
	if err := p2.Verify(); err == nil {
		t.Fatal("Verify accepted tampered proof")
	}
}

// TestProofLen verifies Proof.Len matches the chain link count.
func TestProofLen(t *testing.T) {
	if got := makeProof(t, 4).Len(); got != 4 {
		t.Fatalf("Len = %d, want 4", got)
	}
}

// TestProofLenNil verifies Proof.Len returns 0 on a nil receiver.
func TestProofLenNil(t *testing.T) {
	var p *roughtime.Proof
	if got := p.Len(); got != 0 {
		t.Fatalf("nil Len = %d, want 0", got)
	}
}

// TestProofLinks verifies Proof.Links returns one populated ProofLink per chain
// link.
func TestProofLinks(t *testing.T) {
	proof := makeProof(t, 2)
	links, err := proof.Links()
	if err != nil {
		t.Fatalf("Links: %v", err)
	}
	if len(links) != 2 {
		t.Fatalf("got %d links, want 2", len(links))
	}
	for i, l := range links {
		if len(l.PublicKey) == 0 {
			t.Errorf("link %d: empty PublicKey", i)
		}
		if len(l.Nonce) == 0 {
			t.Errorf("link %d: empty Nonce", i)
		}
		if l.Midpoint.IsZero() {
			t.Errorf("link %d: zero Midpoint", i)
		}
		if l.Radius <= 0 {
			t.Errorf("link %d: non-positive Radius", i)
		}
	}
}

// TestProofLinksNil verifies Proof.Links errors on a nil receiver.
func TestProofLinksNil(t *testing.T) {
	var p *roughtime.Proof
	if _, err := p.Links(); err == nil {
		t.Fatal("nil receiver should error")
	}
}

// TestProofLinksBadRequest verifies Proof.Links surfaces a ParseRequest error
// from corrupt request bytes.
func TestProofLinksBadRequest(t *testing.T) {
	p, err := roughtime.ParseProof(craftBadRequestProof(t))
	if err != nil {
		t.Fatalf("ParseProof: %v", err)
	}
	if _, err := p.Links(); err == nil {
		t.Fatal("Links should error on corrupt request bytes")
	}
}

// TestProofLinksTamperedResponse verifies Proof.Links surfaces a VerifyReply
// error from a tampered reply.
func TestProofLinksTamperedResponse(t *testing.T) {
	proof := makeProof(t, 1)
	data, _ := proof.MarshalGzip()
	tampered := tamperResponse(t, data, 0)
	p2, err := roughtime.ParseProof(tampered)
	if err != nil {
		t.Fatalf("ParseProof: %v", err)
	}
	if _, err := p2.Links(); err == nil {
		t.Fatal("Links should error on tampered response")
	}
}

// TestProofTrust verifies Proof.Trust accepts a chain whose every key is in the
// trusted set.
func TestProofTrust(t *testing.T) {
	f := newFakeServer(t)
	defer f.Close()
	s := f.server()
	var c roughtime.Client
	cr, err := c.QueryChain(context.Background(), []roughtime.Server{s, s})
	if err != nil {
		t.Fatalf("QueryChain: %v", err)
	}
	proof, err := cr.Proof()
	if err != nil {
		t.Fatalf("Proof: %v", err)
	}
	if err := proof.Trust([]roughtime.Server{s}); err != nil {
		t.Fatalf("Trust: %v", err)
	}
}

// TestProofTrustUnknown verifies Proof.Trust rejects a chain when no keys are
// trusted.
func TestProofTrustUnknown(t *testing.T) {
	if err := makeProof(t, 2).Trust(nil); err == nil {
		t.Fatal("Trust(nil) accepted untrusted keys")
	}
}

// TestProofTrustNil verifies Proof.Trust errors on a nil receiver.
func TestProofTrustNil(t *testing.T) {
	var p *roughtime.Proof
	if err := p.Trust(nil); err == nil {
		t.Fatal("nil receiver should error")
	}
}

// TestProofTrustPartial verifies Proof.Trust errors when the trusted set covers
// only some chain keys.
func TestProofTrustPartial(t *testing.T) {
	f1 := newFakeServer(t)
	defer f1.Close()
	f2 := newFakeServer(t)
	defer f2.Close()

	var c roughtime.Client
	cr, err := c.QueryChain(context.Background(), []roughtime.Server{f1.server(), f2.server()})
	if err != nil {
		t.Fatalf("QueryChain: %v", err)
	}
	proof, err := cr.Proof()
	if err != nil {
		t.Fatalf("Proof: %v", err)
	}
	// trust f1 only; f2's link must surface as untrusted
	if err := proof.Trust([]roughtime.Server{f1.server()}); err == nil {
		t.Fatal("Trust accepted a chain with an untrusted key")
	}
}

// TestProofSeedNonce verifies Proof.SeedNonce returns the seed supplied to
// QueryChainWithNonce.
func TestProofSeedNonce(t *testing.T) {
	f := newFakeServer(t)
	defer f.Close()
	seed := bytes.Repeat([]byte{0xCC}, 32)
	var c roughtime.Client
	cr, err := c.QueryChainWithNonce(context.Background(), []roughtime.Server{f.server(), f.server()}, seed)
	if err != nil {
		t.Fatalf("QueryChainWithNonce: %v", err)
	}
	proof, err := cr.Proof()
	if err != nil {
		t.Fatalf("Proof: %v", err)
	}
	got, err := proof.SeedNonce()
	if err != nil {
		t.Fatalf("SeedNonce: %v", err)
	}
	if !bytes.Equal(got, seed) {
		t.Fatalf("SeedNonce = %x, want %x", got, seed)
	}
}

// TestProofSeedNonceNil verifies Proof.SeedNonce errors on a nil receiver.
func TestProofSeedNonceNil(t *testing.T) {
	var p *roughtime.Proof
	if _, err := p.SeedNonce(); err == nil {
		t.Fatal("nil receiver should error")
	}
}

// TestProofSeedNonceBadRequest verifies Proof.SeedNonce surfaces a ParseRequest
// error from corrupt request bytes.
func TestProofSeedNonceBadRequest(t *testing.T) {
	p, err := roughtime.ParseProof(craftBadRequestProof(t))
	if err != nil {
		t.Fatalf("ParseProof: %v", err)
	}
	if _, err := p.SeedNonce(); err == nil {
		t.Fatal("SeedNonce should error on corrupt request bytes")
	}
}

// TestProofAttestationBound verifies Proof.AttestationBound returns an interval
// with earliest before latest.
func TestProofAttestationBound(t *testing.T) {
	proof := makeProof(t, 3)
	earliest, latest, err := proof.AttestationBound()
	if err != nil {
		t.Fatalf("AttestationBound: %v", err)
	}
	if !earliest.Before(latest) {
		t.Fatalf("earliest %s is not before latest %s", earliest, latest)
	}
}

// TestProofAttestationBoundNil verifies Proof.AttestationBound errors on a nil
// receiver.
func TestProofAttestationBoundNil(t *testing.T) {
	var p *roughtime.Proof
	if _, _, err := p.AttestationBound(); err == nil {
		t.Fatal("nil receiver should error")
	}
}

// TestProofAttestationBoundTightens verifies a smaller-radius later link
// tightens the upper bound.
func TestProofAttestationBoundTightens(t *testing.T) {
	wide := newFakeServerWithRadius(t, 5*time.Second)
	defer wide.Close()
	tight := newFakeServerWithRadius(t, 50*time.Millisecond)
	defer tight.Close()

	var c roughtime.Client
	cr, err := c.QueryChain(context.Background(), []roughtime.Server{wide.server(), tight.server()})
	if err != nil {
		t.Fatalf("QueryChain: %v", err)
	}
	proof, err := cr.Proof()
	if err != nil {
		t.Fatalf("Proof: %v", err)
	}
	earliest, latest, err := proof.AttestationBound()
	if err != nil {
		t.Fatalf("AttestationBound: %v", err)
	}
	links, _ := proof.Links()
	_, wideUpper := links[0].Window()
	if !latest.Before(wideUpper) {
		t.Fatalf("latest %s should be tighter than link 0 upper %s", latest, wideUpper)
	}
	if !earliest.Before(latest) {
		t.Fatalf("earliest %s !< latest %s", earliest, latest)
	}
}

// TestProofLinkWindow verifies ProofLink.Window returns Midpoint plus and minus
// Radius.
func TestProofLinkWindow(t *testing.T) {
	mid := time.Unix(1000, 0).UTC()
	l := roughtime.ProofLink{Midpoint: mid, Radius: 3 * time.Second}
	lo, hi := l.Window()
	if want := mid.Add(-3 * time.Second); !lo.Equal(want) {
		t.Fatalf("lower = %s, want %s", lo, want)
	}
	if want := mid.Add(3 * time.Second); !hi.Equal(want) {
		t.Fatalf("upper = %s, want %s", hi, want)
	}
}

// TestParseProofTooLarge verifies ParseProof rejects input larger than
// MaxProofBytes.
func TestParseProofTooLarge(t *testing.T) {
	huge := make([]byte, roughtime.MaxProofBytes+1)
	if _, err := roughtime.ParseProof(huge); err == nil || !strings.Contains(err.Error(), "max") {
		t.Fatalf("ParseProof: %v; want max-bytes error", err)
	}
}

// TestParseProofBadGzipHeader verifies ParseProof rejects input with a
// malformed gzip header.
func TestParseProofBadGzipHeader(t *testing.T) {
	if _, err := roughtime.ParseProof([]byte{0x1f, 0x8b, 0x00, 0x00}); err == nil {
		t.Fatal("ParseProof accepted bad gzip header")
	}
}

// TestParseProofTruncatedGzip verifies ParseProof rejects a truncated gzip
// stream.
func TestParseProofTruncatedGzip(t *testing.T) {
	proof := makeProof(t, 2)
	data, _ := proof.MarshalGzip()
	truncated := data[:len(data)/2]
	if _, err := roughtime.ParseProof(truncated); err == nil {
		t.Fatal("ParseProof accepted truncated gzip")
	}
}

// TestParseProofGzipBomb verifies ParseProof caps decompressed size at
// MaxProofBytes.
func TestParseProofGzipBomb(t *testing.T) {
	bomb := bytes.Repeat([]byte("A"), roughtime.MaxProofBytes+1)
	if _, err := roughtime.ParseProof(gzipReport(t, bomb)); err == nil ||
		!strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("ParseProof: %v; want exceeds-size error", err)
	}
}

// TestParseProofBadJSON verifies ParseProof rejects non-JSON, non-gzipped
// input.
func TestParseProofBadJSON(t *testing.T) {
	if _, err := roughtime.ParseProof([]byte("not a malfeasance report")); err == nil {
		t.Fatal("ParseProof accepted non-JSON input")
	}
}

// TestParseProofRawJSON verifies ParseProof accepts non-gzipped malfeasance
// JSON directly.
func TestParseProofRawJSON(t *testing.T) {
	proof := makeProof(t, 2)
	data, _ := proof.MarshalGzip()
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	raw, err := io.ReadAll(gr)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	_ = gr.Close()
	parsed, err := roughtime.ParseProof(raw)
	if err != nil {
		t.Fatalf("ParseProof(raw): %v", err)
	}
	if parsed.Len() != 2 {
		t.Fatalf("Len = %d, want 2", parsed.Len())
	}
}

// TestVerifyOfflineProof verifies Verify reproduces the midpoint from a live
// query's request and reply.
func TestVerifyOfflineProof(t *testing.T) {
	f := newFakeServer(t)
	defer f.Close()

	s := f.server()
	resp, err := roughtime.Query(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	midpoint, _, err := roughtime.Verify(s.PublicKey, resp.Request, resp.Reply)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !midpoint.Equal(resp.Midpoint) {
		t.Fatalf("midpoint mismatch: got %v want %v", midpoint, resp.Midpoint)
	}
}

// TestVerifyOfflineProofRejectsTamperedReply verifies Verify rejects a reply
// with a flipped byte.
func TestVerifyOfflineProofRejectsTamperedReply(t *testing.T) {
	f := newFakeServer(t)
	defer f.Close()

	s := f.server()
	resp, err := roughtime.Query(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), resp.Reply...)
	tampered[len(tampered)-1] ^= 0x01
	if _, _, err := roughtime.Verify(s.PublicKey, resp.Request, tampered); err == nil {
		t.Fatal("expected Verify to reject tampered reply")
	}
}

// TestVerifyRejectsJunkReply verifies Verify rejects an unparseable reply.
func TestVerifyRejectsJunkReply(t *testing.T) {
	if _, _, err := roughtime.Verify(make([]byte, 32), []byte{0, 1, 2}, []byte{0, 1, 2}); err == nil {
		t.Fatal("Verify accepted junk reply")
	}
}

// TestVerifyRejectsReplyChoosingUnofferedVersion verifies Verify uses the
// request's offered VER list, rejecting a reply that picked something not in
// it.
func TestVerifyRejectsReplyChoosingUnofferedVersion(t *testing.T) {
	f := newFakeServer(t)
	defer f.Close()
	s := f.server()
	resp, err := roughtime.Query(context.Background(), s)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	parsed, err := protocol.ParseRequest(resp.Request)
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}
	// Synthetic request: same nonce, but offers only draft-10 (fakeServer
	// replied at draft-12).
	synth, err := protocol.CreateRequestWithNonce([]protocol.Version{protocol.VersionDraft10}, parsed.Nonce, protocol.ComputeSRV(s.PublicKey))
	if err != nil {
		t.Fatalf("CreateRequestWithNonce: %v", err)
	}
	if _, _, err := roughtime.Verify(s.PublicKey, synth, resp.Reply); err == nil {
		t.Fatal("Verify accepted a reply whose chosen version was not offered")
	}
}

// TestVerifyFallsBackToGoogleForVERLess verifies a VER-less reply is treated as
// VersionGoogle rather than rejected outright.
func TestVerifyFallsBackToGoogleForVERLess(t *testing.T) {
	junkReply := []byte{0, 1, 2, 3}
	junkRequest := []byte{0, 1, 2, 3} // unparsable; ParseRequest fails first
	_, _, err := roughtime.Verify(make([]byte, 32), junkRequest, junkReply)
	if err == nil {
		t.Fatal("Verify accepted junk")
	}
	if strings.Contains(err.Error(), "cannot determine reply version") {
		t.Fatalf("Verify still surfaces removed pre-H-1 error: %v", err)
	}
}

// TestVerifyRejectsJunkRequest verifies Verify rejects an unparseable request.
func TestVerifyRejectsJunkRequest(t *testing.T) {
	f := newFakeServer(t)
	defer f.Close()
	resp, err := roughtime.Query(context.Background(), f.server())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := roughtime.Verify(f.server().PublicKey, []byte{0, 1, 2, 3}, resp.Reply); err == nil {
		t.Fatal("Verify accepted junk request")
	}
}

// FuzzParseProof fuzzes ParseProof to ensure successful parses always yield a
// non-empty Proof.
func FuzzParseProof(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("{}"))
	f.Add([]byte(`{"responses":[]}`))
	f.Add([]byte("not json"))
	f.Add([]byte{0x1f, 0x8b})
	f.Add([]byte{0x1f, 0x8b, 0x08})

	raw, _ := json.Marshal(map[string]any{
		"responses": []map[string]string{
			{
				"publicKey": base64.StdEncoding.EncodeToString(make([]byte, 32)),
				"request":   base64.StdEncoding.EncodeToString(make([]byte, 64)),
				"response":  base64.StdEncoding.EncodeToString(make([]byte, 128)),
			},
		},
	})
	f.Add(raw)

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	_, _ = gw.Write(raw)
	_ = gw.Close()
	f.Add(buf.Bytes())

	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := roughtime.ParseProof(data)
		if err != nil {
			return
		}
		if p == nil {
			t.Fatal("ParseProof returned nil with no error")
		}
		if p.Len() == 0 {
			t.Fatal("ParseProof returned empty proof with no error")
		}
	})
}

// FuzzVerify fuzzes Verify with arbitrary keys, requests, and replies to ensure
// it never panics.
func FuzzVerify(f *testing.F) {
	f.Add([]byte{}, []byte{}, []byte{})
	f.Add(make([]byte, 32), []byte{}, []byte{})
	f.Add(make([]byte, 32), []byte{0, 1, 2}, []byte{0, 1, 2})
	f.Add(make([]byte, 32), make([]byte, 64), make([]byte, 128))
	f.Add(make([]byte, 1312), make([]byte, 64), make([]byte, 128))

	f.Fuzz(func(t *testing.T, pk, req, reply []byte) {
		_, _, _ = roughtime.Verify(pk, req, reply)
	})
}
