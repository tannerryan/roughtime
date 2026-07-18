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
	// report contains the response fields changed by this test.
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

// TestProofLinksGoogleChain covers Google-Roughtime proof links.
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

// TestChainResultProof covers proof extraction from a query chain.
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

// TestProofVerifyTampered covers tampered proof rejection.
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

// TestProofTrust covers trusted witness matching.
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

// TestProofTrustUnknown covers an unknown witness key.
func TestProofTrustUnknown(t *testing.T) {
	if err := makeProof(t, 2).Trust(nil); err == nil {
		t.Fatal("Trust(nil) accepted untrusted keys")
	}
}

// TestParseProofTooLarge covers the serialized size limit.
func TestParseProofTooLarge(t *testing.T) {
	huge := make([]byte, roughtime.MaxProofBytes+1)
	if _, err := roughtime.ParseProof(huge); err == nil || !strings.Contains(err.Error(), "max") {
		t.Fatalf("ParseProof: %v; want max-bytes error", err)
	}
}

// TestParseProofGzipBomb covers the decompressed size limit.
func TestParseProofGzipBomb(t *testing.T) {
	bomb := bytes.Repeat([]byte("A"), roughtime.MaxProofBytes+1)
	if _, err := roughtime.ParseProof(gzipReport(t, bomb)); err == nil ||
		!strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("ParseProof: %v; want exceeds-size error", err)
	}
}

// TestParseProofBadJSON covers malformed proof JSON.
func TestParseProofBadJSON(t *testing.T) {
	if _, err := roughtime.ParseProof([]byte("not a malfeasance report")); err == nil {
		t.Fatal("ParseProof accepted non-JSON input")
	}
}

// TestParseProofRawJSON covers uncompressed proof JSON.
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

// FuzzParseProof exercises compressed and raw proof parsing.
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
