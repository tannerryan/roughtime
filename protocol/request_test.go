// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"testing"
)

// TestParseRequestGoogle covers the Google request layout.
func TestParseRequestGoogle(t *testing.T) {
	nonce := randBytes(t, 64)
	raw := buildGoogleRequest(nonce)
	req, err := ParseRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(req.Nonce, nonce) || len(req.Versions) != 0 || req.HasType || !bytes.Equal(req.RawPacket, raw) {
		t.Fatal("Google request parse mismatch")
	}
}

// TestParseRequestIETF covers framed IETF requests.
func TestParseRequestIETF(t *testing.T) {
	nonce := randBytes(t, 32)
	req, err := ParseRequest(buildIETFRequest(nonce, []Version{VersionDraft10, VersionDraft12}, false))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(req.Nonce, nonce) || len(req.Versions) != 2 || req.HasType {
		t.Fatal("IETF request parse mismatch")
	}
}

// TestParseRequestWithTYPE covers typed requests.
func TestParseRequestWithTYPE(t *testing.T) {
	nonce := randBytes(t, 32)
	req, err := ParseRequest(buildIETFRequest(nonce, []Version{VersionDraft12}, true))
	if err != nil || !req.HasType {
		t.Fatal("TYPE=0 should set HasType")
	}
}

// TestParseRequestSRV covers server binding extraction.
func TestParseRequestSRV(t *testing.T) {
	srv := randBytes(t, 32)
	nonce := randBytes(t, 32)
	msg, _ := encode(map[uint32][]byte{
		TagNONC: nonce, TagVER: {0x0c, 0x00, 0x00, 0x80},
		TagSRV: srv, TagZZZZ: make([]byte, 900),
	})
	req, err := ParseRequest(wrapPacket(msg))
	if err != nil || !bytes.Equal(req.SRV, srv) {
		t.Fatal("SRV mismatch")
	}
}

// TestCreateRequestGoogle covers Google request construction.
func TestCreateRequestGoogle(t *testing.T) {
	nonce, req, err := CreateRequest([]Version{VersionGoogle}, rand.Reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(nonce) != 64 || len(req) != 1024 {
		t.Fatalf("nonce=%d req=%d, want 64/1024", len(nonce), len(req))
	}
	parsed, err := ParseRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsed.Nonce, nonce) || len(parsed.Versions) != 0 {
		t.Fatal("Google request mismatch")
	}
}

// TestCreateRequestDraft01 covers draft-01 request construction.
func TestCreateRequestDraft01(t *testing.T) {
	nonce, req, err := CreateRequest([]Version{VersionDraft01}, rand.Reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(nonce) != 64 || len(req) != 1036 {
		t.Fatalf("nonce=%d req=%d, want 64/1036", len(nonce), len(req))
	}
	parsed, err := ParseRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsed.Nonce, nonce) {
		t.Fatal("nonce mismatch")
	}
}

// TestCreateRequestDraft12 covers shared-version request construction.
func TestCreateRequestDraft12(t *testing.T) {
	nonce, req, err := CreateRequest([]Version{VersionDraft12}, rand.Reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(nonce) != 32 || len(req) != 1036 {
		t.Fatalf("nonce=%d req=%d, want 32/1036", len(nonce), len(req))
	}
	parsed, err := ParseRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.HasType {
		t.Fatal("draft 12 request should have TYPE")
	}
}

// TestParseRequestVERVersionRules covers offer ordering and uniqueness.
func TestParseRequestVERVersionRules(t *testing.T) {
	nonce := randBytes(t, 32)
	raw := buildIETFRequest(nonce, []Version{VersionDraft10, VersionDraft05}, false)
	if _, err := ParseRequest(raw); err != nil {
		t.Fatalf("drafts 10-11 unsorted VER list should be accepted: %v", err)
	}
	raw = buildIETFRequest(nonce, []Version{VersionDraft10, VersionDraft10}, false)
	if _, err := ParseRequest(raw); err == nil {
		t.Fatal("drafts 10-11 duplicate VER list should be rejected")
	}
}

// TestParseRequestPaddingStrictness covers version-specific padding tags.
func TestParseRequestPaddingStrictness(t *testing.T) {
	// Cases cover padding rules across protocol generations.
	cases := []struct {
		name       string
		padTag     uint32
		version    Version
		wantReject bool
	}{
		{"ZZZZ draft08 accepts", TagZZZZ, VersionDraft08, false},
		{"ZZZZ draft11 rejects", TagZZZZ, VersionDraft11, true},
		{"ZZZZ draft12 rejects", TagZZZZ, VersionDraft12, true},
		{"PAD google accepts", TagPAD, VersionGoogle, false},
		{"PADIETF draft01 accepts", tagPADIETF, VersionDraft01, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nonce := randBytes(t, nonceSize(wireGroupOf(tc.version, false)))
			tags := map[uint32][]byte{TagNONC: nonce}
			if tc.version != VersionGoogle {
				vb := make([]byte, 4)
				binary.LittleEndian.PutUint32(vb, uint32(tc.version))
				tags[TagVER] = vb
			}
			pad := make([]byte, 64)
			pad[7] = 0x01
			tags[tc.padTag] = pad
			msg, err := encode(tags)
			if err != nil {
				t.Fatal(err)
			}
			pkt := msg
			if tc.version != VersionGoogle {
				pkt = wrapPacket(msg)
			}
			_, err = ParseRequest(pkt)
			if tc.wantReject && err == nil {
				t.Fatal("expected error for non-zero padding byte")
			}
			if !tc.wantReject && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestCreateRequestWithNonceWithSRV covers caller nonces and server binding.
func TestCreateRequestWithNonceWithSRV(t *testing.T) {
	pk := make(ed25519.PublicKey, ed25519.PublicKeySize)
	srv := ComputeSRV(pk)
	nonce := randBytes(t, 32)

	req, err := CreateRequestWithNonce([]Version{VersionDraft12}, nonce, srv)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := unwrapPacket(req)
	if err != nil {
		t.Fatal(err)
	}
	tags, err := Decode(msg)
	if err != nil {
		t.Fatal(err)
	}
	srvVal, ok := tags[TagSRV]
	if !ok {
		t.Fatal("SRV tag should be present")
	}
	if !bytes.Equal(srvVal, srv) {
		t.Fatal("SRV value mismatch")
	}
}

// TestPQComputeSRV covers ML-DSA-44 server binding.
func TestPQComputeSRV(t *testing.T) {
	_, rootPK := testPQCert(t)
	got := ComputeSRV(rootPK)
	if len(got) != 32 {
		t.Fatalf("ComputeSRV length = %d, want 32", len(got))
	}
	if bytes.Equal(got, make([]byte, 32)) {
		t.Fatal("ComputeSRV returned zero bytes")
	}
}

// TestCreateRequestMLDSA44PadsToAmplificationBudget covers PQ request sizing.
func TestCreateRequestMLDSA44PadsToAmplificationBudget(t *testing.T) {
	nonce, req, err := CreateRequest([]Version{VersionMLDSA44}, rand.Reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(nonce) != 32 || len(req) != 8204 {
		t.Fatalf("nonce=%d req=%d, want 32/8204", len(nonce), len(req))
	}
	parsed, err := ParseRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Nonce) != 32 {
		t.Fatalf("parsed nonce length = %d, want 32", len(parsed.Nonce))
	}
}

// FuzzParseRequest exercises arbitrary request packets.
func FuzzParseRequest(f *testing.F) {
	_, googleReq, _ := CreateRequest([]Version{VersionGoogle}, rand.Reader, nil)
	f.Add(googleReq)

	_, ietfReq, _ := CreateRequest([]Version{VersionDraft12}, rand.Reader, nil)
	f.Add(ietfReq)

	_, d01Req, _ := CreateRequest([]Version{VersionDraft01}, rand.Reader, nil)
	f.Add(d01Req)

	f.Add([]byte{})
	f.Add([]byte{0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		ParseRequest(data) //nolint:errcheck // fuzz target tests for panics
	})
}
