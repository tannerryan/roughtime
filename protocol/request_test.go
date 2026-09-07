// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"strings"
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

// TestParseRequestVersionListCompatibility covers the draft-12/13 shared-ID
// policy: untyped historical lists are tolerated, while TYPE makes the modern
// 32-entry limit enforceable.
func TestParseRequestVersionListCompatibility(t *testing.T) {
	for _, tc := range []struct {
		name       string
		version    Version
		count      int
		withType   bool
		wantReject bool
	}{
		{"draft 01 untyped 33", VersionDraft01, 33, false, false},
		{"draft 10 untyped 33", VersionDraft10, 33, false, false},
		{"draft 12 untyped 32", VersionDraft12, 32, false, false},
		{"draft 12 untyped 33", VersionDraft12, 33, false, false},
		{"draft 12 typed 32", VersionDraft12, 32, true, false},
		{"draft 12 typed 33", VersionDraft12, 33, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nonce := randBytes(t, nonceSize(wireGroupOf(tc.version, false)))
			raw := buildIETFRequest(nonce, longVersionList(tc.version, tc.count), tc.withType)
			parsed, err := ParseRequest(raw)
			if tc.wantReject {
				if err == nil || !strings.Contains(err.Error(), "max 32") {
					t.Fatalf("ParseRequest error = %v, want 32-entry limit", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseRequest: %v", err)
			}
			if len(parsed.Versions) != tc.count {
				t.Fatalf("parsed %d versions, want %d", len(parsed.Versions), tc.count)
			}
		})
	}
}

// TestParseRequestPaddingStrictness covers version-specific padding tags.
func TestParseRequestPaddingStrictness(t *testing.T) {
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
	for _, ver := range []Version{
		VersionGoogle,
		VersionDraft01,
		VersionDraft02,
		VersionDraft03,
		VersionDraft05,
		VersionDraft07,
		VersionDraft08,
		VersionDraft10,
		VersionDraft12,
		VersionMLDSA44,
	} {
		_, req, err := CreateRequest([]Version{ver}, rand.Reader, nil)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(req)
	}
	_, untyped, err := CreateRequestWithOptions(
		[]Version{VersionDraft12}, rand.Reader, nil, RequestOptions{OmitTYPE: true})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(untyped)

	f.Add([]byte{})
	f.Add([]byte{0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		parsed, err := ParseRequest(data)
		if err != nil {
			return
		}
		off, err := NonceOffsetInRequest(data)
		if err != nil {
			t.Fatalf("valid request has no nonce offset: %v", err)
		}
		if end := off + len(parsed.Nonce); off < 0 || end > len(data) || !bytes.Equal(data[off:end], parsed.Nonce) {
			t.Fatal("NonceOffsetInRequest does not locate parsed NONC")
		}
	})
}
