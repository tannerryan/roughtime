// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"
	"time"
)

// failReader is an io.Reader that always errors.
type failReader struct{}

// Read always returns "read failed".
func (failReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

// TestParseRequestGoogle verifies ParseRequest decodes a Google-Roughtime
// request.
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

// TestParseRequestIETF verifies ParseRequest decodes a multi-version IETF
// request.
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

// TestParseRequestWithTYPE verifies ParseRequest sets HasType when TYPE=0 is
// present.
func TestParseRequestWithTYPE(t *testing.T) {
	nonce := randBytes(t, 32)
	req, err := ParseRequest(buildIETFRequest(nonce, []Version{VersionDraft12}, true))
	if err != nil || !req.HasType {
		t.Fatal("TYPE=0 should set HasType")
	}
}

// TestParseRequestRejectsTYPENonZero verifies ParseRequest rejects TYPE != 0 in
// a request.
func TestParseRequestRejectsTYPENonZero(t *testing.T) {
	nonce := randBytes(t, 32)
	typeBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(typeBuf, 1)
	msg, _ := encode(map[uint32][]byte{
		TagNONC: nonce, TagVER: {0x0c, 0x00, 0x00, 0x80},
		TagTYPE: typeBuf, TagZZZZ: make([]byte, 900),
	})
	if _, err := ParseRequest(wrapPacket(msg)); err == nil {
		t.Fatal("expected ParseRequest to reject TYPE=1 in a request")
	}
}

// TestParseRequestSRV verifies ParseRequest extracts a 32-byte SRV.
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

// TestParseRequestRejectsSRVWrongLengthD12 verifies drafts 10+ reject SRV != 32
// bytes.
func TestParseRequestRejectsSRVWrongLengthD12(t *testing.T) {
	nonce := randBytes(t, 32)
	msg, _ := encode(map[uint32][]byte{
		TagNONC: nonce,
		TagVER:  {0x0c, 0x00, 0x00, 0x80},
		TagSRV:  make([]byte, 16),
		TagZZZZ: make([]byte, 900),
	})
	if _, err := ParseRequest(wrapPacket(msg)); err == nil {
		t.Fatal("expected SRV length rejection for draft-12")
	}
}

// TestParseRequestAcceptsShortSRVPreD10 verifies pre-draft-10 versions accept
// short SRV.
func TestParseRequestAcceptsShortSRVPreD10(t *testing.T) {
	nonce := randBytes(t, 32)
	msg, _ := encode(map[uint32][]byte{
		TagNONC: nonce,
		TagVER:  {0x08, 0x00, 0x00, 0x80},
		TagSRV:  make([]byte, 16),
		TagZZZZ: make([]byte, 900),
	})
	if _, err := ParseRequest(wrapPacket(msg)); err != nil {
		t.Fatalf("expected draft-08 short SRV to be accepted: %v", err)
	}
}

// TestParseRequestRejectsNonceVersionMismatch verifies ParseRequest rejects
// nonce length not matching the offered version.
func TestParseRequestRejectsNonceVersionMismatch(t *testing.T) {
	msg, _ := encode(map[uint32][]byte{
		TagNONC: make([]byte, 64),
		TagVER:  {0x0c, 0x00, 0x00, 0x80},
		TagZZZZ: make([]byte, 900),
	})
	if _, err := ParseRequest(wrapPacket(msg)); err == nil {
		t.Fatal("expected nonce/version mismatch rejection")
	}
}

// TestParseRequestRejectsFramedMissingVER verifies ParseRequest rejects framed
// requests lacking VER.
func TestParseRequestRejectsFramedMissingVER(t *testing.T) {
	nonce := randBytes(t, 32)
	msg, _ := encode(map[uint32][]byte{
		TagNONC: nonce,
		TagZZZZ: make([]byte, 900),
	})
	if _, err := ParseRequest(wrapPacket(msg)); err == nil {
		t.Fatal("expected framed-request-missing-VER rejection")
	}
}

// TestParseRequestRejectsUnframedWithVER verifies ParseRequest rejects unframed
// requests carrying VER.
func TestParseRequestRejectsUnframedWithVER(t *testing.T) {
	nonce := randBytes(t, 32)
	msg, _ := encode(map[uint32][]byte{
		TagNONC: nonce,
		TagVER:  {0x0c, 0x00, 0x00, 0x80},
		TagZZZZ: make([]byte, 900),
	})
	if _, err := ParseRequest(msg); err == nil {
		t.Fatal("expected unframed-request-with-VER rejection")
	}
}

// TestParseRequestRejectsVersionGoogleInVER verifies ParseRequest rejects
// VersionGoogle inside the VER list.
func TestParseRequestRejectsVersionGoogleInVER(t *testing.T) {
	nonce := randBytes(t, 32)
	ver := []byte{0x0c, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00}
	msg, _ := encode(map[uint32][]byte{
		TagNONC: nonce, TagVER: ver, TagZZZZ: make([]byte, 900),
	})
	if _, err := ParseRequest(wrapPacket(msg)); err == nil {
		t.Fatal("expected VersionGoogle-in-VER rejection")
	}
}

// TestParseRequestNoVER verifies ParseRequest accepts an unframed
// Google-Roughtime request without VER.
func TestParseRequestNoVER(t *testing.T) {
	nonce := randBytes(t, 64)
	msg, _ := encode(map[uint32][]byte{TagNONC: nonce})
	req, err := ParseRequest(msg)
	if err != nil || len(req.Versions) != 0 {
		t.Fatal("expected empty Versions")
	}
}

// TestParseRequestRejectsMissingNONC verifies ParseRequest rejects requests
// lacking NONC.
func TestParseRequestRejectsMissingNONC(t *testing.T) {
	msg, _ := encode(map[uint32][]byte{TagVER: make([]byte, 4)})
	if _, err := ParseRequest(wrapPacket(msg)); err == nil {
		t.Fatal("expected error")
	}
}

// TestParseRequestRejectsBadNonceLength verifies ParseRequest rejects nonces
// that are not 32 or 64 bytes.
func TestParseRequestRejectsBadNonceLength(t *testing.T) {
	msg, _ := encode(map[uint32][]byte{TagNONC: make([]byte, 16)})
	if _, err := ParseRequest(wrapPacket(msg)); err == nil {
		t.Fatal("expected error")
	}
}

// TestParseRequestRejectsCorruptIETF verifies ParseRequest rejects an
// unparseable IETF body.
func TestParseRequestRejectsCorruptIETF(t *testing.T) {
	pkt := wrapPacket([]byte{0xff, 0xff, 0xff, 0xff})
	if _, err := ParseRequest(pkt); err == nil {
		t.Fatal("expected error for corrupt IETF request body")
	}
}

// TestParseRequestRejectsTruncatedIETF verifies ParseRequest rejects an IETF
// packet shorter than the declared body.
func TestParseRequestRejectsTruncatedIETF(t *testing.T) {
	pkt := make([]byte, 16)
	copy(pkt[:8], packetMagic[:])
	binary.LittleEndian.PutUint32(pkt[8:12], 1000)
	if _, err := ParseRequest(pkt); err == nil {
		t.Fatal("expected error for truncated IETF request")
	}
}

// TestCreateRequestGoogle verifies CreateRequest emits a 1024-byte
// Google-Roughtime request.
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

// TestCreateRequestDraft01 verifies CreateRequest emits a 1024-byte draft-01
// request.
func TestCreateRequestDraft01(t *testing.T) {
	nonce, req, err := CreateRequest([]Version{VersionDraft01}, rand.Reader, nil)
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
	if !bytes.Equal(parsed.Nonce, nonce) {
		t.Fatal("nonce mismatch")
	}
}

// TestCreateRequestIETF verifies CreateRequest emits a multi-version IETF
// request.
func TestCreateRequestIETF(t *testing.T) {
	versions := []Version{VersionDraft08, VersionDraft10}
	nonce, req, err := CreateRequest(versions, rand.Reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(nonce) != 32 || len(req) != 1024 {
		t.Fatalf("nonce=%d req=%d, want 32/1024", len(nonce), len(req))
	}
	parsed, err := ParseRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsed.Nonce, nonce) || len(parsed.Versions) != 2 {
		t.Fatal("IETF request mismatch")
	}
}

// TestCreateRequestDraft12 verifies draft-12 requests include TYPE=0.
func TestCreateRequestDraft12(t *testing.T) {
	nonce, req, err := CreateRequest([]Version{VersionDraft12}, rand.Reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(nonce) != 32 || len(req) != 1024 {
		t.Fatalf("nonce=%d req=%d, want 32/1024", len(nonce), len(req))
	}
	parsed, err := ParseRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.HasType {
		t.Fatal("draft 12 request should have TYPE")
	}
}

// TestCreateRequestRejectsEmpty verifies CreateRequest rejects an empty
// versions list.
func TestCreateRequestRejectsEmpty(t *testing.T) {
	if _, _, err := CreateRequest(nil, rand.Reader, nil); err == nil {
		t.Fatal("expected error")
	}
}

// TestCreateRequestRejectsReadError verifies CreateRequest surfaces entropy
// read failures.
func TestCreateRequestRejectsReadError(t *testing.T) {
	if _, _, err := CreateRequest([]Version{VersionDraft08}, &failReader{}, nil); err == nil {
		t.Fatal("expected error for entropy read failure")
	}
}

// TestCreateRequestEarlyDraftHeader verifies drafts 01-04 client requests carry
// the ROUGHTIM header.
func TestCreateRequestEarlyDraftHeader(t *testing.T) {
	for _, v := range []Version{VersionDraft01, VersionDraft02, VersionDraft03, VersionDraft04} {
		_, req, err := CreateRequest([]Version{v}, rand.Reader, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(req) != 1024 {
			t.Fatalf("%s request length = %d, want 1024", v, len(req))
		}
		if !bytes.Equal(req[:8], packetMagic[:]) {
			t.Fatalf("%s request must carry the ROUGHTIM header", v)
		}
	}
}

// TestParseRequestRejectsUnsortedVER verifies drafts 12+ require strictly
// ascending VER lists.
func TestParseRequestRejectsUnsortedVER(t *testing.T) {
	nonce := randBytes(t, 32)
	raw := buildIETFRequest(nonce, []Version{VersionDraft12, VersionDraft10}, false)
	if _, err := ParseRequest(raw); err == nil {
		t.Fatal("expected error for unsorted VER list containing drafts 12+")
	}
	raw = buildIETFRequest(nonce, []Version{VersionDraft12, VersionDraft12}, false)
	if _, err := ParseRequest(raw); err == nil {
		t.Fatal("expected error for repeating VER list containing drafts 12+")
	}
}

// TestParseRequestVERVersionRules verifies drafts 10-11 forbid duplicates while
// drafts 12+ also require ascending order.
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

// TestCreateRequestPaddingTag verifies the padding tag selection across wire
// groups.
func TestCreateRequestPaddingTag(t *testing.T) {
	tests := []struct {
		name    string
		ver     []Version
		wantTag uint32
	}{
		{"Google", []Version{VersionGoogle}, TagPAD},
		{"draft-01", []Version{VersionDraft01}, tagPADIETF},
		{"draft-05", []Version{VersionDraft05}, tagPADIETF},
		{"draft-07", []Version{VersionDraft07}, tagPADIETF},
		{"draft-08", []Version{VersionDraft08}, TagZZZZ},
		{"draft-10", []Version{VersionDraft10}, TagZZZZ},
		{"draft-12", []Version{VersionDraft12}, TagZZZZ},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, req, err := CreateRequest(tt.ver, rand.Reader, nil)
			if err != nil {
				t.Fatal(err)
			}
			msg := req
			if tt.ver[0] != VersionGoogle {
				msg, err = unwrapPacket(req)
				if err != nil {
					t.Fatal(err)
				}
			}
			decoded, err := Decode(msg)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := decoded[tt.wantTag]; !ok {
				t.Fatalf("expected padding tag %#08x in request", tt.wantTag)
			}
		})
	}
}

// TestComputeSRV verifies ComputeSRV equals the first 32 bytes of SHA-512(0xff
// || rootPK).
func TestComputeSRV(t *testing.T) {
	_, rootSK, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootPK := rootSK.Public().(ed25519.PublicKey)

	h := sha512.New()
	h.Write([]byte{0xff})
	h.Write(rootPK)
	want := h.Sum(nil)[:32]

	got := ComputeSRV(rootPK)
	if !bytes.Equal(got, want) {
		t.Fatal("ComputeSRV mismatch")
	}
}

// TestComputeSRVBadKeyLength verifies ComputeSRV returns nil for keys of
// unexpected length.
func TestComputeSRVBadKeyLength(t *testing.T) {
	if got := ComputeSRV(make([]byte, 16)); got != nil {
		t.Fatal("expected nil for short key")
	}
	if got := ComputeSRV(nil); got != nil {
		t.Fatal("expected nil for nil key")
	}
}

// TestParseRequestRejectsOversizedVER verifies ParseRequest rejects VER lists
// with more than 32 entries.
func TestParseRequestRejectsOversizedVER(t *testing.T) {
	nonce := randBytes(t, 32)
	vers := make([]byte, 4*33)
	for i := range 33 {
		binary.LittleEndian.PutUint32(vers[4*i:], uint32(i+1))
	}
	tags := map[uint32][]byte{
		TagNONC: nonce,
		TagVER:  vers,
	}
	msg, err := encode(tags)
	if err != nil {
		t.Fatal(err)
	}
	pkt := wrapPacket(msg)
	if _, err := ParseRequest(pkt); err == nil {
		t.Fatal("expected error for >32 VER entries")
	}
}

// TestParseRequestRejectsTYPEWrongLength verifies ParseRequest rejects TYPE
// values that are not 4 bytes.
func TestParseRequestRejectsTYPEWrongLength(t *testing.T) {
	nonce := randBytes(t, 32)
	for _, typeLen := range []int{0, 1, 2, 3, 5, 8} {
		t.Run(fmt.Sprintf("len=%d", typeLen), func(t *testing.T) {
			msg, _ := encode(map[uint32][]byte{
				TagNONC: nonce,
				TagVER:  {0x0c, 0x00, 0x00, 0x80},
				TagTYPE: make([]byte, typeLen),
				TagZZZZ: make([]byte, 900),
			})
			if _, err := ParseRequest(wrapPacket(msg)); err == nil {
				t.Fatalf("expected error for TYPE length %d", typeLen)
			}
		})
	}
}

// TestParseRequestAcceptsVER32 verifies exactly 32 VER entries are accepted.
func TestParseRequestAcceptsVER32(t *testing.T) {
	nonce := randBytes(t, 32)
	vers := make([]byte, 4*32)
	for i := range 32 {
		binary.LittleEndian.PutUint32(vers[4*i:], uint32(0x80000001+i))
	}
	tags := map[uint32][]byte{
		TagNONC: nonce,
		TagVER:  vers,
		TagZZZZ: make([]byte, 800),
	}
	msg, err := encode(tags)
	if err != nil {
		t.Fatal(err)
	}
	pkt := wrapPacket(msg)
	req, err := ParseRequest(pkt)
	if err != nil {
		t.Fatalf("VER with exactly 32 entries should be accepted: %v", err)
	}
	if len(req.Versions) != 32 {
		t.Fatalf("expected 32 versions, got %d", len(req.Versions))
	}
}

// TestCreateRequestSRVOmittedForOldDrafts verifies CreateRequest omits SRV for
// pre-draft-10 versions.
func TestCreateRequestSRVOmittedForOldDrafts(t *testing.T) {
	pk := make(ed25519.PublicKey, ed25519.PublicKeySize)
	srv := ComputeSRV(pk)
	for _, ver := range []Version{VersionGoogle, VersionDraft01, VersionDraft05, VersionDraft08} {
		t.Run(ver.ShortString(), func(t *testing.T) {
			_, req, err := CreateRequest([]Version{ver}, rand.Reader, srv)
			if err != nil {
				t.Fatal(err)
			}
			var msg []byte
			if ver == VersionGoogle {
				msg = req
			} else {
				msg, err = unwrapPacket(req)
				if err != nil {
					t.Fatal(err)
				}
			}
			tags, err := Decode(msg)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := tags[TagSRV]; ok {
				t.Fatalf("SRV tag should be absent for %s", ver)
			}
		})
	}
}

// TestCreateRequestSRVIncludedForDraft10Plus verifies CreateRequest includes
// SRV for drafts 10+.
func TestCreateRequestSRVIncludedForDraft10Plus(t *testing.T) {
	pk := make(ed25519.PublicKey, ed25519.PublicKeySize)
	srv := ComputeSRV(pk)
	for _, ver := range []Version{VersionDraft10, VersionDraft11, VersionDraft12} {
		t.Run(ver.ShortString(), func(t *testing.T) {
			_, req, err := CreateRequest([]Version{ver}, rand.Reader, srv)
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
				t.Fatalf("SRV tag should be present for %s", ver)
			}
			if !bytes.Equal(srvVal, srv) {
				t.Fatal("SRV value mismatch")
			}
		})
	}
}

// TestCreateRequestZZZZAllZero verifies CreateRequest emits all-zero ZZZZ
// padding for drafts 08+.
func TestCreateRequestZZZZAllZero(t *testing.T) {
	for _, ver := range []Version{VersionDraft08, VersionDraft10, VersionDraft12} {
		t.Run(ver.ShortString(), func(t *testing.T) {
			_, req, err := CreateRequest([]Version{ver}, rand.Reader, nil)
			if err != nil {
				t.Fatal(err)
			}
			msg, err := unwrapPacket(req)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := Decode(msg)
			if err != nil {
				t.Fatal(err)
			}
			pad, ok := decoded[TagZZZZ]
			if !ok {
				t.Fatal("expected ZZZZ tag")
			}
			for i, b := range pad {
				if b != 0 {
					t.Fatalf("ZZZZ byte %d = %#x, want 0", i, b)
				}
			}
		})
	}
}

// TestParseRequestRejectsEmptyVER verifies ParseRequest rejects an empty VER
// tag.
func TestParseRequestRejectsEmptyVER(t *testing.T) {
	nonce := randBytes(t, 32)
	tags := map[uint32][]byte{
		TagNONC: nonce,
		TagVER:  {},
	}
	msg, _ := encode(tags)
	pkt := wrapPacket(msg)
	if _, err := ParseRequest(pkt); err == nil {
		t.Fatal("expected error for empty VER tag")
	}
}

// TestParseRequestRejectsNonMultiple4VER verifies ParseRequest rejects VER
// lengths that are not multiples of 4.
func TestParseRequestRejectsNonMultiple4VER(t *testing.T) {
	nonce := randBytes(t, 32)
	tags := map[uint32][]byte{
		TagNONC: nonce,
		TagVER:  {0x01, 0x02, 0x03},
	}
	msg, _ := encode(tags)
	pkt := wrapPacket(msg)
	if _, err := ParseRequest(pkt); err == nil {
		t.Fatal("expected error for VER tag with non-multiple-of-4 length")
	}
}

// TestParseRequestRejectsDuplicateVERDraft11 verifies draft-11 rejects a
// duplicate VER list.
func TestParseRequestRejectsDuplicateVERDraft11(t *testing.T) {
	nonce := randBytes(t, 32)
	raw := buildIETFRequest(nonce, []Version{VersionDraft11, VersionDraft11}, false)
	if _, err := ParseRequest(raw); err == nil {
		t.Fatal("draft-11 duplicate VER list should be rejected")
	}
}

// TestParseRequestPaddingStrictness verifies drafts 12+ reject non-zero ZZZZ
// while older versions accept it.
func TestParseRequestPaddingStrictness(t *testing.T) {
	cases := []struct {
		name       string
		padTag     uint32
		version    Version
		wantReject bool
	}{
		{"ZZZZ draft08 accepts", TagZZZZ, VersionDraft08, false},
		{"ZZZZ draft11 accepts", TagZZZZ, VersionDraft11, false},
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

// TestParseRequestAcceptsZeroPadding verifies ParseRequest accepts all-zero
// ZZZZ padding for draft-12.
func TestParseRequestAcceptsZeroPadding(t *testing.T) {
	nonce := randBytes(t, 32)
	vb := make([]byte, 4)
	binary.LittleEndian.PutUint32(vb, uint32(VersionDraft12))
	tags := map[uint32][]byte{
		TagNONC: nonce,
		TagVER:  vb,
		TagZZZZ: make([]byte, 64),
	}
	msg, err := encode(tags)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRequest(wrapPacket(msg)); err != nil {
		t.Fatalf("unexpected parse error on zero padding: %v", err)
	}
}

// TestCreateRequestWithNonceAllVersions verifies CreateRequestWithNonce
// produces verifiable requests across versions.
func TestCreateRequestWithNonceAllVersions(t *testing.T) {
	for _, v := range append([]Version{VersionGoogle}, supportedVersionsEd25519...) {
		t.Run(v.ShortString(), func(t *testing.T) {
			versions := []Version{v}
			rootSK, onlineSK := testKeys(t)
			rootPK := rootSK.Public().(ed25519.PublicKey)

			nonce := randBytes(t, nonceSize(wireGroupOf(v, true)))
			req, err := CreateRequestWithNonce(versions, nonce, nil)
			if err != nil {
				t.Fatal(err)
			}

			parsed, err := ParseRequest(req)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(parsed.Nonce, nonce) {
				t.Fatal("nonce mismatch after ParseRequest")
			}

			// drafts 08+ use Unix-second resolution
			now := time.Now().UTC().Truncate(time.Second)
			cert, err := NewCertificate(now.Add(-time.Hour), now.Add(time.Hour), onlineSK, rootSK)
			if err != nil {
				t.Fatal(err)
			}
			replies, err := CreateReplies(v, []Request{*parsed}, now, time.Second, cert)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := VerifyReply(versions, replies[0], rootPK, nonce, req); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestCreateRequestWithNonceWithSRV verifies CreateRequestWithNonce embeds SRV
// in the request.
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

// TestCreateRequestWithNonceRejectsWrongSize verifies CreateRequestWithNonce
// rejects nonces of wrong size.
func TestCreateRequestWithNonceRejectsWrongSize(t *testing.T) {
	nonce := randBytes(t, 31)
	if _, err := CreateRequestWithNonce([]Version{VersionDraft12}, nonce, nil); err == nil {
		t.Fatal("expected error for wrong nonce size")
	}
	nonce = randBytes(t, 33)
	if _, err := CreateRequestWithNonce([]Version{VersionDraft12}, nonce, nil); err == nil {
		t.Fatal("expected error for wrong nonce size")
	}
}

// TestCreateRequestWithNonceRejectsEmptyVersions verifies
// CreateRequestWithNonce rejects an empty versions list.
func TestCreateRequestWithNonceRejectsEmptyVersions(t *testing.T) {
	if _, err := CreateRequestWithNonce(nil, make([]byte, 32), nil); err == nil {
		t.Fatal("expected error")
	}
}

// TestCreateRequestWithNonce64ByteNonce verifies CreateRequestWithNonce handles
// 64-byte nonces for Google and draft-01.
func TestCreateRequestWithNonce64ByteNonce(t *testing.T) {
	for _, v := range []Version{VersionGoogle, VersionDraft01} {
		t.Run(v.ShortString(), func(t *testing.T) {
			nonce := randBytes(t, 64)
			req, err := CreateRequestWithNonce([]Version{v}, nonce, nil)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := ParseRequest(req)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(parsed.Nonce, nonce) {
				t.Fatal("nonce mismatch")
			}
		})
	}
}

// FuzzCreateRequestWithNonce fuzzes CreateRequestWithNonce for parseable
// requests with embedded nonces.
func FuzzCreateRequestWithNonce(f *testing.F) {
	f.Add(make([]byte, 32))
	f.Add(bytes.Repeat([]byte{0xff}, 32))
	f.Add(make([]byte, 64))
	f.Add(bytes.Repeat([]byte{0xff}, 64))
	f.Fuzz(func(t *testing.T, nonce []byte) {
		var version Version
		switch len(nonce) {
		case 32:
			version = VersionDraft12
		case 64:
			version = VersionGoogle
		default:
			t.Skip()
		}
		req, err := CreateRequestWithNonce([]Version{version}, nonce, nil)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseRequest(req)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(parsed.Nonce, nonce) {
			t.Fatal("nonce mismatch")
		}
	})
}

// TestPQComputeSRV verifies ComputeSRV returns 32 non-zero bytes for an
// ML-DSA-44 public key.
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

// FuzzParseRequest fuzzes ParseRequest for panic-safety on arbitrary bytes.
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
