// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"math"
	"testing"
	"time"
)

// testKeys generates a fresh root and online Ed25519 key pair.
func testKeys(t *testing.T) (ed25519.PrivateKey, ed25519.PrivateKey) {
	t.Helper()
	_, rootSK, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, onlineSK, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return rootSK, onlineSK
}

// randBytes returns n random bytes, failing the test on error.
func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// buildGoogleRequest constructs a padded Google-Roughtime request.
func buildGoogleRequest(nonce []byte) []byte {
	pad := make([]byte, 1024-len(nonce)-12)
	msg, _ := Encode(map[uint32][]byte{
		tagNONC:    nonce,
		0x00444150: pad,
	})
	return msg
}

// buildIETFRequest constructs a padded IETF request with ROUGHTIM header.
func buildIETFRequest(nonce []byte, versions []Version, withType bool) []byte {
	tags := map[uint32][]byte{tagNONC: nonce}
	if len(versions) > 0 {
		vb := make([]byte, 4*len(versions))
		for i, v := range versions {
			binary.LittleEndian.PutUint32(vb[4*i:], uint32(v))
		}
		tags[tagVER] = vb
	}
	if withType {
		tags[tagTYPE] = make([]byte, 4)
	}
	msg, _ := Encode(tags)
	if len(msg) < 1012 {
		padded := make(map[uint32][]byte)
		for k, v := range tags {
			padded[k] = v
		}
		padded[tagZZZZ] = make([]byte, 1012-len(msg))
		msg, _ = Encode(padded)
	}
	return WrapPacket(msg)
}

// testCert creates a certificate valid for ±1 hour around now.
func testCert(t *testing.T) (*Certificate, ed25519.PrivateKey) {
	t.Helper()
	rootSK, onlineSK := testKeys(t)
	now := time.Now()
	cert, err := NewCertificate(now.Add(-time.Hour), now.Add(time.Hour), onlineSK, rootSK)
	if err != nil {
		t.Fatal(err)
	}
	return cert, rootSK
}

// verifyResponse decodes a response, checks required tags, verifies both
// signatures, and validates the Merkle proof for a single-request batch.
func verifyResponse(t *testing.T, reply []byte, g wireGroup, nonce []byte, hasType bool, rootSK ed25519.PrivateKey) {
	t.Helper()
	var err error
	respBytes := reply
	if usesRoughtimHeader(g) {
		respBytes, err = UnwrapPacket(respBytes)
		if err != nil {
			t.Fatal(err)
		}
	} else if len(reply) >= 8 && bytes.Equal(reply[:8], packetMagic[:]) {
		t.Fatal("Google response should not have ROUGHTIM header")
	}

	resp, err := Decode(respBytes)
	if err != nil {
		t.Fatal(err)
	}
	for _, tag := range []uint32{tagSIG, tagSREP, tagCERT, tagPATH, tagINDX} {
		if _, ok := resp[tag]; !ok {
			t.Fatalf("missing tag %#x", tag)
		}
	}

	verifyResponseVER(t, resp, g)
	verifyResponseNONC(t, resp, g, nonce)
	verifyResponseTYPE(t, resp, hasType)
	verifySREP(t, resp[tagSREP], g)
	verifyCERT(t, resp, g, rootSK)
	verifyMerkleProof(t, resp)
}

// verifyResponseVER checks VER tag presence matches the wire group.
func verifyResponseVER(t *testing.T, resp map[uint32][]byte, g wireGroup) {
	t.Helper()
	_, ok := resp[tagVER]
	if hasResponseVER(g) && !ok {
		t.Fatal("missing VER")
	}
	if !hasResponseVER(g) && ok {
		t.Fatal("should not have VER")
	}
}

// verifyResponseNONC checks NONC tag presence and value match the wire group.
func verifyResponseNONC(t *testing.T, resp map[uint32][]byte, g wireGroup, nonce []byte) {
	t.Helper()
	nonc, ok := resp[tagNONC]
	if hasResponseNONC(g) {
		if !ok || !bytes.Equal(nonc, nonce) {
			t.Fatal("NONC missing or mismatch")
		}
	} else if ok {
		t.Fatal("should not have top-level NONC")
	}
}

// verifyResponseTYPE checks that TYPE=1 is present when expected.
func verifyResponseTYPE(t *testing.T, resp map[uint32][]byte, hasType bool) {
	t.Helper()
	if !hasType {
		return
	}
	tb, ok := resp[tagTYPE]
	if !ok || binary.LittleEndian.Uint32(tb) != 1 {
		t.Fatal("TYPE should be 1 in response")
	}
}

// verifySREP checks that SREP contains ROOT, MIDP, RADI, and version tags.
func verifySREP(t *testing.T, srepBytes []byte, g wireGroup) {
	t.Helper()
	srep, err := Decode(srepBytes)
	if err != nil {
		t.Fatal(err)
	}
	for _, tag := range []uint32{tagROOT, tagMIDP, tagRADI} {
		if _, ok := srep[tag]; !ok {
			t.Fatalf("missing %#x in SREP", tag)
		}
	}
	if hasSREPVERS(g) {
		if _, ok := srep[tagVER]; !ok {
			t.Fatal("missing VER in SREP")
		}
		if _, ok := srep[tagVERS]; !ok {
			t.Fatal("missing VERS in SREP")
		}
	}
}

// verifyCERT checks CERT structure and verifies both Ed25519 signatures.
func verifyCERT(t *testing.T, resp map[uint32][]byte, g wireGroup, rootSK ed25519.PrivateKey) {
	t.Helper()
	certMsg, err := Decode(resp[tagCERT])
	if err != nil {
		t.Fatal(err)
	}
	dele, err := Decode(certMsg[tagDELE])
	if err != nil {
		t.Fatal(err)
	}
	for _, tag := range []uint32{tagPUBK, tagMINT, tagMAXT} {
		if _, ok := dele[tag]; !ok {
			t.Fatalf("missing %#x in DELE", tag)
		}
	}

	toVerify := append([]byte(nil), responseCtx...)
	toVerify = append(toVerify, resp[tagSREP]...)
	if !ed25519.Verify(dele[tagPUBK], toVerify, resp[tagSIG]) {
		t.Fatal("SREP signature verification failed")
	}

	rootPK := rootSK.Public().(ed25519.PublicKey)
	deleToVerify := append([]byte(nil), delegationContext(g)...)
	deleToVerify = append(deleToVerify, certMsg[tagDELE]...)
	if !ed25519.Verify(rootPK, deleToVerify, certMsg[tagSIG]) {
		t.Fatal("DELE signature verification failed")
	}
}

// verifyMerkleProof checks that PATH is empty and INDX is 0 for a single
// request.
func verifyMerkleProof(t *testing.T, resp map[uint32][]byte) {
	t.Helper()
	if len(resp[tagPATH]) != 0 {
		t.Fatal("PATH should be empty for single request")
	}
	if binary.LittleEndian.Uint32(resp[tagINDX]) != 0 {
		t.Fatal("INDX should be 0")
	}
}

// TestEncodeDecodeRoundTrip verifies that a multi-tag message with mixed value
// sizes survives encoding then decoding.
func TestEncodeDecodeRoundTrip(t *testing.T) {
	msg := map[uint32][]byte{
		0x0001: {0x10, 0x20, 0x30, 0x40},
		0x0002: {0x50, 0x60, 0x70, 0x80, 0xa0, 0xb0, 0xc0, 0xd0},
		0x0003: {},
	}
	encoded, err := Encode(msg)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	for tag, val := range msg {
		got, ok := decoded[tag]
		if !ok {
			t.Fatalf("missing tag %#x", tag)
		}
		if !bytes.Equal(got, val) {
			t.Fatalf("tag %#x: got %x, want %x", tag, got, val)
		}
	}
}

// TestEncodeSingleTag verifies encoding a message with exactly one tag.
func TestEncodeSingleTag(t *testing.T) {
	encoded, err := Encode(map[uint32][]byte{tagNONC: make([]byte, 32)})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 1 {
		t.Fatalf("expected 1 tag, got %d", len(decoded))
	}
}

// TestEncodeTagOrder verifies tags are emitted in ascending numeric order.
func TestEncodeTagOrder(t *testing.T) {
	encoded, err := Encode(map[uint32][]byte{
		0x0003: make([]byte, 4),
		0x0001: make([]byte, 4),
		0x0002: make([]byte, 4),
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		tag := binary.LittleEndian.Uint32(encoded[12+4*i : 12+4*i+4])
		if tag != uint32(i+1) {
			t.Fatalf("tag %d: got %#x, want %#x", i, tag, i+1)
		}
	}
}

// TestEncodeRejectsEmpty verifies that an empty map is rejected.
func TestEncodeRejectsEmpty(t *testing.T) {
	if _, err := Encode(map[uint32][]byte{}); err == nil {
		t.Fatal("expected error")
	}
}

// TestEncodeRejectsNonAlignedValue verifies that values not a multiple of 4
// bytes are rejected.
func TestEncodeRejectsNonAlignedValue(t *testing.T) {
	if _, err := Encode(map[uint32][]byte{0x0001: {1, 2, 3}}); err == nil {
		t.Fatal("expected error")
	}
}

// TestDecodeRejectsTooShort verifies that inputs under 4 bytes are rejected.
func TestDecodeRejectsTooShort(t *testing.T) {
	if _, err := Decode([]byte{1, 2}); err == nil {
		t.Fatal("expected error")
	}
}

// TestDecodeRejectsZeroTags verifies that a zero tag count is rejected.
func TestDecodeRejectsZeroTags(t *testing.T) {
	if _, err := Decode([]byte{0, 0, 0, 0}); err == nil {
		t.Fatal("expected error")
	}
}

// TestDecodeRejectsExcessiveTags verifies that tag counts above maxDecodeTags
// are rejected.
func TestDecodeRejectsExcessiveTags(t *testing.T) {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, maxDecodeTags+1)
	if _, err := Decode(buf); err == nil {
		t.Fatal("expected error")
	}
}

// TestDecodeRejectsTruncatedHeader verifies that data shorter than the header
// requires is rejected.
func TestDecodeRejectsTruncatedHeader(t *testing.T) {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, 5)
	if _, err := Decode(buf); err == nil {
		t.Fatal("expected error")
	}
}

// TestDecodeRejectsNonAscendingTags verifies that non-ascending tag order is
// rejected.
func TestDecodeRejectsNonAscendingTags(t *testing.T) {
	encoded, _ := Encode(map[uint32][]byte{
		0x0001: make([]byte, 4),
		0x0002: make([]byte, 4),
	})
	for i := range 4 {
		encoded[8+i], encoded[12+i] = encoded[12+i], encoded[8+i]
	}
	if _, err := Decode(encoded); err == nil {
		t.Fatal("expected error")
	}
}

// TestDecodeRejectsBadOffset verifies that non-aligned offsets are rejected.
func TestDecodeRejectsBadOffset(t *testing.T) {
	encoded, _ := Encode(map[uint32][]byte{
		0x0001: make([]byte, 4),
		0x0002: make([]byte, 4),
	})
	binary.LittleEndian.PutUint32(encoded[4:8], 3)
	if _, err := Decode(encoded); err == nil {
		t.Fatal("expected error")
	}
}

// TestDecodeRejectsOutOfBoundsOffset verifies that offsets beyond message data
// are rejected.
func TestDecodeRejectsOutOfBoundsOffset(t *testing.T) {
	encoded, _ := Encode(map[uint32][]byte{
		0x0001: make([]byte, 4),
		0x0002: make([]byte, 4),
	})
	binary.LittleEndian.PutUint32(encoded[4:8], 9999)
	if _, err := Decode(encoded); err == nil {
		t.Fatal("expected error")
	}
}

// TestWrapUnwrapRoundTrip verifies that wrapping then unwrapping preserves the
// message bytes.
func TestWrapUnwrapRoundTrip(t *testing.T) {
	msg := []byte("hello world!")
	got, err := UnwrapPacket(WrapPacket(msg))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatal("round-trip mismatch")
	}
}

// TestWrapPacketHeader verifies the ROUGHTIM magic and length field.
func TestWrapPacketHeader(t *testing.T) {
	pkt := WrapPacket(make([]byte, 20))
	if !bytes.Equal(pkt[:8], packetMagic[:]) {
		t.Fatal("bad magic")
	}
	if binary.LittleEndian.Uint32(pkt[8:12]) != 20 {
		t.Fatal("bad message length")
	}
}

// TestUnwrapRejectsTooShort verifies that packets under 12 bytes are rejected.
func TestUnwrapRejectsTooShort(t *testing.T) {
	if _, err := UnwrapPacket([]byte{1, 2}); err == nil {
		t.Fatal("expected error")
	}
}

// TestUnwrapRejectsBadMagic verifies that incorrect magic bytes are rejected.
func TestUnwrapRejectsBadMagic(t *testing.T) {
	pkt := make([]byte, 16)
	copy(pkt[:8], []byte("BADMAGIC"))
	if _, err := UnwrapPacket(pkt); err == nil {
		t.Fatal("expected error")
	}
}

// TestUnwrapRejectsTruncatedMessage verifies that a declared length exceeding
// available data is rejected.
func TestUnwrapRejectsTruncatedMessage(t *testing.T) {
	if _, err := UnwrapPacket(WrapPacket(make([]byte, 20))[:16]); err == nil {
		t.Fatal("expected error")
	}
}

// TestWireGroupOf verifies every version constant maps to the correct wire
// group.
func TestWireGroupOf(t *testing.T) {
	tests := []struct {
		ver     Version
		hasType bool
		want    wireGroup
	}{
		{VersionGoogle, false, groupGoogle},
		{VersionDraft01, false, groupD01},
		{VersionDraft02, false, groupD01},
		{VersionDraft03, false, groupD01},
		{VersionDraft04, false, groupD01},
		{VersionDraft05, false, groupD06},
		{VersionDraft06, false, groupD06},
		{VersionDraft07, false, groupD06},
		{VersionDraft08, false, groupD08},
		{VersionDraft09, false, groupD08},
		{VersionDraft10, false, groupD10},
		{VersionDraft11, false, groupD10},
		{VersionDraft12, false, groupD12},
		{VersionDraft12, true, groupD14},
	}
	for _, tt := range tests {
		if got := wireGroupOf(tt.ver, tt.hasType); got != tt.want {
			t.Errorf("wireGroupOf(%#x, %v) = %d, want %d", tt.ver, tt.hasType, got, tt.want)
		}
	}
}

// TestHashSize verifies 64 bytes for Google and 32 for all IETF drafts.
func TestHashSize(t *testing.T) {
	if hashSize(groupGoogle) != 64 {
		t.Fatal("Google hash size should be 64")
	}
	for _, g := range []wireGroup{groupD01, groupD06, groupD08, groupD10, groupD12, groupD14} {
		if hashSize(g) != 32 {
			t.Fatalf("IETF hash size for group %d should be 32", g)
		}
	}
}

// TestUsesRoughtimHeader verifies the header predicate across groups.
func TestUsesRoughtimHeader(t *testing.T) {
	if usesRoughtimHeader(groupGoogle) {
		t.Fatal("Google should not use ROUGHTIM header")
	}
	for _, g := range []wireGroup{groupD01, groupD06, groupD08, groupD10, groupD12, groupD14} {
		if !usesRoughtimHeader(g) {
			t.Fatalf("group %d should use ROUGHTIM header", g)
		}
	}
}

// TestUsesMJDMicroseconds verifies MJD timestamp predicate across groups.
func TestUsesMJDMicroseconds(t *testing.T) {
	for _, g := range []wireGroup{groupD01, groupD06} {
		if !usesMJDMicroseconds(g) {
			t.Fatalf("group %d should use MJD", g)
		}
	}
	for _, g := range []wireGroup{groupGoogle, groupD08, groupD10, groupD12, groupD14} {
		if usesMJDMicroseconds(g) {
			t.Fatalf("group %d should not use MJD", g)
		}
	}
}

// TestUsesFullPacketLeaf verifies the Merkle leaf predicate across groups.
func TestUsesFullPacketLeaf(t *testing.T) {
	for _, g := range []wireGroup{groupGoogle, groupD01, groupD06, groupD08, groupD10} {
		if usesFullPacketLeaf(g) {
			t.Fatalf("group %d should not use full-packet leaf", g)
		}
	}
	for _, g := range []wireGroup{groupD12, groupD14} {
		if !usesFullPacketLeaf(g) {
			t.Fatalf("group %d should use full-packet leaf", g)
		}
	}
}

// TestNoncInSREP verifies that only groupD01 places NONC inside SREP.
func TestNoncInSREP(t *testing.T) {
	if !noncInSREP(groupD01) {
		t.Fatal("D01 should have NONC in SREP")
	}
	for _, g := range []wireGroup{groupGoogle, groupD06, groupD08, groupD10, groupD12, groupD14} {
		if noncInSREP(g) {
			t.Fatalf("group %d should not have NONC in SREP", g)
		}
	}
}

// TestHasResponseVER verifies that all IETF groups include a top-level VER.
func TestHasResponseVER(t *testing.T) {
	if hasResponseVER(groupGoogle) {
		t.Fatal("Google should not have VER")
	}
	for _, g := range []wireGroup{groupD01, groupD06, groupD08, groupD10, groupD12, groupD14} {
		if !hasResponseVER(g) {
			t.Fatalf("group %d should have VER", g)
		}
	}
}

// TestHasResponseNONC verifies that D06+ groups include a top-level NONC.
func TestHasResponseNONC(t *testing.T) {
	for _, g := range []wireGroup{groupGoogle, groupD01} {
		if hasResponseNONC(g) {
			t.Fatalf("group %d should not have top-level NONC", g)
		}
	}
	for _, g := range []wireGroup{groupD06, groupD08, groupD10, groupD12, groupD14} {
		if !hasResponseNONC(g) {
			t.Fatalf("group %d should have top-level NONC", g)
		}
	}
}

// TestHasSREPVERS verifies that D12+ groups include VER and VERS in SREP.
func TestHasSREPVERS(t *testing.T) {
	for _, g := range []wireGroup{groupGoogle, groupD01, groupD06, groupD08, groupD10} {
		if hasSREPVERS(g) {
			t.Fatalf("group %d should not have SREP VERS", g)
		}
	}
	for _, g := range []wireGroup{groupD12, groupD14} {
		if !hasSREPVERS(g) {
			t.Fatalf("group %d should have SREP VERS", g)
		}
	}
}

// TestDelegationContext verifies old (with --) vs new context strings and null
// termination.
func TestDelegationContext(t *testing.T) {
	old := delegationContext(groupGoogle)
	if !bytes.Contains(old, []byte("--")) || old[len(old)-1] != 0 {
		t.Fatal("old context should contain -- and be null-terminated")
	}
	neu := delegationContext(groupD12)
	if bytes.Contains(neu, []byte("--")) || neu[len(neu)-1] != 0 {
		t.Fatal("new context should not contain -- and be null-terminated")
	}
	for _, g := range []wireGroup{groupGoogle, groupD01, groupD06, groupD08, groupD10} {
		if !bytes.Equal(delegationContext(g), old) {
			t.Fatalf("group %d should use old context", g)
		}
	}
	for _, g := range []wireGroup{groupD12, groupD14} {
		if !bytes.Equal(delegationContext(g), neu) {
			t.Fatalf("group %d should use new context", g)
		}
	}
}

// TestLeafHash verifies H(0x00 || data) for Google (64B) and IETF (32B).
func TestLeafHash(t *testing.T) {
	data := []byte("test input")
	want := sha512.Sum512(append([]byte{0x00}, data...))

	got := leafHash(groupGoogle, data)
	if !bytes.Equal(got, want[:]) {
		t.Fatal("Google leafHash mismatch")
	}
	got = leafHash(groupD12, data)
	if !bytes.Equal(got, want[:32]) {
		t.Fatal("IETF leafHash mismatch")
	}
}

// TestNodeHash verifies H(0x01 || left || right) against manual SHA-512.
func TestNodeHash(t *testing.T) {
	left := bytes.Repeat([]byte{0xaa}, 32)
	right := bytes.Repeat([]byte{0xbb}, 32)
	buf := append([]byte{0x01}, left...)
	buf = append(buf, right...)
	want := sha512.Sum512(buf)
	if !bytes.Equal(nodeHash(groupD08, left, right), want[:32]) {
		t.Fatal("nodeHash mismatch")
	}
}

// TestEncodeTimestampGoogle verifies Unix microsecond encoding.
func TestEncodeTimestampGoogle(t *testing.T) {
	ts := time.Unix(1700000000, 500000000)
	buf := encodeTimestamp(ts, groupGoogle)
	if binary.LittleEndian.Uint64(buf[:]) != uint64(ts.UnixMicro()) {
		t.Fatal("Google timestamp mismatch")
	}
}

// TestEncodeTimestampUnixSeconds verifies sub-second truncation for drafts 08+.
func TestEncodeTimestampUnixSeconds(t *testing.T) {
	buf := encodeTimestamp(time.Unix(1700000000, 999999999), groupD08)
	if binary.LittleEndian.Uint64(buf[:]) != 1700000000 {
		t.Fatal("Unix seconds mismatch")
	}
}

// TestEncodeTimestampMJDEpoch verifies that the Unix epoch encodes to MJD
// 40587, 0 microseconds.
func TestEncodeTimestampMJDEpoch(t *testing.T) {
	buf := encodeTimestamp(time.Unix(0, 0).UTC(), groupD01)
	got := binary.LittleEndian.Uint64(buf[:])
	if got>>40 != 40587 || got&0xFFFFFFFFFF != 0 {
		t.Fatal("MJD epoch mismatch")
	}
}

// TestEncodeTimestampMJDNoon verifies the microsecond-in-day field at noon.
func TestEncodeTimestampMJDNoon(t *testing.T) {
	buf := encodeTimestamp(time.Unix(43200, 0).UTC(), groupD06)
	got := binary.LittleEndian.Uint64(buf[:])
	if got>>40 != 40587 || got&0xFFFFFFFFFF != uint64(12*3600_000_000) {
		t.Fatal("MJD noon mismatch")
	}
}

// TestTimeToMJDMicroKnownDate verifies MJD encoding for a date far from the
// epoch (15 Nov 2024 10:30 UTC).
func TestTimeToMJDMicroKnownDate(t *testing.T) {
	ts := time.Date(2024, 11, 15, 10, 30, 0, 0, time.UTC)
	got := timeToMJDMicro(ts)
	wantMJD := uint64(40587 + ts.Unix()/86400)
	wantUs := uint64(10*3600_000_000 + 30*60_000_000)
	if got>>40 != wantMJD || got&0xFFFFFFFFFF != wantUs {
		t.Fatal("MJD known date mismatch")
	}
}

// TestRadiMicroseconds verifies microsecond RADI clamping behaviour.
func TestRadiMicroseconds(t *testing.T) {
	if radiMicroseconds(time.Second) != 1_000_000 {
		t.Fatal("1s should be 1000000 µs")
	}
	if radiMicroseconds(0) != 1 {
		t.Fatal("0 should clamp to 1")
	}
	if radiMicroseconds(-time.Second) != 1 {
		t.Fatal("negative should clamp to 1")
	}
	if radiMicroseconds(time.Duration(math.MaxInt64)) != math.MaxUint32 {
		t.Fatal("overflow should clamp to MaxUint32")
	}
}

// TestRadiSeconds verifies second RADI clamping: >= 1 for D08, >= 3 for D10+.
func TestRadiSeconds(t *testing.T) {
	if radiSeconds(500*time.Millisecond, groupD08) != 1 {
		t.Fatal("D08: sub-second should clamp to 1")
	}
	if radiSeconds(2*time.Second, groupD08) != 2 {
		t.Fatal("D08: 2s should be 2")
	}
	if radiSeconds(time.Second, groupD10) != 3 {
		t.Fatal("D10: 1s should clamp to 3")
	}
	if radiSeconds(5*time.Second, groupD10) != 5 {
		t.Fatal("D10: 5s should be 5")
	}
	if radiSeconds(time.Duration(math.MaxInt64), groupD08) != math.MaxUint32 {
		t.Fatal("overflow should clamp to MaxUint32")
	}
}

// TestSelectVersionGoogle verifies that no VER with 64-byte nonce selects
// Google-Roughtime.
func TestSelectVersionGoogle(t *testing.T) {
	ver, err := SelectVersion(nil, 64)
	if err != nil || ver != VersionGoogle {
		t.Fatal("expected VersionGoogle")
	}
}

// TestSelectVersionRejectsNoVERShortNonce verifies that no VER with a
// non-64-byte nonce is rejected.
func TestSelectVersionRejectsNoVERShortNonce(t *testing.T) {
	if _, err := SelectVersion(nil, 32); err == nil {
		t.Fatal("expected error")
	}
}

// TestSelectVersionPreference verifies the server picks the highest mutually
// supported version.
func TestSelectVersionPreference(t *testing.T) {
	ver, err := SelectVersion([]Version{VersionDraft01, VersionDraft12}, 32)
	if err != nil || ver != VersionDraft12 {
		t.Fatal("expected VersionDraft12")
	}
}

// TestSelectVersionRejectsNoMutual verifies that disjoint version lists are
// rejected.
func TestSelectVersionRejectsNoMutual(t *testing.T) {
	if _, err := SelectVersion([]Version{0x99999999}, 32); err == nil {
		t.Fatal("expected error")
	}
}

// TestSupportedVersionsAscending verifies VERS list ordering.
func TestSupportedVersionsAscending(t *testing.T) {
	vs := SupportedVersions()
	for i := 1; i < len(vs); i++ {
		if vs[i] <= vs[i-1] {
			t.Fatalf("not ascending at index %d", i)
		}
	}
}

// TestSupportedVersionsBytesLength verifies pre-encoded VERS byte length.
func TestSupportedVersionsBytesLength(t *testing.T) {
	if len(supportedVersionsBytes) != 4*len(supportedVersions) {
		t.Fatal("length mismatch")
	}
}

// TestParseRequestGoogle verifies parsing a Google-Roughtime request.
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

// TestParseRequestIETF verifies parsing an IETF request with VER.
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

// TestParseRequestWithTYPE verifies that TYPE=0 sets HasType.
func TestParseRequestWithTYPE(t *testing.T) {
	nonce := randBytes(t, 32)
	req, err := ParseRequest(buildIETFRequest(nonce, []Version{VersionDraft12}, true))
	if err != nil || !req.HasType {
		t.Fatal("TYPE=0 should set HasType")
	}
}

// TestParseRequestRejectsTYPENonZero verifies TYPE=1 does not set HasType.
func TestParseRequestRejectsTYPENonZero(t *testing.T) {
	nonce := randBytes(t, 32)
	typeBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(typeBuf, 1)
	msg, _ := Encode(map[uint32][]byte{
		tagNONC: nonce, tagVER: {0x0c, 0x00, 0x00, 0x80},
		tagTYPE: typeBuf, tagZZZZ: make([]byte, 900),
	})
	req, err := ParseRequest(WrapPacket(msg))
	if err != nil || req.HasType {
		t.Fatal("TYPE=1 should not set HasType")
	}
}

// TestParseRequestSRV verifies SRV tag extraction.
func TestParseRequestSRV(t *testing.T) {
	srv := randBytes(t, 32)
	nonce := randBytes(t, 32)
	msg, _ := Encode(map[uint32][]byte{
		tagNONC: nonce, tagVER: {0x0c, 0x00, 0x00, 0x80},
		tagSRV: srv, tagZZZZ: make([]byte, 900),
	})
	req, err := ParseRequest(WrapPacket(msg))
	if err != nil || !bytes.Equal(req.SRV, srv) {
		t.Fatal("SRV mismatch")
	}
}

// TestParseRequestNoVER verifies that missing VER yields empty Versions.
func TestParseRequestNoVER(t *testing.T) {
	nonce := randBytes(t, 64)
	msg, _ := Encode(map[uint32][]byte{tagNONC: nonce})
	req, err := ParseRequest(msg)
	if err != nil || len(req.Versions) != 0 {
		t.Fatal("expected empty Versions")
	}
}

// TestParseRequestRejectsMissingNONC verifies missing NONC is rejected.
func TestParseRequestRejectsMissingNONC(t *testing.T) {
	msg, _ := Encode(map[uint32][]byte{tagVER: make([]byte, 4)})
	if _, err := ParseRequest(WrapPacket(msg)); err == nil {
		t.Fatal("expected error")
	}
}

// TestParseRequestRejectsBadNonceLength verifies invalid nonce sizes (not 32 or
// 64) are rejected.
func TestParseRequestRejectsBadNonceLength(t *testing.T) {
	msg, _ := Encode(map[uint32][]byte{tagNONC: make([]byte, 16)})
	if _, err := ParseRequest(WrapPacket(msg)); err == nil {
		t.Fatal("expected error")
	}
}

// TestNewCertificate verifies construction and caching for all wire groups.
func TestNewCertificate(t *testing.T) {
	cert, _ := testCert(t)
	for _, g := range []wireGroup{groupGoogle, groupD01, groupD06, groupD08, groupD10, groupD12} {
		if len(cert.certBytes(g)) == 0 {
			t.Fatalf("empty CERT for group %d", g)
		}
	}
}

// TestNewCertificateRejectsInvalidKeySize verifies that wrong key sizes are
// rejected.
func TestNewCertificateRejectsInvalidKeySize(t *testing.T) {
	if _, err := NewCertificate(time.Now(), time.Now(), make([]byte, 10), make([]byte, 10)); err == nil {
		t.Fatal("expected error")
	}
}

// TestCacheKeyForDistinctGroups verifies that groups with different delegation
// contexts or timestamp encodings produce distinct cache keys.
func TestCacheKeyForDistinctGroups(t *testing.T) {
	cert, _ := testCert(t)
	keys := map[wireGroup]certCacheKey{
		groupGoogle: cert.cacheKeyFor(groupGoogle),
		groupD01:    cert.cacheKeyFor(groupD01),
		groupD08:    cert.cacheKeyFor(groupD08),
		groupD12:    cert.cacheKeyFor(groupD12),
	}
	if keys[groupGoogle] == keys[groupD01] || keys[groupD01] == keys[groupD08] || keys[groupD08] == keys[groupD12] {
		t.Fatal("cache keys should be distinct")
	}
}

// TestMerkleTreeEmpty verifies zero-filled root for an empty tree.
func TestMerkleTreeEmpty(t *testing.T) {
	tree := newMerkleTree(groupD12, nil)
	if len(tree.rootHash) != 32 {
		t.Fatal("wrong root length")
	}
}

// TestMerkleTreeSingleLeaf verifies root equals leaf hash with empty path.
func TestMerkleTreeSingleLeaf(t *testing.T) {
	data := [][]byte{bytes.Repeat([]byte{0xaa}, 32)}
	tree := newMerkleTree(groupD12, data)
	if len(tree.paths[0]) != 0 || !bytes.Equal(tree.rootHash, leafHash(groupD12, data[0])) {
		t.Fatal("single leaf mismatch")
	}
}

// TestMerkleTreeTwoLeaves verifies root and sibling paths for a balanced tree.
func TestMerkleTreeTwoLeaves(t *testing.T) {
	d0 := bytes.Repeat([]byte{0xaa}, 32)
	d1 := bytes.Repeat([]byte{0xbb}, 32)
	tree := newMerkleTree(groupD12, [][]byte{d0, d1})
	h0, h1 := leafHash(groupD12, d0), leafHash(groupD12, d1)
	if !bytes.Equal(tree.rootHash, nodeHash(groupD12, h0, h1)) {
		t.Fatal("root mismatch")
	}
	if !bytes.Equal(tree.paths[0][0], h1) || !bytes.Equal(tree.paths[1][0], h0) {
		t.Fatal("sibling path mismatch")
	}
}

// TestMerkleTreeThreeLeaves verifies the odd-leaf carry-forward case.
func TestMerkleTreeThreeLeaves(t *testing.T) {
	d := [][]byte{bytes.Repeat([]byte{0xaa}, 32), bytes.Repeat([]byte{0xbb}, 32), bytes.Repeat([]byte{0xcc}, 32)}
	tree := newMerkleTree(groupD12, d)
	h0, h1, h2 := leafHash(groupD12, d[0]), leafHash(groupD12, d[1]), leafHash(groupD12, d[2])
	n01 := nodeHash(groupD12, h0, h1)
	if !bytes.Equal(tree.rootHash, nodeHash(groupD12, n01, h2)) || !bytes.Equal(tree.paths[2][0], n01) {
		t.Fatal("three-leaf tree mismatch")
	}
}

// TestMerkleTreeFourLeaves verifies a full two-level tree with path depth.
func TestMerkleTreeFourLeaves(t *testing.T) {
	leaves := make([][]byte, 4)
	for i := range leaves {
		leaves[i] = bytes.Repeat([]byte{byte(i)}, 32)
	}
	tree := newMerkleTree(groupD12, leaves)
	h := make([][]byte, 4)
	for i := range h {
		h[i] = leafHash(groupD12, leaves[i])
	}
	n01, n23 := nodeHash(groupD12, h[0], h[1]), nodeHash(groupD12, h[2], h[3])
	if !bytes.Equal(tree.rootHash, nodeHash(groupD12, n01, n23)) {
		t.Fatal("root mismatch")
	}
	if len(tree.paths[0]) != 2 || !bytes.Equal(tree.paths[0][0], h[1]) || !bytes.Equal(tree.paths[0][1], n23) {
		t.Fatal("path mismatch")
	}
}

// TestCreateRepliesGoogle verifies a Google-Roughtime response end-to-end.
func TestCreateRepliesGoogle(t *testing.T) {
	cert, rootSK := testCert(t)
	nonce := randBytes(t, 64)
	raw := buildGoogleRequest(nonce)
	replies, err := CreateReplies(VersionGoogle, []Request{{Nonce: nonce, RawPacket: raw}}, time.Now(), time.Second, cert)
	if err != nil || len(replies) != 1 {
		t.Fatal("expected one reply")
	}
	verifyResponse(t, replies[0], groupGoogle, nonce, false, rootSK)
}

// TestCreateRepliesDraft01 verifies a draft 01 response end-to-end.
func TestCreateRepliesDraft01(t *testing.T) {
	cert, rootSK := testCert(t)
	nonce := randBytes(t, 64)
	raw := buildIETFRequest(nonce, []Version{VersionDraft01}, false)
	replies, err := CreateReplies(VersionDraft01, []Request{{Nonce: nonce, Versions: []Version{VersionDraft01}, RawPacket: raw}}, time.Now(), time.Second, cert)
	if err != nil || len(replies) != 1 {
		t.Fatal("expected one reply")
	}
	verifyResponse(t, replies[0], groupD01, nonce, false, rootSK)
}

// TestCreateRepliesDraft06 verifies a draft 06 response end-to-end.
func TestCreateRepliesDraft06(t *testing.T) {
	cert, rootSK := testCert(t)
	nonce := randBytes(t, 32)
	raw := buildIETFRequest(nonce, []Version{VersionDraft06}, false)
	replies, err := CreateReplies(VersionDraft06, []Request{{Nonce: nonce, Versions: []Version{VersionDraft06}, RawPacket: raw}}, time.Now(), time.Second, cert)
	if err != nil || len(replies) != 1 {
		t.Fatal("expected one reply")
	}
	verifyResponse(t, replies[0], groupD06, nonce, false, rootSK)
}

// TestCreateRepliesDraft05 verifies a draft 05 response end-to-end.
func TestCreateRepliesDraft05(t *testing.T) {
	cert, rootSK := testCert(t)
	nonce := randBytes(t, 32)
	raw := buildIETFRequest(nonce, []Version{VersionDraft05}, false)
	replies, err := CreateReplies(VersionDraft05, []Request{{Nonce: nonce, Versions: []Version{VersionDraft05}, RawPacket: raw}}, time.Now(), time.Second, cert)
	if err != nil || len(replies) != 1 {
		t.Fatal("expected one reply")
	}
	verifyResponse(t, replies[0], groupD06, nonce, false, rootSK)
}

// TestCreateRepliesDraft07 verifies a draft 07 response end-to-end.
func TestCreateRepliesDraft07(t *testing.T) {
	cert, rootSK := testCert(t)
	nonce := randBytes(t, 32)
	raw := buildIETFRequest(nonce, []Version{VersionDraft07}, false)
	replies, err := CreateReplies(VersionDraft07, []Request{{Nonce: nonce, Versions: []Version{VersionDraft07}, RawPacket: raw}}, time.Now(), time.Second, cert)
	if err != nil || len(replies) != 1 {
		t.Fatal("expected one reply")
	}
	verifyResponse(t, replies[0], groupD06, nonce, false, rootSK)
}

// TestCreateRepliesDraft08 verifies a draft 08 response end-to-end.
func TestCreateRepliesDraft08(t *testing.T) {
	cert, rootSK := testCert(t)
	nonce := randBytes(t, 32)
	raw := buildIETFRequest(nonce, []Version{VersionDraft08}, false)
	replies, err := CreateReplies(VersionDraft08, []Request{{Nonce: nonce, Versions: []Version{VersionDraft08}, RawPacket: raw}}, time.Now(), time.Second, cert)
	if err != nil || len(replies) != 1 {
		t.Fatal("expected one reply")
	}
	verifyResponse(t, replies[0], groupD08, nonce, false, rootSK)
}

// TestCreateRepliesDraft10 verifies a draft 10 response end-to-end.
func TestCreateRepliesDraft10(t *testing.T) {
	cert, rootSK := testCert(t)
	nonce := randBytes(t, 32)
	raw := buildIETFRequest(nonce, []Version{VersionDraft10}, false)
	replies, err := CreateReplies(VersionDraft10, []Request{{Nonce: nonce, Versions: []Version{VersionDraft10}, RawPacket: raw}}, time.Now(), time.Second, cert)
	if err != nil || len(replies) != 1 {
		t.Fatal("expected one reply")
	}
	verifyResponse(t, replies[0], groupD10, nonce, false, rootSK)
}

// TestCreateRepliesDraft12 verifies a draft 12 response end-to-end.
func TestCreateRepliesDraft12(t *testing.T) {
	cert, rootSK := testCert(t)
	nonce := randBytes(t, 32)
	raw := buildIETFRequest(nonce, []Version{VersionDraft12}, false)
	replies, err := CreateReplies(VersionDraft12, []Request{{Nonce: nonce, Versions: []Version{VersionDraft12}, RawPacket: raw}}, time.Now(), time.Second, cert)
	if err != nil || len(replies) != 1 {
		t.Fatal("expected one reply")
	}
	verifyResponse(t, replies[0], groupD12, nonce, false, rootSK)
}

// TestCreateRepliesDraft14 verifies a draft 14 response (with TYPE) end-to-end.
func TestCreateRepliesDraft14(t *testing.T) {
	cert, rootSK := testCert(t)
	nonce := randBytes(t, 32)
	raw := buildIETFRequest(nonce, []Version{VersionDraft12}, true)
	replies, err := CreateReplies(VersionDraft12, []Request{{Nonce: nonce, Versions: []Version{VersionDraft12}, HasType: true, RawPacket: raw}}, time.Now(), time.Second, cert)
	if err != nil || len(replies) != 1 {
		t.Fatal("expected one reply")
	}
	verifyResponse(t, replies[0], groupD14, nonce, true, rootSK)
}

// TestCreateRepliesRejectsEmpty verifies that an empty request slice is
// rejected.
func TestCreateRepliesRejectsEmpty(t *testing.T) {
	cert, _ := testCert(t)
	if _, err := CreateReplies(VersionDraft12, nil, time.Now(), time.Second, cert); err == nil {
		t.Fatal("expected error")
	}
}
