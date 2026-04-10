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
	"maps"
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
	msg, _ := encode(map[uint32][]byte{
		TagNONC: nonce,
		TagPAD:  pad,
	})
	return msg
}

// buildIETFRequest constructs a padded IETF request with ROUGHTIM header.
func buildIETFRequest(nonce []byte, versions []Version, withType bool) []byte {
	tags := map[uint32][]byte{TagNONC: nonce}
	if len(versions) > 0 {
		vb := make([]byte, 4*len(versions))
		for i, v := range versions {
			binary.LittleEndian.PutUint32(vb[4*i:], uint32(v))
		}
		tags[TagVER] = vb
	}
	if withType {
		tags[TagTYPE] = make([]byte, 4)
	}
	msg, _ := encode(tags)
	if len(msg) < 1012 {
		padded := make(map[uint32][]byte, len(tags)+1)
		maps.Copy(padded, tags)
		padded[TagZZZZ] = make([]byte, 1012-len(msg))
		msg, _ = encode(padded)
	}
	return wrapPacket(msg)
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
		respBytes, err = unwrapPacket(respBytes)
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
	for _, tag := range []uint32{TagSIG, TagSREP, TagCERT, TagPATH, TagINDX} {
		if _, ok := resp[tag]; !ok {
			t.Fatalf("missing tag %#x", tag)
		}
	}

	verifyResponseVER(t, resp, g)
	verifyResponseNONC(t, resp, g, nonce)
	verifyResponseTYPE(t, resp, hasType)
	verifySREPTags(t, resp[TagSREP], g)
	verifyCERTSigs(t, resp, g, rootSK)
	verifySingleLeafMerkle(t, resp)
}

// verifyResponseVER checks VER tag presence matches the wire group.
func verifyResponseVER(t *testing.T, resp map[uint32][]byte, g wireGroup) {
	t.Helper()
	_, ok := resp[TagVER]
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
	nonc, ok := resp[TagNONC]
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
	tb, ok := resp[TagTYPE]
	if !ok || binary.LittleEndian.Uint32(tb) != 1 {
		t.Fatal("TYPE should be 1 in response")
	}
}

// verifySREPTags checks that SREP contains ROOT, MIDP, RADI, and version tags.
func verifySREPTags(t *testing.T, srepBytes []byte, g wireGroup) {
	t.Helper()
	srep, err := Decode(srepBytes)
	if err != nil {
		t.Fatal(err)
	}
	for _, tag := range []uint32{TagROOT, TagMIDP, TagRADI} {
		if _, ok := srep[tag]; !ok {
			t.Fatalf("missing %#x in SREP", tag)
		}
	}
	if hasSREPVERS(g) {
		if _, ok := srep[TagVER]; !ok {
			t.Fatal("missing VER in SREP")
		}
		if _, ok := srep[TagVERS]; !ok {
			t.Fatal("missing VERS in SREP")
		}
	}
}

// verifyCERTSigs checks CERT structure and verifies both Ed25519 signatures.
func verifyCERTSigs(t *testing.T, resp map[uint32][]byte, g wireGroup, rootSK ed25519.PrivateKey) {
	t.Helper()
	certMsg, err := Decode(resp[TagCERT])
	if err != nil {
		t.Fatal(err)
	}
	dele, err := Decode(certMsg[TagDELE])
	if err != nil {
		t.Fatal(err)
	}
	for _, tag := range []uint32{TagPUBK, TagMINT, TagMAXT} {
		if _, ok := dele[tag]; !ok {
			t.Fatalf("missing %#x in DELE", tag)
		}
	}

	// Verify SREP signature with online key
	toVerify := append([]byte(nil), responseCtx...)
	toVerify = append(toVerify, resp[TagSREP]...)
	if !ed25519.Verify(dele[TagPUBK], toVerify, resp[TagSIG]) {
		t.Fatal("SREP signature verification failed")
	}

	// Verify DELE signature with root key
	rootPK := rootSK.Public().(ed25519.PublicKey)
	deleToVerify := append([]byte(nil), delegationContext(g)...)
	deleToVerify = append(deleToVerify, certMsg[TagDELE]...)
	if !ed25519.Verify(rootPK, deleToVerify, certMsg[TagSIG]) {
		t.Fatal("DELE signature verification failed")
	}
}

// verifySingleLeafMerkle checks that PATH is empty and INDX is 0 for a
// single-request batch.
func verifySingleLeafMerkle(t *testing.T, resp map[uint32][]byte) {
	t.Helper()
	if len(resp[TagPATH]) != 0 {
		t.Fatal("PATH should be empty for single request")
	}
	if binary.LittleEndian.Uint32(resp[TagINDX]) != 0 {
		t.Fatal("INDX should be 0")
	}
}

// verifyRoundTrip creates a request, generates a server reply via
// CreateReplies, and verifies it with VerifyReply.
func verifyRoundTrip(t *testing.T, versions []Version, ver Version) {
	t.Helper()
	cert, _ := testCert(t)
	rootPK := cert.rootPK

	nonce, req, err := CreateRequest(versions, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := ParseRequest(req)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	replies, err := CreateReplies(ver, []Request{*parsed}, now, time.Second, cert)
	if err != nil || len(replies) != 1 {
		t.Fatal("expected one reply")
	}

	midpoint, radius, err := VerifyReply(versions, replies[0], rootPK, nonce, req)
	if err != nil {
		t.Fatal(err)
	}

	if radius <= 0 {
		t.Fatal("expected positive radius")
	}
	drift := midpoint.Sub(now)
	if drift < -time.Minute || drift > time.Minute {
		t.Fatalf("excessive drift: %v", drift)
	}
}

// TestVersionString verifies the String method for all known versions and an
// unknown value.
func TestVersionString(t *testing.T) {
	tests := []struct {
		ver  Version
		want string
	}{
		{VersionGoogle, "Google-Roughtime"},
		{VersionDraft01, "draft-ietf-ntp-roughtime-01"},
		{VersionDraft02, "draft-ietf-ntp-roughtime-02"},
		{VersionDraft03, "draft-ietf-ntp-roughtime-03"},
		{VersionDraft04, "draft-ietf-ntp-roughtime-04"},
		{VersionDraft05, "draft-ietf-ntp-roughtime-05"},
		{VersionDraft06, "draft-ietf-ntp-roughtime-06"},
		{VersionDraft07, "draft-ietf-ntp-roughtime-07"},
		{VersionDraft08, "draft-ietf-ntp-roughtime-08"},
		{VersionDraft09, "draft-ietf-ntp-roughtime-09"},
		{VersionDraft10, "draft-ietf-ntp-roughtime-10"},
		{VersionDraft11, "draft-ietf-ntp-roughtime-11"},
		{VersionDraft12, "draft-ietf-ntp-roughtime-12"},
		{Version(0xdeadbeef), "Version(0xdeadbeef)"},
	}
	for _, tt := range tests {
		if got := tt.ver.String(); got != tt.want {
			t.Errorf("Version(%#x).String() = %q, want %q", uint32(tt.ver), got, tt.want)
		}
	}
}

// TestShortString verifies the ShortString method for all known versions and an
// unknown value.
func TestShortString(t *testing.T) {
	tests := []struct {
		ver  Version
		want string
	}{
		{VersionGoogle, "Google"},
		{VersionDraft08, "draft-08"},
		{VersionDraft12, "draft-12"},
		{Version(0xdeadbeef), "0xdeadbeef"},
	}
	for _, tt := range tests {
		if got := tt.ver.ShortString(); got != tt.want {
			t.Errorf("Version(%#x).ShortString() = %q, want %q", uint32(tt.ver), got, tt.want)
		}
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
		{VersionDraft02, false, groupD02},
		{VersionDraft03, false, groupD03},
		{VersionDraft04, false, groupD03},
		{VersionDraft05, false, groupD05},
		{VersionDraft06, false, groupD05},
		{VersionDraft07, false, groupD07},
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
	for _, g := range []wireGroup{groupD01, groupD02, groupD03, groupD05, groupD07, groupD08, groupD10, groupD12, groupD14} {
		if hashSize(g) != 32 {
			t.Fatalf("IETF hash size for group %d should be 32", g)
		}
	}
}

// TestUsesRoughtimHeader verifies the header predicate across groups. The
// 12-byte ROUGHTIM header is required by every IETF draft (01–19); only
// Google-Roughtime omits the envelope.
func TestUsesRoughtimHeader(t *testing.T) {
	if usesRoughtimHeader(groupGoogle) {
		t.Fatal("Google should not use ROUGHTIM header")
	}
	for _, g := range []wireGroup{groupD01, groupD02, groupD03, groupD05, groupD07, groupD08, groupD10, groupD12, groupD14} {
		if !usesRoughtimHeader(g) {
			t.Fatalf("group %d should use ROUGHTIM header", g)
		}
	}
}

// TestUsesMJDMicroseconds verifies MJD timestamp predicate across groups.
func TestUsesMJDMicroseconds(t *testing.T) {
	for _, g := range []wireGroup{groupD01, groupD02, groupD03, groupD05, groupD07} {
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
	for _, g := range []wireGroup{groupGoogle, groupD01, groupD02, groupD03, groupD05, groupD07, groupD08, groupD10} {
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

// TestNoncInSREP verifies that groupD01 and groupD02 place NONC inside SREP.
func TestNoncInSREP(t *testing.T) {
	for _, g := range []wireGroup{groupD01, groupD02} {
		if !noncInSREP(g) {
			t.Fatalf("group %d should have NONC in SREP", g)
		}
	}
	for _, g := range []wireGroup{groupGoogle, groupD03, groupD05, groupD07, groupD08, groupD10, groupD12, groupD14} {
		if noncInSREP(g) {
			t.Fatalf("group %d should not have NONC in SREP", g)
		}
	}
}

// TestHasResponseVER verifies that drafts 01–11 include a top-level VER and
// that Google and drafts 12+ do not (drafts 12+ moved VER inside SREP).
func TestHasResponseVER(t *testing.T) {
	for _, g := range []wireGroup{groupGoogle, groupD12, groupD14} {
		if hasResponseVER(g) {
			t.Fatalf("group %d should not have top-level VER", g)
		}
	}
	for _, g := range []wireGroup{groupD01, groupD02, groupD03, groupD05, groupD07, groupD08, groupD10} {
		if !hasResponseVER(g) {
			t.Fatalf("group %d should have top-level VER", g)
		}
	}
}

// TestHasResponseNONC verifies that D03+ groups include a top-level NONC.
func TestHasResponseNONC(t *testing.T) {
	for _, g := range []wireGroup{groupGoogle, groupD01, groupD02} {
		if hasResponseNONC(g) {
			t.Fatalf("group %d should not have top-level NONC", g)
		}
	}
	for _, g := range []wireGroup{groupD03, groupD05, groupD07, groupD08, groupD10, groupD12, groupD14} {
		if !hasResponseNONC(g) {
			t.Fatalf("group %d should have top-level NONC", g)
		}
	}
}

// TestHasSREPVERS verifies that D12+ groups include VER and VERS in SREP.
func TestHasSREPVERS(t *testing.T) {
	for _, g := range []wireGroup{groupGoogle, groupD01, groupD02, groupD03, groupD05, groupD07, groupD08, groupD10} {
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

// TestUsesSHA512_256 verifies that only groupD02 and groupD07 use SHA-512/256.
func TestUsesSHA512_256(t *testing.T) {
	for _, g := range []wireGroup{groupD02, groupD07} {
		if !usesSHA512_256(g) {
			t.Fatalf("group %d should use SHA-512/256", g)
		}
	}
	for _, g := range []wireGroup{groupGoogle, groupD01, groupD03, groupD05, groupD08, groupD10, groupD12, groupD14} {
		if usesSHA512_256(g) {
			t.Fatalf("group %d should not use SHA-512/256", g)
		}
	}
}

// TestNonceSize verifies nonce length for all version constants.
func TestNonceSize(t *testing.T) {
	tests := []struct {
		ver  Version
		want int
	}{
		{VersionGoogle, 64},
		{VersionDraft01, 64},
		{VersionDraft04, 64},
		{VersionDraft05, 32},
		{VersionDraft06, 32},
		{VersionDraft08, 32},
		{VersionDraft10, 32},
		{VersionDraft12, 32},
	}
	for _, tt := range tests {
		if got := nonceSize(wireGroupOf(tt.ver, false)); got != tt.want {
			t.Errorf("nonceSize(%#x) = %d, want %d", tt.ver, got, tt.want)
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
	for _, g := range []wireGroup{groupGoogle, groupD01, groupD02, groupD03, groupD05, groupD08, groupD10} {
		if !bytes.Equal(delegationContext(g), old) {
			t.Fatalf("group %d should use old context", g)
		}
	}
	for _, g := range []wireGroup{groupD07, groupD12, groupD14} {
		if !bytes.Equal(delegationContext(g), neu) {
			t.Fatalf("group %d should use new context", g)
		}
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
		t.Fatal("Unix seconds should truncate sub-second")
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
	buf := encodeTimestamp(time.Unix(43200, 0).UTC(), groupD05)
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

// TestDecodeTimestampGoogle verifies Unix microsecond round-trip.
func TestDecodeTimestampGoogle(t *testing.T) {
	ts := time.Unix(1700000000, 500000000).UTC()
	buf := encodeTimestamp(ts, groupGoogle)
	got, err := decodeTimestamp(buf[:], groupGoogle)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(ts) {
		t.Fatalf("got %v, want %v", got, ts)
	}
}

// TestDecodeTimestampMJD verifies MJD microsecond round-trip.
func TestDecodeTimestampMJD(t *testing.T) {
	ts := time.Date(2024, 11, 15, 10, 30, 0, 0, time.UTC)
	buf := encodeTimestamp(ts, groupD01)
	got, err := decodeTimestamp(buf[:], groupD01)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(ts) {
		t.Fatalf("got %v, want %v", got, ts)
	}
}

// TestDecodeTimestampUnixSeconds verifies Unix seconds round-trip.
func TestDecodeTimestampUnixSeconds(t *testing.T) {
	ts := time.Unix(1700000000, 0).UTC()
	buf := encodeTimestamp(ts, groupD08)
	got, err := decodeTimestamp(buf[:], groupD08)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(ts) {
		t.Fatalf("got %v, want %v", got, ts)
	}
}

// TestDecodeTimestampRejectsShort verifies that short timestamp buffers are
// rejected.
func TestDecodeTimestampRejectsShort(t *testing.T) {
	if _, err := decodeTimestamp([]byte{1, 2, 3}, groupGoogle); err == nil {
		t.Fatal("expected error")
	}
}

// TestDecodeTimestampPublic verifies the public DecodeTimestamp API for all
// three timestamp formats.
func TestDecodeTimestampPublic(t *testing.T) {
	tests := []struct {
		name string
		ver  Version
		g    wireGroup
		ts   time.Time
	}{
		{"Google", VersionGoogle, groupGoogle, time.Unix(1700000000, 500000000).UTC()},
		{"MJD", VersionDraft01, groupD01, time.Date(2024, 11, 15, 10, 30, 0, 0, time.UTC)},
		{"UnixSec", VersionDraft08, groupD08, time.Unix(1700000000, 0).UTC()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := encodeTimestamp(tt.ts, tt.g)
			got, err := DecodeTimestamp(tt.ver, buf[:])
			if err != nil {
				t.Fatal(err)
			}
			if !got.Equal(tt.ts) {
				t.Fatalf("got %v, want %v", got, tt.ts)
			}
		})
	}
}

// TestDecodeTimestampPublicRejectsShort verifies that short buffers are
// rejected by the public API.
func TestDecodeTimestampPublicRejectsShort(t *testing.T) {
	if _, err := DecodeTimestamp(VersionGoogle, []byte{1, 2, 3}); err == nil {
		t.Fatal("expected error")
	}
}

// TestMJDMicroToTimeEpoch verifies that MJD 40587, 0 microseconds is the Unix
// epoch.
func TestMJDMicroToTimeEpoch(t *testing.T) {
	got := mjdMicroToTime(uint64(40587) << 40)
	if !got.Equal(time.Unix(0, 0).UTC()) {
		t.Fatalf("got %v, want Unix epoch", got)
	}
}

// TestMJDMicroToTimeNoon verifies microsecond-in-day field at noon.
func TestMJDMicroToTimeNoon(t *testing.T) {
	v := (uint64(40587) << 40) | uint64(12*3600_000_000)
	got := mjdMicroToTime(v)
	want := time.Unix(43200, 0).UTC()
	if !got.Equal(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// TestMJDMicroRoundTrip verifies encode/decode round-trip for a known date.
func TestMJDMicroRoundTrip(t *testing.T) {
	ts := time.Date(2024, 11, 15, 10, 30, 0, 0, time.UTC)
	if decoded := mjdMicroToTime(timeToMJDMicro(ts)); !decoded.Equal(ts) {
		t.Fatalf("round-trip failed: got %v, want %v", decoded, ts)
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

// TestDecodeRadiusMicroseconds verifies microsecond RADI decoding.
func TestDecodeRadiusMicroseconds(t *testing.T) {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], 1_000_000)
	got, err := decodeRadius(buf[:], groupGoogle)
	if err != nil {
		t.Fatal(err)
	}
	if got != time.Second {
		t.Fatalf("got %v, want %v", got, time.Second)
	}
}

// TestDecodeRadiusSeconds verifies second RADI decoding.
func TestDecodeRadiusSeconds(t *testing.T) {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], 5)
	got, err := decodeRadius(buf[:], groupD10)
	if err != nil {
		t.Fatal(err)
	}
	if got != 5*time.Second {
		t.Fatalf("got %v, want %v", got, 5*time.Second)
	}
}

// TestDecodeRadiusRejectsShort verifies that short RADI buffers are rejected.
func TestDecodeRadiusRejectsShort(t *testing.T) {
	if _, err := decodeRadius([]byte{1, 2}, groupGoogle); err == nil {
		t.Fatal("expected error")
	}
}

// TestDecodeRadiusRejectsZero verifies that RADI=0 is rejected per §5.2.5.
func TestDecodeRadiusRejectsZero(t *testing.T) {
	for _, g := range []wireGroup{groupGoogle, groupD05, groupD10, groupD14} {
		if _, err := decodeRadius(make([]byte, 4), g); err == nil {
			t.Fatalf("expected error for RADI=0 with group %d", g)
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

// TestEncodeDecodeRoundTrip verifies that a multi-tag message with mixed value
// sizes survives encoding then decoding.
func TestEncodeDecodeRoundTrip(t *testing.T) {
	msg := map[uint32][]byte{
		0x0001: {0x10, 0x20, 0x30, 0x40},
		0x0002: {0x50, 0x60, 0x70, 0x80, 0xa0, 0xb0, 0xc0, 0xd0},
		0x0003: {},
	}
	encoded, err := encode(msg)
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
	encoded, err := encode(map[uint32][]byte{TagNONC: make([]byte, 32)})
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
	encoded, err := encode(map[uint32][]byte{
		0x0003: make([]byte, 4),
		0x0001: make([]byte, 4),
		0x0002: make([]byte, 4),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Tags start at offset 12 (4 count + 8 offsets)
	for i := range 3 {
		tag := binary.LittleEndian.Uint32(encoded[12+4*i : 12+4*i+4])
		if tag != uint32(i+1) {
			t.Fatalf("tag %d: got %#x, want %#x", i, tag, i+1)
		}
	}
}

// TestEncodeRejectsEmpty verifies that an empty map is rejected.
func TestEncodeRejectsEmpty(t *testing.T) {
	if _, err := encode(map[uint32][]byte{}); err == nil {
		t.Fatal("expected error")
	}
}

// TestEncodeRejectsNonAlignedValue verifies that values not a multiple of 4
// bytes are rejected.
func TestEncodeRejectsNonAlignedValue(t *testing.T) {
	if _, err := encode(map[uint32][]byte{0x0001: {1, 2, 3}}); err == nil {
		t.Fatal("expected error")
	}
}

// TestEncodeRejectsExcessiveTags verifies that tag counts above maxEncodeTags
// are rejected.
func TestEncodeRejectsExcessiveTags(t *testing.T) {
	msg := make(map[uint32][]byte, maxEncodeTags+1)
	for i := range maxEncodeTags + 1 {
		msg[uint32(i+1)] = make([]byte, 4)
	}
	if _, err := encode(msg); err == nil {
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
	encoded, _ := encode(map[uint32][]byte{
		0x0001: make([]byte, 4),
		0x0002: make([]byte, 4),
	})
	// Swap the two tags in the header
	for i := range 4 {
		encoded[8+i], encoded[12+i] = encoded[12+i], encoded[8+i]
	}
	if _, err := Decode(encoded); err == nil {
		t.Fatal("expected error")
	}
}

// TestDecodeRejectsBadOffset verifies that non-aligned offsets are rejected.
func TestDecodeRejectsBadOffset(t *testing.T) {
	encoded, _ := encode(map[uint32][]byte{
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
	encoded, _ := encode(map[uint32][]byte{
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
	got, err := unwrapPacket(wrapPacket(msg))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatal("round-trip mismatch")
	}
}

// TestWrapPacketHeader verifies the ROUGHTIM magic and length field.
func TestWrapPacketHeader(t *testing.T) {
	pkt := wrapPacket(make([]byte, 20))
	if !bytes.Equal(pkt[:8], packetMagic[:]) {
		t.Fatal("bad magic")
	}
	if binary.LittleEndian.Uint32(pkt[8:12]) != 20 {
		t.Fatal("bad message length")
	}
}

// TestUnwrapRejectsTooShort verifies that packets under 12 bytes are rejected.
func TestUnwrapRejectsTooShort(t *testing.T) {
	if _, err := unwrapPacket([]byte{1, 2}); err == nil {
		t.Fatal("expected error")
	}
}

// TestUnwrapRejectsBadMagic verifies that incorrect magic bytes are rejected.
func TestUnwrapRejectsBadMagic(t *testing.T) {
	pkt := make([]byte, 16)
	copy(pkt[:8], []byte("BADMAGIC"))
	if _, err := unwrapPacket(pkt); err == nil {
		t.Fatal("expected error")
	}
}

// TestUnwrapRejectsTruncatedMessage verifies that a declared length exceeding
// available data is rejected.
func TestUnwrapRejectsTruncatedMessage(t *testing.T) {
	if _, err := unwrapPacket(wrapPacket(make([]byte, 20))[:16]); err == nil {
		t.Fatal("expected error")
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

// TestParseRequestRejectsTYPENonZero verifies that a request with TYPE != 0 is
// rejected, per draft-ietf-ntp-roughtime-14 §5.1.3 and later: "Requests
// containing a TYPE tag with any other value MUST be ignored by servers."
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

// TestParseRequestSRV verifies SRV tag extraction.
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

// TestParseRequestNoVER verifies that missing VER yields empty Versions.
func TestParseRequestNoVER(t *testing.T) {
	nonce := randBytes(t, 64)
	msg, _ := encode(map[uint32][]byte{TagNONC: nonce})
	req, err := ParseRequest(msg)
	if err != nil || len(req.Versions) != 0 {
		t.Fatal("expected empty Versions")
	}
}

// TestParseRequestRejectsMissingNONC verifies missing NONC is rejected.
func TestParseRequestRejectsMissingNONC(t *testing.T) {
	msg, _ := encode(map[uint32][]byte{TagVER: make([]byte, 4)})
	if _, err := ParseRequest(wrapPacket(msg)); err == nil {
		t.Fatal("expected error")
	}
}

// TestParseRequestRejectsBadNonceLength verifies invalid nonce sizes (not 32 or
// 64) are rejected.
func TestParseRequestRejectsBadNonceLength(t *testing.T) {
	msg, _ := encode(map[uint32][]byte{TagNONC: make([]byte, 16)})
	if _, err := ParseRequest(wrapPacket(msg)); err == nil {
		t.Fatal("expected error")
	}
}

// TestNewCertificate verifies construction and caching for all wire groups.
func TestNewCertificate(t *testing.T) {
	cert, _ := testCert(t)
	for _, g := range []wireGroup{groupGoogle, groupD01, groupD02, groupD03, groupD05, groupD07, groupD08, groupD10, groupD12} {
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
	groups := []wireGroup{groupGoogle, groupD01, groupD02, groupD03, groupD05, groupD07, groupD08, groupD10, groupD12}
	seen := make(map[certCacheKey]wireGroup)
	for _, g := range groups {
		k := cert.cacheKeyFor(g)
		if prev, ok := seen[k]; ok {
			// Groups that share a cache key must have the same delegation
			// context and timestamp encoding. Verify this is expected.
			if !bytes.Equal(delegationContext(g), delegationContext(prev)) ||
				usesMJDMicroseconds(g) != usesMJDMicroseconds(prev) {
				t.Fatalf("groups %d and %d have same cache key but different behavior", prev, g)
			}
		}
		seen[k] = g
	}
	// At minimum, Google, MJD, Unix-seconds, and new-delegation-ctx must differ
	if cert.cacheKeyFor(groupGoogle) == cert.cacheKeyFor(groupD01) ||
		cert.cacheKeyFor(groupD01) == cert.cacheKeyFor(groupD08) ||
		cert.cacheKeyFor(groupD08) == cert.cacheKeyFor(groupD12) {
		t.Fatal("cache keys should be distinct across encoding/context changes")
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

// TestMerkleTreeThreeLeaves verifies the power-of-2 padding for an odd leaf
// count.
func TestMerkleTreeThreeLeaves(t *testing.T) {
	d := [][]byte{
		bytes.Repeat([]byte{0xaa}, 32),
		bytes.Repeat([]byte{0xbb}, 32),
		bytes.Repeat([]byte{0xcc}, 32),
	}
	tree := newMerkleTree(groupD12, d)
	h0 := leafHash(groupD12, d[0])
	h1 := leafHash(groupD12, d[1])
	h2 := leafHash(groupD12, d[2])

	// With power-of-2 padding, 3 leaves become [h0, h1, h2, h2]
	n01 := nodeHash(groupD12, h0, h1)
	n22 := nodeHash(groupD12, h2, h2)
	wantRoot := nodeHash(groupD12, n01, n22)
	if !bytes.Equal(tree.rootHash, wantRoot) {
		t.Fatal("three-leaf root mismatch")
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

// TestMerkleTreeNonPowerOfTwo verifies that non-power-of-2 batch sizes produce
// valid proofs that pass the verification algorithm for every leaf.
func TestMerkleTreeNonPowerOfTwo(t *testing.T) {
	for _, n := range []int{3, 5, 6, 7, 9, 15, 17} {
		t.Run("", func(t *testing.T) {
			leaves := make([][]byte, n)
			for i := range leaves {
				leaves[i] = randBytes(t, 32)
			}
			tree := newMerkleTree(groupD12, leaves)

			for i, d := range leaves {
				hash := leafHash(groupD12, d)
				index := uint32(i)
				for _, sib := range tree.paths[i] {
					if index&1 == 0 {
						hash = nodeHash(groupD12, hash, sib)
					} else {
						hash = nodeHash(groupD12, sib, hash)
					}
					index >>= 1
				}
				if index != 0 {
					t.Fatalf("leaf %d: trailing INDX bits non-zero", i)
				}
				if !bytes.Equal(hash, tree.rootHash) {
					t.Fatalf("leaf %d: root mismatch", i)
				}
			}
		})
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

// TestCreateRepliesAllDrafts exercises the server-side reply path for every
// supported version. Each row covers exactly one wire group and asserts the
// response is structurally well-formed and signature-valid for that draft.
func TestCreateRepliesAllDrafts(t *testing.T) {
	cases := []struct {
		ver     Version
		group   wireGroup
		nonce   int
		hasType bool
	}{
		{VersionDraft01, groupD01, 64, false},
		{VersionDraft02, groupD02, 64, false},
		{VersionDraft03, groupD03, 64, false},
		{VersionDraft04, groupD03, 64, false},
		{VersionDraft05, groupD05, 32, false},
		{VersionDraft06, groupD05, 32, false},
		{VersionDraft07, groupD07, 32, false},
		{VersionDraft08, groupD08, 32, false},
		{VersionDraft09, groupD08, 32, false},
		{VersionDraft10, groupD10, 32, false},
		{VersionDraft11, groupD10, 32, false},
		{VersionDraft12, groupD12, 32, false},
		{VersionDraft12, groupD14, 32, true}, // drafts 14–19 set TYPE
	}
	for _, tc := range cases {
		name := tc.ver.ShortString()
		if tc.hasType {
			name += "+TYPE"
		}
		t.Run(name, func(t *testing.T) {
			cert, rootSK := testCert(t)
			nonce := randBytes(t, tc.nonce)
			raw := buildIETFRequest(nonce, []Version{tc.ver}, tc.hasType)
			replies, err := CreateReplies(tc.ver, []Request{{
				Nonce: nonce, Versions: []Version{tc.ver}, HasType: tc.hasType, RawPacket: raw,
			}}, time.Now(), time.Second, cert)
			if err != nil || len(replies) != 1 {
				t.Fatalf("CreateReplies: %v (len=%d)", err, len(replies))
			}
			verifyResponse(t, replies[0], tc.group, nonce, tc.hasType, rootSK)
		})
	}
}

// TestCreateRepliesRejectsEmpty verifies that an empty request slice is
// rejected.
func TestCreateRepliesRejectsEmpty(t *testing.T) {
	cert, _ := testCert(t)
	if _, err := CreateReplies(VersionDraft12, nil, time.Now(), time.Second, cert); err == nil {
		t.Fatal("expected error")
	}
}

// TestClientVersionPreference verifies that the highest version is selected.
func TestClientVersionPreference(t *testing.T) {
	ver, g, err := clientVersionPreference([]Version{VersionDraft08, VersionDraft12})
	if err != nil || ver != VersionDraft12 || g != groupD14 {
		t.Fatal("expected Draft12/groupD14")
	}
}

// TestClientVersionPreferenceRejectsEmpty verifies that an empty version list
// is rejected.
func TestClientVersionPreferenceRejectsEmpty(t *testing.T) {
	if _, _, err := clientVersionPreference(nil); err == nil {
		t.Fatal("expected error")
	}
}

// TestCreateRequestGoogle verifies that a Google-Roughtime request is exactly
// 1024 bytes, contains NONC and PAD, and can be parsed by ParseRequest.
func TestCreateRequestGoogle(t *testing.T) {
	nonce, req, err := CreateRequest([]Version{VersionGoogle}, rand.Reader)
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

// TestCreateRequestDraft01 verifies a draft 01 request with 64-byte nonce.
func TestCreateRequestDraft01(t *testing.T) {
	nonce, req, err := CreateRequest([]Version{VersionDraft01}, rand.Reader)
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

// TestCreateRequestIETF verifies that IETF requests are 1024 bytes (including
// ROUGHTIM header), contain VER, and can be parsed by ParseRequest.
func TestCreateRequestIETF(t *testing.T) {
	versions := []Version{VersionDraft08, VersionDraft10}
	nonce, req, err := CreateRequest(versions, rand.Reader)
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

// TestCreateRequestDraft12 verifies that draft 12+ requests include TYPE=0.
// TYPE is required by drafts 14–19 and harmlessly ignored by drafts 12–13 (all
// share wire version 0x8000000c).
func TestCreateRequestDraft12(t *testing.T) {
	nonce, req, err := CreateRequest([]Version{VersionDraft12}, rand.Reader)
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
		t.Fatal("draft 12+ request should have TYPE=0")
	}
}

// TestCreateRequestRejectsEmpty verifies that an empty version list is
// rejected.
func TestCreateRequestRejectsEmpty(t *testing.T) {
	if _, _, err := CreateRequest(nil, rand.Reader); err == nil {
		t.Fatal("expected error")
	}
}

// TestVerifyReplyAllVersions exercises the full client/server round-trip for
// every supported version (Google + drafts 01–12, where 12 covers wire-version
// 0x8000000c shared by drafts 12–19). Each subtest creates a request, parses it
// as the server, signs a reply, and verifies the reply as the client.
func TestVerifyReplyAllVersions(t *testing.T) {
	for _, v := range append([]Version{VersionGoogle}, SupportedVersions()...) {
		t.Run(v.ShortString(), func(t *testing.T) {
			verifyRoundTrip(t, []Version{v}, v)
		})
	}
}

// TestVerifyReplyRejectsBadRootPK verifies that a wrong root public key is
// rejected.
func TestVerifyReplyRejectsBadRootPK(t *testing.T) {
	cert, _ := testCert(t)
	nonce, req, _ := CreateRequest([]Version{VersionGoogle}, rand.Reader)
	parsed, _ := ParseRequest(req)
	replies, _ := CreateReplies(VersionGoogle, []Request{*parsed}, time.Now(), time.Second, cert)

	badPK := make([]byte, ed25519.PublicKeySize)
	if _, _, err := VerifyReply([]Version{VersionGoogle}, replies[0], badPK, nonce, req); err == nil {
		t.Fatal("expected error for bad root PK")
	}
}

// TestVerifyReplyRejectsBadNonce verifies that a wrong nonce causes Merkle
// verification to fail.
func TestVerifyReplyRejectsBadNonce(t *testing.T) {
	cert, _ := testCert(t)
	rootPK := cert.rootPK
	nonce, req, _ := CreateRequest([]Version{VersionGoogle}, rand.Reader)
	parsed, _ := ParseRequest(req)
	replies, _ := CreateReplies(VersionGoogle, []Request{*parsed}, time.Now(), time.Second, cert)

	badNonce := make([]byte, len(nonce))
	copy(badNonce, nonce)
	badNonce[0] ^= 0xff

	if _, _, err := VerifyReply([]Version{VersionGoogle}, replies[0], rootPK, badNonce, req); err == nil {
		t.Fatal("expected error for bad nonce")
	}
}

// TestVerifyReplyRejectsInvalidPKSize verifies that a public key of wrong
// length is rejected.
func TestVerifyReplyRejectsInvalidPKSize(t *testing.T) {
	if _, _, err := VerifyReply([]Version{VersionGoogle}, nil, []byte{1, 2, 3}, nil, nil); err == nil {
		t.Fatal("expected error for invalid PK size")
	}
}

// TestVerifyReplyRejectsEmptyVersions verifies that an empty version list is
// rejected.
func TestVerifyReplyRejectsEmptyVersions(t *testing.T) {
	pk := make([]byte, ed25519.PublicKeySize)
	if _, _, err := VerifyReply(nil, nil, pk, nil, nil); err == nil {
		t.Fatal("expected error for empty versions")
	}
}

// TestVerifyReplyRejectsMissingRequestBytes verifies that draft 12+ replies
// fail verification when requestBytes is nil.
func TestVerifyReplyRejectsMissingRequestBytes(t *testing.T) {
	cert, _ := testCert(t)
	rootPK := cert.rootPK
	nonce, req, _ := CreateRequest([]Version{VersionDraft12}, rand.Reader)
	parsed, _ := ParseRequest(req)
	replies, _ := CreateReplies(VersionDraft12, []Request{*parsed}, time.Now(), time.Second, cert)

	if _, _, err := VerifyReply([]Version{VersionDraft12}, replies[0], rootPK, nonce, nil); err == nil {
		t.Fatal("expected error for nil requestBytes on draft 12+")
	}
}

// TestVerifyReplyRejectsExpiredCert verifies that a midpoint outside the
// delegation window is rejected.
func TestVerifyReplyRejectsExpiredCert(t *testing.T) {
	rootSK, onlineSK := testKeys(t)
	rootPK := rootSK.Public().(ed25519.PublicKey)
	past := time.Now().Add(-48 * time.Hour)
	cert, _ := NewCertificate(past.Add(-time.Hour), past, onlineSK, rootSK)

	nonce, req, _ := CreateRequest([]Version{VersionGoogle}, rand.Reader)
	parsed, _ := ParseRequest(req)
	replies, _ := CreateReplies(VersionGoogle, []Request{*parsed}, time.Now(), time.Second, cert)

	if _, _, err := VerifyReply([]Version{VersionGoogle}, replies[0], rootPK, nonce, req); err == nil {
		t.Fatal("expected error for expired cert")
	}
}

// TestVerifyReplyBatchIndex verifies that VerifyReply works when the client's
// request is at a non-zero Merkle tree index.
func TestVerifyReplyBatchIndex(t *testing.T) {
	cert, _ := testCert(t)
	rootPK := cert.rootPK

	// Create 4 requests; verify the one at index 2
	reqs := make([]Request, 4)
	var targetNonce, targetReq []byte
	for i := range 4 {
		n, r, err := CreateRequest([]Version{VersionGoogle}, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseRequest(r)
		if err != nil {
			t.Fatal(err)
		}
		reqs[i] = *parsed
		if i == 2 {
			targetNonce = n
			targetReq = r
		}
	}

	replies, err := CreateReplies(VersionGoogle, reqs, time.Now(), time.Second, cert)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := VerifyReply([]Version{VersionGoogle}, replies[2], rootPK, targetNonce, targetReq); err != nil {
		t.Fatal(err)
	}
}

// TestVerifyReplyBatchDraft12 verifies a non-power-of-2 batch with full-packet
// Merkle leaves (draft 12+).
func TestVerifyReplyBatchDraft12(t *testing.T) {
	cert, _ := testCert(t)
	rootPK := cert.rootPK

	reqs := make([]Request, 5)
	nonces := make([][]byte, 5)
	rawReqs := make([][]byte, 5)
	for i := range 5 {
		n, r, err := CreateRequest([]Version{VersionDraft12}, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseRequest(r)
		if err != nil {
			t.Fatal(err)
		}
		reqs[i] = *parsed
		nonces[i] = n
		rawReqs[i] = r
	}

	replies, err := CreateReplies(VersionDraft12, reqs, time.Now(), time.Second, cert)
	if err != nil {
		t.Fatal(err)
	}

	for i := range 5 {
		if _, _, err := VerifyReply([]Version{VersionDraft12}, replies[i], rootPK, nonces[i], rawReqs[i]); err != nil {
			t.Fatalf("reply %d: %v", i, err)
		}
	}
}

// TestExtractResponseVERTopLevel verifies VER extraction from the top-level
// response.
func TestExtractResponseVERTopLevel(t *testing.T) {
	resp := map[uint32][]byte{
		TagVER: {0x08, 0x00, 0x00, 0x80},
	}
	ver, ok := extractResponseVER(resp)
	if !ok || ver != VersionDraft08 {
		t.Fatal("expected VersionDraft08 from top-level VER")
	}
}

// TestExtractResponseVERFromSREP verifies VER extraction from inside SREP when
// no top-level VER is present.
func TestExtractResponseVERFromSREP(t *testing.T) {
	srepMsg, _ := encode(map[uint32][]byte{
		TagVER:  {0x0c, 0x00, 0x00, 0x80},
		TagRADI: make([]byte, 4),
		TagMIDP: make([]byte, 8),
		TagROOT: make([]byte, 32),
	})
	resp := map[uint32][]byte{TagSREP: srepMsg}
	ver, ok := extractResponseVER(resp)
	if !ok || ver != VersionDraft12 {
		t.Fatal("expected VersionDraft12 from SREP VER")
	}
}

// TestExtractResponseVERMissing verifies that a response with no VER anywhere
// returns false.
func TestExtractResponseVERMissing(t *testing.T) {
	resp := map[uint32][]byte{TagSIG: make([]byte, 64)}
	if _, ok := extractResponseVER(resp); ok {
		t.Fatal("expected no VER")
	}
}

// TestVersionOffered verifies the version membership check.
func TestVersionOffered(t *testing.T) {
	versions := []Version{VersionDraft08, VersionDraft12}
	if !versionOffered(VersionDraft12, versions) {
		t.Fatal("VersionDraft12 should be offered")
	}
	if versionOffered(VersionDraft10, versions) {
		t.Fatal("VersionDraft10 should not be offered")
	}
}

// TestUnwrapReplyRejectsGoogleWithHeader verifies that a Google-Roughtime reply
// with a ROUGHTIM header is rejected.
func TestUnwrapReplyRejectsGoogleWithHeader(t *testing.T) {
	pkt := wrapPacket(make([]byte, 20))
	if _, err := unwrapReply(pkt, groupGoogle); err == nil {
		t.Fatal("expected error for Google reply with ROUGHTIM header")
	}
}

// validReply builds a complete server reply for the given version using
// CreateReplies and returns the raw reply, root public key, nonce, and request
// bytes.
func validReply(t *testing.T, ver Version, versions []Version) (reply, rootPK, nonce, reqBytes []byte) {
	t.Helper()
	cert, _ := testCert(t)
	rootPK = cert.rootPK

	nonce, req, err := CreateRequest(versions, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	replies, err := CreateReplies(ver, []Request{*parsed}, time.Now(), time.Second, cert)
	if err != nil {
		t.Fatal(err)
	}
	return replies[0], rootPK, nonce, req
}

// corruptReplyTag decodes a reply, applies fn to the tag map, and re-encodes.
// For IETF versions (with ROUGHTIM header) it unwraps/rewraps automatically.
func corruptReplyTag(t *testing.T, reply []byte, ietf bool, fn func(map[uint32][]byte)) []byte {
	t.Helper()
	var msg []byte
	if ietf {
		var err error
		msg, err = unwrapPacket(reply)
		if err != nil {
			t.Fatal(err)
		}
	} else {
		msg = reply
	}
	tags, err := Decode(msg)
	if err != nil {
		t.Fatal(err)
	}
	fn(tags)
	out, err := encode(tags)
	if err != nil {
		t.Fatal(err)
	}
	if ietf {
		return wrapPacket(out)
	}
	return out
}

// TestDecodeRejectsValueOutOfBounds verifies that an offset pointing beyond the
// data section is rejected.
func TestDecodeRejectsValueOutOfBounds(t *testing.T) {
	encoded, _ := encode(map[uint32][]byte{
		0x0001: make([]byte, 8),
		0x0002: make([]byte, 4),
	})
	// Corrupt offset and truncate to force start > totalVal
	binary.LittleEndian.PutUint32(encoded[4:8], 4)
	if _, err := Decode(encoded[:16]); err == nil {
		t.Fatal("expected error for value out of bounds")
	}
}

// TestParseRequestRejectsCorruptIETF verifies that an IETF request with an
// invalid message body after the ROUGHTIM header is rejected.
func TestParseRequestRejectsCorruptIETF(t *testing.T) {
	// Valid header but corrupt message body
	pkt := wrapPacket([]byte{0xff, 0xff, 0xff, 0xff})
	if _, err := ParseRequest(pkt); err == nil {
		t.Fatal("expected error for corrupt IETF request body")
	}
}

// TestParseRequestRejectsTruncatedIETF verifies that a truncated ROUGHTIM
// packet is rejected.
func TestParseRequestRejectsTruncatedIETF(t *testing.T) {
	// ROUGHTIM header claiming 1000 bytes but only 4 bytes present
	pkt := make([]byte, 16)
	copy(pkt[:8], packetMagic[:])
	binary.LittleEndian.PutUint32(pkt[8:12], 1000)
	if _, err := ParseRequest(pkt); err == nil {
		t.Fatal("expected error for truncated IETF request")
	}
}

// TestCreateRequestRejectsReadError verifies that an entropy read failure is
// propagated.
func TestCreateRequestRejectsReadError(t *testing.T) {
	if _, _, err := CreateRequest([]Version{VersionDraft08}, &failReader{}); err == nil {
		t.Fatal("expected error for entropy read failure")
	}
}

// failReader is an [io.Reader] that always returns an error.
type failReader struct{}

// Read always returns an error.
func (failReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

// TestVerifyReplyRejectsUnwrapError verifies that a malformed IETF packet (bad
// ROUGHTIM header) is rejected during reply verification.
func TestVerifyReplyRejectsUnwrapError(t *testing.T) {
	pk := make([]byte, ed25519.PublicKeySize)
	badPkt := []byte("ROUGHTIMxxxx") // valid magic but declared length exceeds data
	binary.LittleEndian.PutUint32(badPkt[8:12], 9999)
	if _, _, err := VerifyReply([]Version{VersionDraft08}, badPkt, pk, nil, nil); err == nil {
		t.Fatal("expected error for bad ROUGHTIM header")
	}
}

// TestVerifyReplyRejectsDecodeError verifies that a reply with a corrupt
// message body after a valid ROUGHTIM header is rejected.
func TestVerifyReplyRejectsDecodeError(t *testing.T) {
	pk := make([]byte, ed25519.PublicKeySize)
	pkt := wrapPacket([]byte{0xff, 0xff, 0xff, 0xff})
	if _, _, err := VerifyReply([]Version{VersionDraft08}, pkt, pk, nil, nil); err == nil {
		t.Fatal("expected error for corrupt reply body")
	}
}

// TestVerifyReplyRejectsUnofferedVersion verifies that a server response
// advertising a version not in the client's list is rejected.
func TestVerifyReplyRejectsUnofferedVersion(t *testing.T) {
	reply, rootPK, nonce, req := validReply(t, VersionDraft08, []Version{VersionDraft08})
	// Replace VER tag with a version not offered
	corrupted := corruptReplyTag(t, reply, true, func(tags map[uint32][]byte) {
		var vBuf [4]byte
		binary.LittleEndian.PutUint32(vBuf[:], uint32(VersionDraft10))
		tags[TagVER] = vBuf[:]
	})
	if _, _, err := VerifyReply([]Version{VersionDraft08}, corrupted, rootPK, nonce, req); err == nil {
		t.Fatal("expected error for unoffered version")
	}
}

// TestVerifyReplyRejectsMissingSREP verifies that a response missing the SREP
// tag is rejected.
func TestVerifyReplyRejectsMissingSREP(t *testing.T) {
	reply, rootPK, nonce, req := validReply(t, VersionGoogle, []Version{VersionGoogle})
	corrupted := corruptReplyTag(t, reply, false, func(tags map[uint32][]byte) {
		delete(tags, TagSREP)
	})
	if _, _, err := VerifyReply([]Version{VersionGoogle}, corrupted, rootPK, nonce, req); err == nil {
		t.Fatal("expected error for missing SREP")
	}
}

// TestVerifyReplyRejectsBadSIG verifies that a response with an invalid SIG tag
// is rejected.
func TestVerifyReplyRejectsBadSIG(t *testing.T) {
	reply, rootPK, nonce, req := validReply(t, VersionGoogle, []Version{VersionGoogle})
	corrupted := corruptReplyTag(t, reply, false, func(tags map[uint32][]byte) {
		tags[TagSIG] = make([]byte, 12) // wrong length
	})
	if _, _, err := VerifyReply([]Version{VersionGoogle}, corrupted, rootPK, nonce, req); err == nil {
		t.Fatal("expected error for invalid SIG")
	}
}

// TestVerifyReplyRejectsMissingSIG verifies that a response missing the SIG tag
// is rejected.
func TestVerifyReplyRejectsMissingSIG(t *testing.T) {
	reply, rootPK, nonce, req := validReply(t, VersionGoogle, []Version{VersionGoogle})
	corrupted := corruptReplyTag(t, reply, false, func(tags map[uint32][]byte) {
		delete(tags, TagSIG)
	})
	if _, _, err := VerifyReply([]Version{VersionGoogle}, corrupted, rootPK, nonce, req); err == nil {
		t.Fatal("expected error for missing SIG")
	}
}

// TestVerifyReplyRejectsMissingCERT verifies that a response missing the CERT
// tag is rejected.
func TestVerifyReplyRejectsMissingCERT(t *testing.T) {
	reply, rootPK, nonce, req := validReply(t, VersionGoogle, []Version{VersionGoogle})
	corrupted := corruptReplyTag(t, reply, false, func(tags map[uint32][]byte) {
		delete(tags, TagCERT)
	})
	if _, _, err := VerifyReply([]Version{VersionGoogle}, corrupted, rootPK, nonce, req); err == nil {
		t.Fatal("expected error for missing CERT")
	}
}

// TestVerifyReplyRejectsCorruptCERT verifies that a response with an
// un-decodable CERT is rejected.
func TestVerifyReplyRejectsCorruptCERT(t *testing.T) {
	reply, rootPK, nonce, req := validReply(t, VersionGoogle, []Version{VersionGoogle})
	corrupted := corruptReplyTag(t, reply, false, func(tags map[uint32][]byte) {
		tags[TagCERT] = []byte{0xff, 0xff, 0xff, 0xff}
	})
	if _, _, err := VerifyReply([]Version{VersionGoogle}, corrupted, rootPK, nonce, req); err == nil {
		t.Fatal("expected error for corrupt CERT")
	}
}

// TestVerifyReplyRejectsMissingDELE verifies that a CERT without a DELE tag is
// rejected.
func TestVerifyReplyRejectsMissingDELE(t *testing.T) {
	reply, rootPK, nonce, req := validReply(t, VersionGoogle, []Version{VersionGoogle})
	corrupted := corruptReplyTag(t, reply, false, func(tags map[uint32][]byte) {
		certMsg, _ := encode(map[uint32][]byte{
			TagSIG: make([]byte, ed25519.SignatureSize),
		})
		tags[TagCERT] = certMsg
	})
	if _, _, err := VerifyReply([]Version{VersionGoogle}, corrupted, rootPK, nonce, req); err == nil {
		t.Fatal("expected error for missing DELE")
	}
}

// TestVerifyReplyRejectsBadCERTSig verifies that a CERT with an invalid
// delegation signature size is rejected.
func TestVerifyReplyRejectsBadCERTSig(t *testing.T) {
	reply, rootPK, nonce, req := validReply(t, VersionGoogle, []Version{VersionGoogle})
	corrupted := corruptReplyTag(t, reply, false, func(tags map[uint32][]byte) {
		certMsg, _ := Decode(tags[TagCERT])
		certMsg[TagSIG] = make([]byte, 12) // wrong size
		tags[TagCERT], _ = encode(certMsg)
	})
	if _, _, err := VerifyReply([]Version{VersionGoogle}, corrupted, rootPK, nonce, req); err == nil {
		t.Fatal("expected error for bad CERT SIG size")
	}
}

// TestVerifyReplyRejectsDELESignatureFailure verifies that a CERT with a
// corrupted delegation signature is rejected.
func TestVerifyReplyRejectsDELESignatureFailure(t *testing.T) {
	reply, rootPK, nonce, req := validReply(t, VersionGoogle, []Version{VersionGoogle})
	corrupted := corruptReplyTag(t, reply, false, func(tags map[uint32][]byte) {
		certMsg, _ := Decode(tags[TagCERT])
		sig := make([]byte, ed25519.SignatureSize)
		copy(sig, certMsg[TagSIG])
		sig[0] ^= 0xff // corrupt signature
		certMsg[TagSIG] = sig
		tags[TagCERT], _ = encode(certMsg)
	})
	if _, _, err := VerifyReply([]Version{VersionGoogle}, corrupted, rootPK, nonce, req); err == nil {
		t.Fatal("expected error for DELE signature failure")
	}
}

// TestVerifyReplyRejectsBadPUBK verifies that a DELE with an invalid PUBK size
// is rejected.
func TestVerifyReplyRejectsBadPUBK(t *testing.T) {
	reply, rootPK, nonce, req := validReply(t, VersionGoogle, []Version{VersionGoogle})
	corrupted := corruptReplyTag(t, reply, false, func(tags map[uint32][]byte) {
		certMsg, _ := Decode(tags[TagCERT])
		dele, _ := Decode(certMsg[TagDELE])
		dele[TagPUBK] = make([]byte, 16) // wrong size
		deleBytes, _ := encode(dele)
		certMsg[TagDELE] = deleBytes
		tags[TagCERT], _ = encode(certMsg)
	})
	if _, _, err := VerifyReply([]Version{VersionGoogle}, corrupted, rootPK, nonce, req); err == nil {
		t.Fatal("expected error for bad PUBK in DELE")
	}
}

// TestVerifyReplyRejectsBadMINT verifies that a DELE with an invalid MINT size
// is rejected.
func TestVerifyReplyRejectsBadMINT(t *testing.T) {
	reply, rootPK, nonce, req := validReply(t, VersionGoogle, []Version{VersionGoogle})
	corrupted := corruptReplyTag(t, reply, false, func(tags map[uint32][]byte) {
		certMsg, _ := Decode(tags[TagCERT])
		dele, _ := Decode(certMsg[TagDELE])
		dele[TagMINT] = make([]byte, 4) // should be 8
		deleBytes, _ := encode(dele)
		certMsg[TagDELE] = deleBytes
		tags[TagCERT], _ = encode(certMsg)
	})
	if _, _, err := VerifyReply([]Version{VersionGoogle}, corrupted, rootPK, nonce, req); err == nil {
		t.Fatal("expected error for bad MINT in DELE")
	}
}

// TestVerifyReplyRejectsBadMAXT verifies that a DELE with an invalid MAXT size
// is rejected.
func TestVerifyReplyRejectsBadMAXT(t *testing.T) {
	reply, rootPK, nonce, req := validReply(t, VersionGoogle, []Version{VersionGoogle})
	corrupted := corruptReplyTag(t, reply, false, func(tags map[uint32][]byte) {
		certMsg, _ := Decode(tags[TagCERT])
		dele, _ := Decode(certMsg[TagDELE])
		dele[TagMAXT] = make([]byte, 4) // should be 8
		deleBytes, _ := encode(dele)
		certMsg[TagDELE] = deleBytes
		tags[TagCERT], _ = encode(certMsg)
	})
	if _, _, err := VerifyReply([]Version{VersionGoogle}, corrupted, rootPK, nonce, req); err == nil {
		t.Fatal("expected error for bad MAXT in DELE")
	}
}

// TestVerifyReplyRejectsSREPSignatureFailure verifies that a response with a
// corrupted SREP signature is rejected.
func TestVerifyReplyRejectsSREPSignatureFailure(t *testing.T) {
	reply, rootPK, nonce, req := validReply(t, VersionGoogle, []Version{VersionGoogle})
	corrupted := corruptReplyTag(t, reply, false, func(tags map[uint32][]byte) {
		sig := make([]byte, ed25519.SignatureSize)
		copy(sig, tags[TagSIG])
		sig[0] ^= 0xff
		tags[TagSIG] = sig
	})
	if _, _, err := VerifyReply([]Version{VersionGoogle}, corrupted, rootPK, nonce, req); err == nil {
		t.Fatal("expected error for SREP signature failure")
	}
}

// TestVerifyReplyRejectsCorruptSREP verifies that a response with an
// un-decodable SREP is rejected.
func TestVerifyReplyRejectsCorruptSREP(t *testing.T) {
	reply, rootPK, nonce, req := validReply(t, VersionGoogle, []Version{VersionGoogle})
	corrupted := corruptReplyTag(t, reply, false, func(tags map[uint32][]byte) {
		tags[TagSREP] = []byte{0xff, 0xff, 0xff, 0xff}
	})
	if _, _, err := VerifyReply([]Version{VersionGoogle}, corrupted, rootPK, nonce, req); err == nil {
		t.Fatal("expected error for corrupt SREP")
	}
}

// TestVerifyReplyRejectsMissingMIDP verifies that a SREP without MIDP is
// rejected.
func TestVerifyReplyRejectsMissingMIDP(t *testing.T) {
	reply, rootPK, nonce, req := validReply(t, VersionGoogle, []Version{VersionGoogle})
	corrupted := corruptReplyTag(t, reply, false, func(tags map[uint32][]byte) {
		srep, _ := Decode(tags[TagSREP])
		delete(srep, TagMIDP)
		tags[TagSREP], _ = encode(srep)
	})
	if _, _, err := VerifyReply([]Version{VersionGoogle}, corrupted, rootPK, nonce, req); err == nil {
		t.Fatal("expected error for missing MIDP")
	}
}

// TestVerifyReplyRejectsMissingRADI verifies that a SREP without RADI is
// rejected.
func TestVerifyReplyRejectsMissingRADI(t *testing.T) {
	reply, rootPK, nonce, req := validReply(t, VersionGoogle, []Version{VersionGoogle})
	corrupted := corruptReplyTag(t, reply, false, func(tags map[uint32][]byte) {
		srep, _ := Decode(tags[TagSREP])
		delete(srep, TagRADI)
		tags[TagSREP], _ = encode(srep)
	})
	if _, _, err := VerifyReply([]Version{VersionGoogle}, corrupted, rootPK, nonce, req); err == nil {
		t.Fatal("expected error for missing RADI")
	}
}

// TestVerifyReplyRejectsBadROOT verifies that a SREP with a wrong-length ROOT
// is rejected.
func TestVerifyReplyRejectsBadROOT(t *testing.T) {
	reply, rootPK, nonce, req := validReply(t, VersionGoogle, []Version{VersionGoogle})
	corrupted := corruptReplyTag(t, reply, false, func(tags map[uint32][]byte) {
		srep, _ := Decode(tags[TagSREP])
		srep[TagROOT] = make([]byte, 16) // should be 64 for Google
		tags[TagSREP], _ = encode(srep)
	})
	if _, _, err := VerifyReply([]Version{VersionGoogle}, corrupted, rootPK, nonce, req); err == nil {
		t.Fatal("expected error for bad ROOT size")
	}
}

// TestVerifyMerkleRejectsMissingINDX verifies that a response without INDX is
// rejected during Merkle verification.
func TestVerifyMerkleRejectsMissingINDX(t *testing.T) {
	resp := map[uint32][]byte{
		TagPATH: {},
	}
	if err := verifyMerkle(resp, make([]byte, 32), make([]byte, 32), groupD12); err == nil {
		t.Fatal("expected error for missing INDX")
	}
}

// TestVerifyMerkleRejectsBadPATHLength verifies that a PATH not a multiple of
// the hash size is rejected.
func TestVerifyMerkleRejectsBadPATHLength(t *testing.T) {
	var indx [4]byte
	resp := map[uint32][]byte{
		TagINDX: indx[:],
		TagPATH: make([]byte, 17), // not a multiple of 32
	}
	if err := verifyMerkle(resp, make([]byte, 32), make([]byte, 32), groupD12); err == nil {
		t.Fatal("expected error for bad PATH length")
	}
}

// TestVerifyMerkleRejectsTrailingINDXBits verifies that leftover non-zero bits
// in INDX after consuming the PATH are rejected.
func TestVerifyMerkleRejectsTrailingINDXBits(t *testing.T) {
	// Single PATH entry (one level) but INDX = 4 (bit pattern 100), so after
	// consuming 1 bit, index >> 1 = 2 which is non-zero
	var indx [4]byte
	binary.LittleEndian.PutUint32(indx[:], 4)
	resp := map[uint32][]byte{
		TagINDX: indx[:],
		TagPATH: make([]byte, 32), // one node
	}
	if err := verifyMerkle(resp, make([]byte, 32), make([]byte, 32), groupD12); err == nil {
		t.Fatal("expected error for trailing INDX bits")
	}
}

// TestVerifyMerkleRejectsLongPATH verifies that PATH with more than 32 entries
// is rejected per §5.2.4.
func TestVerifyMerkleRejectsLongPATH(t *testing.T) {
	var indx [4]byte
	resp := map[uint32][]byte{
		TagINDX: indx[:],
		TagPATH: make([]byte, 33*32), // 33 entries > max 32
	}
	if err := verifyMerkle(resp, make([]byte, 32), make([]byte, 32), groupD12); err == nil {
		t.Fatal("expected error for PATH exceeding 32 entries")
	}
}

// TestVerifyReplySREPRejectsCorruptSREP verifies that verifyReplySREP rejects
// an un-decodable SREP body.
func TestVerifyReplySREPRejectsCorruptSREP(t *testing.T) {
	resp := map[uint32][]byte{
		TagSREP: {0xff, 0xff, 0xff, 0xff},
	}
	if _, _, err := verifyReplySREP(resp, nil, nil, groupGoogle); err == nil {
		t.Fatal("expected error for corrupt SREP")
	}
}

// TestVerifyReplySREPRejectsMissingMIDP verifies that verifyReplySREP rejects a
// SREP without MIDP.
func TestVerifyReplySREPRejectsMissingMIDP(t *testing.T) {
	srepBytes, _ := encode(map[uint32][]byte{
		TagRADI: make([]byte, 4),
		TagROOT: make([]byte, 64),
	})
	resp := map[uint32][]byte{TagSREP: srepBytes}
	if _, _, err := verifyReplySREP(resp, nil, nil, groupGoogle); err == nil {
		t.Fatal("expected error for missing MIDP")
	}
}

// TestVerifyReplySREPRejectsMissingRADI verifies that verifyReplySREP rejects a
// SREP without RADI.
func TestVerifyReplySREPRejectsMissingRADI(t *testing.T) {
	srepBytes, _ := encode(map[uint32][]byte{
		TagMIDP: make([]byte, 8),
		TagROOT: make([]byte, 64),
	})
	resp := map[uint32][]byte{TagSREP: srepBytes}
	if _, _, err := verifyReplySREP(resp, nil, nil, groupGoogle); err == nil {
		t.Fatal("expected error for missing RADI")
	}
}

// TestVerifyReplySREPRejectsBadROOT verifies that verifyReplySREP rejects a
// SREP with a wrong-length ROOT hash.
func TestVerifyReplySREPRejectsBadROOT(t *testing.T) {
	srepBytes, _ := encode(map[uint32][]byte{
		TagMIDP: make([]byte, 8),
		TagRADI: make([]byte, 4),
		TagROOT: make([]byte, 16), // should be 64 for Google
	})
	resp := map[uint32][]byte{TagSREP: srepBytes}
	if _, _, err := verifyReplySREP(resp, nil, nil, groupGoogle); err == nil {
		t.Fatal("expected error for bad ROOT size")
	}
}

// TestVerifyReplySREPRejectsBadMIDP verifies that verifyReplySREP rejects a
// SREP with a non-8-byte MIDP.
func TestVerifyReplySREPRejectsBadMIDP(t *testing.T) {
	nonce := make([]byte, 64)
	root := leafHash(groupGoogle, nonce)
	var indx [4]byte
	srepBytes, _ := encode(map[uint32][]byte{
		TagMIDP: make([]byte, 4), // should be 8
		TagRADI: make([]byte, 4),
		TagROOT: root,
	})
	resp := map[uint32][]byte{
		TagSREP: srepBytes,
		TagINDX: indx[:],
		TagPATH: {},
	}
	if _, _, err := verifyReplySREP(resp, nonce, nil, groupGoogle); err == nil {
		t.Fatal("expected error for bad MIDP size")
	}
}

// TestVerifyReplySREPRejectsBadRADI verifies that verifyReplySREP rejects a
// SREP with a non-4-byte RADI.
func TestVerifyReplySREPRejectsBadRADI(t *testing.T) {
	nonce := make([]byte, 64)
	root := leafHash(groupGoogle, nonce)
	var indx [4]byte
	srepBytes, _ := encode(map[uint32][]byte{
		TagMIDP: make([]byte, 8),
		TagRADI: make([]byte, 8), // should be 4
		TagROOT: root,
	})
	resp := map[uint32][]byte{
		TagSREP: srepBytes,
		TagINDX: indx[:],
		TagPATH: {},
	}
	if _, _, err := verifyReplySREP(resp, nonce, nil, groupGoogle); err == nil {
		t.Fatal("expected error for bad RADI size")
	}
}

// TestValidateDelegationWindowRejectsBadMINT verifies that
// validateDelegationWindow rejects a non-8-byte MINT buffer.
func TestValidateDelegationWindowRejectsBadMINT(t *testing.T) {
	if _, _, err := validateDelegationWindow(time.Now(), time.Second, make([]byte, 4), make([]byte, 8), groupGoogle); err == nil {
		t.Fatal("expected error for bad MINT")
	}
}

// TestValidateDelegationWindowRejectsBadMAXT verifies that
// validateDelegationWindow rejects a non-8-byte MAXT buffer.
func TestValidateDelegationWindowRejectsBadMAXT(t *testing.T) {
	if _, _, err := validateDelegationWindow(time.Now(), time.Second, make([]byte, 8), make([]byte, 4), groupGoogle); err == nil {
		t.Fatal("expected error for bad MAXT")
	}
}

// TestVerifyCertRejectsCorruptCERT verifies that verifyCert rejects an
// un-decodable CERT body.
func TestVerifyCertRejectsCorruptCERT(t *testing.T) {
	pk := make([]byte, ed25519.PublicKeySize)
	if _, _, _, err := verifyCert([]byte{0xff, 0xff, 0xff, 0xff}, pk, groupGoogle); err == nil {
		t.Fatal("expected error for corrupt CERT")
	}
}

// TestVerifyCertRejectsMissingDELE verifies that verifyCert rejects a CERT
// without DELE.
func TestVerifyCertRejectsMissingDELE(t *testing.T) {
	pk := make([]byte, ed25519.PublicKeySize)
	certBytes, _ := encode(map[uint32][]byte{
		TagSIG: make([]byte, ed25519.SignatureSize),
	})
	if _, _, _, err := verifyCert(certBytes, pk, groupGoogle); err == nil {
		t.Fatal("expected error for missing DELE")
	}
}

// TestVerifyCertRejectsBadSIGSize verifies that verifyCert rejects a CERT with
// a wrong-size SIG.
func TestVerifyCertRejectsBadSIGSize(t *testing.T) {
	pk := make([]byte, ed25519.PublicKeySize)
	certBytes, _ := encode(map[uint32][]byte{
		TagSIG:  make([]byte, 32), // wrong size
		TagDELE: make([]byte, 4),
	})
	if _, _, _, err := verifyCert(certBytes, pk, groupGoogle); err == nil {
		t.Fatal("expected error for bad SIG size in CERT")
	}
}

// TestVerifyCertRejectsSignatureFailure verifies that verifyCert rejects a CERT
// with an invalid delegation signature.
func TestVerifyCertRejectsSignatureFailure(t *testing.T) {
	pk := make([]byte, ed25519.PublicKeySize)
	dele, _ := encode(map[uint32][]byte{
		TagPUBK: make([]byte, ed25519.PublicKeySize),
		TagMINT: make([]byte, 8),
		TagMAXT: make([]byte, 8),
	})
	certBytes, _ := encode(map[uint32][]byte{
		TagSIG:  make([]byte, ed25519.SignatureSize),
		TagDELE: dele,
	})
	if _, _, _, err := verifyCert(certBytes, pk, groupGoogle); err == nil {
		t.Fatal("expected error for signature failure")
	}
}

// TestVerifyCertRejectsBadPUBK verifies that verifyCert rejects a DELE with an
// invalid PUBK after signature verification. This test signs the DELE with a
// real key to pass the signature check.
func TestVerifyCertRejectsBadPUBK(t *testing.T) {
	rootSK, _ := testKeys(t)
	rootPK := rootSK.Public().(ed25519.PublicKey)

	dele, _ := encode(map[uint32][]byte{
		TagPUBK: make([]byte, 16), // wrong size
		TagMINT: make([]byte, 8),
		TagMAXT: make([]byte, 8),
	})
	ctx := delegationContext(groupGoogle)
	toSign := make([]byte, len(ctx)+len(dele))
	copy(toSign, ctx)
	copy(toSign[len(ctx):], dele)
	sig := ed25519.Sign(rootSK, toSign)

	certBytes, _ := encode(map[uint32][]byte{TagSIG: sig, TagDELE: dele})
	if _, _, _, err := verifyCert(certBytes, rootPK, groupGoogle); err == nil {
		t.Fatal("expected error for bad PUBK size")
	}
}

// TestVerifyCertRejectsBadMINTSize verifies that verifyCert rejects a DELE with
// an invalid MINT size after signature verification.
func TestVerifyCertRejectsBadMINTSize(t *testing.T) {
	rootSK, _ := testKeys(t)
	rootPK := rootSK.Public().(ed25519.PublicKey)

	dele, _ := encode(map[uint32][]byte{
		TagPUBK: make([]byte, ed25519.PublicKeySize),
		TagMINT: make([]byte, 4), // wrong size
		TagMAXT: make([]byte, 8),
	})
	ctx := delegationContext(groupGoogle)
	toSign := make([]byte, len(ctx)+len(dele))
	copy(toSign, ctx)
	copy(toSign[len(ctx):], dele)
	sig := ed25519.Sign(rootSK, toSign)

	certBytes, _ := encode(map[uint32][]byte{TagSIG: sig, TagDELE: dele})
	if _, _, _, err := verifyCert(certBytes, rootPK, groupGoogle); err == nil {
		t.Fatal("expected error for bad MINT size")
	}
}

// TestVerifyCertRejectsBadMAXTSize verifies that verifyCert rejects a DELE with
// an invalid MAXT size after signature verification.
func TestVerifyCertRejectsBadMAXTSize(t *testing.T) {
	rootSK, _ := testKeys(t)
	rootPK := rootSK.Public().(ed25519.PublicKey)

	dele, _ := encode(map[uint32][]byte{
		TagPUBK: make([]byte, ed25519.PublicKeySize),
		TagMINT: make([]byte, 8),
		TagMAXT: make([]byte, 4), // wrong size
	})
	ctx := delegationContext(groupGoogle)
	toSign := make([]byte, len(ctx)+len(dele))
	copy(toSign, ctx)
	copy(toSign[len(ctx):], dele)
	sig := ed25519.Sign(rootSK, toSign)

	certBytes, _ := encode(map[uint32][]byte{TagSIG: sig, TagDELE: dele})
	if _, _, _, err := verifyCert(certBytes, rootPK, groupGoogle); err == nil {
		t.Fatal("expected error for bad MAXT size")
	}
}

// TestVerifyCertRejectsCorruptDELE verifies that verifyCert rejects a DELE
// whose bytes are not a valid Roughtime message even though the signature is
// valid.
func TestVerifyCertRejectsCorruptDELE(t *testing.T) {
	rootSK, _ := testKeys(t)
	rootPK := rootSK.Public().(ed25519.PublicKey)

	// Sign raw bytes that are not a valid Roughtime message (zero tag count)
	dele := []byte{0x00, 0x00, 0x00, 0x00}
	ctx := delegationContext(groupGoogle)
	toSign := make([]byte, len(ctx)+len(dele))
	copy(toSign, ctx)
	copy(toSign[len(ctx):], dele)
	sig := ed25519.Sign(rootSK, toSign)

	certBytes, _ := encode(map[uint32][]byte{TagSIG: sig, TagDELE: dele})
	if _, _, _, err := verifyCert(certBytes, rootPK, groupGoogle); err == nil {
		t.Fatal("expected error for corrupt DELE after valid signature")
	}
}

// TestCreateRequestEarlyDraftHeader verifies that every IETF draft (01–04)
// client request carries the ROUGHTIM packet header. The header is mandated by
// §5/§6 "Roughtime Packet Format" of every draft.
func TestCreateRequestEarlyDraftHeader(t *testing.T) {
	for _, v := range []Version{VersionDraft01, VersionDraft02, VersionDraft03, VersionDraft04} {
		_, req, err := CreateRequest([]Version{v}, rand.Reader)
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

// TestCreateRepliesEarlyDraftHeader verifies that every IETF draft (01–04)
// server response carries the ROUGHTIM packet header.
func TestCreateRepliesEarlyDraftHeader(t *testing.T) {
	cert, _ := testCert(t)
	for _, v := range []Version{VersionDraft01, VersionDraft02, VersionDraft03, VersionDraft04} {
		nonce := randBytes(t, 64)
		raw := buildIETFRequest(nonce, []Version{v}, false)
		replies, err := CreateReplies(v, []Request{{Nonce: nonce, Versions: []Version{v}, RawPacket: raw}}, time.Now(), time.Second, cert)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(replies[0][:8], packetMagic[:]) {
			t.Fatalf("%s response must carry the ROUGHTIM header", v)
		}
	}
}

// TestDraft12NoTopLevelVER verifies that drafts 12+ emit VER inside SREP only,
// not at the top level (drafts 12–19, Figure 3).
func TestDraft12NoTopLevelVER(t *testing.T) {
	cert, _ := testCert(t)
	nonce, req, _ := CreateRequest([]Version{VersionDraft12}, rand.Reader)
	parsed, _ := ParseRequest(req)
	replies, _ := CreateReplies(VersionDraft12, []Request{*parsed}, time.Now(), time.Second, cert)
	inner, err := unwrapPacket(replies[0])
	if err != nil {
		t.Fatal(err)
	}
	resp, err := Decode(inner)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := resp[TagVER]; ok {
		t.Fatal("drafts 12+ must not include top-level VER")
	}
	srep, _ := Decode(resp[TagSREP])
	if _, ok := srep[TagVER]; !ok {
		t.Fatal("drafts 12+ require VER inside SREP")
	}
	_ = nonce
}

// TestParseRequestRejectsUnsortedVER verifies that VER lists which are not
// strictly ascending are rejected (drafts 13+ §5.1.2 MUST).
func TestParseRequestRejectsUnsortedVER(t *testing.T) {
	nonce := randBytes(t, 32)
	// Out of order: Draft12 then Draft10.
	raw := buildIETFRequest(nonce, []Version{VersionDraft12, VersionDraft10}, false)
	if _, err := ParseRequest(raw); err == nil {
		t.Fatal("expected error for unsorted VER list")
	}
	// Duplicates should also be rejected.
	raw = buildIETFRequest(nonce, []Version{VersionDraft10, VersionDraft10}, false)
	if _, err := ParseRequest(raw); err == nil {
		t.Fatal("expected error for repeating VER list")
	}
}

// TestDecodeRejectsOversizedInput verifies the [Decode] size cap.
func TestDecodeRejectsOversizedInput(t *testing.T) {
	if _, err := Decode(make([]byte, maxMessageSize+1)); err == nil {
		t.Fatal("expected error for oversized message")
	}
}

// TestVerifyReplyDetectsDowngrade verifies that a hostile server which signs a
// SREP claiming a lower version than the client's best mutually-supported
// version is rejected.
func TestVerifyReplyDetectsDowngrade(t *testing.T) {
	cert, _ := testCert(t)
	rootPK := cert.rootPK
	// Client offers Draft11 and Draft12; the highest mutual is Draft12.
	clientVers := []Version{VersionDraft11, VersionDraft12}
	nonce, req, _ := CreateRequest(clientVers, rand.Reader)
	parsed, _ := ParseRequest(req)
	// Force the server to claim Draft11 inside the signed SREP, while still
	// using draft-12 wire format. This simulates a server (or compromised
	// online key) attempting a version downgrade.
	g := groupD14
	tree := newMerkleTree(g, [][]byte{parsed.RawPacket})
	midpBuf := encodeTimestamp(time.Now(), g)
	var radiBuf [4]byte
	binary.LittleEndian.PutUint32(radiBuf[:], radiSeconds(time.Second, g))
	var verBuf [4]byte
	binary.LittleEndian.PutUint32(verBuf[:], uint32(VersionDraft11)) // wrong!
	srepTags := map[uint32][]byte{
		TagRADI: radiBuf[:],
		TagMIDP: midpBuf[:],
		TagROOT: tree.rootHash,
		TagVER:  verBuf[:],
		TagVERS: supportedVersionsBytes,
	}
	srepBytes, _ := encode(srepTags)
	toSign := make([]byte, len(responseCtx)+len(srepBytes))
	copy(toSign, responseCtx)
	copy(toSign[len(responseCtx):], srepBytes)
	srepSig := ed25519.Sign(cert.onlineSK, toSign)
	resp := map[uint32][]byte{
		TagSIG:  srepSig,
		TagSREP: srepBytes,
		TagCERT: cert.certBytes(g),
		TagPATH: nil,
		TagINDX: make([]byte, 4),
		TagNONC: nonce,
		TagTYPE: func() []byte { b := make([]byte, 4); binary.LittleEndian.PutUint32(b, 1); return b }(),
	}
	replyMsg, _ := encode(resp)
	reply := wrapPacket(replyMsg)
	if _, _, err := VerifyReply(clientVers, reply, rootPK, nonce, req); err == nil {
		t.Fatal("expected downgrade detection error")
	}
}

// TestVerifyReplyRejectsResponseTYPENot1 verifies that a response with TYPE !=
// 1 is rejected per §5.2.3: "Responses containing a TYPE tag with any other
// value MUST be ignored by clients."
func TestVerifyReplyRejectsResponseTYPENot1(t *testing.T) {
	cert, _ := testCert(t)
	rootPK := cert.rootPK
	clientVers := []Version{VersionDraft12}
	nonce, req, _ := CreateRequest(clientVers, rand.Reader)
	parsed, _ := ParseRequest(req)
	g := groupD14
	tree := newMerkleTree(g, [][]byte{parsed.RawPacket})
	midpBuf := encodeTimestamp(time.Now(), g)
	var radiBuf [4]byte
	binary.LittleEndian.PutUint32(radiBuf[:], radiSeconds(time.Second, g))
	var verBuf [4]byte
	binary.LittleEndian.PutUint32(verBuf[:], uint32(VersionDraft12))
	srepTags := map[uint32][]byte{
		TagRADI: radiBuf[:],
		TagMIDP: midpBuf[:],
		TagROOT: tree.rootHash,
		TagVER:  verBuf[:],
		TagVERS: supportedVersionsBytes,
	}
	srepBytes, _ := encode(srepTags)
	toSign := make([]byte, len(responseCtx)+len(srepBytes))
	copy(toSign, responseCtx)
	copy(toSign[len(responseCtx):], srepBytes)
	srepSig := ed25519.Sign(cert.onlineSK, toSign)
	for _, badType := range []uint32{0, 2, 0xFFFFFFFF} {
		typeBuf := make([]byte, 4)
		binary.LittleEndian.PutUint32(typeBuf, badType)
		resp := map[uint32][]byte{
			TagSIG:  srepSig,
			TagSREP: srepBytes,
			TagCERT: cert.certBytes(g),
			TagPATH: nil,
			TagINDX: make([]byte, 4),
			TagNONC: nonce,
			TagTYPE: typeBuf,
		}
		replyMsg, _ := encode(resp)
		reply := wrapPacket(replyMsg)
		if _, _, err := VerifyReply(clientVers, reply, rootPK, nonce, req); err == nil {
			t.Fatalf("expected error for response TYPE=%d", badType)
		}
	}
}
