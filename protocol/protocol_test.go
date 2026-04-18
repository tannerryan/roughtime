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
	"maps"
	"math"
	"strings"
	"testing"
	"time"
)

// wrapPacket prepends the 12-byte ROUGHTIM header to a raw message.
func wrapPacket(msg []byte) []byte {
	pkt := make([]byte, 12+len(msg))
	copy(pkt[0:8], packetMagic[:])
	binary.LittleEndian.PutUint32(pkt[8:12], uint32(len(msg)))
	copy(pkt[12:], msg)
	return pkt
}

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
	// Header: 4 (tag count) + 4 (1 offset) + 8 (2 tags) = 16 bytes
	pad := make([]byte, 1024-len(nonce)-16)
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
		// Select the correct padding tag: drafts 08+ use ZZZZ, 01-07 use PAD\0
		padTag := tagPADIETF
		if len(versions) > 0 && versions[0] >= VersionDraft08 {
			padTag = TagZZZZ
		}
		padded[padTag] = make([]byte, 1012-len(msg))
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

// verifySREPTags checks that SREP contains ROOT, MIDP, RADI, version tags, and
// NONC (for wire groups that embed it).
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
	if noncInSREP(g) {
		if _, ok := srep[TagNONC]; !ok {
			t.Fatal("NONC should be inside SREP for this wire group")
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

	toVerify := append([]byte(nil), responseCtx...)
	toVerify = append(toVerify, resp[TagSREP]...)
	if !ed25519.Verify(dele[TagPUBK], toVerify, resp[TagSIG]) {
		t.Fatal("SREP signature verification failed")
	}

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

	nonce, req, err := CreateRequest(versions, rand.Reader, nil)
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

// TestDecodeTimestampZero verifies all-zero MIDP buffers decode without error
// across every timestamp format.
func TestDecodeTimestampZero(t *testing.T) {
	zero := make([]byte, 8)
	for _, ver := range []Version{VersionGoogle, VersionDraft01, VersionDraft08, VersionDraft12} {
		t.Run(ver.String(), func(t *testing.T) {
			if _, err := DecodeTimestamp(ver, zero); err != nil {
				t.Fatalf("zero MIDP rejected for %s: %v", ver, err)
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
	got, err := mjdMicroToTime(uint64(40587) << 40)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(time.Unix(0, 0).UTC()) {
		t.Fatalf("got %v, want Unix epoch", got)
	}
}

// TestMJDMicroToTimeNoon verifies microsecond-in-day field at noon.
func TestMJDMicroToTimeNoon(t *testing.T) {
	v := (uint64(40587) << 40) | uint64(12*3600_000_000)
	got, err := mjdMicroToTime(v)
	if err != nil {
		t.Fatal(err)
	}
	want := time.Unix(43200, 0).UTC()
	if !got.Equal(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// TestMJDMicroRoundTrip verifies encode/decode round-trip for a known date.
func TestMJDMicroRoundTrip(t *testing.T) {
	ts := time.Date(2024, 11, 15, 10, 30, 0, 0, time.UTC)
	decoded, err := mjdMicroToTime(timeToMJDMicro(ts))
	if err != nil {
		t.Fatal(err)
	}
	if !decoded.Equal(ts) {
		t.Fatalf("round-trip failed: got %v, want %v", decoded, ts)
	}
}

// TestMJDMicroToTimeRejectsOverflow verifies that a sub-day µs field >= 86400s
// is rejected rather than silently re-mapping onto the next MJD day.
func TestMJDMicroToTimeRejectsOverflow(t *testing.T) {
	// 40587 µs-of-day = 86_400_000_000 (exactly one day) → must reject
	v := (uint64(40587) << 40) | uint64(microsPerDay)
	if _, err := mjdMicroToTime(v); err == nil {
		t.Fatal("expected error for sub-day µs >= 86400_000_000")
	}
	// 40-bit maximum (0xFFFFFFFFFF ≈ 12.7 days worth of µs) → must reject
	v = (uint64(40587) << 40) | 0xFFFFFFFFFF
	if _, err := mjdMicroToTime(v); err == nil {
		t.Fatal("expected error for 40-bit-max sub-day µs")
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

// TestRadiSeconds verifies second RADI clamping: floor is 3 for all drafts 08+
// (drafts 10–11 MUST; drafts 08–09 and 12+ SHOULD by default).
func TestRadiSeconds(t *testing.T) {
	if radiSeconds(500*time.Millisecond) != 3 {
		t.Fatal("sub-second should clamp to 3")
	}
	if radiSeconds(2*time.Second) != 3 {
		t.Fatal("2s should clamp to 3")
	}
	if radiSeconds(3*time.Second) != 3 {
		t.Fatal("3s should be 3")
	}
	if radiSeconds(5*time.Second) != 5 {
		t.Fatal("5s should be 5")
	}
	if radiSeconds(time.Duration(math.MaxInt64)) != math.MaxUint32 {
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

// TestDecodeRadiusAcceptsZero verifies that RADI=0 is accepted across all wire
// groups. Drafts 10+ §6.2.5 mandate RADI ≥ 3 as a server MUST, but the client
// is liberal since RADI is advisory (see decodeRadius).
func TestDecodeRadiusAcceptsZero(t *testing.T) {
	for _, g := range []wireGroup{groupGoogle, groupD01, groupD05, groupD07, groupD08, groupD10, groupD12, groupD14} {
		if _, err := decodeRadius(make([]byte, 4), g); err != nil {
			t.Fatalf("RADI=0 should be accepted for group %d: %v", g, err)
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

// TestDecodeZeroTags verifies that a zero-tag message returns an empty map.
func TestDecodeZeroTags(t *testing.T) {
	msg, err := Decode([]byte{0, 0, 0, 0})
	if err != nil {
		t.Fatalf("zero-tag message should be valid: %v", err)
	}
	if len(msg) != 0 {
		t.Fatalf("expected empty map, got %d entries", len(msg))
	}
}

// TestDecodeZeroTagsTrailingData verifies that trailing data after a zero-tag
// header is rejected.
func TestDecodeZeroTagsTrailingData(t *testing.T) {
	if _, err := Decode([]byte{0, 0, 0, 0, 0xff}); err == nil {
		t.Fatal("expected error for trailing data")
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

// TestSupportedAscending verifies the internal VERS list is ascending.
func TestSupportedAscending(t *testing.T) {
	vs := supportedVersions
	for i := 1; i < len(vs); i++ {
		if vs[i] <= vs[i-1] {
			t.Fatalf("not ascending at index %d", i)
		}
	}
}

// TestSupportedBytesLength verifies the pre-encoded VERS byte length.
func TestSupportedBytesLength(t *testing.T) {
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
// rejected (§5.1.3 drafts 14+).
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

// TestParseRequestRejectsSRVWrongLengthD12 verifies that drafts 10+ reject an
// SRV tag whose length is not 32 bytes (exercised here with a draft-12
// request).
func TestParseRequestRejectsSRVWrongLengthD12(t *testing.T) {
	nonce := randBytes(t, 32)
	msg, _ := encode(map[uint32][]byte{
		TagNONC: nonce,
		TagVER:  {0x0c, 0x00, 0x00, 0x80}, // draft-12
		TagSRV:  make([]byte, 16),         // wrong length
		TagZZZZ: make([]byte, 900),
	})
	if _, err := ParseRequest(wrapPacket(msg)); err == nil {
		t.Fatal("expected SRV length rejection for draft-12")
	}
}

// TestParseRequestAcceptsShortSRVPreD10 verifies that pre-draft-10 VER lists do
// not enforce the SRV-length rule (drafts 05–09 did not constrain SRV length).
func TestParseRequestAcceptsShortSRVPreD10(t *testing.T) {
	nonce := randBytes(t, 32)
	msg, _ := encode(map[uint32][]byte{
		TagNONC: nonce,
		TagVER:  {0x08, 0x00, 0x00, 0x80}, // draft-08
		TagSRV:  make([]byte, 16),
		TagZZZZ: make([]byte, 900),
	})
	if _, err := ParseRequest(wrapPacket(msg)); err != nil {
		t.Fatalf("expected draft-08 short SRV to be accepted: %v", err)
	}
}

// TestParseRequestRejectsNonceVersionMismatch verifies that a request whose
// nonce length does not match its declared max version is rejected.
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

// TestParseRequestRejectsFramedMissingVER verifies a framed (ROUGHTIM header)
// request without a VER tag is rejected.
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

// TestParseRequestRejectsUnframedWithVER verifies that an unframed request
// carrying a VER tag is rejected.
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

// TestParseRequestRejectsVersionGoogleInVER verifies that VersionGoogle (0)
// inside a VER list is rejected.
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

// TestNewCertificateRejectsInvalidWindow verifies that MINT >= MAXT is
// rejected.
func TestNewCertificateRejectsInvalidWindow(t *testing.T) {
	_, onlineSK, _ := ed25519.GenerateKey(rand.Reader)
	_, rootSK, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()

	if _, err := NewCertificate(now, now, onlineSK, rootSK); err == nil {
		t.Fatal("expected error for MINT == MAXT")
	}
	if _, err := NewCertificate(now.Add(time.Hour), now, onlineSK, rootSK); err == nil {
		t.Fatal("expected error for MINT > MAXT")
	}
	if _, err := NewCertificate(now, now.Add(time.Hour), onlineSK, rootSK); err != nil {
		t.Fatalf("unexpected error for valid window: %v", err)
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
			if !bytes.Equal(delegationContext(g), delegationContext(prev)) ||
				usesMJDMicroseconds(g) != usesMJDMicroseconds(prev) {
				t.Fatalf("groups %d and %d have same cache key but different behavior", prev, g)
			}
		}
		seen[k] = g
	}
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

// TestMerkleTreeTwoLeaves verifies root and sibling paths for a balanced tree
// under groupD12's node-first convention: parent = H(0x01 || right || left).
func TestMerkleTreeTwoLeaves(t *testing.T) {
	d0 := bytes.Repeat([]byte{0xaa}, 32)
	d1 := bytes.Repeat([]byte{0xbb}, 32)
	tree := newMerkleTree(groupD12, [][]byte{d0, d1})
	h0, h1 := leafHash(groupD12, d0), leafHash(groupD12, d1)
	if !bytes.Equal(tree.rootHash, nodeHash(groupD12, h1, h0)) {
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

	// Power-of-2 padding yields [h0, h1, h2, h2] under node-first
	n01 := nodeHash(groupD12, h1, h0)
	n22 := nodeHash(groupD12, h2, h2)
	wantRoot := nodeHash(groupD12, n22, n01)
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
	n01, n23 := nodeHash(groupD12, h[1], h[0]), nodeHash(groupD12, h[3], h[2])
	if !bytes.Equal(tree.rootHash, nodeHash(groupD12, n23, n01)) {
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
						hash = nodeHash(groupD12, sib, hash)
					} else {
						hash = nodeHash(groupD12, hash, sib)
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

// TestCreateRepliesZeroMidpoint verifies that a zero midpoint causes
// CreateReplies to self-timestamp. The resulting reply must verify and its MIDP
// must be close to time.Now().
func TestCreateRepliesZeroMidpoint(t *testing.T) {
	cert, rootSK := testCert(t)
	rootPK := rootSK.Public().(ed25519.PublicKey)

	for _, tc := range []struct {
		ver     Version
		hasType bool
	}{
		{VersionGoogle, false},
		{VersionDraft08, false},
		{VersionDraft12, true},
	} {
		t.Run(tc.ver.ShortString(), func(t *testing.T) {
			nonce, raw, err := CreateRequest([]Version{tc.ver}, rand.Reader, nil)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := ParseRequest(raw)
			if err != nil {
				t.Fatal(err)
			}
			before := time.Now()
			replies, err := CreateReplies(tc.ver, []Request{*parsed}, time.Time{}, time.Second, cert)
			after := time.Now()
			if err != nil || len(replies) != 1 {
				t.Fatalf("CreateReplies: %v (len=%d)", err, len(replies))
			}
			midpoint, _, err := VerifyReply([]Version{tc.ver}, replies[0], rootPK, nonce, raw)
			if err != nil {
				t.Fatalf("VerifyReply: %v", err)
			}
			if midpoint.Before(before.Add(-time.Second)) || midpoint.After(after.Add(time.Second)) {
				t.Fatalf("midpoint %v not between %v and %v (±1s for rounding)", midpoint, before, after)
			}
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
// The client includes TYPE in the request, so draft-12 maps to groupD14.
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

// TestCreateRequestDraft01 verifies a draft 01 request with 64-byte nonce.
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

// TestCreateRequestIETF verifies that IETF requests are 1024 bytes (including
// ROUGHTIM header), contain VER, and can be parsed by ParseRequest.
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

// TestCreateRequestDraft12 verifies that draft 12 requests include TYPE=0. The
// client always sends TYPE to signal draft-14+ support; if the server responds
// without TYPE the client falls back to groupD12.
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

// TestCreateRequestRejectsEmpty verifies that an empty version list is
// rejected.
func TestCreateRequestRejectsEmpty(t *testing.T) {
	if _, _, err := CreateRequest(nil, rand.Reader, nil); err == nil {
		t.Fatal("expected error")
	}
}

// TestVerifyReplyAllVersions exercises the full client/server round-trip for
// every supported version (Google + drafts 01–12, where 12 covers wire-version
// 0x8000000c shared by drafts 12–19). Each subtest creates a request, parses it
// as the server, signs a reply, and verifies the reply as the client.
func TestVerifyReplyAllVersions(t *testing.T) {
	for _, v := range append([]Version{VersionGoogle}, supportedVersions...) {
		t.Run(v.ShortString(), func(t *testing.T) {
			verifyRoundTrip(t, []Version{v}, v)
		})
	}
}

// TestVerifyNoVersionDowngradeSingleEntryVERS verifies that a single-entry VERS
// list passes the downgrade check when it matches the chosen version.
func TestVerifyNoVersionDowngradeSingleEntryVERS(t *testing.T) {
	verBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(verBuf, uint32(VersionDraft12))
	srep := map[uint32][]byte{
		TagVER:  verBuf,
		TagVERS: verBuf,
	}
	if err := verifyNoVersionDowngrade(srep, []Version{VersionDraft12}); err != nil {
		t.Fatalf("single-entry VERS should verify: %v", err)
	}
}

// TestVerifyReplyRejectsBadRootPK verifies that a wrong root public key is
// rejected.
func TestVerifyReplyRejectsBadRootPK(t *testing.T) {
	cert, _ := testCert(t)
	nonce, req, _ := CreateRequest([]Version{VersionGoogle}, rand.Reader, nil)
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
	nonce, req, _ := CreateRequest([]Version{VersionGoogle}, rand.Reader, nil)
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
	nonce, req, _ := CreateRequest([]Version{VersionDraft12}, rand.Reader, nil)
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

	nonce, req, _ := CreateRequest([]Version{VersionGoogle}, rand.Reader, nil)
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

	reqs := make([]Request, 4)
	var targetNonce, targetReq []byte
	for i := range 4 {
		n, r, err := CreateRequest([]Version{VersionGoogle}, rand.Reader, nil)
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
		n, r, err := CreateRequest([]Version{VersionDraft12}, rand.Reader, nil)
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

// TestCreateRepliesRejectsMixedHasType verifies that a batch where requests
// share VersionDraft12 but differ in HasType (draft 12-13 vs 14-19 clients) is
// rejected. Mixed HasType values resolve to different wire groups, so the
// shared SREP/Merkle/CERT would be built for the wrong group for some requests.
func TestCreateRepliesRejectsMixedHasType(t *testing.T) {
	cert, _ := testCert(t)

	_, req0, err := CreateRequest([]Version{VersionDraft12}, rand.Reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	parsed0, err := ParseRequest(req0)
	if err != nil {
		t.Fatal(err)
	}
	parsed0.HasType = false // simulate a draft 12-13 client

	_, req1, err := CreateRequest([]Version{VersionDraft12}, rand.Reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	parsed1, err := ParseRequest(req1)
	if err != nil {
		t.Fatal(err)
	}

	reqs := []Request{*parsed0, *parsed1}
	if _, err := CreateReplies(VersionDraft12, reqs, time.Now(), time.Second, cert); err == nil {
		t.Fatal("expected error for mixed HasType batch")
	}
}

// TestCreateRepliesBatchDraft01Rejected verifies that multi-request batches are
// rejected for drafts 01-02 (NONC is inside SREP).
func TestCreateRepliesBatchDraft01Rejected(t *testing.T) {
	cert, _ := testCert(t)
	nonce0 := randBytes(t, 64)
	nonce1 := randBytes(t, 64)
	raw0 := buildIETFRequest(nonce0, []Version{VersionDraft01}, false)
	raw1 := buildIETFRequest(nonce1, []Version{VersionDraft01}, false)
	reqs := []Request{
		{Nonce: nonce0, Versions: []Version{VersionDraft01}, RawPacket: raw0},
		{Nonce: nonce1, Versions: []Version{VersionDraft01}, RawPacket: raw1},
	}
	if _, err := CreateReplies(VersionDraft01, reqs, time.Now(), time.Second, cert); err == nil {
		t.Fatal("expected error for multi-request draft-01 batch")
	}
}

// TestExtractResponseVERTopLevel verifies VER extraction from the top-level
// response.
func TestExtractResponseVERTopLevel(t *testing.T) {
	resp := map[uint32][]byte{
		TagVER: {0x08, 0x00, 0x00, 0x80},
	}
	ver, ok := extractResponseVER(resp, nil)
	if !ok || ver != VersionDraft08 {
		t.Fatal("expected VersionDraft08 from top-level VER")
	}
}

// TestExtractResponseVERFromSREP verifies VER extraction from inside SREP when
// no top-level VER is present.
func TestExtractResponseVERFromSREP(t *testing.T) {
	srep := map[uint32][]byte{
		TagVER:  {0x0c, 0x00, 0x00, 0x80},
		TagRADI: make([]byte, 4),
		TagMIDP: make([]byte, 8),
		TagROOT: make([]byte, 32),
	}
	resp := map[uint32][]byte{}
	ver, ok := extractResponseVER(resp, srep)
	if !ok || ver != VersionDraft12 {
		t.Fatal("expected VersionDraft12 from SREP VER")
	}
}

// TestExtractResponseVERMissing verifies that a response with no VER anywhere
// returns false.
func TestExtractResponseVERMissing(t *testing.T) {
	resp := map[uint32][]byte{TagSIG: make([]byte, 64)}
	if _, ok := extractResponseVER(resp, nil); ok {
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

	nonce, req, err := CreateRequest(versions, rand.Reader, nil)
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
	binary.LittleEndian.PutUint32(encoded[4:8], 4)
	if _, err := Decode(encoded[:16]); err == nil {
		t.Fatal("expected error for value out of bounds")
	}
}

// TestParseRequestRejectsCorruptIETF verifies that an IETF request with an
// invalid message body after the ROUGHTIM header is rejected.
func TestParseRequestRejectsCorruptIETF(t *testing.T) {
	pkt := wrapPacket([]byte{0xff, 0xff, 0xff, 0xff})
	if _, err := ParseRequest(pkt); err == nil {
		t.Fatal("expected error for corrupt IETF request body")
	}
}

// TestParseRequestRejectsTruncatedIETF verifies that a truncated ROUGHTIM
// packet is rejected.
func TestParseRequestRejectsTruncatedIETF(t *testing.T) {
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
	if _, _, err := CreateRequest([]Version{VersionDraft08}, &failReader{}, nil); err == nil {
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

// TestVerifyReplySREPRejectsNilSREP verifies that verifyReplySREP rejects a nil
// pre-decoded SREP (the caller decodes SREP once and passes it in).
func TestVerifyReplySREPRejectsNilSREP(t *testing.T) {
	if _, _, err := verifyReplySREP(nil, map[uint32][]byte{}, nil, nil, groupGoogle); err == nil {
		t.Fatal("expected error for nil SREP")
	}
}

// TestVerifyReplySREPRejectsMissingMIDP verifies that verifyReplySREP rejects a
// SREP without MIDP.
func TestVerifyReplySREPRejectsMissingMIDP(t *testing.T) {
	srep := map[uint32][]byte{
		TagRADI: make([]byte, 4),
		TagROOT: make([]byte, 64),
	}
	if _, _, err := verifyReplySREP(srep, map[uint32][]byte{}, nil, nil, groupGoogle); err == nil {
		t.Fatal("expected error for missing MIDP")
	}
}

// TestVerifyReplySREPRejectsMissingRADI verifies that verifyReplySREP rejects a
// SREP without RADI.
func TestVerifyReplySREPRejectsMissingRADI(t *testing.T) {
	srep := map[uint32][]byte{
		TagMIDP: make([]byte, 8),
		TagROOT: make([]byte, 64),
	}
	if _, _, err := verifyReplySREP(srep, map[uint32][]byte{}, nil, nil, groupGoogle); err == nil {
		t.Fatal("expected error for missing RADI")
	}
}

// TestVerifyReplySREPRejectsBadROOT verifies that verifyReplySREP rejects a
// SREP with a wrong-length ROOT hash.
func TestVerifyReplySREPRejectsBadROOT(t *testing.T) {
	srep := map[uint32][]byte{
		TagMIDP: make([]byte, 8),
		TagRADI: make([]byte, 4),
		TagROOT: make([]byte, 16), // should be 64 for Google
	}
	if _, _, err := verifyReplySREP(srep, map[uint32][]byte{}, nil, nil, groupGoogle); err == nil {
		t.Fatal("expected error for bad ROOT size")
	}
}

// TestVerifyReplySREPRejectsBadMIDP verifies that verifyReplySREP rejects a
// SREP with a non-8-byte MIDP.
func TestVerifyReplySREPRejectsBadMIDP(t *testing.T) {
	nonce := make([]byte, 64)
	root := leafHash(groupGoogle, nonce)
	var indx [4]byte
	srep := map[uint32][]byte{
		TagMIDP: make([]byte, 4), // should be 8
		TagRADI: make([]byte, 4),
		TagROOT: root,
	}
	resp := map[uint32][]byte{
		TagINDX: indx[:],
		TagPATH: {},
	}
	if _, _, err := verifyReplySREP(srep, resp, nonce, nil, groupGoogle); err == nil {
		t.Fatal("expected error for bad MIDP size")
	}
}

// TestVerifyReplySREPRejectsBadRADI verifies that verifyReplySREP rejects a
// SREP with a non-4-byte RADI.
func TestVerifyReplySREPRejectsBadRADI(t *testing.T) {
	nonce := make([]byte, 64)
	root := leafHash(groupGoogle, nonce)
	var indx [4]byte
	srep := map[uint32][]byte{
		TagMIDP: make([]byte, 8),
		TagRADI: make([]byte, 8), // should be 4
		TagROOT: root,
	}
	resp := map[uint32][]byte{
		TagINDX: indx[:],
		TagPATH: {},
	}
	if _, _, err := verifyReplySREP(srep, resp, nonce, nil, groupGoogle); err == nil {
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

// TestCreateRequestEarlyDraftHeader verifies that IETF drafts 01–04 client
// requests carry the ROUGHTIM packet header (§5/§6).
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
	nonce, req, _ := CreateRequest([]Version{VersionDraft12}, rand.Reader, nil)
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
// strictly ascending are rejected when the highest declared version is drafts
// 12+ (§5.1.1 MUST).
func TestParseRequestRejectsUnsortedVER(t *testing.T) {
	nonce := randBytes(t, 32)
	// Out of order: Draft12 then Draft10 (max=12, gate applies)
	raw := buildIETFRequest(nonce, []Version{VersionDraft12, VersionDraft10}, false)
	if _, err := ParseRequest(raw); err == nil {
		t.Fatal("expected error for unsorted VER list containing drafts 12+")
	}
	// Duplicates within drafts 12+ must also be rejected
	raw = buildIETFRequest(nonce, []Version{VersionDraft12, VersionDraft12}, false)
	if _, err := ParseRequest(raw); err == nil {
		t.Fatal("expected error for repeating VER list containing drafts 12+")
	}
}

// TestParseRequestVERVersionRules verifies VER ordering/duplicate rules per
// draft group: drafts 10-11 (§6.1.1) forbid duplicates but not unsorted order,
// drafts 12+ (§5.1.1) additionally require strictly ascending order.
func TestParseRequestVERVersionRules(t *testing.T) {
	// Drafts 10-11: unsorted is allowed, duplicates are not
	nonce := randBytes(t, 32)
	raw := buildIETFRequest(nonce, []Version{VersionDraft10, VersionDraft05}, false)
	if _, err := ParseRequest(raw); err != nil {
		t.Fatalf("drafts 10-11 unsorted VER list should be accepted: %v", err)
	}
	raw = buildIETFRequest(nonce, []Version{VersionDraft10, VersionDraft10}, false)
	if _, err := ParseRequest(raw); err == nil {
		t.Fatal("drafts 10-11 duplicate VER list should be rejected (§6.1.1)")
	}
}

// TestDecodeRejectsOversizedInput verifies the [Decode] size cap.
func TestDecodeRejectsOversizedInput(t *testing.T) {
	if _, err := Decode(make([]byte, maxMessageSize+1)); err == nil {
		t.Fatal("expected error for oversized message")
	}
}

// TestVerifyReplyDetectsDowngrade verifies that a server claiming a lower
// version in the signed SREP than the client's best mutually-supported version
// is rejected.
func TestVerifyReplyDetectsDowngrade(t *testing.T) {
	cert, _ := testCert(t)
	rootPK := cert.rootPK
	clientVers := []Version{VersionDraft11, VersionDraft12}
	nonce, req, _ := CreateRequest(clientVers, rand.Reader, nil)
	parsed, _ := ParseRequest(req)
	// Sign a SREP claiming Draft11 while using draft-12 wire format
	g := groupD14
	tree := newMerkleTree(g, [][]byte{parsed.RawPacket})
	midpBuf := encodeTimestamp(time.Now(), g)
	var radiBuf [4]byte
	binary.LittleEndian.PutUint32(radiBuf[:], radiSeconds(time.Second))
	var verBuf [4]byte
	binary.LittleEndian.PutUint32(verBuf[:], uint32(VersionDraft11)) // downgrade attempt
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
// 1 is rejected (§5.2.3).
func TestVerifyReplyRejectsResponseTYPENot1(t *testing.T) {
	cert, _ := testCert(t)
	rootPK := cert.rootPK
	clientVers := []Version{VersionDraft12}
	nonce, req, _ := CreateRequest(clientVers, rand.Reader, nil)
	parsed, _ := ParseRequest(req)
	g := groupD14
	tree := newMerkleTree(g, [][]byte{parsed.RawPacket})
	midpBuf := encodeTimestamp(time.Now(), g)
	var radiBuf [4]byte
	binary.LittleEndian.PutUint32(radiBuf[:], radiSeconds(time.Second))
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

// TestVerifyNoVersionDowngradeRejectsLargeVERS verifies that a server VERS list
// with more than 32 entries is rejected (drafts 14+ §5.2.5).
func TestVerifyNoVersionDowngradeRejectsLargeVERS(t *testing.T) {
	cert, rootSK := testCert(t)
	rootPK := rootSK.Public().(ed25519.PublicKey)

	g := groupD14
	nonce := randBytes(t, 32)
	req := buildIETFRequest(nonce, []Version{VersionDraft12}, true)
	parsed, _ := ParseRequest(req)
	tree := newMerkleTree(g, [][]byte{parsed.RawPacket})

	midpBuf := encodeTimestamp(time.Now(), g)
	var radiBuf [4]byte
	binary.LittleEndian.PutUint32(radiBuf[:], radiSeconds(time.Second))
	var verBuf [4]byte
	binary.LittleEndian.PutUint32(verBuf[:], uint32(VersionDraft12))

	largeVERS := make([]byte, 33*4)
	for i := range 33 {
		binary.LittleEndian.PutUint32(largeVERS[i*4:], uint32(0x80000001+i))
	}

	srepTags := map[uint32][]byte{
		TagRADI: radiBuf[:],
		TagMIDP: midpBuf[:],
		TagROOT: tree.rootHash,
		TagVER:  verBuf[:],
		TagVERS: largeVERS,
	}
	srepBytes, _ := encode(srepTags)
	toSign := make([]byte, len(responseCtx)+len(srepBytes))
	copy(toSign, responseCtx)
	copy(toSign[len(responseCtx):], srepBytes)
	srepSig := ed25519.Sign(cert.onlineSK, toSign)

	var typeBuf [4]byte
	binary.LittleEndian.PutUint32(typeBuf[:], 1)
	resp := map[uint32][]byte{
		TagSIG:  srepSig,
		TagSREP: srepBytes,
		TagCERT: cert.certBytes(g),
		TagPATH: nil,
		TagINDX: make([]byte, 4),
		TagNONC: nonce,
		TagTYPE: typeBuf[:],
	}
	replyMsg, _ := encode(resp)
	reply := wrapPacket(replyMsg)
	if _, _, err := VerifyReply([]Version{VersionDraft12}, reply, rootPK, nonce, req); err == nil {
		t.Fatal("expected error for VERS with >32 entries")
	}
}

// TestMerkleNodeFirstConvention verifies that the Merkle tree convention
// differs between wire groups: groupD05–groupD12 use node-first, others use
// hash-first.
func TestMerkleNodeFirstConvention(t *testing.T) {
	d0 := bytes.Repeat([]byte{0xaa}, 32)
	d1 := bytes.Repeat([]byte{0xbb}, 32)

	treeG := newMerkleTree(groupGoogle, [][]byte{d0, d1})
	h0g, h1g := leafHash(groupGoogle, d0), leafHash(groupGoogle, d1)
	if !bytes.Equal(treeG.rootHash, nodeHash(groupGoogle, h0g, h1g)) {
		t.Fatal("groupGoogle: expected hash-first")
	}

	tree08 := newMerkleTree(groupD08, [][]byte{d0, d1})
	h0_08, h1_08 := leafHash(groupD08, d0), leafHash(groupD08, d1)
	if !bytes.Equal(tree08.rootHash, nodeHash(groupD08, h1_08, h0_08)) {
		t.Fatal("groupD08: expected node-first")
	}

	// groupD14 reverted to hash-first (draft 16+)
	tree14 := newMerkleTree(groupD14, [][]byte{d0, d1})
	h0_14, h1_14 := leafHash(groupD14, d0), leafHash(groupD14, d1)
	if !bytes.Equal(tree14.rootHash, nodeHash(groupD14, h0_14, h1_14)) {
		t.Fatal("groupD14: expected hash-first")
	}
}

// TestMerkleCrossConventionRejected asserts a proof built under one Merkle
// convention fails verification under the other.
func TestMerkleCrossConventionRejected(t *testing.T) {
	leaf0 := bytes.Repeat([]byte{0xaa}, 32)
	leaf1 := bytes.Repeat([]byte{0xbb}, 32)
	leaves := [][]byte{leaf0, leaf1}

	nodeFirst := newMerkleTree(groupD08, leaves)
	hashFirst := newMerkleTree(groupD14, leaves)

	var indx0 [4]byte
	binary.LittleEndian.PutUint32(indx0[:], 0)

	nfResp := map[uint32][]byte{
		TagINDX: indx0[:],
		TagPATH: bytes.Join(nodeFirst.paths[0], nil),
	}
	if err := verifyMerkle(nfResp, leaf0, nodeFirst.rootHash, groupD08); err != nil {
		t.Fatalf("node-first self-verify: %v", err)
	}
	if err := verifyMerkle(nfResp, leaf0, nodeFirst.rootHash, groupD14); !errors.Is(err, ErrMerkleMismatch) {
		t.Fatalf("node-first proof under hash-first verifier: err=%v want ErrMerkleMismatch", err)
	}

	hfResp := map[uint32][]byte{
		TagINDX: indx0[:],
		TagPATH: bytes.Join(hashFirst.paths[0], nil),
	}
	if err := verifyMerkle(hfResp, leaf0, hashFirst.rootHash, groupD14); err != nil {
		t.Fatalf("hash-first self-verify: %v", err)
	}
	if err := verifyMerkle(hfResp, leaf0, hashFirst.rootHash, groupD08); !errors.Is(err, ErrMerkleMismatch) {
		t.Fatalf("hash-first proof under node-first verifier: err=%v want ErrMerkleMismatch", err)
	}
}

// TestCreateRequestPaddingTag verifies that CreateRequest emits the correct
// padding tag per wire group: PAD\xff for Google, PAD\0 for IETF drafts 01–07,
// and ZZZZ for IETF drafts 08+.
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

// TestLeafHashSHA512_256 verifies that SHA-512/256 groups (groupD02, groupD07)
// produce distinct Merkle leaf hashes from SHA-512-truncated groups.
func TestLeafHashSHA512_256(t *testing.T) {
	data := []byte("test SHA-512/256 leaf")
	h256 := sha512.Sum512_256(append([]byte{0x00}, data...))
	h512 := sha512.Sum512(append([]byte{0x00}, data...))

	for _, g := range []wireGroup{groupD02, groupD07} {
		got := leafHash(g, data)
		if !bytes.Equal(got, h256[:]) {
			t.Fatalf("group %d leafHash should use SHA-512/256", g)
		}
		if bytes.Equal(got, h512[:32]) {
			t.Fatalf("group %d leafHash matches SHA-512 truncated (should be SHA-512/256)", g)
		}
	}
}

// TestNodeHashSHA512_256 verifies that SHA-512/256 groups produce nodeHash
// using the SHA-512/256 algorithm.
func TestNodeHashSHA512_256(t *testing.T) {
	left := bytes.Repeat([]byte{0xcc}, 32)
	right := bytes.Repeat([]byte{0xdd}, 32)
	buf := append([]byte{0x01}, left...)
	buf = append(buf, right...)
	want256 := sha512.Sum512_256(buf)
	want512 := sha512.Sum512(buf)

	for _, g := range []wireGroup{groupD02, groupD07} {
		got := nodeHash(g, left, right)
		if !bytes.Equal(got, want256[:]) {
			t.Fatalf("group %d nodeHash should use SHA-512/256", g)
		}
		if bytes.Equal(got, want512[:32]) {
			t.Fatalf("group %d nodeHash matches SHA-512 truncated (should be SHA-512/256)", g)
		}
	}
}

// TestComputeSRV verifies the SRV tag value matches SHA-512(0xff ||
// pubkey)[:32].
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

// TestComputeSRVBadKeyLength verifies ComputeSRV returns nil for invalid key
// lengths.
func TestComputeSRVBadKeyLength(t *testing.T) {
	if got := ComputeSRV(make([]byte, 16)); got != nil {
		t.Fatal("expected nil for short key")
	}
	if got := ComputeSRV(nil); got != nil {
		t.Fatal("expected nil for nil key")
	}
}

// TestCreateRepliesBatchDraft03 verifies that multi-request batches succeed for
// draft-03+ (NONC at top level, enabling Merkle batching).
func TestCreateRepliesBatchDraft03(t *testing.T) {
	cert, _ := testCert(t)
	rootPK := cert.rootPK
	const n = 3
	reqs := make([]Request, n)
	nonces := make([][]byte, n)
	rawReqs := make([][]byte, n)
	for i := range n {
		nonce, req, err := CreateRequest([]Version{VersionDraft03}, rand.Reader, nil)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseRequest(req)
		if err != nil {
			t.Fatal(err)
		}
		reqs[i] = *parsed
		nonces[i] = nonce
		rawReqs[i] = req
	}
	replies, err := CreateReplies(VersionDraft03, reqs, time.Now(), time.Second, cert)
	if err != nil {
		t.Fatal(err)
	}
	for i := range n {
		if _, _, err := VerifyReply([]Version{VersionDraft03}, replies[i], rootPK, nonces[i], rawReqs[i]); err != nil {
			t.Fatalf("reply %d: %v", i, err)
		}
	}
}

// TestCreateRepliesBatchDraft02Rejected verifies that multi-request batches are
// rejected for draft-02 (NONC is inside SREP, same as draft-01).
func TestCreateRepliesBatchDraft02Rejected(t *testing.T) {
	cert, _ := testCert(t)
	nonce0 := randBytes(t, 64)
	nonce1 := randBytes(t, 64)
	raw0 := buildIETFRequest(nonce0, []Version{VersionDraft02}, false)
	raw1 := buildIETFRequest(nonce1, []Version{VersionDraft02}, false)
	reqs := []Request{
		{Nonce: nonce0, Versions: []Version{VersionDraft02}, RawPacket: raw0},
		{Nonce: nonce1, Versions: []Version{VersionDraft02}, RawPacket: raw1},
	}
	if _, err := CreateReplies(VersionDraft02, reqs, time.Now(), time.Second, cert); err == nil {
		t.Fatal("expected error for multi-request draft-02 batch")
	}
}

// TestExtractVersionFromReply verifies the ExtractVersion public API for IETF
// replies (Google has no VER tag so it returns false).
func TestExtractVersionFromReply(t *testing.T) {
	for _, ver := range []Version{VersionDraft08, VersionDraft12} {
		t.Run(ver.ShortString(), func(t *testing.T) {
			cert, _ := testCert(t)
			nonce, req, err := CreateRequest([]Version{ver}, rand.Reader, nil)
			if err != nil {
				t.Fatal(err)
			}
			_ = nonce
			parsed, err := ParseRequest(req)
			if err != nil {
				t.Fatal(err)
			}
			replies, err := CreateReplies(ver, []Request{*parsed}, time.Now(), time.Second, cert)
			if err != nil {
				t.Fatal(err)
			}
			got, ok := ExtractVersion(replies[0])
			if !ok {
				t.Fatal("ExtractVersion returned false")
			}
			if ver == VersionDraft12 && got != VersionDraft12 {
				t.Fatalf("got %s, want %s", got, VersionDraft12)
			}
		})
	}

	t.Run("Google", func(t *testing.T) {
		cert, _ := testCert(t)
		_, req, err := CreateRequest([]Version{VersionGoogle}, rand.Reader, nil)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseRequest(req)
		if err != nil {
			t.Fatal(err)
		}
		replies, err := CreateReplies(VersionGoogle, []Request{*parsed}, time.Now(), time.Second, cert)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := ExtractVersion(replies[0]); ok {
			t.Fatal("Google-Roughtime should not have extractable version")
		}
	})
}

// TestVerifyReplyRejectsMismatchedNONC verifies that a present but wrong
// top-level NONC in drafts 03+ is rejected.
func TestVerifyReplyRejectsMismatchedNONC(t *testing.T) {
	cert, _ := testCert(t)
	rootPK := cert.rootPK
	nonce, req, err := CreateRequest([]Version{VersionDraft08}, rand.Reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	replies, err := CreateReplies(VersionDraft08, []Request{*parsed}, time.Now(), time.Second, cert)
	if err != nil {
		t.Fatal(err)
	}

	reply := replies[0]
	inner, err := unwrapPacket(reply)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := Decode(inner)
	if err != nil {
		t.Fatal(err)
	}
	badNonce := make([]byte, len(resp[TagNONC]))
	copy(badNonce, resp[TagNONC])
	badNonce[0] ^= 0xff
	resp[TagNONC] = badNonce
	tampered, err := encode(resp)
	if err != nil {
		t.Fatal(err)
	}
	tamperedReply := wrapPacket(tampered)

	if _, _, err := VerifyReply([]Version{VersionDraft08}, tamperedReply, rootPK, nonce, req); err == nil {
		t.Fatal("expected error for mismatched NONC")
	}
}

// TestVerifyReplyMidpointAtDELEBoundary verifies that midpoint exactly equal to
// MINT or MAXT passes validation.
func TestVerifyReplyMidpointAtDELEBoundary(t *testing.T) {
	rootSK, onlineSK := testKeys(t)
	rootPK := rootSK.Public().(ed25519.PublicKey)
	now := time.Now().Truncate(time.Second)
	cert, err := NewCertificate(now, now.Add(time.Hour), onlineSK, rootSK)
	if err != nil {
		t.Fatal(err)
	}

	// MIDP == MINT
	nonce, req, err := CreateRequest([]Version{VersionDraft08}, rand.Reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	replies, err := CreateReplies(VersionDraft08, []Request{*parsed}, now, time.Second, cert)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyReply([]Version{VersionDraft08}, replies[0], rootPK, nonce, req); err != nil {
		t.Fatalf("midpoint=MINT should pass: %v", err)
	}

	// MIDP == MAXT
	maxtTime := now.Add(time.Hour)
	nonce2, req2, err := CreateRequest([]Version{VersionDraft08}, rand.Reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	parsed2, err := ParseRequest(req2)
	if err != nil {
		t.Fatal(err)
	}
	replies2, err := CreateReplies(VersionDraft08, []Request{*parsed2}, maxtTime, time.Second, cert)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyReply([]Version{VersionDraft08}, replies2[0], rootPK, nonce2, req2); err != nil {
		t.Fatalf("midpoint=MAXT should pass: %v", err)
	}
}

// TestVerifyReplyToleratesUnknownTags verifies that extra unknown tags in a
// response do not break verification.
func TestVerifyReplyToleratesUnknownTags(t *testing.T) {
	cert, _ := testCert(t)
	rootPK := cert.rootPK
	nonce, req, err := CreateRequest([]Version{VersionDraft08}, rand.Reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	replies, err := CreateReplies(VersionDraft08, []Request{*parsed}, time.Now(), time.Second, cert)
	if err != nil {
		t.Fatal(err)
	}

	inner, err := unwrapPacket(replies[0])
	if err != nil {
		t.Fatal(err)
	}
	resp, err := Decode(inner)
	if err != nil {
		t.Fatal(err)
	}
	resp[0xFFFFFFFC] = make([]byte, 4) // unknown tag
	tampered, err := encode(resp)
	if err != nil {
		t.Fatal(err)
	}
	tamperedReply := wrapPacket(tampered)

	if _, _, err := VerifyReply([]Version{VersionDraft08}, tamperedReply, rootPK, nonce, req); err != nil {
		t.Fatalf("unknown tag should not break verification: %v", err)
	}
}

// TestVerifyNoVersionDowngradeRejectsUnsortedVERS verifies that an unsorted
// VERS list in SREP is rejected.
func TestVerifyNoVersionDowngradeRejectsUnsortedVERS(t *testing.T) {
	srepVER := make([]byte, 4)
	binary.LittleEndian.PutUint32(srepVER, uint32(VersionDraft12))

	unsortedVERS := make([]byte, 8)
	binary.LittleEndian.PutUint32(unsortedVERS[0:], uint32(VersionDraft12))
	binary.LittleEndian.PutUint32(unsortedVERS[4:], uint32(VersionDraft08))

	srepInner := map[uint32][]byte{
		TagROOT: make([]byte, 32),
		TagMIDP: make([]byte, 8),
		TagRADI: {0x03, 0x00, 0x00, 0x00},
		TagVER:  srepVER,
		TagVERS: unsortedVERS,
	}
	srepBytes, err := encode(srepInner)
	if err != nil {
		t.Fatal(err)
	}
	srep, err := Decode(srepBytes)
	if err != nil {
		t.Fatal(err)
	}
	err = verifyNoVersionDowngrade(srep, []Version{VersionDraft12})
	if err == nil {
		t.Fatal("expected error for unsorted VERS in SREP")
	}
	if got := err.Error(); got != "protocol: VERS not sorted in ascending order" {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestExtractResponseVERPrefersSREP verifies that when both top-level VER and
// SREP VER are present, the SREP VER takes precedence.
func TestExtractResponseVERPrefersSREP(t *testing.T) {
	srepInner := map[uint32][]byte{
		TagROOT: make([]byte, 32),
		TagMIDP: make([]byte, 8),
		TagRADI: {0x03, 0x00, 0x00, 0x00},
	}
	srepVER := make([]byte, 4)
	binary.LittleEndian.PutUint32(srepVER, uint32(VersionDraft12))
	srepInner[TagVER] = srepVER
	srepBytes, err := encode(srepInner)
	if err != nil {
		t.Fatal(err)
	}

	topVER := make([]byte, 4)
	binary.LittleEndian.PutUint32(topVER, uint32(VersionDraft08))
	resp := map[uint32][]byte{
		TagSREP: srepBytes,
		TagVER:  topVER,
	}

	srep, err := Decode(srepBytes)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := extractResponseVER(resp, srep)
	if !ok {
		t.Fatal("extractResponseVER returned false")
	}
	if got != VersionDraft12 {
		t.Fatalf("got %s, want %s (SREP VER should take precedence)", got, VersionDraft12)
	}
}

// TestCreateRepliesBatchDraft08 verifies that multi-request batches work for
// draft-08 (NONC at top level, node-first Merkle, Unix seconds).
func TestCreateRepliesBatchDraft08(t *testing.T) {
	cert, _ := testCert(t)
	rootPK := cert.rootPK
	const n = 4
	reqs := make([]Request, n)
	nonces := make([][]byte, n)
	rawReqs := make([][]byte, n)
	for i := range n {
		nonce, req, err := CreateRequest([]Version{VersionDraft08}, rand.Reader, nil)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseRequest(req)
		if err != nil {
			t.Fatal(err)
		}
		reqs[i] = *parsed
		nonces[i] = nonce
		rawReqs[i] = req
	}
	replies, err := CreateReplies(VersionDraft08, reqs, time.Now(), time.Second, cert)
	if err != nil {
		t.Fatal(err)
	}
	for i := range n {
		if _, _, err := VerifyReply([]Version{VersionDraft08}, replies[i], rootPK, nonces[i], rawReqs[i]); err != nil {
			t.Fatalf("reply %d: %v", i, err)
		}
	}
}

// TestParseRequestRejectsOversizedVER verifies that a request with >32 VER
// entries is rejected.
func TestParseRequestRejectsOversizedVER(t *testing.T) {
	nonce := randBytes(t, 32)
	vers := make([]byte, 4*33) // 33 entries
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

// TestParseRequestRejectsTYPEWrongLength verifies that a TYPE tag with a length
// other than 4 bytes is rejected. The spec requires TYPE to be a uint32.
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

// TestParseRequestAcceptsVER32 verifies that a request with exactly 32 VER
// entries (the maximum allowed by drafts 14+) is accepted.
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

// TestVerifyReplyRejectsMismatchedNONCInSREP verifies that a tampered NONC
// inside SREP is detected for drafts 01–02 (which place NONC inside SREP rather
// than at the top level).
func TestVerifyReplyRejectsMismatchedNONCInSREP(t *testing.T) {
	for _, ver := range []Version{VersionDraft01, VersionDraft02} {
		t.Run(ver.ShortString(), func(t *testing.T) {
			reply, rootPK, nonce, req := validReply(t, ver, []Version{ver})

			// Tamper with the NONC inside SREP
			tampered := corruptReplyTag(t, reply, true, func(tags map[uint32][]byte) {
				srepBytes := tags[TagSREP]
				srepTags, err := Decode(srepBytes)
				if err != nil {
					t.Fatal(err)
				}
				srepNonce := srepTags[TagNONC]
				if len(srepNonce) == 0 {
					t.Fatal("expected NONC in SREP for this draft")
				}
				srepNonce[0] ^= 0xff
				srepTags[TagNONC] = srepNonce
				newSREP, err := encode(srepTags)
				if err != nil {
					t.Fatal(err)
				}
				tags[TagSREP] = newSREP
			})

			if _, _, err := VerifyReply([]Version{ver}, tampered, rootPK, nonce, req); err == nil {
				t.Fatal("expected error for tampered NONC in SREP")
			}
		})
	}
}

// TestMerkleTreeNonPowerOfTwoD14 verifies that non-power-of-2 batch sizes
// produce valid Merkle proofs for groupD14 (hash-first convention), mirroring
// TestMerkleTreeNonPowerOfTwo which covers groupD12 (node-first).
func TestMerkleTreeNonPowerOfTwoD14(t *testing.T) {
	for _, n := range []int{3, 5, 6, 7, 9, 15, 17} {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			leaves := make([][]byte, n)
			for i := range leaves {
				leaves[i] = randBytes(t, 32)
			}
			tree := newMerkleTree(groupD14, leaves)

			for i, d := range leaves {
				hash := leafHash(groupD14, d)
				index := uint32(i)
				for _, sib := range tree.paths[i] {
					// groupD14 uses hash-first: left-right by hash comparison
					if index&1 == 0 {
						hash = nodeHash(groupD14, hash, sib)
					} else {
						hash = nodeHash(groupD14, sib, hash)
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

// TestCreateRepliesBatchDraft14 verifies that multi-request batches work for
// drafts 14+ (TYPE tag present, hash-first Merkle, full-packet leaf).
func TestCreateRepliesBatchDraft14(t *testing.T) {
	cert, _ := testCert(t)
	rootPK := cert.rootPK
	const n = 5
	reqs := make([]Request, n)
	nonces := make([][]byte, n)
	rawReqs := make([][]byte, n)
	for i := range n {
		nonce, req, err := CreateRequest([]Version{VersionDraft12}, rand.Reader, nil)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseRequest(req)
		if err != nil {
			t.Fatal(err)
		}
		if !parsed.HasType {
			t.Fatal("CreateRequest for draft-12 should set TYPE")
		}
		reqs[i] = *parsed
		nonces[i] = nonce
		rawReqs[i] = req
	}
	replies, err := CreateReplies(VersionDraft12, reqs, time.Now(), time.Second, cert)
	if err != nil {
		t.Fatal(err)
	}
	for i := range n {
		mid, rad, err := VerifyReply([]Version{VersionDraft12}, replies[i], rootPK, nonces[i], rawReqs[i])
		if err != nil {
			t.Fatalf("reply %d: %v", i, err)
		}
		if mid.IsZero() || rad == 0 {
			t.Fatalf("reply %d: zero midpoint or radius", i)
		}
	}
}

// TestVerifyReplyToleratesMissingNONC verifies that a response missing the
// top-level NONC tag is tolerated for drafts 03+ because the Merkle proof
// already binds the nonce to the signed root.
func TestVerifyReplyToleratesMissingNONC(t *testing.T) {
	for _, ver := range []Version{VersionDraft03, VersionDraft05, VersionDraft08, VersionDraft10, VersionDraft12} {
		t.Run(ver.ShortString(), func(t *testing.T) {
			reply, rootPK, nonce, req := validReply(t, ver, []Version{ver})
			tampered := corruptReplyTag(t, reply, true, func(tags map[uint32][]byte) {
				delete(tags, TagNONC)
			})
			if _, _, err := VerifyReply([]Version{ver}, tampered, rootPK, nonce, req); err != nil {
				t.Fatalf("missing NONC should be tolerated (Merkle proof binds nonce): %v", err)
			}
		})
	}
}

// TestVerifyReplyRejectsMissingPATH verifies that a response missing the PATH
// tag is rejected.
func TestVerifyReplyRejectsMissingPATH(t *testing.T) {
	for _, ver := range []Version{VersionGoogle, VersionDraft08, VersionDraft12} {
		t.Run(ver.ShortString(), func(t *testing.T) {
			reply, rootPK, nonce, req := validReply(t, ver, []Version{ver})
			ietf := ver != VersionGoogle
			tampered := corruptReplyTag(t, reply, ietf, func(tags map[uint32][]byte) {
				delete(tags, TagPATH)
			})
			if _, _, err := VerifyReply([]Version{ver}, tampered, rootPK, nonce, req); err == nil {
				t.Fatal("expected error for missing PATH")
			}
		})
	}
}

// TestVerifyReplyToleratesMissingTYPE verifies that a draft-12+ response
// without TYPE falls back to groupD12 and still verifies, preserving
// compatibility with servers that predate TYPE.
func TestVerifyReplyToleratesMissingTYPE(t *testing.T) {
	reply, rootPK, nonce, req := validReply(t, VersionDraft12, []Version{VersionDraft12})
	tampered := corruptReplyTag(t, reply, true, func(tags map[uint32][]byte) {
		delete(tags, TagTYPE)
	})
	if _, _, err := VerifyReply([]Version{VersionDraft12}, tampered, rootPK, nonce, req); err != nil {
		t.Fatalf("expected graceful fallback without TYPE: %v", err)
	}
}

// TestVerifyReplyRejectsZeroRADI verifies that drafts 12+ reject a properly
// signed response carrying RADI=0 (§5.2.4 drafts 12-13, §5.2.5 drafts 14+). The
// SREP is re-signed with RADI=0 so signature validity is not the blocker.
func TestVerifyReplyRejectsZeroRADI(t *testing.T) {
	cert, _ := testCert(t)
	rootPK := cert.rootPK
	clientVers := []Version{VersionDraft12}
	nonce, req, err := CreateRequest(clientVers, rand.Reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	g := groupD14
	tree := newMerkleTree(g, [][]byte{parsed.RawPacket})
	midpBuf := encodeTimestamp(time.Now(), g)
	radiBuf := make([]byte, 4)
	var verBuf [4]byte
	binary.LittleEndian.PutUint32(verBuf[:], uint32(VersionDraft12))
	srepTags := map[uint32][]byte{
		TagRADI: radiBuf,
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
	pathBytes := make([]byte, 0)
	resp := map[uint32][]byte{
		TagSIG:  srepSig,
		TagSREP: srepBytes,
		TagCERT: cert.certBytes(g),
		TagPATH: pathBytes,
		TagINDX: make([]byte, 4),
		TagNONC: nonce,
		TagTYPE: func() []byte { b := make([]byte, 4); binary.LittleEndian.PutUint32(b, 1); return b }(),
	}
	replyMsg, _ := encode(resp)
	reply := wrapPacket(replyMsg)
	_, _, err = VerifyReply(clientVers, reply, rootPK, nonce, req)
	if err == nil {
		t.Fatal("expected RADI=0 rejection for draft-12+, got nil")
	}
	if !strings.Contains(err.Error(), "RADI must not be zero") {
		t.Fatalf("expected RADI=0 error, got: %v", err)
	}
}

// TestDecodeRadiusMJDMicroseconds verifies that decodeRadius returns
// microsecond-scale durations for MJD-microsecond groups (drafts 01–07).
func TestDecodeRadiusMJDMicroseconds(t *testing.T) {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, 1000000) // 1 second in microseconds
	for _, g := range []wireGroup{groupD01, groupD02, groupD03, groupD05, groupD07} {
		d, err := decodeRadius(buf, g)
		if err != nil {
			t.Fatalf("group %d: %v", g, err)
		}
		if d != time.Second {
			t.Fatalf("group %d: radius = %v, want 1s", g, d)
		}
	}
}

// TestRadiSecondsFloor verifies radiSeconds clamps sub-3s durations to 3.
func TestRadiSecondsFloor(t *testing.T) {
	got := radiSeconds(time.Second)
	if got != 3 {
		t.Fatalf("radiSeconds(1s) = %d, want 3", got)
	}
	got = radiSeconds(500 * time.Millisecond)
	if got != 3 {
		t.Fatalf("radiSeconds(500ms) = %d, want 3", got)
	}
	got = radiSeconds(10 * time.Second)
	if got != 10 {
		t.Fatalf("radiSeconds(10s) = %d, want 10", got)
	}
}

// TestNewCertificateGroupD14 verifies that NewCertificate produces valid
// certificates for groupD14 (same wire format as groupD12).
func TestNewCertificateGroupD14(t *testing.T) {
	rootSK, onlineSK := testKeys(t)
	rootPK := rootSK.Public().(ed25519.PublicKey)
	now := time.Now()
	cert, err := NewCertificate(now.Add(-time.Hour), now.Add(time.Hour), onlineSK, rootSK)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, err = verifyCert(cert.certBytes(groupD14), rootPK, groupD14)
	if err != nil {
		t.Fatalf("verifyCert with groupD14 failed: %v", err)
	}
}

// TestMerkleTreeGoogleBatch verifies that Google-Roughtime Merkle trees work
// correctly with multiple leaves (64-byte SHA-512 hashes).
func TestMerkleTreeGoogleBatch(t *testing.T) {
	g := groupGoogle
	leaves := make([][]byte, 5)
	for i := range leaves {
		leaves[i] = randBytes(t, 64) // 64-byte nonces
	}
	tree := newMerkleTree(g, leaves)
	if len(tree.rootHash) != 64 {
		t.Fatalf("Google Merkle root length = %d, want 64", len(tree.rootHash))
	}
	for i, leaf := range leaves {
		path := tree.paths[i]
		hash := leafHash(g, leaf)
		index := uint32(i)
		for _, sibling := range path {
			if index&1 == 0 {
				hash = nodeHash(g, hash, sibling)
			} else {
				hash = nodeHash(g, sibling, hash)
			}
			index >>= 1
		}
		if !bytes.Equal(hash, tree.rootHash) {
			t.Fatalf("proof %d: Merkle root mismatch", i)
		}
	}
}

// TestCreateRepliesBatchGoogle verifies batch signing for Google-Roughtime with
// multiple requests (non-power-of-2 batch size).
func TestCreateRepliesBatchGoogle(t *testing.T) {
	cert, _ := testCert(t)
	rootPK := cert.rootPK
	const n = 3
	reqs := make([]Request, n)
	nonces := make([][]byte, n)
	rawReqs := make([][]byte, n)
	for i := range n {
		nonce, req, err := CreateRequest([]Version{VersionGoogle}, rand.Reader, nil)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseRequest(req)
		if err != nil {
			t.Fatal(err)
		}
		reqs[i] = *parsed
		nonces[i] = nonce
		rawReqs[i] = req
	}
	replies, err := CreateReplies(VersionGoogle, reqs, time.Now(), time.Second, cert)
	if err != nil {
		t.Fatal(err)
	}
	for i := range n {
		mid, rad, err := VerifyReply([]Version{VersionGoogle}, replies[i], rootPK, nonces[i], rawReqs[i])
		if err != nil {
			t.Fatalf("reply %d: %v", i, err)
		}
		if mid.IsZero() || rad == 0 {
			t.Fatalf("reply %d: zero midpoint or radius", i)
		}
	}
}

// TestCreateRequestSRVOmittedForOldDrafts verifies that CreateRequest omits the
// SRV tag for pre-draft-10 versions.
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

// TestCreateRequestSRVIncludedForDraft10Plus verifies that CreateRequest
// includes the SRV tag for draft-10+ versions.
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

// TestMerkleTreeLargeBatchD14 verifies Merkle tree construction and proof
// verification with a 32-leaf batch (maximum PATH depth per spec) for groupD14.
func TestMerkleTreeLargeBatchD14(t *testing.T) {
	g := groupD14
	const n = 32
	leaves := make([][]byte, n)
	for i := range leaves {
		leaves[i] = randBytes(t, 1024) // full-packet leaf data
	}
	tree := newMerkleTree(g, leaves)
	if len(tree.rootHash) != 32 {
		t.Fatalf("root hash length = %d, want 32", len(tree.rootHash))
	}
	for i, leaf := range leaves {
		path := tree.paths[i]
		hash := leafHash(g, leaf)
		index := uint32(i)
		for _, sibling := range path {
			if index&1 == 0 {
				hash = nodeHash(g, hash, sibling)
			} else {
				hash = nodeHash(g, sibling, hash)
			}
			index >>= 1
		}
		if !bytes.Equal(hash, tree.rootHash) {
			t.Fatalf("leaf %d: Merkle root mismatch", i)
		}
	}
}

// TestCreateRequestZZZZAllZero verifies that ZZZZ padding emitted by
// CreateRequest is all-zero (§6.1 drafts 08-09, §6.1.4 drafts 10-11, §5.2.5
// drafts 14+).
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

// TestSREPContainsVERSForDraft12 verifies that SREP in draft-12+ responses
// contains the VERS tag with all supported versions in ascending order.
func TestSREPContainsVERSForDraft12(t *testing.T) {
	cert, _ := testCert(t)
	_, req, err := CreateRequest([]Version{VersionDraft12}, rand.Reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	replies, err := CreateReplies(VersionDraft12, []Request{*parsed}, time.Now(), time.Second, cert)
	if err != nil {
		t.Fatal(err)
	}
	reply := replies[0]
	inner, err := unwrapPacket(reply)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := Decode(inner)
	if err != nil {
		t.Fatal(err)
	}
	srepBytes, ok := resp[TagSREP]
	if !ok {
		t.Fatal("missing SREP in response")
	}
	srep, err := Decode(srepBytes)
	if err != nil {
		t.Fatal(err)
	}
	versBytes, ok := srep[TagVERS]
	if !ok {
		t.Fatal("missing VERS in SREP")
	}
	if len(versBytes)%4 != 0 || len(versBytes) == 0 {
		t.Fatalf("VERS length = %d, not a positive multiple of 4", len(versBytes))
	}
	nv := len(versBytes) / 4
	var prev Version
	found12 := false
	for i := range nv {
		v := Version(binary.LittleEndian.Uint32(versBytes[4*i : 4*i+4]))
		if i > 0 && v <= prev {
			t.Fatalf("VERS not ascending: %s <= %s", v, prev)
		}
		if v == VersionDraft12 {
			found12 = true
		}
		prev = v
	}
	if !found12 {
		t.Fatal("VersionDraft12 not found in VERS")
	}
}

// TestParseRequestRejectsEmptyVER verifies that a VER tag with zero length is
// rejected.
func TestParseRequestRejectsEmptyVER(t *testing.T) {
	nonce := randBytes(t, 32)
	tags := map[uint32][]byte{
		TagNONC: nonce,
		TagVER:  {}, // empty VER
	}
	msg, _ := encode(tags)
	pkt := wrapPacket(msg)
	if _, err := ParseRequest(pkt); err == nil {
		t.Fatal("expected error for empty VER tag")
	}
}

// TestParseRequestRejectsNonMultiple4VER verifies that a VER tag with length
// not a multiple of 4 is rejected.
func TestParseRequestRejectsNonMultiple4VER(t *testing.T) {
	nonce := randBytes(t, 32)
	tags := map[uint32][]byte{
		TagNONC: nonce,
		TagVER:  {0x01, 0x02, 0x03}, // 3 bytes, not a multiple of 4
	}
	msg, _ := encode(tags)
	pkt := wrapPacket(msg)
	if _, err := ParseRequest(pkt); err == nil {
		t.Fatal("expected error for VER tag with non-multiple-of-4 length")
	}
}

// FuzzDecode exercises the wire-format parser on arbitrary inputs.
func FuzzDecode(f *testing.F) {
	valid, _ := encode(map[uint32][]byte{TagNONC: make([]byte, 32)})
	f.Add(valid)

	multi, _ := encode(map[uint32][]byte{
		TagNONC: make([]byte, 32),
		TagVER:  {0x0c, 0x00, 0x00, 0x80},
		TagZZZZ: make([]byte, 64),
	})
	f.Add(multi)

	f.Add([]byte{0x00, 0x00, 0x00, 0x00})
	f.Add([]byte{})
	f.Add([]byte{0x01})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		msg, err := Decode(data)
		if err != nil {
			return
		}
		reencoded, err := encode(msg)
		if err != nil {
			return
		}
		msg2, err := Decode(reencoded)
		if err != nil {
			t.Fatalf("re-decode failed: %v", err)
		}
		if len(msg) != len(msg2) {
			t.Fatalf("tag count mismatch: %d vs %d", len(msg), len(msg2))
		}
		for tag, val := range msg {
			if !bytes.Equal(val, msg2[tag]) {
				t.Fatalf("value mismatch for tag %#x", tag)
			}
		}
	})
}

// FuzzParseRequest exercises request parsing on arbitrary inputs.
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

// FuzzVerifyReply exercises reply verification against a fixed key. Must not
// panic on any input.
func FuzzVerifyReply(f *testing.F) {
	// Inline cert setup: testCert takes *testing.T, not *testing.F
	_, rootSK, _ := ed25519.GenerateKey(rand.Reader)
	_, onlineSK, _ := ed25519.GenerateKey(rand.Reader)
	rootPK := rootSK.Public().(ed25519.PublicKey)
	now := time.Now()
	cert, _ := NewCertificate(now.Add(-time.Hour), now.Add(time.Hour), onlineSK, rootSK)
	nonce, req, _ := CreateRequest([]Version{VersionDraft12}, rand.Reader, nil)
	parsed, _ := ParseRequest(req)
	replies, _ := CreateReplies(VersionDraft12, []Request{*parsed}, now, time.Second, cert)
	f.Add(replies[0], []byte(rootPK), nonce, req)

	f.Fuzz(func(t *testing.T, reply, rootKey, nonce, request []byte) {
		VerifyReply([]Version{VersionDraft12}, reply, rootKey, nonce, request) //nolint:errcheck // fuzz target tests for panics
	})
}

// FuzzVerifyReplyAllVersions exercises VerifyReply across every wire group to
// cover each version's hash, nonce, timestamp, context, and NONC-placement
// combination.
func FuzzVerifyReplyAllVersions(f *testing.F) {
	versions := []Version{
		VersionGoogle, VersionDraft01, VersionDraft02, VersionDraft03,
		VersionDraft05, VersionDraft07, VersionDraft08, VersionDraft10,
		VersionDraft12,
	}

	_, rootSK, _ := ed25519.GenerateKey(rand.Reader)
	_, onlineSK, _ := ed25519.GenerateKey(rand.Reader)
	rootPK := rootSK.Public().(ed25519.PublicKey)
	now := time.Now()
	cert, _ := NewCertificate(now.Add(-time.Hour), now.Add(time.Hour), onlineSK, rootSK)

	for _, ver := range versions {
		clientVers := []Version{ver}
		nonce, req, err := CreateRequest(clientVers, rand.Reader, nil)
		if err != nil {
			continue
		}
		parsed, err := ParseRequest(req)
		if err != nil {
			continue
		}
		replies, err := CreateReplies(ver, []Request{*parsed}, now, time.Second, cert)
		if err != nil {
			continue
		}
		f.Add(replies[0], []byte(rootPK), nonce, req, byte(ver&0xff))
	}

	f.Fuzz(func(t *testing.T, reply, rootKey, nonce, request []byte, verHint byte) {
		idx := int(verHint) % len(versions)
		ver := versions[idx]
		VerifyReply([]Version{ver}, reply, rootKey, nonce, request) //nolint:errcheck // fuzz target tests for panics
	})
}

// FuzzCreateReplies exercises server-side reply creation with fuzzed requests.
// A panic here would be a DoS vector against the server.
func FuzzCreateReplies(f *testing.F) {
	versions := []Version{
		VersionGoogle, VersionDraft01, VersionDraft02, VersionDraft05,
		VersionDraft08, VersionDraft12,
	}

	for _, ver := range versions {
		_, req, err := CreateRequest([]Version{ver}, rand.Reader, nil)
		if err != nil {
			continue
		}
		f.Add(req, byte(ver&0xff))
	}

	f.Add([]byte{}, byte(0))
	f.Add([]byte{0xff, 0xff, 0xff, 0xff}, byte(0))
	f.Add(make([]byte, 1024), byte(0x0c))

	_, rootSK, _ := ed25519.GenerateKey(rand.Reader)
	_, onlineSK, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	cert, _ := NewCertificate(now.Add(-time.Hour), now.Add(time.Hour), onlineSK, rootSK)

	f.Fuzz(func(t *testing.T, reqBytes []byte, verHint byte) {
		idx := int(verHint) % len(versions)
		ver := versions[idx]

		parsed, err := ParseRequest(reqBytes)
		if err != nil {
			return
		}
		CreateReplies(ver, []Request{*parsed}, now, time.Second, cert) //nolint:errcheck // fuzz target tests for panics
	})
}

// FuzzCreateRepliesBatch exercises batch reply creation with multiple fuzzed
// requests, stressing Merkle tree construction.
func FuzzCreateRepliesBatch(f *testing.F) {
	_, req1, _ := CreateRequest([]Version{VersionDraft12}, rand.Reader, nil)
	_, req2, _ := CreateRequest([]Version{VersionDraft12}, rand.Reader, nil)
	f.Add(req1, req2)

	_, gReq1, _ := CreateRequest([]Version{VersionGoogle}, rand.Reader, nil)
	_, gReq2, _ := CreateRequest([]Version{VersionGoogle}, rand.Reader, nil)
	f.Add(gReq1, gReq2)

	_, rootSK, _ := ed25519.GenerateKey(rand.Reader)
	_, onlineSK, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	cert, _ := NewCertificate(now.Add(-time.Hour), now.Add(time.Hour), onlineSK, rootSK)

	f.Fuzz(func(t *testing.T, reqBytes1, reqBytes2 []byte) {
		p1, err := ParseRequest(reqBytes1)
		if err != nil {
			return
		}
		p2, err := ParseRequest(reqBytes2)
		if err != nil {
			return
		}
		CreateReplies(VersionDraft12, []Request{*p1, *p2}, now, time.Second, cert) //nolint:errcheck // fuzz target tests for panics
		CreateReplies(VersionGoogle, []Request{*p1, *p2}, now, time.Second, cert)  //nolint:errcheck // fuzz target tests for panics
	})
}

// FuzzDecodeTimestamp exercises timestamp decoding across all encoding formats
// (Unix µs, MJD µs, Unix seconds).
func FuzzDecodeTimestamp(f *testing.F) {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], uint64(time.Now().UnixMicro()))
	f.Add(buf[:], byte(0))
	f.Add(buf[:], byte(1))
	f.Add([]byte{}, byte(0))
	f.Add([]byte{0x01, 0x02, 0x03}, byte(5))
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, byte(0))

	versions := []Version{
		VersionGoogle, VersionDraft01, VersionDraft05, VersionDraft08, VersionDraft12,
	}

	f.Fuzz(func(t *testing.T, data []byte, verHint byte) {
		idx := int(verHint) % len(versions)
		DecodeTimestamp(versions[idx], data) //nolint:errcheck // fuzz target tests for panics
	})
}

// FuzzEncode exercises the wire format encoder with arbitrary tag-value maps.
func FuzzEncode(f *testing.F) {
	f.Add(uint32(1), []byte{0x00, 0x00, 0x00, 0x00})
	f.Add(uint32(3), make([]byte, 256))

	f.Fuzz(func(t *testing.T, numTags uint32, valTemplate []byte) {
		// Bound tag count to avoid OOM
		n := int(numTags%64) + 1
		// valTemplate must be 4-byte aligned
		if len(valTemplate)%4 != 0 {
			aligned := len(valTemplate) &^ 3
			if aligned == 0 {
				valTemplate = []byte{0, 0, 0, 0}
			} else {
				valTemplate = valTemplate[:aligned]
			}
		}
		if len(valTemplate) == 0 {
			valTemplate = []byte{0, 0, 0, 0}
		}

		msg := make(map[uint32][]byte, n)
		for i := range n {
			tag := uint32(i * 0x01010101)
			msg[tag] = valTemplate
		}

		encoded, err := encode(msg)
		if err != nil {
			return
		}
		// Decode enforces maxMessageSize; skip round-trip for oversized
		// messages
		if len(encoded) > maxMessageSize {
			return
		}
		decoded, err := Decode(encoded)
		if err != nil {
			t.Fatalf("round-trip decode failed: %v", err)
		}
		if len(decoded) != len(msg) {
			t.Fatalf("tag count mismatch: got %d, want %d", len(decoded), len(msg))
		}
		for tag, val := range msg {
			if !bytes.Equal(val, decoded[tag]) {
				t.Fatalf("value mismatch for tag %#x", tag)
			}
		}
	})
}

// FuzzExtractVersion exercises the public ExtractVersion API with arbitrary
// reply bytes.
func FuzzExtractVersion(f *testing.F) {
	_, rootSK, _ := ed25519.GenerateKey(rand.Reader)
	_, onlineSK, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	cert, _ := NewCertificate(now.Add(-time.Hour), now.Add(time.Hour), onlineSK, rootSK)

	for _, ver := range []Version{VersionGoogle, VersionDraft08, VersionDraft12} {
		_, req, err := CreateRequest([]Version{ver}, rand.Reader, nil)
		if err != nil {
			continue
		}
		parsed, _ := ParseRequest(req)
		if parsed == nil {
			continue
		}
		replies, err := CreateReplies(ver, []Request{*parsed}, now, time.Second, cert)
		if err != nil {
			continue
		}
		f.Add(replies[0])
	}

	f.Add([]byte{})
	f.Add([]byte{0x00, 0x00, 0x00, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		ExtractVersion(data)
	})
}

// FuzzSelectVersion exercises the server-side version selector with arbitrary
// client VER lists and nonce lengths.
func FuzzSelectVersion(f *testing.F) {
	f.Add([]byte{}, 32)
	f.Add([]byte{}, 64)
	f.Add([]byte{0x0c, 0x00, 0x00, 0x80}, 32)
	f.Add([]byte{0x08, 0x00, 0x00, 0x80, 0x0c, 0x00, 0x00, 0x80}, 32)

	f.Fuzz(func(t *testing.T, verBytes []byte, nonceLen int) {
		if len(verBytes)%4 != 0 || len(verBytes) > 4*maxVersionList {
			return
		}
		vers := make([]Version, 0, len(verBytes)/4)
		for i := 0; i < len(verBytes); i += 4 {
			vers = append(vers, Version(binary.LittleEndian.Uint32(verBytes[i:i+4])))
		}
		if nonceLen < 0 || nonceLen > 1024 {
			return
		}
		_, _ = SelectVersion(vers, nonceLen)
	})
}

// TestGreaseDoesNotPanic verifies that Grease does not panic on valid replies.
func TestGreaseDoesNotPanic(t *testing.T) {
	for _, ver := range []Version{VersionGoogle, VersionDraft08, VersionDraft12} {
		t.Run(ver.String(), func(t *testing.T) {
			reply, _, _, _ := validReply(t, ver, []Version{ver})
			for range 200 {
				cp := make([]byte, len(reply))
				copy(cp, reply)
				Grease(cp, ver)
			}
		})
	}
}

// TestGreaseCorruptSig verifies that greaseCorruptSig always produces a reply
// that fails verification.
func TestGreaseCorruptSig(t *testing.T) {
	for _, ver := range []Version{VersionGoogle, VersionDraft08, VersionDraft12} {
		t.Run(ver.String(), func(t *testing.T) {
			reply, rootPK, nonce, req := validReply(t, ver, []Version{ver})
			for range 50 {
				cp := make([]byte, len(reply))
				copy(cp, reply)
				greaseCorruptSig(cp, ver)
				if _, _, err := VerifyReply([]Version{ver}, cp, rootPK, nonce, req); err == nil {
					t.Fatal("greaseCorruptSig produced a reply that still verifies")
				}
			}
		})
	}
}

// TestGreaseDropTag verifies that greaseDropTag produces a reply that fails
// verification.
func TestGreaseDropTag(t *testing.T) {
	for _, ver := range []Version{VersionGoogle, VersionDraft08, VersionDraft12} {
		t.Run(ver.String(), func(t *testing.T) {
			reply, rootPK, nonce, req := validReply(t, ver, []Version{ver})
			out := greaseDropTag(reply, ver)
			if out == nil {
				t.Fatal("greaseDropTag returned nil")
			}
			if _, _, err := VerifyReply([]Version{ver}, out, rootPK, nonce, req); err == nil {
				t.Fatal("expected verification failure after dropping a mandatory tag")
			}
		})
	}
}

// TestGreaseWrongVersion verifies that greaseWrongVersion produces a reply that
// fails verification (draft 08 has a top-level VER).
func TestGreaseWrongVersion(t *testing.T) {
	reply, rootPK, nonce, req := validReply(t, VersionDraft08, []Version{VersionDraft08})
	out := greaseWrongVersion(reply, VersionDraft08)
	if out == nil {
		t.Fatal("greaseWrongVersion returned nil for draft08")
	}
	if _, _, err := VerifyReply([]Version{VersionDraft08}, out, rootPK, nonce, req); err == nil {
		t.Fatal("expected verification failure for wrong version")
	}
}

// TestGreaseWrongVersionNilForGoogle verifies that greaseWrongVersion returns
// nil for Google-Roughtime (no top-level VER).
func TestGreaseWrongVersionNilForGoogle(t *testing.T) {
	reply, _, _, _ := validReply(t, VersionGoogle, []Version{VersionGoogle})
	if out := greaseWrongVersion(reply, VersionGoogle); out != nil {
		t.Fatal("expected nil for Google version (no top-level VER)")
	}
}

// TestGreaseWrongVersionNilForDraft12 verifies that greaseWrongVersion returns
// nil for drafts 12+ (VER is inside SREP, not top-level).
func TestGreaseWrongVersionNilForDraft12(t *testing.T) {
	reply, _, _, _ := validReply(t, VersionDraft12, []Version{VersionDraft12})
	if out := greaseWrongVersion(reply, VersionDraft12); out != nil {
		t.Fatal("expected nil for draft12 (no top-level VER)")
	}
}

// TestGreaseUndefinedTag verifies that greaseUndefinedTag produces a reply that
// still verifies (clients MUST ignore undefined tags).
func TestGreaseUndefinedTag(t *testing.T) {
	for _, ver := range []Version{VersionGoogle, VersionDraft08, VersionDraft12} {
		t.Run(ver.String(), func(t *testing.T) {
			reply, rootPK, nonce, req := validReply(t, ver, []Version{ver})
			out := greaseUndefinedTag(reply, ver)
			if out == nil {
				t.Fatal("greaseUndefinedTag returned nil")
			}
			if len(out) <= len(reply) {
				t.Fatal("expected greased reply to be larger (added tag)")
			}
			if _, _, err := VerifyReply([]Version{ver}, out, rootPK, nonce, req); err != nil {
				t.Fatalf("undefined tag should not break verification: %v", err)
			}
		})
	}
}

// TestGreaseAllModesReachable verifies that all four grease modes fire over
// many iterations. Uses Draft08 because its top-level VER lets every mode
// apply.
func TestGreaseAllModesReachable(t *testing.T) {
	reply, rootPK, nonce, req := validReply(t, VersionDraft08, []Version{VersionDraft08})

	var sigCorrupt, tagDrop, wrongVer, undefinedTag int
	for range 1000 {
		cp := make([]byte, len(reply))
		copy(cp, reply)
		out := Grease(cp, VersionDraft08)

		_, _, err := VerifyReply([]Version{VersionDraft08}, out, rootPK, nonce, req)
		switch {
		case err == nil:
			undefinedTag++
		case len(out) < len(reply):
			tagDrop++
		default:
			// Same size, verification failed: distinguish sig corruption from
			// wrong-version by inspecting VER
			_, body := greaseSplit(out, VersionDraft08)
			if body != nil {
				if lo, hi, ok := findTagRange(body, TagVER); ok && hi-lo == 4 {
					v := binary.LittleEndian.Uint32(body[lo:])
					if v == 0xFFFFFFFF {
						wrongVer++
						continue
					}
				}
			}
			sigCorrupt++
		}
	}

	if sigCorrupt == 0 {
		t.Error("signature corruption mode never fired")
	}
	if tagDrop == 0 {
		t.Error("tag drop mode never fired")
	}
	if wrongVer == 0 {
		t.Error("wrong version mode never fired")
	}
	if undefinedTag == 0 {
		t.Error("undefined tag mode never fired")
	}
	t.Logf("distribution: sig=%d drop=%d ver=%d undef=%d", sigCorrupt, tagDrop, wrongVer, undefinedTag)
}

// TestGreaseNeverProducesSentinels verifies grease never produces
// ErrMerkleMismatch or ErrDelegationWindow.
func TestGreaseNeverProducesSentinels(t *testing.T) {
	for _, ver := range []Version{VersionGoogle, VersionDraft08, VersionDraft12} {
		t.Run(ver.ShortString(), func(t *testing.T) {
			reply, rootPK, nonce, req := validReply(t, ver, []Version{ver})
			for range 500 {
				cp := make([]byte, len(reply))
				copy(cp, reply)
				out := Grease(cp, ver)
				_, _, err := VerifyReply([]Version{ver}, out, rootPK, nonce, req)
				if err == nil {
					continue
				}
				if errors.Is(err, ErrMerkleMismatch) || errors.Is(err, ErrDelegationWindow) {
					t.Fatalf("grease produced sentinel error: %v", err)
				}
			}
		})
	}
}

// TestGreaseMalformedInput verifies that Grease does not panic on malformed
// input.
func TestGreaseMalformedInput(t *testing.T) {
	for _, ver := range []Version{VersionGoogle, VersionDraft08, VersionDraft12} {
		t.Run(ver.String(), func(t *testing.T) {
			for _, input := range [][]byte{nil, {}, {0x00}, make([]byte, 11)} {
				Grease(input, ver)
			}
		})
	}
}

// FuzzGrease verifies that Grease does not panic on arbitrary input.
func FuzzGrease(f *testing.F) {
	_, rootSK, _ := ed25519.GenerateKey(rand.Reader)
	_, onlineSK, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	cert, _ := NewCertificate(now.Add(-time.Hour), now.Add(time.Hour), onlineSK, rootSK)

	for _, ver := range []Version{VersionGoogle, VersionDraft08, VersionDraft12} {
		_, req, err := CreateRequest([]Version{ver}, rand.Reader, nil)
		if err != nil {
			continue
		}
		parsed, err := ParseRequest(req)
		if err != nil {
			continue
		}
		replies, err := CreateReplies(ver, []Request{*parsed}, now, time.Second, cert)
		if err != nil {
			continue
		}
		f.Add(replies[0], uint32(ver))
	}
	f.Add([]byte{}, uint32(0))
	f.Add([]byte{0xff}, uint32(VersionDraft08))

	f.Fuzz(func(t *testing.T, data []byte, verRaw uint32) {
		Grease(data, Version(verRaw))
	})
}

// TestNoncInSREPExported verifies that the exported NoncInSREP wrapper agrees
// with the internal noncInSREP for every (version, hasType) combination.
func TestNoncInSREPExported(t *testing.T) {
	versions := []Version{
		VersionGoogle, VersionDraft01, VersionDraft02, VersionDraft03,
		VersionDraft04, VersionDraft05, VersionDraft07, VersionDraft08,
		VersionDraft10, VersionDraft12,
	}
	for _, v := range versions {
		for _, hasType := range []bool{false, true} {
			want := noncInSREP(wireGroupOf(v, hasType))
			if got := NoncInSREP(v, hasType); got != want {
				t.Errorf("NoncInSREP(%s, %v) = %v, want %v", v, hasType, got, want)
			}
		}
	}
	// Sanity check: only drafts 01–02 place NONC inside SREP
	if !NoncInSREP(VersionDraft01, false) || !NoncInSREP(VersionDraft02, false) {
		t.Fatal("drafts 01 and 02 must report NONC-in-SREP")
	}
	if NoncInSREP(VersionDraft12, true) {
		t.Fatal("draft 12 must not report NONC-in-SREP")
	}
}

// TestSupportedExported verifies that the exported Supported() returns every
// IETF version (newest first) followed by VersionGoogle as the final entry.
func TestSupportedExported(t *testing.T) {
	got := Supported()
	if len(got) != len(supportedVersions)+1 {
		t.Fatalf("len(Supported()) = %d, want %d", len(got), len(supportedVersions)+1)
	}
	if got[len(got)-1] != VersionGoogle {
		t.Fatalf("last entry = %s, want VersionGoogle", got[len(got)-1])
	}
	// IETF entries must be in descending order
	for i := 1; i < len(got)-1; i++ {
		if got[i] >= got[i-1] {
			t.Fatalf("IETF entries not descending at index %d: %s >= %s", i, got[i], got[i-1])
		}
	}
	// Mutating the returned slice must not affect future calls
	got[0] = VersionGoogle
	if Supported()[0] == VersionGoogle {
		t.Fatal("Supported() must return a defensive copy")
	}
}

// TestCertBytesPanicsOnCacheMiss verifies that certBytes panics when the
// certificate cache lacks an entry (programming-error guard, not runtime input
// check).
func TestCertBytesPanicsOnCacheMiss(t *testing.T) {
	c := &Certificate{cache: map[certCacheKey][]byte{}}
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic on cache miss")
		}
		msg, ok := r.(string)
		if !ok || !bytes.Contains([]byte(msg), []byte("cache miss")) {
			t.Fatalf("unexpected panic value: %v", r)
		}
	}()
	_ = c.certBytes(groupD12)
}

// TestVerifyNoVersionDowngradeBranches exercises every error branch in
// verifyNoVersionDowngrade that's not already covered by integration tests.
func TestVerifyNoVersionDowngradeBranches(t *testing.T) {
	srepWithVER := func(ver Version, vers ...Version) map[uint32][]byte {
		verBuf := make([]byte, 4)
		binary.LittleEndian.PutUint32(verBuf, uint32(ver))
		versBuf := make([]byte, 4*len(vers))
		for i, v := range vers {
			binary.LittleEndian.PutUint32(versBuf[4*i:], uint32(v))
		}
		return map[uint32][]byte{TagVER: verBuf, TagVERS: versBuf}
	}

	t.Run("nil srep", func(t *testing.T) {
		if err := verifyNoVersionDowngrade(nil, []Version{VersionDraft12}); err == nil {
			t.Fatal("expected error for nil srep")
		}
	})

	t.Run("missing VER", func(t *testing.T) {
		srep := map[uint32][]byte{TagVERS: make([]byte, 4)}
		if err := verifyNoVersionDowngrade(srep, []Version{VersionDraft12}); err == nil {
			t.Fatal("expected error for missing VER")
		}
	})

	t.Run("short VER", func(t *testing.T) {
		srep := map[uint32][]byte{TagVER: {1, 2, 3}, TagVERS: make([]byte, 4)}
		if err := verifyNoVersionDowngrade(srep, []Version{VersionDraft12}); err == nil {
			t.Fatal("expected error for short VER")
		}
	})

	t.Run("missing VERS", func(t *testing.T) {
		srep := map[uint32][]byte{TagVER: make([]byte, 4)}
		if err := verifyNoVersionDowngrade(srep, []Version{VersionDraft12}); err == nil {
			t.Fatal("expected error for missing VERS")
		}
	})

	t.Run("malformed VERS length", func(t *testing.T) {
		srep := map[uint32][]byte{TagVER: make([]byte, 4), TagVERS: {1, 2, 3}}
		if err := verifyNoVersionDowngrade(srep, []Version{VersionDraft12}); err == nil {
			t.Fatal("expected error for malformed VERS length")
		}
	})

	t.Run("no mutual version", func(t *testing.T) {
		srep := srepWithVER(VersionDraft12, VersionDraft12)
		if err := verifyNoVersionDowngrade(srep, []Version{VersionDraft08}); err == nil {
			t.Fatal("expected error when client and server share nothing")
		}
	})

	t.Run("downgrade detected", func(t *testing.T) {
		// Server chose 10 but signed VERS includes 12; client also supports 12
		srep := srepWithVER(VersionDraft10, VersionDraft10, VersionDraft12)
		err := verifyNoVersionDowngrade(srep, []Version{VersionDraft10, VersionDraft12})
		if err == nil {
			t.Fatal("expected downgrade error")
		}
	})

	t.Run("happy path", func(t *testing.T) {
		srep := srepWithVER(VersionDraft12, VersionDraft10, VersionDraft12)
		if err := verifyNoVersionDowngrade(srep, []Version{VersionDraft10, VersionDraft12}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

// TestGreaseDropTagOnGarbageBody verifies that greaseDropTag returns nil when
// the response body cannot be decoded.
func TestGreaseDropTagOnGarbageBody(t *testing.T) {
	header := make([]byte, 12)
	copy(header[:8], []byte("ROUGHTIM"))
	binary.LittleEndian.PutUint32(header[8:12], 4)
	reply := append(header, []byte{0xff, 0xff, 0xff, 0xff}...)
	if got := greaseDropTag(reply, VersionDraft08); got != nil {
		t.Fatalf("expected nil for garbage body, got %d bytes", len(got))
	}
}

// TestGreaseDropTagNoCandidates verifies that greaseDropTag returns nil when
// the response body decodes but contains none of the mandatory tags it would
// otherwise drop (SIG/SREP/CERT/PATH/INDX).
func TestGreaseDropTagNoCandidates(t *testing.T) {
	body, err := encode(map[uint32][]byte{TagNONC: make([]byte, 32)})
	if err != nil {
		t.Fatal(err)
	}
	header := make([]byte, 12)
	copy(header[:8], []byte("ROUGHTIM"))
	binary.LittleEndian.PutUint32(header[8:12], uint32(len(body)))
	reply := append(header, body...)
	if got := greaseDropTag(reply, VersionDraft08); got != nil {
		t.Fatalf("expected nil when no candidate tags exist, got %d bytes", len(got))
	}
}

// TestFindTagRangeMalformed exercises the malformed-input branches of
// findTagRange directly with crafted byte slices.
func TestFindTagRangeMalformed(t *testing.T) {
	t.Run("too short", func(t *testing.T) {
		if _, _, ok := findTagRange([]byte{1, 2, 3}, TagNONC); ok {
			t.Fatal("expected ok=false for <4 byte msg")
		}
	})
	t.Run("zero tag count", func(t *testing.T) {
		msg := make([]byte, 4)
		if _, _, ok := findTagRange(msg, TagNONC); ok {
			t.Fatal("expected ok=false for zero tag count")
		}
	})
	t.Run("oversized tag count", func(t *testing.T) {
		msg := make([]byte, 4)
		binary.LittleEndian.PutUint32(msg, 513)
		if _, _, ok := findTagRange(msg, TagNONC); ok {
			t.Fatal("expected ok=false for tag count > 512")
		}
	})
	t.Run("truncated header", func(t *testing.T) {
		// n=2 requires 16 bytes of header but we supply only 8
		msg := make([]byte, 8)
		binary.LittleEndian.PutUint32(msg, 2)
		if _, _, ok := findTagRange(msg, TagNONC); ok {
			t.Fatal("expected ok=false for truncated header")
		}
	})
	t.Run("tag not found", func(t *testing.T) {
		msg := make([]byte, 8)
		binary.LittleEndian.PutUint32(msg, 1)
		binary.LittleEndian.PutUint32(msg[4:], TagNONC)
		if _, _, ok := findTagRange(msg, TagSIG); ok {
			t.Fatal("expected ok=false when tag absent")
		}
	})
	t.Run("last tag with values", func(t *testing.T) {
		// Exercises the idx == n-1 branch where hi derives from len(msg)
		body, err := encode(map[uint32][]byte{
			TagNONC: bytes.Repeat([]byte{0x11}, 32),
			TagPAD:  bytes.Repeat([]byte{0x22}, 8),
		})
		if err != nil {
			t.Fatal(err)
		}
		lo, hi, ok := findTagRange(body, TagPAD)
		if !ok {
			t.Fatal("expected to find PAD")
		}
		if hi-lo != 8 {
			t.Fatalf("PAD length = %d, want 8", hi-lo)
		}
		if !bytes.Equal(body[lo:hi], bytes.Repeat([]byte{0x22}, 8)) {
			t.Fatal("PAD value mismatch")
		}
	})
}

// TestCreateRequestWithNonceAllVersions verifies CreateRequestWithNonce
// produces valid requests for every supported version, and that the nonce
// survives the round-trip through ParseRequest and VerifyReply.
func TestCreateRequestWithNonceAllVersions(t *testing.T) {
	for _, v := range append([]Version{VersionGoogle}, supportedVersions...) {
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

			// Drafts 08+ use Unix-seconds resolution
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

// TestCreateRequestWithNonceWithSRV verifies the SRV tag is included for drafts
// 10+ when using CreateRequestWithNonce.
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

// TestCreateRequestWithNonceRejectsWrongSize verifies that a nonce of the wrong
// length is rejected.
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

// TestCreateRequestWithNonceRejectsEmptyVersions verifies that an empty version
// list is rejected.
func TestCreateRequestWithNonceRejectsEmptyVersions(t *testing.T) {
	if _, err := CreateRequestWithNonce(nil, make([]byte, 32), nil); err == nil {
		t.Fatal("expected error")
	}
}

// TestCreateRequestWithNonce64ByteNonce verifies that Google/draft-01 versions
// accept the expected 64-byte nonce.
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

// FuzzCreateRequestWithNonce exercises CreateRequestWithNonce with arbitrary
// nonce values, verifying that valid-length nonces always produce parseable
// requests with the exact nonce embedded.
func FuzzCreateRequestWithNonce(f *testing.F) {
	f.Add(make([]byte, 32))
	f.Add(bytes.Repeat([]byte{0xff}, 32))
	f.Fuzz(func(t *testing.T, nonce []byte) {
		if len(nonce) != 32 {
			t.Skip()
		}
		req, err := CreateRequestWithNonce([]Version{VersionDraft12}, nonce, nil)
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

// TestNonceOffsetInRequest verifies that the returned offset points at the
// request's NONC value for both framed and unframed inputs, and that malformed
// or NONC-less inputs produce an error without panicking.
func TestNonceOffsetInRequest(t *testing.T) {
	nonce := bytes.Repeat([]byte{0x42}, 32)

	framed, err := CreateRequestWithNonce([]Version{VersionDraft12}, nonce, nil)
	if err != nil {
		t.Fatalf("CreateRequestWithNonce: %v", err)
	}
	off, err := NonceOffsetInRequest(framed)
	if err != nil {
		t.Fatalf("framed: %v", err)
	}
	if !bytes.Equal(framed[off:off+32], nonce) {
		t.Fatalf("framed: slice at offset %d does not match nonce", off)
	}

	raw := framed[12:]
	off, err = NonceOffsetInRequest(raw)
	if err != nil {
		t.Fatalf("unframed: %v", err)
	}
	if !bytes.Equal(raw[off:off+32], nonce) {
		t.Fatalf("unframed: slice at offset %d does not match nonce", off)
	}

	noNONC, err := encode(map[uint32][]byte{TagPAD: make([]byte, 32)})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, err := NonceOffsetInRequest(noNONC); err == nil {
		t.Fatal("expected error for message without NONC")
	}

	for _, bad := range [][]byte{nil, {}, {0x01}, {0x00, 0x00, 0x00}} {
		if _, err := NonceOffsetInRequest(bad); err == nil {
			t.Fatalf("expected error for malformed input %x", bad)
		}
	}
}

// FuzzNonceOffsetInRequest asserts NonceOffsetInRequest never panics on
// arbitrary input, and that any reported offset lies strictly within the buffer
// (the NONC value has at least one byte).
func FuzzNonceOffsetInRequest(f *testing.F) {
	if req, err := CreateRequestWithNonce([]Version{VersionDraft12}, bytes.Repeat([]byte{0xaa}, 32), nil); err == nil {
		f.Add(req)
		f.Add(req[12:])
	}
	f.Add([]byte{})
	f.Add([]byte{0x01, 0x00, 0x00, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		off, err := NonceOffsetInRequest(data)
		if err != nil {
			return
		}
		if off < 0 || off >= len(data) {
			t.Fatalf("offset %d out of bounds (len=%d)", off, len(data))
		}
	})
}

// TestSelectVersionRejectsNonceSizeMismatch verifies that SelectVersion won't
// return a version whose required nonce size differs from the request's actual
// nonce length, even if that version is in the client's offered list.
func TestSelectVersionRejectsNonceSizeMismatch(t *testing.T) {
	if _, err := SelectVersion([]Version{VersionDraft12}, 64); err == nil {
		t.Fatal("expected error: Draft12 with 64-byte nonce")
	}
	if _, err := SelectVersion([]Version{VersionDraft04}, 32); err == nil {
		t.Fatal("expected error: Draft04 with 32-byte nonce")
	}
	// 64-byte nonce forces Draft04 despite Draft12 having higher preference
	v, err := SelectVersion([]Version{VersionDraft04, VersionDraft12}, 64)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v != VersionDraft04 {
		t.Fatalf("got %v, want VersionDraft04", v)
	}
	v, err = SelectVersion([]Version{VersionDraft04, VersionDraft12}, 32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v != VersionDraft12 {
		t.Fatalf("got %v, want VersionDraft12", v)
	}
}

// TestVerifyNoVersionDowngradeRejectsChosenNotInVERS verifies that the chosen
// SREP.VER must appear in the signed VERS list (§5.2.4 drafts 12-13, §5.2.5
// drafts 14+).
func TestVerifyNoVersionDowngradeRejectsChosenNotInVERS(t *testing.T) {
	var verBuf [4]byte
	binary.LittleEndian.PutUint32(verBuf[:], uint32(VersionDraft12))
	var versBuf [4]byte
	binary.LittleEndian.PutUint32(versBuf[:], uint32(VersionDraft11))
	srep := map[uint32][]byte{
		TagVER:  verBuf[:],
		TagVERS: versBuf[:],
	}
	err := verifyNoVersionDowngrade(srep, []Version{VersionDraft11, VersionDraft12})
	if err == nil {
		t.Fatal("expected error: chosen version not in VERS")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("not present in signed VERS")) {
		t.Fatalf("error message should call out VERS mismatch, got: %v", err)
	}
}

// TestParseRequestPaddingStrictness verifies drafts 12+ reject non-zero ZZZZ
// (§5.1.1 MUST) while drafts 01-11 and Google accept it (SHOULD, kept lenient
// for interop with older implementations).
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

// TestParseRequestAcceptsZeroPadding verifies all-zero ZZZZ parses
// successfully.
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

// TestVerifyMerkleReturnsErrMerkleMismatch verifies that Merkle-root mismatches
// return the [ErrMerkleMismatch] sentinel.
func TestVerifyMerkleReturnsErrMerkleMismatch(t *testing.T) {
	var indx [4]byte
	resp := map[uint32][]byte{
		TagINDX: indx[:],
		TagPATH: nil,
	}
	leaf := make([]byte, 32)
	root := bytes.Repeat([]byte{0xFF}, 32)
	err := verifyMerkle(resp, leaf, root, groupD12)
	if err == nil {
		t.Fatal("expected Merkle mismatch error")
	}
	if !errors.Is(err, ErrMerkleMismatch) {
		t.Fatalf("expected ErrMerkleMismatch, got %v", err)
	}
}

// TestValidateDelegationWindowReturnsErrDelegationWindow verifies that a
// midpoint outside [MINT, MAXT] returns [ErrDelegationWindow].
func TestValidateDelegationWindowReturnsErrDelegationWindow(t *testing.T) {
	g := groupD14
	mint := time.Now().Add(time.Hour)
	maxt := time.Now().Add(2 * time.Hour)
	mintBuf := encodeTimestamp(mint, g)
	maxtBuf := encodeTimestamp(maxt, g)
	midpoint := time.Now().Add(-time.Hour)
	_, _, err := validateDelegationWindow(midpoint, time.Second, mintBuf[:], maxtBuf[:], g)
	if err == nil {
		t.Fatal("expected delegation-window error")
	}
	if !errors.Is(err, ErrDelegationWindow) {
		t.Fatalf("expected ErrDelegationWindow, got %v", err)
	}
}

// TestGreaseDropTagSubTagsReachable verifies that greaseDropTag can reach
// SREP/CERT sub-tag drops in addition to top-level drops.
func TestGreaseDropTagSubTagsReachable(t *testing.T) {
	reply, _, _, _ := validReply(t, VersionDraft12, []Version{VersionDraft12})

	var topOnly, subTag int
	origBody, _ := unwrapPacket(reply)
	origMsg, _ := Decode(origBody)
	origSREP := origMsg[TagSREP]
	origCERT := origMsg[TagCERT]

	for range 500 {
		cp := make([]byte, len(reply))
		copy(cp, reply)
		out := greaseDropTag(cp, VersionDraft12)
		if out == nil {
			t.Fatal("greaseDropTag returned nil")
		}
		outBody, err := unwrapPacket(out)
		if err != nil {
			t.Fatalf("unwrap grease output: %v", err)
		}
		outMsg, err := Decode(outBody)
		if err != nil {
			t.Fatalf("decode grease output: %v", err)
		}
		// Classify: changed SREP/CERT = sub-tag drop, missing = top-level
		switch {
		case outMsg[TagSREP] == nil, outMsg[TagCERT] == nil,
			outMsg[TagPATH] == nil && origMsg[TagPATH] != nil,
			len(outMsg) < len(origMsg):
			topOnly++
		case !bytes.Equal(outMsg[TagSREP], origSREP), !bytes.Equal(outMsg[TagCERT], origCERT):
			subTag++
		default:
			topOnly++
		}
	}
	if subTag == 0 {
		t.Error("sub-tag drop mode never fired (SREP/CERT sub-tag drop unreachable)")
	}
	if topOnly == 0 {
		t.Error("top-level drop mode never fired")
	}
	t.Logf("distribution: top-level=%d sub-tag=%d", topOnly, subTag)
}

// TestDecodeRadiusToleratesShortRadii verifies that RADI < 3 is accepted by the
// low-level decoder across all wire groups. Server-side rules (≥ 3s in 10-11,
// != 0 in 12+) are enforced at higher layers, not in decodeRadius.
func TestDecodeRadiusToleratesShortRadii(t *testing.T) {
	enc := func(v uint32) []byte {
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, v)
		return b
	}
	for _, g := range []wireGroup{groupGoogle, groupD01, groupD05, groupD08, groupD10, groupD12, groupD14} {
		for _, v := range []uint32{0, 1, 2, 3} {
			if _, err := decodeRadius(enc(v), g); err != nil {
				t.Errorf("group %v RADI=%d: unexpected error: %v", g, v, err)
			}
		}
	}
}

// TestParseRequestRejectsDuplicateVERDraft11 verifies duplicate-VER rejection
// also covers draft-11 (shared wire group with draft-10 per §6.1.1).
func TestParseRequestRejectsDuplicateVERDraft11(t *testing.T) {
	nonce := randBytes(t, 32)
	raw := buildIETFRequest(nonce, []Version{VersionDraft11, VersionDraft11}, false)
	if _, err := ParseRequest(raw); err == nil {
		t.Fatal("draft-11 duplicate VER list should be rejected (§6.1.1)")
	}
}

// TestVerifyReplyRejectsMissingTopLevelVER verifies that drafts 01–11 reject a
// response missing the top-level VER tag (§6.2). Drafts 12+ moved VER into SREP
// and are not affected.
func TestVerifyReplyRejectsMissingTopLevelVER(t *testing.T) {
	for _, ver := range []Version{VersionDraft03, VersionDraft05, VersionDraft08, VersionDraft10, VersionDraft11} {
		t.Run(ver.ShortString(), func(t *testing.T) {
			reply, rootPK, nonce, req := validReply(t, ver, []Version{ver})
			tampered := corruptReplyTag(t, reply, true, func(tags map[uint32][]byte) {
				delete(tags, TagVER)
			})
			if _, _, err := VerifyReply([]Version{ver}, tampered, rootPK, nonce, req); err == nil {
				t.Fatal("expected error for missing top-level VER")
			}
		})
	}
}

// TestCertificateWipe verifies Wipe zeroes the online signing key and tolerates
// a nil receiver.
func TestCertificateWipe(t *testing.T) {
	cert, _ := testCert(t)
	if allZero(cert.onlineSK) {
		t.Fatal("precondition: onlineSK should not already be zero")
	}
	cert.Wipe()
	if !allZero(cert.onlineSK) {
		t.Fatal("onlineSK not zeroed after Wipe")
	}
	// nil receiver must not panic
	var nilCert *Certificate
	nilCert.Wipe()
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
