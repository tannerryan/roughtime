// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"maps"
	"testing"
	"time"

	"filippo.io/mldsa"
	"go.uber.org/goleak"
)

// TestMain verifies no goroutine leaks across the package's tests.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// wrapPacket prepends the ROUGHTIM header to msg.
func wrapPacket(msg []byte) []byte {
	pkt := make([]byte, 12+len(msg))
	copy(pkt[0:8], packetMagic[:])
	binary.LittleEndian.PutUint32(pkt[8:12], uint32(len(msg)))
	copy(pkt[12:], msg)
	return pkt
}

// testKeys returns a fresh root and online Ed25519 private key.
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

// randBytes returns n cryptographically random bytes.
func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// buildGoogleRequest constructs a Google-Roughtime request padded to 1024
// bytes.
func buildGoogleRequest(nonce []byte) []byte {
	// header: 4 (tag count) + 4 (1 offset) + 8 (2 tags) = 16 bytes
	pad := make([]byte, 1024-len(nonce)-16)
	msg, _ := encode(map[uint32][]byte{
		TagNONC: nonce,
		TagPAD:  pad,
	})
	return msg
}

// buildIETFRequest constructs an IETF-framed request padded to 1024 bytes.
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
		padTag := tagPADIETF
		if len(versions) > 0 && versions[0] >= VersionDraft08 {
			padTag = TagZZZZ
		}
		padded[padTag] = make([]byte, 1012-len(msg))
		msg, _ = encode(padded)
	}
	return wrapPacket(msg)
}

// testCert returns a fresh Ed25519 Certificate spanning ±1 hour and the root
// private key.
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

// testPQCert returns a fresh ML-DSA-44 Certificate and the encoded root public
// key.
func testPQCert(t *testing.T) (*Certificate, []byte) {
	t.Helper()
	rootSK, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatal(err)
	}
	onlineSK, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	cert, err := NewCertificateMLDSA44(now.Add(-time.Hour), now.Add(time.Hour), onlineSK, rootSK)
	if err != nil {
		t.Fatal(err)
	}
	return cert, rootSK.PublicKey().Bytes()
}

// verifyResponse checks tags, signatures, and Merkle proof for a single-request
// batch.
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

// verifyResponseVER asserts top-level VER presence matches the wire group's
// expectation.
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

// verifyResponseNONC asserts top-level NONC presence and value match the wire
// group's expectation.
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

// verifyResponseTYPE asserts TYPE is 1 when the request carried a TYPE tag.
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

// verifySREPTags asserts SREP carries ROOT, MIDP, RADI, and per-group tags.
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

// verifyCERTSigs validates SREP against DELE.PUBK and DELE against the root
// key.
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

// verifySingleLeafMerkle asserts a single-request batch has empty PATH and
// INDX=0.
func verifySingleLeafMerkle(t *testing.T, resp map[uint32][]byte) {

	t.Helper()
	if len(resp[TagPATH]) != 0 {
		t.Fatal("PATH should be empty for single request")
	}
	if binary.LittleEndian.Uint32(resp[TagINDX]) != 0 {
		t.Fatal("INDX should be 0")
	}
}

// verifyRoundTrip drives a full client/server round-trip for ver and asserts
// midpoint drift.
func verifyRoundTrip(t *testing.T, versions []Version, ver Version) {
	t.Helper()
	cert, _ := testCert(t)
	rootPK := cert.edRootPK

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

// validReply returns a fresh signed reply with rootPK, nonce, and request
// bytes.
func validReply(t *testing.T, ver Version, versions []Version) (reply, rootPK, nonce, reqBytes []byte) {
	t.Helper()
	cert, _ := testCert(t)
	rootPK = cert.edRootPK

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

// corruptReplyTag decodes reply, mutates the tag map via fn, and re-encodes.
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

// allZero reports whether b is all zero bytes.
func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
