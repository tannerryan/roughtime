// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"encoding/binary"
	"maps"
	"testing"
	"time"

	"go.uber.org/goleak"
)

// TestMain enables goroutine leak checks for protocol tests.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// wrapPacket adds ROUGHTIM framing.
func wrapPacket(msg []byte) []byte {
	pkt := make([]byte, 12+len(msg))
	copy(pkt[0:8], packetMagic[:])
	binary.LittleEndian.PutUint32(pkt[8:12], uint32(len(msg)))
	copy(pkt[12:], msg)
	return pkt
}

// testKeys returns fresh Ed25519 root and online keys.
func testKeys(t testing.TB) (ed25519.PrivateKey, ed25519.PrivateKey) {
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

// randBytes returns n random bytes.
func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// buildGoogleRequest returns a legacy-sized Google request.
func buildGoogleRequest(nonce []byte) []byte {
	// header: 4 (tag count) + 4 (1 offset) + 8 (2 tags) = 16 bytes
	pad := make([]byte, 1024-len(nonce)-16)
	msg, _ := encode(map[uint32][]byte{
		TagNONC: nonce,
		TagPAD:  pad,
	})
	return msg
}

// buildIETFRequest returns a padded, framed IETF request.
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
func testCert(t testing.TB) (*Certificate, ed25519.PrivateKey) {
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

// allZero reports whether b contains only zero bytes.
func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// testVersionBytes encodes a version list.
func testVersionBytes(versions []Version) []byte {
	out := make([]byte, 4*len(versions))
	for i, version := range versions {
		binary.LittleEndian.PutUint32(out[4*i:], uint32(version))
	}
	return out
}

// mustRadiSeconds encodes radius or fails the test.
func mustRadiSeconds(t testing.TB, radius time.Duration) uint32 {
	t.Helper()
	value, err := radiSeconds(radius)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
