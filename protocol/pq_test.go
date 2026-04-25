// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"testing"
	"time"

	"filippo.io/mldsa"
)

// testPQCert returns a ML-DSA-44 cert valid for ±1 hour and the root public
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
	cert, err := NewCertificatePQ(now.Add(-time.Hour), now.Add(time.Hour), onlineSK, rootSK)
	if err != nil {
		t.Fatal(err)
	}
	return cert, rootSK.PublicKey().Bytes()
}

// TestPQRoundTrip exercises CreateRequest, CreateReplies and VerifyReply for
// the PQ version.
func TestPQRoundTrip(t *testing.T) {
	cert, rootPK := testPQCert(t)

	srv := ComputeSRV(rootPK)
	if len(srv) != 32 {
		t.Fatalf("SRV length %d, want 32", len(srv))
	}

	versions := []Version{VersionMLDSA44}
	nonce, req, err := CreateRequest(versions, rand.Reader, srv)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	if len(nonce) != 32 {
		t.Fatalf("nonce length %d, want 32", len(nonce))
	}

	parsed, err := ParseRequest(req)
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}

	now := time.Now()
	replies, err := CreateReplies(VersionMLDSA44, []Request{*parsed}, now, 5*time.Second, cert)
	if err != nil {
		t.Fatalf("CreateReplies: %v", err)
	}
	if len(replies) != 1 {
		t.Fatalf("got %d replies, want 1", len(replies))
	}

	mid, radius, err := VerifyReply(versions, replies[0], rootPK, nonce, req)
	if err != nil {
		t.Fatalf("VerifyReply: %v", err)
	}
	if radius != 5*time.Second {
		t.Fatalf("radius = %v, want 5s", radius)
	}
	if diff := mid.Sub(now); diff < -time.Second || diff > time.Second {
		t.Fatalf("midpoint drift %v exceeds 1s", diff)
	}
}

// TestPQBatch verifies a multi-request batch signed with ML-DSA-44.
func TestPQBatch(t *testing.T) {
	cert, rootPK := testPQCert(t)

	const batch = 4
	versions := []Version{VersionMLDSA44}
	nonces := make([][]byte, batch)
	reqs := make([]Request, batch)
	rawReqs := make([][]byte, batch)

	for i := range batch {
		nonce, req, err := CreateRequest(versions, rand.Reader, nil)
		if err != nil {
			t.Fatalf("CreateRequest %d: %v", i, err)
		}
		nonces[i] = nonce
		rawReqs[i] = req
		parsed, err := ParseRequest(req)
		if err != nil {
			t.Fatalf("ParseRequest %d: %v", i, err)
		}
		reqs[i] = *parsed
	}

	replies, err := CreateReplies(VersionMLDSA44, reqs, time.Now(), 3*time.Second, cert)
	if err != nil {
		t.Fatalf("CreateReplies: %v", err)
	}
	for i := range replies {
		if _, _, err := VerifyReply(versions, replies[i], rootPK, nonces[i], rawReqs[i]); err != nil {
			t.Fatalf("VerifyReply %d: %v", i, err)
		}
	}
}

// TestPQRejectsWrongScheme verifies CreateReplies refuses cross-scheme
// cert/version pairings.
func TestPQRejectsWrongScheme(t *testing.T) {
	edCert, _ := testCert(t)
	pqCert, _ := testPQCert(t)

	// Ed25519 cert cannot sign VersionMLDSA44 replies
	_, req, err := CreateRequest([]Version{VersionMLDSA44}, rand.Reader, nil)
	if err != nil {
		t.Fatalf("CreateRequest(PQ): %v", err)
	}
	parsed, err := ParseRequest(req)
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}
	if _, err := CreateReplies(VersionMLDSA44, []Request{*parsed}, time.Now(), time.Second, edCert); err == nil {
		t.Fatal("expected error signing PQ version with Ed25519 cert")
	}

	// PQ cert cannot sign VersionDraft12 replies
	_, req2, err := CreateRequest([]Version{VersionDraft12}, rand.Reader, nil)
	if err != nil {
		t.Fatalf("CreateRequest(Draft12): %v", err)
	}
	parsed2, err := ParseRequest(req2)
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}
	if _, err := CreateReplies(VersionDraft12, []Request{*parsed2}, time.Now(), time.Second, pqCert); err == nil {
		t.Fatal("expected error signing Ed25519 version with PQ cert")
	}
}

// TestPQRejectsWrongRootKeyLength verifies VerifyReply rejects a root key sized
// for the wrong scheme.
func TestPQRejectsWrongRootKeyLength(t *testing.T) {
	cert, _ := testPQCert(t)
	versions := []Version{VersionMLDSA44}
	nonce, req, err := CreateRequest(versions, rand.Reader, nil)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	parsed, _ := ParseRequest(req)
	replies, err := CreateReplies(VersionMLDSA44, []Request{*parsed}, time.Now(), time.Second, cert)
	if err != nil {
		t.Fatalf("CreateReplies: %v", err)
	}
	edKey := make([]byte, ed25519.PublicKeySize)
	if _, _, err := VerifyReply(versions, replies[0], edKey, nonce, req); err == nil {
		t.Fatal("expected error on wrong root key length")
	}
}

// TestPQTamperedSREPFailsVerify confirms VerifyReply rejects a corrupted signed
// response.
func TestPQTamperedSREPFailsVerify(t *testing.T) {
	cert, rootPK := testPQCert(t)
	versions := []Version{VersionMLDSA44}
	nonce, req, err := CreateRequest(versions, rand.Reader, nil)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	parsed, _ := ParseRequest(req)
	replies, err := CreateReplies(VersionMLDSA44, []Request{*parsed}, time.Now(), time.Second, cert)
	if err != nil {
		t.Fatalf("CreateReplies: %v", err)
	}
	// flip last byte (inside signed region for a single-request batch)
	reply := append([]byte(nil), replies[0]...)
	reply[len(reply)-1] ^= 0xff
	if _, _, err := VerifyReply(versions, reply, rootPK, nonce, req); err == nil {
		t.Fatal("expected error on tampered reply")
	}
}

// TestPQVERSDowngradeRejected verifies the client enforces the downgrade check
// against the signed VERS.
func TestPQVERSDowngradeRejected(t *testing.T) {
	cert, rootPK := testPQCert(t)
	versions := []Version{VersionMLDSA44}
	nonce, req, err := CreateRequest(versions, rand.Reader, nil)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	parsed, _ := ParseRequest(req)
	replies, err := CreateReplies(VersionMLDSA44, []Request{*parsed}, time.Now(), time.Second, cert)
	if err != nil {
		t.Fatalf("CreateReplies: %v", err)
	}
	// baseline: verify succeeds
	if _, _, err := VerifyReply(versions, replies[0], rootPK, nonce, req); err != nil {
		t.Fatalf("VerifyReply baseline: %v", err)
	}

	// mixed client offer; PQ-only VERS still yields PQ as mutual-best, so check
	// passes
	offered := []Version{VersionDraft12, VersionMLDSA44}
	if _, _, err := VerifyReply(offered, replies[0], rootPK, nonce, req); err != nil {
		t.Fatalf("PQ-only VERS with mixed client offer unexpectedly rejected: %v", err)
	}
}

// TestPQComputeSRV verifies ComputeSRV returns 32 bytes for a ML-DSA-44 public
// key.
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

// TestPQNewCertificateRejectsNilKey covers the nil-key guard in
// NewCertificatePQ.
func TestPQNewCertificateRejectsNilKey(t *testing.T) {
	now := time.Now()
	if _, err := NewCertificatePQ(now, now.Add(time.Hour), nil, nil); err == nil {
		t.Fatal("expected error on nil keys")
	}
}

// TestPQNewCertificateRejectsBadWindow covers the MINT≥MAXT guard.
func TestPQNewCertificateRejectsBadWindow(t *testing.T) {
	rootSK, _ := mldsa.GenerateKey(mldsa.MLDSA44())
	onlineSK, _ := mldsa.GenerateKey(mldsa.MLDSA44())
	now := time.Now()
	if _, err := NewCertificatePQ(now.Add(time.Hour), now, onlineSK, rootSK); err == nil {
		t.Fatal("expected error when MINT >= MAXT")
	}
}

// TestPQWipeDropsReference verifies Wipe releases the PQ online signing key
// (mldsa exposes no zeroization, so Wipe relies on GC).
func TestPQWipeDropsReference(t *testing.T) {
	cert, _ := testPQCert(t)
	if cert.pqOnlineSK == nil {
		t.Fatal("PQ cert missing online key before Wipe")
	}
	cert.Wipe()
	if cert.pqOnlineSK != nil {
		t.Fatal("Wipe did not release the PQ online signing key")
	}
}

// TestPQSchemeOf verifies schemeOf maps versions to their signature schemes.
func TestPQSchemeOf(t *testing.T) {
	if s := schemeOf(VersionGoogle); s != schemeEd25519 {
		t.Fatalf("schemeOf(Google) = %v, want Ed25519", s)
	}
	if s := schemeOf(VersionDraft12); s != schemeEd25519 {
		t.Fatalf("schemeOf(Draft12) = %v, want Ed25519", s)
	}
	if s := schemeOf(VersionMLDSA44); s != schemeMLDSA44 {
		t.Fatalf("schemeOf(MLDSA44) = %v, want ML-DSA-44", s)
	}
}

// TestPQSizes confirms public key and signature sizing helpers match per-scheme
// constants.
func TestPQSizes(t *testing.T) {
	if SchemePublicKeySize(VersionMLDSA44) != mldsa.MLDSA44PublicKeySize {
		t.Fatal("PQ public key size mismatch")
	}
	if SchemeSignatureSize(VersionMLDSA44) != mldsa.MLDSA44SignatureSize {
		t.Fatal("PQ signature size mismatch")
	}
	if SchemePublicKeySize(VersionDraft12) != ed25519.PublicKeySize {
		t.Fatal("Ed25519 public key size mismatch")
	}
	if SchemeSignatureSize(VersionDraft12) != ed25519.SignatureSize {
		t.Fatal("Ed25519 signature size mismatch")
	}
}

// TestPQChainVerify verifies Chain.Verify over two PQ links.
func TestPQChainVerify(t *testing.T) {
	cert, rootPK := testPQCert(t)
	versions := []Version{VersionMLDSA44}

	var chain Chain
	for i := range 2 {
		link, err := chain.NextRequest(versions, rootPK, rand.Reader)
		if err != nil {
			t.Fatalf("NextRequest %d: %v", i, err)
		}
		parsed, err := ParseRequest(link.Request)
		if err != nil {
			t.Fatalf("ParseRequest %d: %v", i, err)
		}
		replies, err := CreateReplies(VersionMLDSA44, []Request{*parsed}, time.Now().Add(time.Duration(i)*time.Second), time.Second, cert)
		if err != nil {
			t.Fatalf("CreateReplies %d: %v", i, err)
		}
		link.Response = replies[0]
		chain.Append(link)
	}
	if err := chain.Verify(); err != nil {
		t.Fatalf("Chain.Verify: %v", err)
	}
}

// TestPQChainNonce verifies ChainNonce returns 32-byte nonces for the PQ
// version.
func TestPQChainNonce(t *testing.T) {
	prevResp := randBytes(t, 128)
	nonce, blind, err := ChainNonce(prevResp, rand.Reader, []Version{VersionMLDSA44})
	if err != nil {
		t.Fatalf("ChainNonce: %v", err)
	}
	if len(blind) != 32 || len(nonce) != 32 {
		t.Fatalf("PQ chain nonce/blind lengths = %d/%d, want 32/32", len(nonce), len(blind))
	}
}

// TestVersCrossSchemeInflationRejected verifies a forged Ed25519 SREP with an
// inflated VERS (claiming MLDSA44) is rejected by a dual-stack client.
func TestVersCrossSchemeInflationRejected(t *testing.T) {
	cert, _ := testCert(t)
	rootPK := cert.edRootPK
	clientVers := []Version{VersionDraft12, VersionMLDSA44}
	nonce, req, _ := CreateRequest([]Version{VersionDraft12}, rand.Reader, nil)
	parsed, _ := ParseRequest(req)
	g := groupD14
	tree := newMerkleTree(g, [][]byte{parsed.RawPacket})
	midpBuf := encodeTimestamp(time.Now(), g)
	var radiBuf [4]byte
	binary.LittleEndian.PutUint32(radiBuf[:], radiSeconds(time.Second))
	var verBuf [4]byte
	binary.LittleEndian.PutUint32(verBuf[:], uint32(VersionDraft12))

	// inflated VERS: Ed25519 versions plus a bogus MLDSA44 claim
	inflated := append([]byte(nil), supportedVersionsEd25519Bytes...)
	var pqBuf [4]byte
	binary.LittleEndian.PutUint32(pqBuf[:], uint32(VersionMLDSA44))
	inflated = append(inflated, pqBuf[:]...)

	srepBytes, _ := encode(map[uint32][]byte{
		TagRADI: radiBuf[:],
		TagMIDP: midpBuf[:],
		TagROOT: tree.rootHash,
		TagVER:  verBuf[:],
		TagVERS: inflated,
	})
	srepSig := signEd25519(cert.edOnlineSK, srepBytes, responseCtx)
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
		t.Fatal("expected rejection of inflated VERS claiming cross-scheme support")
	}
}

// TestPQSelectVersion verifies SelectVersion behavior across PQ-only and
// dual-suite preferences.
func TestPQSelectVersion(t *testing.T) {
	v, err := SelectVersion([]Version{VersionMLDSA44}, 32, ServerPreferenceMLDSA44)
	if err != nil || v != VersionMLDSA44 {
		t.Fatalf("SelectVersion PQ: v=%v err=%v", v, err)
	}
	if _, err := SelectVersion([]Version{VersionDraft12}, 32, ServerPreferenceMLDSA44); err == nil {
		t.Fatal("expected error: Draft12 not in PQ preference")
	}
	// dual-suite: PQ wins when offered, else Ed25519
	dual := append([]Version{}, ServerPreferenceMLDSA44...)
	dual = append(dual, ServerPreferenceEd25519...)
	v, err = SelectVersion([]Version{VersionMLDSA44, VersionDraft12}, 32, dual)
	if err != nil || v != VersionMLDSA44 {
		t.Fatalf("dual server preferring PQ: v=%v err=%v", v, err)
	}
	v, err = SelectVersion([]Version{VersionDraft12}, 32, dual)
	if err != nil || v != VersionDraft12 {
		t.Fatalf("dual server falling back to Draft12: v=%v err=%v", v, err)
	}
}
