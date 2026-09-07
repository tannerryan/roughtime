// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

// TestVerifyReplyAllVersions covers Google and recognized Ed25519 versions.
func TestVerifyReplyAllVersions(t *testing.T) {
	for _, v := range append([]Version{VersionGoogle}, supportedVersionsEd25519...) {
		t.Run(v.ShortString(), func(t *testing.T) {
			verifyRoundTrip(t, []Version{v}, v)
		})
	}
}

// TestVerifyReplyRejectsBadRootPK covers root-key authentication.
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

// TestVerifyReplyRejectsBadNonce covers nonce authentication.
func TestVerifyReplyRejectsBadNonce(t *testing.T) {
	cert, _ := testCert(t)
	rootPK := cert.edRootPK
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

// TestVerifyReplyRejectsUnofferedVersion covers an unoffered response version.
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

// TestVerifyReplyRejectsResponseTYPENot1 covers invalid response types.
func TestVerifyReplyRejectsResponseTYPENot1(t *testing.T) {
	cert, _ := testCert(t)
	rootPK := cert.edRootPK
	clientVers := []Version{VersionDraft12}
	nonce, req, _ := CreateRequest(clientVers, rand.Reader, nil)
	parsed, _ := ParseRequest(req)
	g := groupD14
	tree := newMerkleTreeWithOrder(g, [][]byte{parsed.RawPacket}, merkleNodeFirst(g))
	midpBuf := encodeTimestamp(time.Now(), g)
	var radiBuf [4]byte
	binary.LittleEndian.PutUint32(radiBuf[:], mustRadiSeconds(t, time.Second))
	var verBuf [4]byte
	binary.LittleEndian.PutUint32(verBuf[:], uint32(VersionDraft12))
	srepTags := map[uint32][]byte{
		TagRADI: radiBuf[:],
		TagMIDP: midpBuf[:],
		TagROOT: tree.rootHash,
		TagVER:  verBuf[:],
		TagVERS: testVersionBytes(supportedVersionsEd25519),
	}
	srepBytes, _ := encode(srepTags)
	toSign := make([]byte, len(responseCtx)+len(srepBytes))
	copy(toSign, responseCtx)
	copy(toSign[len(responseCtx):], srepBytes)
	srepSig := ed25519.Sign(cert.edOnlineSK, toSign)
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

// TestVerifyReplyMidpointAtDELEBoundary covers inclusive delegation bounds.
func TestVerifyReplyMidpointAtDELEBoundary(t *testing.T) {
	rootSK, onlineSK := testKeys(t)
	rootPK := rootSK.Public().(ed25519.PublicKey)
	now := time.Now().Truncate(time.Second)
	cert, err := NewCertificate(now, now.Add(time.Hour), onlineSK, rootSK)
	if err != nil {
		t.Fatal(err)
	}

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

// TestVerifyReplyToleratesUnknownTags covers extension tags.
func TestVerifyReplyToleratesUnknownTags(t *testing.T) {
	cert, _ := testCert(t)
	rootPK := cert.edRootPK
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
	resp[0xFFFFFFFC] = make([]byte, 4)
	tampered, err := encode(resp)
	if err != nil {
		t.Fatal(err)
	}
	tamperedReply := wrapPacket(tampered)

	if _, _, err := VerifyReply([]Version{VersionDraft08}, tamperedReply, rootPK, nonce, req); err != nil {
		t.Fatalf("unknown tag should not break verification: %v", err)
	}
}

// TestVerifyNoVersionDowngradeRejectsUnsortedVERS covers noncanonical VERS.
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
	err = verifySREPVersions(srep, []Version{VersionDraft12}, groupD12)
	if err == nil {
		t.Fatal("expected error for unsorted VERS in SREP")
	}
	if got := err.Error(); got != "protocol: VERS not sorted in ascending order" {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestVerifyReplyVersionListCompatibility covers signed 32/33-entry VERS at the
// draft-12/13 boundary. Untyped input follows the historical draft-12 policy.
// TYPE makes the modern cap enforceable.
func TestVerifyReplyVersionListCompatibility(t *testing.T) {
	cert, _ := testCert(t)
	for _, tc := range []struct {
		name       string
		count      int
		withType   bool
		wantReject bool
	}{
		{"untyped 32", 32, false, false},
		{"untyped 33", 33, false, false},
		{"typed 32", 32, true, false},
		{"typed 33", 33, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := RequestOptions{OmitTYPE: !tc.withType}
			nonce, request, err := CreateRequestWithOptions(
				[]Version{VersionDraft12}, rand.Reader, nil, opts)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := ParseRequest(request)
			if err != nil {
				t.Fatal(err)
			}
			replies, err := CreateReplies(
				VersionDraft12, []Request{*parsed}, time.Now(), time.Second, cert)
			if err != nil {
				t.Fatal(err)
			}
			reply := resignSREP(t, replies[0], cert.edOnlineSK, func(srep map[uint32][]byte) {
				srep[TagVERS] = testVersionBytes(longVersionList(VersionDraft12, tc.count))
			})
			_, _, err = VerifyReply(
				[]Version{VersionDraft12}, reply, cert.edRootPK, nonce, request)
			if tc.wantReject {
				if err == nil || !strings.Contains(err.Error(), "max 32") {
					t.Fatalf("VerifyReply error = %v, want 32-entry limit", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("VerifyReply: %v", err)
			}
		})
	}
}

// TestVerifyReplyRejectsSignedMalformedSREPFields exercises semantic checks
// after a valid online-key signature, rather than failing at authentication.
func TestVerifyReplyRejectsSignedMalformedSREPFields(t *testing.T) {
	cert, _ := testCert(t)
	nonce, request, err := CreateRequest([]Version{VersionDraft12}, rand.Reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	replies, err := CreateReplies(
		VersionDraft12, []Request{*parsed}, time.Now(), time.Second, cert)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name    string
		mutate  func(map[uint32][]byte)
		wantErr string
	}{
		{"missing MIDP", func(s map[uint32][]byte) { delete(s, TagMIDP) }, "missing MIDP"},
		{"short MIDP", func(s map[uint32][]byte) { s[TagMIDP] = make([]byte, 4) }, "timestamp must be 8 bytes"},
		{"missing RADI", func(s map[uint32][]byte) { delete(s, TagRADI) }, "missing RADI"},
		{"long RADI", func(s map[uint32][]byte) { s[TagRADI] = make([]byte, 8) }, "RADI must be 4 bytes"},
		{"missing ROOT", func(s map[uint32][]byte) { delete(s, TagROOT) }, "missing or invalid ROOT"},
		{"short ROOT", func(s map[uint32][]byte) { s[TagROOT] = make([]byte, 28) }, "missing or invalid ROOT"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reply := resignSREP(t, replies[0], cert.edOnlineSK, tc.mutate)
			if _, _, err := VerifyReply(
				[]Version{VersionDraft12}, reply, cert.edRootPK, nonce, request); err == nil ||
				!strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("VerifyReply error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

// resignSREP replaces and signs a nested SREP in an otherwise valid IETF reply.
// It lets tests distinguish authenticated malformed fields from random
// signature corruption.
func resignSREP(t *testing.T, reply []byte, onlineSK ed25519.PrivateKey, mutate func(map[uint32][]byte)) []byte {
	t.Helper()
	inner, err := unwrapPacket(reply)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := Decode(inner)
	if err != nil {
		t.Fatal(err)
	}
	srep, err := Decode(resp[TagSREP])
	if err != nil {
		t.Fatal(err)
	}
	mutate(srep)
	srepBytes, err := encode(srep)
	if err != nil {
		t.Fatal(err)
	}
	resp[TagSREP] = srepBytes
	resp[TagSIG] = signEd25519(onlineSK, srepBytes, responseCtx)
	inner, err = encode(resp)
	if err != nil {
		t.Fatal(err)
	}
	return wrapPacket(inner)
}

// TestVerifyReplyRejectsMismatchedNONCInSREP covers signed nonce mismatch.
func TestVerifyReplyRejectsMismatchedNONCInSREP(t *testing.T) {
	for _, ver := range []Version{VersionDraft01, VersionDraft02} {
		t.Run(ver.ShortString(), func(t *testing.T) {
			cert, _ := testCert(t)
			nonce, req, err := CreateRequest([]Version{ver}, rand.Reader, nil)
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
			tampered := resignSREP(t, replies[0], cert.edOnlineSK, func(srep map[uint32][]byte) {
				srep[TagNONC][0] ^= 0xff
			})

			if _, _, err := VerifyReply([]Version{ver}, tampered, cert.edRootPK, nonce, req); err == nil ||
				!strings.Contains(err.Error(), "NONC in SREP does not match request nonce") {
				t.Fatalf("VerifyReply error = %v, want signed NONC mismatch", err)
			}
		})
	}
}

// TestVerifyReplyToleratesMissingNONC covers optional top-level NONC echoes.
func TestVerifyReplyToleratesMissingNONC(t *testing.T) {
	for _, ver := range []Version{VersionDraft03, VersionDraft05, VersionDraft08, VersionDraft10, VersionDraft12} {
		t.Run(ver.ShortString(), func(t *testing.T) {
			reply, rootPK, nonce, req := validReply(t, ver, []Version{ver})
			tampered := corruptReplyTag(t, reply, true, func(tags map[uint32][]byte) {
				delete(tags, TagNONC)
			})
			if _, _, err := VerifyReply([]Version{ver}, tampered, rootPK, nonce, req); err != nil {
				t.Fatalf("VerifyReply rejected missing NONC: %v", err)
			}
		})
	}
}

// TestVerifyReplyToleratesMissingTYPE covers draft-12/13 compatibility.
func TestVerifyReplyToleratesMissingTYPE(t *testing.T) {
	reply, rootPK, nonce, req := validReply(t, VersionDraft12, []Version{VersionDraft12})
	tampered := corruptReplyTag(t, reply, true, func(tags map[uint32][]byte) {
		delete(tags, TagTYPE)
	})
	if _, _, err := VerifyReply([]Version{VersionDraft12}, tampered, rootPK, nonce, req); err != nil {
		t.Fatalf("expected graceful fallback without TYPE: %v", err)
	}
}

// TestVerifyReplyRejectsZeroRADI covers invalid zero uncertainty.
func TestVerifyReplyRejectsZeroRADI(t *testing.T) {
	cert, _ := testCert(t)
	rootPK := cert.edRootPK
	for _, ver := range []Version{VersionDraft10, VersionDraft12} {
		t.Run(ver.ShortString(), func(t *testing.T) {
			versions := []Version{ver}
			nonce, req, err := CreateRequest(versions, rand.Reader, nil)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := ParseRequest(req)
			if err != nil {
				t.Fatal(err)
			}
			g := wireGroupOf(ver, parsed.HasType)
			leaf := parsed.Nonce
			if usesFullPacketLeaf(g) {
				leaf = parsed.RawPacket
			}
			tree := newMerkleTreeWithOrder(g, [][]byte{leaf}, merkleNodeFirst(g))
			midpBuf := encodeTimestamp(time.Now(), g)
			srepTags := map[uint32][]byte{
				TagRADI: make([]byte, 4),
				TagMIDP: midpBuf[:],
				TagROOT: tree.rootHash,
			}
			if hasSREPVERS(g) {
				var verBuf [4]byte
				binary.LittleEndian.PutUint32(verBuf[:], uint32(ver))
				srepTags[TagVER] = verBuf[:]
				srepTags[TagVERS] = testVersionBytes(supportedVersionsEd25519)
			}
			srepBytes, err := encode(srepTags)
			if err != nil {
				t.Fatal(err)
			}
			resp := map[uint32][]byte{
				TagSIG:  signEd25519(cert.edOnlineSK, srepBytes, responseCtx),
				TagSREP: srepBytes,
				TagCERT: cert.certBytes(g),
				TagPATH: nil,
				TagINDX: make([]byte, 4),
			}
			if hasResponseVER(g) {
				var verBuf [4]byte
				binary.LittleEndian.PutUint32(verBuf[:], uint32(ver))
				resp[TagVER] = verBuf[:]
			}
			if hasResponseNONC(g) {
				resp[TagNONC] = nonce
			}
			if g >= groupD14 {
				resp[TagTYPE] = []byte{1, 0, 0, 0}
			}
			reply, err := encode(resp)
			if err != nil {
				t.Fatal(err)
			}
			if usesRoughtimHeader(g) {
				reply = wrapPacket(reply)
			}
			_, _, err = VerifyReply(versions, reply, rootPK, nonce, req)
			if err == nil || !strings.Contains(err.Error(), "RADI must not be zero") {
				t.Fatalf("VerifyReply error = %v, want zero-RADI error", err)
			}
		})
	}
}

// TestVerifyReplyRejectsBadNonceLengthWithoutRequest covers legacy callers.
func TestVerifyReplyRejectsBadNonceLengthWithoutRequest(t *testing.T) {
	for _, ver := range []Version{VersionGoogle, VersionDraft05, VersionDraft11} {
		t.Run(ver.ShortString(), func(t *testing.T) {
			reply, rootPK, nonce, _ := validReply(t, ver, []Version{ver})
			nonce = append(nonce, 0)
			if _, _, err := VerifyReply([]Version{ver}, reply, rootPK, nonce, nil); err == nil || !strings.Contains(err.Error(), "nonce length") {
				t.Fatalf("VerifyReply error = %v, want nonce-length error", err)
			}
		})
	}
}

// TestVerifyReplyRejectsMissingTopLevelVER covers required version tags.
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

// TestPQRoundTrip covers an ML-DSA-44 exchange.
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

// TestPQTamperedSREPFailsVerify covers PQ SREP authentication.
func TestPQTamperedSREPFailsVerify(t *testing.T) {
	cert, rootPK := testPQCert(t)
	versions := []Version{VersionMLDSA44}
	nonce, req, err := CreateRequest(versions, rand.Reader, nil)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	parsed, err := ParseRequest(req)
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}
	replies, err := CreateReplies(VersionMLDSA44, []Request{*parsed}, time.Now(), time.Second, cert)
	if err != nil {
		t.Fatalf("CreateReplies: %v", err)
	}
	reply := corruptReplyTag(t, replies[0], true, func(resp map[uint32][]byte) {
		srep := append([]byte(nil), resp[TagSREP]...)
		lo, _, ok := findTagRange(srep, TagMIDP)
		if !ok {
			t.Fatal("missing MIDP in SREP")
		}
		srep[lo] ^= 0xff
		resp[TagSREP] = srep
	})
	if _, _, err := VerifyReply(versions, reply, rootPK, nonce, req); err == nil ||
		!strings.Contains(err.Error(), "SREP signature verification failed") {
		t.Fatalf("VerifyReply error = %v, want SREP authentication failure", err)
	}
}

// TestPQVERSMixedOfferAccepted covers a PQ-only VERS with a mixed wire offer.
func TestPQVERSMixedOfferAccepted(t *testing.T) {
	cert, rootPK := testPQCert(t)
	offered := []Version{VersionDraft12, VersionMLDSA44}
	nonce, req, err := CreateRequest(offered, rand.Reader, nil)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	parsed, err := ParseRequest(req)
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}
	if len(parsed.Versions) != 2 || parsed.Versions[0] != VersionDraft12 || parsed.Versions[1] != VersionMLDSA44 {
		t.Fatalf("wire offer = %v, want %v", parsed.Versions, offered)
	}
	replies, err := CreateReplies(VersionMLDSA44, []Request{*parsed}, time.Now(), time.Second, cert)
	if err != nil {
		t.Fatalf("CreateReplies: %v", err)
	}
	if _, _, err := VerifyReply(offered, replies[0], rootPK, nonce, req); err != nil {
		t.Fatalf("PQ-only VERS with mixed client offer unexpectedly rejected: %v", err)
	}
}

// TestVersCrossSchemeInflationRejected covers cross-scheme VERS claims.
func TestVersCrossSchemeInflationRejected(t *testing.T) {
	cert, _ := testCert(t)
	rootPK := cert.edRootPK
	clientVers := []Version{VersionDraft12, VersionMLDSA44}
	nonce, req, _ := CreateRequest([]Version{VersionDraft12}, rand.Reader, nil)
	parsed, _ := ParseRequest(req)
	g := groupD14
	tree := newMerkleTreeWithOrder(g, [][]byte{parsed.RawPacket}, merkleNodeFirst(g))
	midpBuf := encodeTimestamp(time.Now(), g)
	var radiBuf [4]byte
	binary.LittleEndian.PutUint32(radiBuf[:], mustRadiSeconds(t, time.Second))
	var verBuf [4]byte
	binary.LittleEndian.PutUint32(verBuf[:], uint32(VersionDraft12))

	// inflated VERS: Ed25519 versions plus a bogus MLDSA44 claim
	inflated := testVersionBytes(supportedVersionsEd25519)

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

// FuzzVerifyReply exercises response authentication on arbitrary input.
func FuzzVerifyReply(f *testing.F) {
	edCert, _ := testCert(f)
	pqCert, pqRootKey := testPQCert(f)
	for _, ver := range []Version{VersionGoogle, VersionDraft08, VersionDraft12, VersionMLDSA44} {
		cert, rootKey := edCert, []byte(edCert.edRootPK)
		if ver == VersionMLDSA44 {
			cert, rootKey = pqCert, pqRootKey
		}
		nonce, request, err := CreateRequest([]Version{ver}, rand.Reader, nil)
		if err != nil {
			f.Fatal(err)
		}
		parsed, err := ParseRequest(request)
		if err != nil {
			f.Fatal(err)
		}
		replies, err := CreateReplies(ver, []Request{*parsed}, time.Now(), time.Second, cert)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(replies[0], rootKey, nonce, request)
	}

	f.Fuzz(func(t *testing.T, reply, rootKey, nonce, request []byte) {
		parsed, err := ParseRequest(request)
		if err != nil {
			return
		}
		versions := parsed.Versions
		if len(versions) == 0 {
			versions = []Version{VersionGoogle}
		}
		midA, radA, errA := VerifyReply(versions, reply, rootKey, nonce, request)
		if errA != nil {
			return
		}
		// idempotency: a second call with identical bytes must match, catching
		// stateful or time-dependent bugs
		midB, radB, errB := VerifyReply(versions, reply, rootKey, nonce, request)
		if errB != nil {
			t.Fatalf("non-idempotent: first ok, second err=%v", errB)
		}
		if !midA.Equal(midB) || radA != radB {
			t.Fatalf("non-deterministic: %v±%v vs %v±%v", midA, radA, midB, radB)
		}
		badNonce := append([]byte(nil), nonce...)
		badNonce[0] ^= 0xff
		if _, _, err := VerifyReply(versions, reply, rootKey, badNonce, request); err == nil {
			t.Fatal("authenticated reply accepted a mutated nonce")
		}
	})
}

// TestVerifyReplyRejectsEpochMisdecode covers ambiguous epoch decoding.
func TestVerifyReplyRejectsEpochMisdecode(t *testing.T) {
	cert, _ := testCert(t)
	rootPK := cert.edRootPK
	offered := []Version{VersionDraft05, VersionDraft08}

	// honest draft-05 (MJD) reply with the current time verifies
	nonce, req, _ := CreateRequest(offered, rand.Reader, nil)
	parsed, _ := ParseRequest(req)
	honest, _ := CreateReplies(VersionDraft05, []Request{*parsed}, time.Now(), time.Second, cert)
	if _, _, err := VerifyReply(offered, honest[0], rootPK, nonce, req); err != nil {
		t.Fatalf("honest draft-05 reply should verify: %v", err)
	}

	// forge a draft-08 (Unix) reply down to draft-05 so its timestamp decodes
	// as MJD, giving the year 1858
	forged, _ := CreateReplies(VersionDraft08, []Request{*parsed}, time.Now(), time.Second, cert)
	reply := forged[0]
	body, _ := unwrapPacket(reply)
	lo, _, ok := findTagRange(body, TagVER)
	if !ok {
		t.Fatal("no top-level VER in draft-08 reply")
	}
	binary.LittleEndian.PutUint32(reply[PacketHeaderSize+lo:], uint32(VersionDraft05))
	if _, _, err := VerifyReply(offered, reply, rootPK, nonce, req); err == nil {
		t.Fatal("forged epoch-crossing VER should be rejected")
	}
}
