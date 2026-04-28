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
	"time"

	"filippo.io/mldsa"
)

// TestVerifyReplyAllVersions verifies VerifyReply round-trips across every
// supported version.
func TestVerifyReplyAllVersions(t *testing.T) {
	for _, v := range append([]Version{VersionGoogle}, supportedVersionsEd25519...) {
		t.Run(v.ShortString(), func(t *testing.T) {
			verifyRoundTrip(t, []Version{v}, v)
		})
	}
}

// TestVerifyNoVersionDowngradeSingleEntryVERS verifies single-entry VERS
// matching the chosen VER passes.
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

// TestVerifyReplyRejectsBadRootPK verifies VerifyReply rejects a wrong root
// public key.
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

// TestVerifyReplyRejectsBadNonce verifies VerifyReply rejects a mismatched
// nonce.
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

// TestVerifyReplyRejectsInvalidPKSize verifies VerifyReply rejects a wrong-size
// public key.
func TestVerifyReplyRejectsInvalidPKSize(t *testing.T) {
	if _, _, err := VerifyReply([]Version{VersionGoogle}, nil, []byte{1, 2, 3}, nil, nil); err == nil {
		t.Fatal("expected error for invalid PK size")
	}
}

// TestVerifyReplyRejectsEmptyVersions verifies VerifyReply rejects an empty
// versions list.
func TestVerifyReplyRejectsEmptyVersions(t *testing.T) {
	pk := make([]byte, ed25519.PublicKeySize)
	if _, _, err := VerifyReply(nil, nil, pk, nil, nil); err == nil {
		t.Fatal("expected error for empty versions")
	}
}

// TestVerifyReplyRejectsMissingRequestBytes verifies drafts 12+ require
// requestBytes.
func TestVerifyReplyRejectsMissingRequestBytes(t *testing.T) {
	cert, _ := testCert(t)
	rootPK := cert.edRootPK
	nonce, req, _ := CreateRequest([]Version{VersionDraft12}, rand.Reader, nil)
	parsed, _ := ParseRequest(req)
	replies, _ := CreateReplies(VersionDraft12, []Request{*parsed}, time.Now(), time.Second, cert)

	if _, _, err := VerifyReply([]Version{VersionDraft12}, replies[0], rootPK, nonce, nil); err == nil {
		t.Fatal("expected error for nil requestBytes on draft 12+")
	}
}

// TestVerifyReplyRejectsExpiredCert verifies VerifyReply rejects a midpoint
// outside the certificate window.
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

// TestVerifyReplyBatchIndex verifies VerifyReply at a non-zero Merkle index.
func TestVerifyReplyBatchIndex(t *testing.T) {
	cert, _ := testCert(t)
	rootPK := cert.edRootPK

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

// TestVerifyReplyBatchDraft12 verifies a non-power-of-two draft-12 batch with
// full-packet leaves.
func TestVerifyReplyBatchDraft12(t *testing.T) {
	cert, _ := testCert(t)
	rootPK := cert.edRootPK

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

// TestExtractResponseVERTopLevel verifies extractResponseVER reads top-level
// VER when SREP is nil.
func TestExtractResponseVERTopLevel(t *testing.T) {
	resp := map[uint32][]byte{
		TagVER: {0x08, 0x00, 0x00, 0x80},
	}
	ver, ok := extractResponseVER(resp, nil)
	if !ok || ver != VersionDraft08 {
		t.Fatal("expected VersionDraft08 from top-level VER")
	}
}

// TestExtractResponseVERFromSREP verifies extractResponseVER reads SREP.VER.
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

// TestExtractResponseVERMissing verifies extractResponseVER returns ok=false
// when no VER is present.
func TestExtractResponseVERMissing(t *testing.T) {
	resp := map[uint32][]byte{TagSIG: make([]byte, 64)}
	if _, ok := extractResponseVER(resp, nil); ok {
		t.Fatal("expected no VER")
	}
}

// TestVersionOffered verifies versionOffered membership test.
func TestVersionOffered(t *testing.T) {
	versions := []Version{VersionDraft08, VersionDraft12}
	if !versionOffered(VersionDraft12, versions) {
		t.Fatal("VersionDraft12 should be offered")
	}
	if versionOffered(VersionDraft10, versions) {
		t.Fatal("VersionDraft10 should not be offered")
	}
}

// TestVerifyReplyRejectsUnwrapError verifies VerifyReply rejects a malformed
// ROUGHTIM header.
func TestVerifyReplyRejectsUnwrapError(t *testing.T) {
	pk := make([]byte, ed25519.PublicKeySize)
	badPkt := []byte("ROUGHTIMxxxx")
	binary.LittleEndian.PutUint32(badPkt[8:12], 9999)
	if _, _, err := VerifyReply([]Version{VersionDraft08}, badPkt, pk, nil, nil); err == nil {
		t.Fatal("expected error for bad ROUGHTIM header")
	}
}

// TestVerifyReplyRejectsDecodeError verifies VerifyReply rejects an unparseable
// reply body.
func TestVerifyReplyRejectsDecodeError(t *testing.T) {
	pk := make([]byte, ed25519.PublicKeySize)
	pkt := wrapPacket([]byte{0xff, 0xff, 0xff, 0xff})
	if _, _, err := VerifyReply([]Version{VersionDraft08}, pkt, pk, nil, nil); err == nil {
		t.Fatal("expected error for corrupt reply body")
	}
}

// TestVerifyReplyRejectsUnofferedVersion verifies VerifyReply rejects a server
// VER not offered by the client.
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

// TestVerifyReplyRejectsMissingSREP verifies VerifyReply rejects replies
// lacking SREP.
func TestVerifyReplyRejectsMissingSREP(t *testing.T) {
	reply, rootPK, nonce, req := validReply(t, VersionGoogle, []Version{VersionGoogle})
	corrupted := corruptReplyTag(t, reply, false, func(tags map[uint32][]byte) {
		delete(tags, TagSREP)
	})
	if _, _, err := VerifyReply([]Version{VersionGoogle}, corrupted, rootPK, nonce, req); err == nil {
		t.Fatal("expected error for missing SREP")
	}
}

// TestVerifyReplyRejectsBadSIG verifies VerifyReply rejects SIG of wrong
// length.
func TestVerifyReplyRejectsBadSIG(t *testing.T) {
	reply, rootPK, nonce, req := validReply(t, VersionGoogle, []Version{VersionGoogle})
	corrupted := corruptReplyTag(t, reply, false, func(tags map[uint32][]byte) {
		tags[TagSIG] = make([]byte, 12)
	})
	if _, _, err := VerifyReply([]Version{VersionGoogle}, corrupted, rootPK, nonce, req); err == nil {
		t.Fatal("expected error for invalid SIG")
	}
}

// TestVerifyReplyRejectsMissingSIG verifies VerifyReply rejects replies lacking
// SIG.
func TestVerifyReplyRejectsMissingSIG(t *testing.T) {
	reply, rootPK, nonce, req := validReply(t, VersionGoogle, []Version{VersionGoogle})
	corrupted := corruptReplyTag(t, reply, false, func(tags map[uint32][]byte) {
		delete(tags, TagSIG)
	})
	if _, _, err := VerifyReply([]Version{VersionGoogle}, corrupted, rootPK, nonce, req); err == nil {
		t.Fatal("expected error for missing SIG")
	}
}

// TestVerifyReplyRejectsMissingCERT verifies VerifyReply rejects replies
// lacking CERT.
func TestVerifyReplyRejectsMissingCERT(t *testing.T) {
	reply, rootPK, nonce, req := validReply(t, VersionGoogle, []Version{VersionGoogle})
	corrupted := corruptReplyTag(t, reply, false, func(tags map[uint32][]byte) {
		delete(tags, TagCERT)
	})
	if _, _, err := VerifyReply([]Version{VersionGoogle}, corrupted, rootPK, nonce, req); err == nil {
		t.Fatal("expected error for missing CERT")
	}
}

// TestVerifyReplyRejectsCorruptCERT verifies VerifyReply rejects an unparseable
// CERT.
func TestVerifyReplyRejectsCorruptCERT(t *testing.T) {
	reply, rootPK, nonce, req := validReply(t, VersionGoogle, []Version{VersionGoogle})
	corrupted := corruptReplyTag(t, reply, false, func(tags map[uint32][]byte) {
		tags[TagCERT] = []byte{0xff, 0xff, 0xff, 0xff}
	})
	if _, _, err := VerifyReply([]Version{VersionGoogle}, corrupted, rootPK, nonce, req); err == nil {
		t.Fatal("expected error for corrupt CERT")
	}
}

// TestVerifyReplyRejectsMissingDELE verifies VerifyReply rejects a CERT lacking
// DELE.
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

// TestVerifyReplyRejectsBadCERTSig verifies VerifyReply rejects a CERT with
// wrong-size SIG.
func TestVerifyReplyRejectsBadCERTSig(t *testing.T) {
	reply, rootPK, nonce, req := validReply(t, VersionGoogle, []Version{VersionGoogle})
	corrupted := corruptReplyTag(t, reply, false, func(tags map[uint32][]byte) {
		certMsg, _ := Decode(tags[TagCERT])
		certMsg[TagSIG] = make([]byte, 12)
		tags[TagCERT], _ = encode(certMsg)
	})
	if _, _, err := VerifyReply([]Version{VersionGoogle}, corrupted, rootPK, nonce, req); err == nil {
		t.Fatal("expected error for bad CERT SIG size")
	}
}

// TestVerifyReplyRejectsDELESignatureFailure verifies VerifyReply rejects an
// invalid DELE signature.
func TestVerifyReplyRejectsDELESignatureFailure(t *testing.T) {
	reply, rootPK, nonce, req := validReply(t, VersionGoogle, []Version{VersionGoogle})
	corrupted := corruptReplyTag(t, reply, false, func(tags map[uint32][]byte) {
		certMsg, _ := Decode(tags[TagCERT])
		sig := make([]byte, ed25519.SignatureSize)
		copy(sig, certMsg[TagSIG])
		sig[0] ^= 0xff
		certMsg[TagSIG] = sig
		tags[TagCERT], _ = encode(certMsg)
	})
	if _, _, err := VerifyReply([]Version{VersionGoogle}, corrupted, rootPK, nonce, req); err == nil {
		t.Fatal("expected error for DELE signature failure")
	}
}

// TestVerifyReplyRejectsBadPUBK verifies VerifyReply rejects DELE with
// wrong-size PUBK.
func TestVerifyReplyRejectsBadPUBK(t *testing.T) {
	reply, rootPK, nonce, req := validReply(t, VersionGoogle, []Version{VersionGoogle})
	corrupted := corruptReplyTag(t, reply, false, func(tags map[uint32][]byte) {
		certMsg, _ := Decode(tags[TagCERT])
		dele, _ := Decode(certMsg[TagDELE])
		dele[TagPUBK] = make([]byte, 16)
		deleBytes, _ := encode(dele)
		certMsg[TagDELE] = deleBytes
		tags[TagCERT], _ = encode(certMsg)
	})
	if _, _, err := VerifyReply([]Version{VersionGoogle}, corrupted, rootPK, nonce, req); err == nil {
		t.Fatal("expected error for bad PUBK in DELE")
	}
}

// TestVerifyReplyRejectsBadMINT verifies VerifyReply rejects DELE with
// wrong-size MINT.
func TestVerifyReplyRejectsBadMINT(t *testing.T) {
	reply, rootPK, nonce, req := validReply(t, VersionGoogle, []Version{VersionGoogle})
	corrupted := corruptReplyTag(t, reply, false, func(tags map[uint32][]byte) {
		certMsg, _ := Decode(tags[TagCERT])
		dele, _ := Decode(certMsg[TagDELE])
		dele[TagMINT] = make([]byte, 4)
		deleBytes, _ := encode(dele)
		certMsg[TagDELE] = deleBytes
		tags[TagCERT], _ = encode(certMsg)
	})
	if _, _, err := VerifyReply([]Version{VersionGoogle}, corrupted, rootPK, nonce, req); err == nil {
		t.Fatal("expected error for bad MINT in DELE")
	}
}

// TestVerifyReplyRejectsBadMAXT verifies VerifyReply rejects DELE with
// wrong-size MAXT.
func TestVerifyReplyRejectsBadMAXT(t *testing.T) {
	reply, rootPK, nonce, req := validReply(t, VersionGoogle, []Version{VersionGoogle})
	corrupted := corruptReplyTag(t, reply, false, func(tags map[uint32][]byte) {
		certMsg, _ := Decode(tags[TagCERT])
		dele, _ := Decode(certMsg[TagDELE])
		dele[TagMAXT] = make([]byte, 4)
		deleBytes, _ := encode(dele)
		certMsg[TagDELE] = deleBytes
		tags[TagCERT], _ = encode(certMsg)
	})
	if _, _, err := VerifyReply([]Version{VersionGoogle}, corrupted, rootPK, nonce, req); err == nil {
		t.Fatal("expected error for bad MAXT in DELE")
	}
}

// TestVerifyReplyRejectsSREPSignatureFailure verifies VerifyReply rejects an
// invalid SREP signature.
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

// TestVerifyReplyRejectsCorruptSREP verifies VerifyReply rejects an unparseable
// SREP.
func TestVerifyReplyRejectsCorruptSREP(t *testing.T) {
	reply, rootPK, nonce, req := validReply(t, VersionGoogle, []Version{VersionGoogle})
	corrupted := corruptReplyTag(t, reply, false, func(tags map[uint32][]byte) {
		tags[TagSREP] = []byte{0xff, 0xff, 0xff, 0xff}
	})
	if _, _, err := VerifyReply([]Version{VersionGoogle}, corrupted, rootPK, nonce, req); err == nil {
		t.Fatal("expected error for corrupt SREP")
	}
}

// TestVerifyReplyRejectsMissingMIDP verifies VerifyReply rejects SREP lacking
// MIDP.
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

// TestVerifyReplyRejectsMissingRADI verifies VerifyReply rejects SREP lacking
// RADI.
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

// TestVerifyReplyRejectsBadROOT verifies VerifyReply rejects SREP with
// wrong-size ROOT.
func TestVerifyReplyRejectsBadROOT(t *testing.T) {
	reply, rootPK, nonce, req := validReply(t, VersionGoogle, []Version{VersionGoogle})
	corrupted := corruptReplyTag(t, reply, false, func(tags map[uint32][]byte) {
		srep, _ := Decode(tags[TagSREP])
		srep[TagROOT] = make([]byte, 16)
		tags[TagSREP], _ = encode(srep)
	})
	if _, _, err := VerifyReply([]Version{VersionGoogle}, corrupted, rootPK, nonce, req); err == nil {
		t.Fatal("expected error for bad ROOT size")
	}
}

// TestVerifyReplySREPRejectsNilSREP verifies verifyReplySREP rejects a nil
// SREP.
func TestVerifyReplySREPRejectsNilSREP(t *testing.T) {
	if _, _, err := verifyReplySREP(nil, map[uint32][]byte{}, nil, nil, groupGoogle); err == nil {
		t.Fatal("expected error for nil SREP")
	}
}

// TestVerifyReplySREPRejectsMissingMIDP verifies verifyReplySREP rejects SREP
// lacking MIDP.
func TestVerifyReplySREPRejectsMissingMIDP(t *testing.T) {
	srep := map[uint32][]byte{
		TagRADI: make([]byte, 4),
		TagROOT: make([]byte, 64),
	}
	if _, _, err := verifyReplySREP(srep, map[uint32][]byte{}, nil, nil, groupGoogle); err == nil {
		t.Fatal("expected error for missing MIDP")
	}
}

// TestVerifyReplySREPRejectsMissingRADI verifies verifyReplySREP rejects SREP
// lacking RADI.
func TestVerifyReplySREPRejectsMissingRADI(t *testing.T) {
	srep := map[uint32][]byte{
		TagMIDP: make([]byte, 8),
		TagROOT: make([]byte, 64),
	}
	if _, _, err := verifyReplySREP(srep, map[uint32][]byte{}, nil, nil, groupGoogle); err == nil {
		t.Fatal("expected error for missing RADI")
	}
}

// TestVerifyReplySREPRejectsBadROOT verifies verifyReplySREP rejects SREP with
// wrong-size ROOT.
func TestVerifyReplySREPRejectsBadROOT(t *testing.T) {
	srep := map[uint32][]byte{
		TagMIDP: make([]byte, 8),
		TagRADI: make([]byte, 4),
		TagROOT: make([]byte, 16),
	}
	if _, _, err := verifyReplySREP(srep, map[uint32][]byte{}, nil, nil, groupGoogle); err == nil {
		t.Fatal("expected error for bad ROOT size")
	}
}

// TestVerifyReplySREPRejectsBadMIDP verifies verifyReplySREP rejects SREP with
// wrong-size MIDP.
func TestVerifyReplySREPRejectsBadMIDP(t *testing.T) {
	nonce := make([]byte, 64)
	root := leafHash(groupGoogle, nonce)
	var indx [4]byte
	srep := map[uint32][]byte{
		TagMIDP: make([]byte, 4),
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

// TestVerifyReplySREPRejectsBadRADI verifies verifyReplySREP rejects SREP with
// wrong-size RADI.
func TestVerifyReplySREPRejectsBadRADI(t *testing.T) {
	nonce := make([]byte, 64)
	root := leafHash(groupGoogle, nonce)
	var indx [4]byte
	srep := map[uint32][]byte{
		TagMIDP: make([]byte, 8),
		TagRADI: make([]byte, 8),
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

// TestVerifyReplyDetectsDowngrade verifies VerifyReply rejects a downgraded
// SREP.VER.
func TestVerifyReplyDetectsDowngrade(t *testing.T) {
	cert, _ := testCert(t)
	rootPK := cert.edRootPK
	clientVers := []Version{VersionDraft11, VersionDraft12}
	nonce, req, _ := CreateRequest(clientVers, rand.Reader, nil)
	parsed, _ := ParseRequest(req)
	g := groupD14
	tree := newMerkleTree(g, [][]byte{parsed.RawPacket})
	midpBuf := encodeTimestamp(time.Now(), g)
	var radiBuf [4]byte
	binary.LittleEndian.PutUint32(radiBuf[:], radiSeconds(time.Second))
	var verBuf [4]byte
	binary.LittleEndian.PutUint32(verBuf[:], uint32(VersionDraft11))
	srepTags := map[uint32][]byte{
		TagRADI: radiBuf[:],
		TagMIDP: midpBuf[:],
		TagROOT: tree.rootHash,
		TagVER:  verBuf[:],
		TagVERS: supportedVersionsEd25519Bytes,
	}
	srepBytes, _ := encode(srepTags)
	toSign := make([]byte, len(responseCtx)+len(srepBytes))
	copy(toSign, responseCtx)
	copy(toSign[len(responseCtx):], srepBytes)
	srepSig := ed25519.Sign(cert.edOnlineSK, toSign)
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

// TestVerifyReplyRejectsResponseTYPENot1 verifies VerifyReply rejects response
// TYPE values other than 1.
func TestVerifyReplyRejectsResponseTYPENot1(t *testing.T) {
	cert, _ := testCert(t)
	rootPK := cert.edRootPK
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
		TagVERS: supportedVersionsEd25519Bytes,
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

// TestVerifyReplyRejectsResponseTYPEWrongLength verifies VerifyReply rejects
// response TYPE not 4 bytes.
func TestVerifyReplyRejectsResponseTYPEWrongLength(t *testing.T) {
	cert, _ := testCert(t)
	rootPK := cert.edRootPK
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
		TagVERS: supportedVersionsEd25519Bytes,
	}
	srepBytes, _ := encode(srepTags)
	toSign := make([]byte, len(responseCtx)+len(srepBytes))
	copy(toSign, responseCtx)
	copy(toSign[len(responseCtx):], srepBytes)
	srepSig := ed25519.Sign(cert.edOnlineSK, toSign)
	for _, badLen := range []int{0, 8} {
		resp := map[uint32][]byte{
			TagSIG:  srepSig,
			TagSREP: srepBytes,
			TagCERT: cert.certBytes(g),
			TagPATH: nil,
			TagINDX: make([]byte, 4),
			TagNONC: nonce,
			TagTYPE: make([]byte, badLen),
		}
		replyMsg, _ := encode(resp)
		reply := wrapPacket(replyMsg)
		if _, _, err := VerifyReply(clientVers, reply, rootPK, nonce, req); err == nil {
			t.Fatalf("expected error for response TYPE length=%d", badLen)
		}
	}
}

// TestVerifyNoVersionDowngradeRejectsLargeVERS verifies VERS lists with more
// than 32 entries are rejected.
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
	srepSig := ed25519.Sign(cert.edOnlineSK, toSign)

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

// TestExtractVersionFromReply verifies ExtractVersion returns IETF versions and
// false for Google.
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

// TestVerifyReplyRejectsMismatchedNONC verifies VerifyReply rejects a
// mismatched top-level NONC for drafts 03+.
func TestVerifyReplyRejectsMismatchedNONC(t *testing.T) {
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

// TestVerifyReplyMidpointAtDELEBoundary verifies midpoints equal to MINT or
// MAXT pass validation.
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

// TestVerifyReplyToleratesUnknownTags verifies VerifyReply tolerates unknown
// top-level tags.
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

// TestVerifyNoVersionDowngradeRejectsUnsortedVERS verifies
// verifyNoVersionDowngrade rejects unsorted VERS lists.
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

// TestExtractResponseVERPrefersSREP verifies extractResponseVER prefers
// SREP.VER over top-level VER.
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

// TestVerifyReplyRejectsMismatchedNONCInSREP verifies VerifyReply detects
// tampered NONC inside SREP for drafts 01-02.
func TestVerifyReplyRejectsMismatchedNONCInSREP(t *testing.T) {
	for _, ver := range []Version{VersionDraft01, VersionDraft02} {
		t.Run(ver.ShortString(), func(t *testing.T) {
			reply, rootPK, nonce, req := validReply(t, ver, []Version{ver})

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

// TestVerifyReplyToleratesMissingNONC verifies VerifyReply tolerates missing
// top-level NONC for drafts 03+.
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

// TestVerifyReplyRejectsMissingPATH verifies VerifyReply rejects replies
// lacking PATH.
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

// TestVerifyReplyToleratesMissingTYPE verifies a draft-12+ response without
// TYPE falls back to groupD12.
func TestVerifyReplyToleratesMissingTYPE(t *testing.T) {
	reply, rootPK, nonce, req := validReply(t, VersionDraft12, []Version{VersionDraft12})
	tampered := corruptReplyTag(t, reply, true, func(tags map[uint32][]byte) {
		delete(tags, TagTYPE)
	})
	if _, _, err := VerifyReply([]Version{VersionDraft12}, tampered, rootPK, nonce, req); err != nil {
		t.Fatalf("expected graceful fallback without TYPE: %v", err)
	}
}

// TestVerifyReplyRejectsZeroRADI verifies drafts 12+ reject RADI=0 in the
// reply.
func TestVerifyReplyRejectsZeroRADI(t *testing.T) {
	cert, _ := testCert(t)
	rootPK := cert.edRootPK
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
		TagVERS: supportedVersionsEd25519Bytes,
	}
	srepBytes, _ := encode(srepTags)
	toSign := make([]byte, len(responseCtx)+len(srepBytes))
	copy(toSign, responseCtx)
	copy(toSign[len(responseCtx):], srepBytes)
	srepSig := ed25519.Sign(cert.edOnlineSK, toSign)
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

// TestVerifyNoVersionDowngradeBranches verifies verifyNoVersionDowngrade error
// branches not covered by integration tests.
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

// TestVerifyNoVersionDowngradeRejectsChosenNotInVERS verifies SREP.VER must
// appear in the signed VERS list.
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

// TestVerifyReplyRejectsMissingTopLevelVER verifies drafts 01-11 reject
// responses missing top-level VER.
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

// TestExtractVersionShortInputs verifies ExtractVersion returns false on short
// inputs.
func TestExtractVersionShortInputs(t *testing.T) {
	for _, in := range [][]byte{nil, {}, {0x01}, {0x01, 0x02, 0x03}} {
		if _, ok := ExtractVersion(in); ok {
			t.Fatalf("ExtractVersion(%v) returned ok=true on short input", in)
		}
	}
}

// TestPQRoundTrip verifies an end-to-end ML-DSA-44 client/server round-trip.
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

// TestPQRejectsWrongRootKeyLength verifies VerifyReply rejects a root key of
// wrong scheme size.
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

// TestPQTamperedSREPFailsVerify verifies VerifyReply rejects a tampered
// ML-DSA-44 reply.
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
	if _, _, err := VerifyReply(versions, replies[0], rootPK, nonce, req); err != nil {
		t.Fatalf("VerifyReply baseline: %v", err)
	}

	// mixed client offer; PQ-only VERS still yields PQ as mutual-best, so the
	// check passes
	offered := []Version{VersionDraft12, VersionMLDSA44}
	if _, _, err := VerifyReply(offered, replies[0], rootPK, nonce, req); err != nil {
		t.Fatalf("PQ-only VERS with mixed client offer unexpectedly rejected: %v", err)
	}
}

// TestVersCrossSchemeInflationRejected verifies an Ed25519 SREP cannot inflate
// VERS to claim ML-DSA-44 support.
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

// FuzzPQVerifyReply fuzzes ML-DSA-44 reply verification for panic-safety and
// idempotency.
func FuzzPQVerifyReply(f *testing.F) {
	rootSK, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		f.Fatal(err)
	}
	onlineSK, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		f.Fatal(err)
	}
	rootPKBytes := rootSK.PublicKey().Bytes()
	now := time.Now()
	cert, err := NewCertificateMLDSA44(now.Add(-time.Hour), now.Add(time.Hour), onlineSK, rootSK)
	if err != nil {
		f.Fatal(err)
	}
	versions := []Version{VersionMLDSA44}
	srv := ComputeSRV(rootPKBytes)
	nonce, req, err := CreateRequest(versions, rand.Reader, srv)
	if err != nil {
		f.Fatal(err)
	}
	parsed, err := ParseRequest(req)
	if err != nil {
		f.Fatal(err)
	}
	replies, err := CreateReplies(VersionMLDSA44, []Request{*parsed}, now, time.Second, cert)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(replies[0], rootPKBytes, nonce, req)

	f.Fuzz(func(t *testing.T, reply, rootKey, nonce, request []byte) {
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
	})
}

// FuzzVerifyReply fuzzes VerifyReply for panic-safety and idempotency on a
// fixed key.
func FuzzVerifyReply(f *testing.F) {
	// inline cert setup since testCert takes *testing.T, not *testing.F
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
		midA, radA, errA := VerifyReply([]Version{VersionDraft12}, reply, rootKey, nonce, request)
		if errA != nil {
			return
		}
		// idempotency: a second call with identical bytes must match, catching
		// stateful or time-dependent bugs
		midB, radB, errB := VerifyReply([]Version{VersionDraft12}, reply, rootKey, nonce, request)
		if errB != nil {
			t.Fatalf("non-idempotent: first ok, second err=%v", errB)
		}
		if !midA.Equal(midB) || radA != radB {
			t.Fatalf("non-deterministic: %v±%v vs %v±%v", midA, radA, midB, radB)
		}
	})
}

// FuzzVerifyReplyAllVersions fuzzes VerifyReply across every wire group for
// panic-safety.
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

// FuzzExtractVersion fuzzes ExtractVersion for panic-safety on arbitrary reply
// bytes.
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
