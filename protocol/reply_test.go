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
)

// TestCreateRepliesGoogle verifies CreateReplies produces a Google-Roughtime
// reply that passes verifyResponse.
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

// TestCreateRepliesAllDrafts verifies CreateReplies across every IETF draft and
// groupD14 with TYPE.
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

// TestCreateRepliesZeroMidpoint verifies a zero midpoint self-timestamps to
// time.Now.
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

// TestCreateRepliesRejectsEmpty verifies CreateReplies rejects an empty request
// batch.
func TestCreateRepliesRejectsEmpty(t *testing.T) {
	cert, _ := testCert(t)
	if _, err := CreateReplies(VersionDraft12, nil, time.Now(), time.Second, cert); err == nil {
		t.Fatal("expected error")
	}
}

// TestCreateRepliesRejectsMixedHasType verifies CreateReplies rejects batches
// with inconsistent HasType.
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
	parsed0.HasType = false

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

// TestCreateRepliesRejectsWrongNonceSize verifies CreateReplies rejects
// requests with mismatched nonce sizes.
func TestCreateRepliesRejectsWrongNonceSize(t *testing.T) {
	cert, _ := testCert(t)

	// draft-12 expects 32-byte nonces; second request supplies 64
	_, req0, err := CreateRequest([]Version{VersionDraft12}, rand.Reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	parsed0, err := ParseRequest(req0)
	if err != nil {
		t.Fatal(err)
	}

	bad := *parsed0
	bad.Nonce = randBytes(t, 64)

	reqs := []Request{*parsed0, bad}
	if _, err := CreateReplies(VersionDraft12, reqs, time.Now(), time.Second, cert); err == nil {
		t.Fatal("expected error for batch with mismatched nonce size")
	}
}

// TestCreateRepliesBatchDraft01Rejected verifies draft-01 multi-request batches
// are rejected.
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

// TestCreateRepliesBatchDraft03 verifies CreateReplies handles a multi-request
// draft-03 batch.
func TestCreateRepliesBatchDraft03(t *testing.T) {
	cert, _ := testCert(t)
	rootPK := cert.edRootPK
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

// TestCreateRepliesBatchDraft02Rejected verifies draft-02 multi-request batches
// are rejected.
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

// TestCreateRepliesBatchDraft08 verifies CreateReplies handles a multi-request
// draft-08 batch.
func TestCreateRepliesBatchDraft08(t *testing.T) {
	cert, _ := testCert(t)
	rootPK := cert.edRootPK
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

// TestCreateRepliesBatchDraft14 verifies CreateReplies handles a multi-request
// draft-14 batch.
func TestCreateRepliesBatchDraft14(t *testing.T) {
	cert, _ := testCert(t)
	rootPK := cert.edRootPK
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

// TestCreateRepliesBatchGoogle verifies CreateReplies handles a
// non-power-of-two Google-Roughtime batch.
func TestCreateRepliesBatchGoogle(t *testing.T) {
	cert, _ := testCert(t)
	rootPK := cert.edRootPK
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

// TestCreateRepliesEarlyDraftHeader verifies drafts 01-04 server responses
// carry the ROUGHTIM header.
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

// TestSREPContainsVERSForDraft12 verifies draft-12 SREP carries an ascending
// VERS list including draft-12.
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

// TestDraft12NoTopLevelVER verifies draft-12 replies omit top-level VER and
// place it inside SREP.
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

// TestPQBatch verifies CreateReplies handles a multi-request ML-DSA-44 batch.
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

// TestPQRejectsWrongScheme verifies CreateReplies rejects cross-scheme
// cert/version pairings.
func TestPQRejectsWrongScheme(t *testing.T) {
	edCert, _ := testCert(t)
	pqCert, _ := testPQCert(t)

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

// FuzzCreateReplies fuzzes CreateReplies for panic-safety on adversarial
// requests.
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

// FuzzCreateRepliesBatch fuzzes CreateReplies for panic-safety on multi-request
// batches.
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
