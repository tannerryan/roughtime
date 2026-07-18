// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"crypto/rand"
	"encoding/binary"
	"testing"
	"time"
)

// TestCreateRepliesBatch covers batched responses across versions.
func TestCreateRepliesBatch(t *testing.T) {
	// Cases cover batching across representative wire groups.
	for _, tc := range []struct {
		version Version
		size    int
	}{
		{VersionGoogle, 3},
		{VersionDraft03, 3},
		{VersionDraft08, 4},
		{VersionDraft12, 5},
	} {
		t.Run(tc.version.ShortString(), func(t *testing.T) {
			cert, _ := testCert(t)
			requests := make([]Request, tc.size)
			nonces := make([][]byte, tc.size)
			raw := make([][]byte, tc.size)
			for i := range requests {
				var err error
				nonces[i], raw[i], err = CreateRequest([]Version{tc.version}, rand.Reader, nil)
				if err != nil {
					t.Fatal(err)
				}
				parsed, err := ParseRequest(raw[i])
				if err != nil {
					t.Fatal(err)
				}
				requests[i] = *parsed
			}
			replies, err := CreateReplies(tc.version, requests, time.Now(), time.Second, cert)
			if err != nil {
				t.Fatal(err)
			}
			for i := range replies {
				if _, _, err := VerifyReply([]Version{tc.version}, replies[i], cert.edRootPK, nonces[i], raw[i]); err != nil {
					t.Fatalf("reply %d: %v", i, err)
				}
			}
		})
	}
}

// TestSREPContainsVERSForDraft12 covers signed version advertisement.
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

// TestDraft12NoTopLevelVER covers the shared-version response layout.
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

// TestPQBatch covers batched ML-DSA-44 responses.
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
		if len(replies[i]) > len(rawReqs[i]) {
			t.Fatalf("reply %d length %d exceeds request length %d", i, len(replies[i]), len(rawReqs[i]))
		}
		if _, _, err := VerifyReply(versions, replies[i], rootPK, nonces[i], rawReqs[i]); err != nil {
			t.Fatalf("VerifyReply %d: %v", i, err)
		}
	}
}

// TestCreateRepliesRejectsNilAndWipedCertificate covers unusable certificates.
func TestCreateRepliesRejectsNilAndWipedCertificate(t *testing.T) {
	_, req, err := CreateRequest([]Version{VersionDraft12}, rand.Reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CreateReplies(VersionDraft12, []Request{*parsed}, time.Now(), time.Second, nil); err == nil {
		t.Fatal("CreateReplies accepted nil certificate")
	}
	cert, _ := testCert(t)
	cert.Wipe()
	if _, err := CreateReplies(VersionDraft12, []Request{*parsed}, time.Now(), time.Second, cert); err == nil {
		t.Fatal("CreateReplies accepted wiped certificate")
	}
}
