// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

// TestRequestOptionsPublicAPIs covers TYPE omission and legacy packet sizing
// through both public option-bearing request constructors.
func TestRequestOptionsPublicAPIs(t *testing.T) {
	versions := []Version{VersionDraft12}
	nonce, randomReq, err := CreateRequestWithOptions(
		versions, rand.Reader, nil, RequestOptions{OmitTYPE: true})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseRequest(randomReq)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.HasType {
		t.Fatal("CreateRequestWithOptions(OmitTYPE) emitted TYPE")
	}

	callerReq, err := CreateRequestWithNonceOptions(
		versions, nonce, nil, RequestOptions{OmitTYPE: true})
	if err != nil {
		t.Fatal(err)
	}
	callerParsed, err := ParseRequest(callerReq)
	if err != nil {
		t.Fatal(err)
	}
	if callerParsed.HasType || !bytes.Equal(callerParsed.Nonce, nonce) {
		t.Fatal("CreateRequestWithNonceOptions did not preserve nonce/untyped form")
	}

	for _, tc := range []struct {
		name        string
		version     Version
		defaultSize int
		legacySize  int
	}{
		{"IETF", VersionDraft12, 1036, 1024},
		{"ML-DSA-44", VersionMLDSA44, 8204, 8192},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, defaultReq, err := CreateRequestWithOptions(
				[]Version{tc.version}, rand.Reader, nil, RequestOptions{})
			if err != nil {
				t.Fatal(err)
			}
			_, legacyReq, err := CreateRequestWithOptions(
				[]Version{tc.version}, rand.Reader, nil, RequestOptions{LegacyPacketSize: true})
			if err != nil {
				t.Fatal(err)
			}
			if len(defaultReq) != tc.defaultSize || len(legacyReq) != tc.legacySize {
				t.Fatalf("default/legacy sizes = %d/%d, want %d/%d",
					len(defaultReq), len(legacyReq), tc.defaultSize, tc.legacySize)
			}
		})
	}

	if _, _, err := CreateRequestWithOptions(
		[]Version{VersionDraft11}, rand.Reader, nil, RequestOptions{OmitTYPE: true}); err == nil {
		t.Fatal("CreateRequestWithOptions accepted OmitTYPE for draft 11")
	}
	if _, err := CreateRequestWithNonceOptions(
		[]Version{VersionDraft11}, make([]byte, 32), nil, RequestOptions{OmitTYPE: true}); err == nil {
		t.Fatal("CreateRequestWithNonceOptions accepted OmitTYPE for draft 11")
	}
}

// TestCreateRepliesDraft14NodeFirstOption proves that the public reply option
// emits the draft-14/15 Merkle orientation for a non-singleton tree.
func TestCreateRepliesDraft14NodeFirstOption(t *testing.T) {
	cert, _ := testCert(t)
	requests := make([]Request, 2)
	nonces := make([][]byte, 2)
	raw := make([][]byte, 2)
	for i := range requests {
		var err error
		nonces[i], raw[i], err = CreateRequestWithOptions(
			[]Version{VersionDraft12}, rand.Reader, nil, RequestOptions{})
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseRequest(raw[i])
		if err != nil {
			t.Fatal(err)
		}
		requests[i] = *parsed
	}

	replies, err := CreateRepliesWithOptions(
		VersionDraft12, requests, time.Now(), time.Second, cert, ReplyOptions{Draft14NodeFirst: true})
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
	srep, err := Decode(resp[TagSREP])
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyMerkleOrder(0, resp[TagPATH], raw[0], srep[TagROOT], groupD14, true); err != nil {
		t.Fatalf("node-first proof: %v", err)
	}
	if err := verifyMerkleOrder(0, resp[TagPATH], raw[0], srep[TagROOT], groupD14, false); !errors.Is(err, ErrMerkleMismatch) {
		t.Fatalf("hash-first verification error = %v, want ErrMerkleMismatch", err)
	}
	if _, _, err := VerifyReplyWithOptions(
		[]Version{VersionDraft12}, replies[0], cert.edRootPK, nonces[0], raw[0], VerifyOptions{RequireTYPE: true}); err != nil {
		t.Fatalf("strict verification of typed node-first reply: %v", err)
	}

	untypedNonce, untypedRaw, err := CreateRequestWithOptions(
		[]Version{VersionDraft12}, rand.Reader, nil, RequestOptions{OmitTYPE: true})
	if err != nil {
		t.Fatal(err)
	}
	untypedRequest, err := ParseRequest(untypedRaw)
	if err != nil {
		t.Fatal(err)
	}
	untypedReplies, err := CreateRepliesWithOptions(
		VersionDraft12, []Request{*untypedRequest}, time.Now(), time.Second, cert, ReplyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyReplyWithOptions(
		[]Version{VersionDraft12}, untypedReplies[0], cert.edRootPK, untypedNonce, untypedRaw,
		VerifyOptions{RequireTYPE: true}); err == nil {
		t.Fatal("RequireTYPE accepted an untyped draft-12/13 exchange")
	}

	if _, err := CreateRepliesWithOptions(
		VersionDraft11, []Request{{Nonce: make([]byte, 32)}}, time.Now(), time.Second, cert,
		ReplyOptions{Draft14NodeFirst: true}); err == nil {
		t.Fatal("Draft14NodeFirst accepted a draft-11 request")
	}
}
