// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"slices"
	"testing"
	"time"
)

// TestRequestOptionsPublicAPIs covers TYPE omission and legacy packet sizing
// through both public option-bearing request constructors.
func TestRequestOptionsPublicAPIs(t *testing.T) {
	versions := []Version{VersionDraft12}
	nonce, randomReq, err := CreateRequestWithOptions(
		versions, rand.Reader, nil, RequestOptions{Mode: Flex, OmitTYPE: true})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseRequestWithMode(randomReq, Flex)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.HasType {
		t.Fatal("CreateRequestWithOptions(OmitTYPE) emitted TYPE")
	}

	callerReq, err := CreateRequestWithNonceOptions(
		versions, nonce, nil, RequestOptions{Mode: Flex, OmitTYPE: true})
	if err != nil {
		t.Fatal(err)
	}
	callerParsed, err := ParseRequestWithMode(callerReq, Flex)
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
				[]Version{tc.version}, rand.Reader, nil, RequestOptions{Mode: Flex})
			if err != nil {
				t.Fatal(err)
			}
			_, legacyReq, err := CreateRequestWithOptions(
				[]Version{tc.version}, rand.Reader, nil, RequestOptions{Mode: Flex, LegacyPacketSize: true})
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
		[]Version{VersionDraft11}, rand.Reader, nil, RequestOptions{Mode: Flex, OmitTYPE: true}); err == nil {
		t.Fatal("CreateRequestWithOptions accepted OmitTYPE for draft 11")
	}
	if _, err := CreateRequestWithNonceOptions(
		[]Version{VersionDraft11}, make([]byte, 32), nil, RequestOptions{Mode: Flex, OmitTYPE: true}); err == nil {
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
			[]Version{VersionDraft12}, rand.Reader, nil, RequestOptions{Mode: Flex})
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseRequestWithMode(raw[i], Flex)
		if err != nil {
			t.Fatal(err)
		}
		requests[i] = *parsed
	}

	replies, err := CreateRepliesWithOptions(
		VersionDraft12, requests, time.Now(), time.Second, cert, ReplyOptions{Mode: Flex, Draft14NodeFirst: true})
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
		[]Version{VersionDraft12}, replies[0], cert.edRootPK, nonces[0], raw[0], VerifyOptions{Mode: Flex, RequireTYPE: true}); err != nil {
		t.Fatalf("strict verification of typed node-first reply: %v", err)
	}

	untypedNonce, untypedRaw, err := CreateRequestWithOptions(
		[]Version{VersionDraft12}, rand.Reader, nil, RequestOptions{Mode: Flex, OmitTYPE: true})
	if err != nil {
		t.Fatal(err)
	}
	untypedRequest, err := ParseRequestWithMode(untypedRaw, Flex)
	if err != nil {
		t.Fatal(err)
	}
	untypedReplies, err := CreateRepliesWithOptions(
		VersionDraft12, []Request{*untypedRequest}, time.Now(), time.Second, cert, ReplyOptions{Mode: Flex})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyReplyWithOptions(
		[]Version{VersionDraft12}, untypedReplies[0], cert.edRootPK, untypedNonce, untypedRaw,
		VerifyOptions{Mode: Flex, RequireTYPE: true}); err == nil {
		t.Fatal("RequireTYPE accepted an untyped draft-12/13 exchange")
	}

	if _, err := CreateRepliesWithOptions(
		VersionDraft11, []Request{{Nonce: make([]byte, 32)}}, time.Now(), time.Second, cert,
		ReplyOptions{Mode: Flex, Draft14NodeFirst: true}); err == nil {
		t.Fatal("Draft14NodeFirst accepted a draft-11 request")
	}
}

// TestReplySupportedVersions checks authenticated per-listener version lists
// and rejects claims outside the shared delegation's configured support.
func TestReplySupportedVersions(t *testing.T) {
	cert, rootSK := testCert(t)
	nonce, packet, err := CreateRequest([]Version{Version1}, rand.Reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	req, err := ParseRequest(packet)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string    // subtest label
		versions []Version // configured per-listener advertisement
		wantErr  bool      // whether the advertisement must be rejected
	}{
		{"primary", []Version{Version1}, false},
		{"compatibility", nil, false},
		{"subset", []Version{VersionDraft12, Version1}, false},
		{"empty", []Version{}, true},
		{"missing selected", []Version{VersionDraft12}, true},
		{"unknown", []Version{Version1, 2}, true},
		{"different scheme", []Version{Version1, VersionMLDSA44}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			replies, err := CreateRepliesWithOptions(Version1, []Request{*req}, time.Now(), time.Second,
				cert, ReplyOptions{SupportedVersions: tc.versions})
			if tc.wantErr {
				if err == nil {
					t.Fatal("invalid advertisement accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := VerifyReply([]Version{Version1}, replies[0], rootSK.Public().(ed25519.PublicKey), nonce, packet); err != nil {
				t.Fatal(err)
			}
			msg, err := Decode(replies[0][PacketHeaderSize:])
			if err != nil {
				t.Fatal(err)
			}
			srep, err := Decode(msg[TagSREP])
			if err != nil {
				t.Fatal(err)
			}
			want := cert.signedVERS()
			if tc.versions != nil {
				versions := slices.Clone(tc.versions)
				slices.Sort(versions)
				want = testVersionBytes(versions)
			}
			if !bytes.Equal(srep[TagVERS], want) {
				t.Fatalf("signed VERS = %x, want %x", srep[TagVERS], want)
			}
		})
	}
	rootSK, onlineSK := testKeys(t)
	now := time.Now()
	strictCert, err := NewCertificate(now.Add(-time.Hour), now.Add(time.Hour), onlineSK, rootSK)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CreateRepliesWithOptions(Version1, []Request{*req}, now, time.Second, strictCert,
		ReplyOptions{SupportedVersions: []Version{Version1, VersionDraft12}}); err == nil {
		t.Fatal("advertised draft absent from certificate support")
	}
}
