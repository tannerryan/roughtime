// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestDraftRepliesRejectInconsistentMetadata checks both draft full-packet
// forms, preserving valid single and batched replies.
func TestDraftRepliesRejectInconsistentMetadata(t *testing.T) {
	cert, _ := testCert(t)
	for _, omitTYPE := range []bool{false, true} {
		for _, count := range []int{1, 2} {
			t.Run(fmt.Sprintf("untyped=%t/batch=%d", omitTYPE, count), func(t *testing.T) {
				requests := make([]Request, count)
				for i := range requests {
					_, raw, err := CreateRequestWithOptions([]Version{VersionDraft12}, rand.Reader, ComputeSRV(cert.edRootPK), RequestOptions{Mode: Flex, OmitTYPE: omitTYPE})
					if err != nil {
						t.Fatal(err)
					}
					req, err := ParseRequestWithMode(raw, Flex)
					if err != nil {
						t.Fatal(err)
					}
					requests[i] = *req
				}
				replies, err := CreateRepliesWithOptions(VersionDraft12, requests, time.Now(), time.Second, cert, ReplyOptions{Mode: Flex})
				if err != nil {
					t.Fatal(err)
				}
				for i, reply := range replies {
					req := requests[i]
					if _, _, err := VerifyReplyWithOptions(req.Versions, reply, cert.edRootPK, req.Nonce, req.RawPacket, VerifyOptions{Mode: Flex}); err != nil {
						t.Fatalf("valid request %d: %v", i, err)
					}
				}
				for _, field := range []string{"Nonce", "Versions", "SRV", "HasType"} {
					t.Run(field, func(t *testing.T) {
						changed := append([]Request(nil), requests...)
						req := &changed[len(changed)-1]
						switch field {
						case "Nonce":
							req.Nonce = bytes.Clone(req.Nonce)
							req.Nonce[0] ^= 1
						case "Versions":
							req.Versions = []Version{Version1, VersionDraft12}
						case "SRV":
							req.SRV = bytes.Clone(req.SRV)
							req.SRV[0] ^= 1
						case "HasType":
							req.HasType = !req.HasType
						}
						_, err := CreateRepliesWithOptions(VersionDraft12, changed, time.Now(), time.Second, cert, ReplyOptions{Mode: Flex})
						if err == nil || !strings.Contains(err.Error(), "fields do not match packet") {
							t.Fatalf("inconsistent %s: %v", field, err)
						}
					})
				}
			})
		}
	}
}

// TestValidateRequestForReply covers version offers, root binding, and the
// historical nonce-only Request API.
func TestValidateRequestForReply(t *testing.T) {
	cert, _ := testCert(t)
	srv := ComputeSRV(cert.edRootPK)
	for _, tc := range []struct {
		name    string
		ver     Version
		req     Request
		wantErr string
	}{
		{"Google nonce only", VersionGoogle, Request{}, ""},
		{"Google with versions", VersionGoogle, Request{Versions: []Version{VersionDraft08}}, "unexpectedly contains versions"},
		{"legacy nonce only", VersionDraft08, Request{}, ""},
		{"legacy matching offer", VersionDraft08, Request{Versions: []Version{VersionDraft08}}, ""},
		{"legacy wrong offer", VersionDraft08, Request{Versions: []Version{VersionDraft07}}, "not offered"},
		{"matching root", VersionDraft11, Request{SRV: srv}, ""},
		{"wrong root", VersionDraft11, Request{SRV: make([]byte, 32)}, "does not identify"},
		{"missing packet", VersionDraft12, Request{Versions: []Version{VersionDraft12}}, "missing RawPacket"},
		{"typed missing packet", VersionDraft12, Request{HasType: true, Versions: []Version{VersionDraft12}}, "missing RawPacket"},
		{"PQ missing packet", VersionMLDSA44, Request{HasType: true, Versions: []Version{VersionMLDSA44}}, "missing RawPacket"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateRequestForReply(tc.ver, tc.req, cert)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want %q", err, tc.wantErr)
			}
		})
	}
	for _, ver := range []Version{VersionGoogle, VersionDraft08, VersionDraft12} {
		t.Run("parsed "+ver.ShortString(), func(t *testing.T) {
			_, raw, err := CreateRequestWithOptions([]Version{ver}, rand.Reader, nil, RequestOptions{Mode: Flex})
			if err != nil {
				t.Fatal(err)
			}
			req, err := ParseRequestWithMode(raw, Flex)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateRequestForReply(ver, *req, cert); err != nil {
				t.Fatal(err)
			}
			req.Versions = []Version{VersionDraft07}
			if err := validateRequestForReply(ver, *req, cert); err == nil {
				t.Fatal("accepted a mismatched offer")
			}
		})
	}
}

// TestCreateRepliesBatch covers batched responses across versions.
func TestCreateRepliesBatch(t *testing.T) {
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
				nonces[i], raw[i], err = CreateRequestWithOptions([]Version{tc.version}, rand.Reader, nil, RequestOptions{Mode: Flex})
				if err != nil {
					t.Fatal(err)
				}
				parsed, err := ParseRequestWithMode(raw[i], Flex)
				if err != nil {
					t.Fatal(err)
				}
				requests[i] = *parsed
			}
			replies, err := CreateRepliesWithOptions(tc.version, requests, time.Now(), time.Second, cert, ReplyOptions{Mode: Flex})
			if err != nil {
				t.Fatal(err)
			}
			for i := range replies {
				if _, _, err := VerifyReplyWithOptions([]Version{tc.version}, replies[i], cert.edRootPK, nonces[i], raw[i], VerifyOptions{Mode: Flex}); err != nil {
					t.Fatalf("reply %d: %v", i, err)
				}
			}
		})
	}
}

// TestSREPContainsVERSForDraft12 covers signed version advertisement.
func TestSREPContainsVERSForDraft12(t *testing.T) {
	cert, _ := testCert(t)
	_, req, err := CreateRequestWithOptions([]Version{VersionDraft12}, rand.Reader, nil, RequestOptions{Mode: Flex})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseRequestWithMode(req, Flex)
	if err != nil {
		t.Fatal(err)
	}
	replies, err := CreateRepliesWithOptions(VersionDraft12, []Request{*parsed}, time.Now(), time.Second, cert, ReplyOptions{Mode: Flex})
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
	nonce, req, _ := CreateRequestWithOptions([]Version{VersionDraft12}, rand.Reader, nil, RequestOptions{Mode: Flex})
	parsed, _ := ParseRequestWithMode(req, Flex)
	replies, _ := CreateRepliesWithOptions(VersionDraft12, []Request{*parsed}, time.Now(), time.Second, cert, ReplyOptions{Mode: Flex})
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
		nonce, req, err := CreateRequestWithOptions(versions, rand.Reader, nil, RequestOptions{Mode: Flex})
		if err != nil {
			t.Fatalf("CreateRequest %d: %v", i, err)
		}
		nonces[i] = nonce
		rawReqs[i] = req
		parsed, err := ParseRequestWithMode(req, Flex)
		if err != nil {
			t.Fatalf("ParseRequest %d: %v", i, err)
		}
		reqs[i] = *parsed
	}

	replies, err := CreateRepliesWithOptions(VersionMLDSA44, reqs, time.Now(), 3*time.Second, cert, ReplyOptions{Mode: Flex})
	if err != nil {
		t.Fatalf("CreateReplies: %v", err)
	}
	for i := range replies {
		if len(replies[i]) > len(rawReqs[i]) {
			t.Fatalf("reply %d length %d exceeds request length %d", i, len(replies[i]), len(rawReqs[i]))
		}
		if _, _, err := VerifyReplyWithOptions(versions, replies[i], rootPK, nonces[i], rawReqs[i], VerifyOptions{Mode: Flex}); err != nil {
			t.Fatalf("VerifyReply %d: %v", i, err)
		}
	}
}

// TestCreateRepliesRejectsNilAndWipedCertificate covers unusable certificates.
func TestCreateRepliesRejectsNilAndWipedCertificate(t *testing.T) {
	_, req, err := CreateRequestWithOptions([]Version{VersionDraft12}, rand.Reader, nil, RequestOptions{Mode: Flex})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseRequestWithMode(req, Flex)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CreateRepliesWithOptions(VersionDraft12, []Request{*parsed}, time.Now(), time.Second, nil, ReplyOptions{Mode: Flex}); err == nil {
		t.Fatal("CreateReplies accepted nil certificate")
	}
	cert, _ := testCert(t)
	cert.Wipe()
	if _, err := CreateRepliesWithOptions(VersionDraft12, []Request{*parsed}, time.Now(), time.Second, cert, ReplyOptions{Mode: Flex}); err == nil {
		t.Fatal("CreateReplies accepted wiped certificate")
	}
}
