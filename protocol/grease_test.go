// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"testing"
	"time"
)

// TestGreaseJoin covers framing preservation and body-length repair.
func TestGreaseJoin(t *testing.T) {
	body, err := encode(map[uint32][]byte{TagNONC: make([]byte, 32)})
	if err != nil {
		t.Fatal(err)
	}
	header := make([]byte, PacketHeaderSize)
	copy(header, packetMagic[:])
	binary.LittleEndian.PutUint32(header[8:], 1)

	joined := greaseJoin(header, body)
	length, err := ParsePacketHeader(joined)
	if err != nil {
		t.Fatal(err)
	}
	if int(length) != len(body) || !bytes.Equal(joined[PacketHeaderSize:], body) {
		t.Fatal("greaseJoin did not preserve the body and repair frame length")
	}
	if got := greaseJoin(nil, body); !bytes.Equal(got, body) {
		t.Fatal("greaseJoin changed an unframed Google body")
	}
}

// TestDropOneTag covers mandatory-candidate removal without disturbing
// unrelated tags, plus the no-candidate path.
func TestDropOneTag(t *testing.T) {
	msg := map[uint32][]byte{
		TagSIG:     make([]byte, 64),
		TagSREP:    make([]byte, 4),
		0xfffffffc: {1, 2, 3, 4},
	}
	if !dropOneTag(msg, []uint32{TagSIG, TagSREP}) {
		t.Fatal("dropOneTag did not remove a present candidate")
	}
	_, hasSIG := msg[TagSIG]
	_, hasSREP := msg[TagSREP]
	if hasSIG == hasSREP {
		t.Fatal("dropOneTag must remove exactly one present candidate")
	}
	if _, ok := msg[0xfffffffc]; !ok {
		t.Fatal("dropOneTag removed an unrelated tag")
	}
	before := len(msg)
	if dropOneTag(msg, []uint32{TagCERT, TagPATH}) || len(msg) != before {
		t.Fatal("dropOneTag changed a message with no matching candidate")
	}
}

// TestGreaseTransforms checks each transformation without relying on Grease's
// random mode selection. Unknown outer tags preserve authentication.
func TestGreaseTransforms(t *testing.T) {
	for _, ver := range []Version{VersionGoogle, VersionDraft08, VersionDraft12} {
		t.Run(ver.ShortString(), func(t *testing.T) {
			versions := []Version{ver}
			reply, rootPK, nonce, request := validReply(t, ver, versions)
			for _, tc := range []struct {
				name  string
				apply func([]byte, Version) []byte
				valid bool
			}{
				{"missing tag", greaseDropTag, false},
				{"unknown tag", greaseUndefinedTag, true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					out := tc.apply(bytes.Clone(reply), ver)
					if len(out) == 0 || bytes.Equal(out, reply) {
						t.Fatal("transformation did not change reply")
					}
					_, _, err := VerifyReply(versions, out, rootPK, nonce, request)
					if (err == nil) != tc.valid {
						t.Fatalf("verification error = %v, want valid=%v", err, tc.valid)
					}
				})
			}
			corrupt := bytes.Clone(reply)
			if !greaseCorruptSig(corrupt, ver) {
				t.Fatal("signature corruption failed")
			}
			if _, _, err := VerifyReply(versions, corrupt, rootPK, nonce, request); err == nil {
				t.Fatal("corrupted signature verified")
			}
			out := greaseWrongVersion(bytes.Clone(reply), ver)
			if ver != VersionDraft08 {
				if out != nil {
					t.Fatal("changed a reply without a top-level VER")
				}
			} else if _, _, err := VerifyReply(versions, out, rootPK, nonce, request); err == nil {
				t.Fatal("unsupported version verified")
			}
		})
	}
}

// TestGreaseMalformedInput covers invalid reply handling.
func TestGreaseMalformedInput(t *testing.T) {
	for _, ver := range []Version{VersionGoogle, VersionDraft08, VersionDraft12} {
		t.Run(ver.String(), func(t *testing.T) {
			for _, input := range [][]byte{nil, {}, {0x00}, make([]byte, 11)} {
				Grease(input, ver)
			}
		})
	}
}

// TestGreaseDoesNotPanicMLDSA44 covers large ML-DSA-44 replies.
func TestGreaseDoesNotPanicMLDSA44(t *testing.T) {
	cert, rootPK := testPQCert(t)
	versions := []Version{VersionMLDSA44}
	srv := ComputeSRV(rootPK)
	_, request, err := CreateRequest(versions, rand.Reader, srv)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	parsed, err := ParseRequest(request)
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}
	replies, err := CreateReplies(VersionMLDSA44, []Request{*parsed}, time.Now(), 3*time.Second, cert)
	if err != nil {
		t.Fatalf("CreateReplies: %v", err)
	}
	Grease(replies[0], VersionMLDSA44)
}
