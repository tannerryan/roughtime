// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"bytes"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"testing"
	"time"
)

// TestMLDSA44RFCWireFormat checks RFC fields, signature inputs, time units, and
// Merkle ordering.
func TestMLDSA44RFCWireFormat(t *testing.T) {
	root, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatal(err)
	}
	online, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatal(err)
	}
	// An early Unix timestamp also checks that legacy calendar limits do not
	// apply.
	midpoint := time.Unix(100000, 0).UTC()
	cert, err := NewCertificateMLDSA44(midpoint.Add(-time.Hour), midpoint.Add(time.Hour), online, root)
	if err != nil {
		t.Fatal(err)
	}
	defer cert.Wipe()
	requests := make([]Request, 3)
	for i := range requests {
		nonce := bytes.Repeat([]byte{byte(i + 1)}, 32)
		raw, err := CreateRequestWithNonceOptions([]Version{VersionMLDSA44}, nonce, ComputeSRV(root.PublicKey().Bytes()), RequestOptions{Mode: Flex})
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) != 8204 || string(raw[:8]) != "ROUGHTIM" || binary.LittleEndian.Uint32(raw[8:12]) != 8192 {
			t.Fatal("incorrect request framing or padding")
		}
		parsed, err := ParseRequestWithMode(raw, Flex)
		if err != nil {
			t.Fatal(err)
		}
		if !parsed.HasType || !bytes.Equal(parsed.Nonce, nonce) {
			t.Fatal("incorrect request TYPE or NONC")
		}
		requests[i] = *parsed
	}
	replies, err := CreateRepliesWithOptions(VersionMLDSA44, requests, midpoint, time.Second, cert, ReplyOptions{Mode: Flex})
	if err != nil {
		t.Fatal(err)
	}
	for i, reply := range replies {
		if string(reply[:8]) != "ROUGHTIM" || int(binary.LittleEndian.Uint32(reply[8:12])) != len(reply)-12 {
			t.Fatal("incorrect response framing")
		}
		response, err := Decode(reply[12:])
		if err != nil {
			t.Fatal(err)
		}
		for _, tag := range []uint32{TagSIG, TagNONC, TagTYPE, TagPATH, TagSREP, TagCERT, TagINDX} {
			if _, ok := response[tag]; !ok {
				t.Fatalf("missing RFC response tag %08x", tag)
			}
		}
		if len(response[TagTYPE]) != 4 || binary.LittleEndian.Uint32(response[TagTYPE]) != 1 || !bytes.Equal(response[TagNONC], requests[i].Nonce) {
			t.Fatal("incorrect response TYPE or NONC")
		}
		certificate, err := Decode(response[TagCERT])
		if err != nil {
			t.Fatal(err)
		}
		delegation, err := Decode(certificate[TagDELE])
		if err != nil {
			t.Fatal(err)
		}
		if len(delegation[TagPUBK]) != mldsa.MLDSA44PublicKeySize ||
			len(delegation[TagMINT]) != 8 || len(delegation[TagMAXT]) != 8 ||
			binary.LittleEndian.Uint64(delegation[TagMINT]) != uint64(midpoint.Add(-time.Hour).Unix()) ||
			binary.LittleEndian.Uint64(delegation[TagMAXT]) != uint64(midpoint.Add(time.Hour).Unix()) {
			t.Fatal("incorrect RFC delegation fields")
		}
		// Verify exact RFC signature inputs directly through the standard
		// library.
		if err := mldsa.Verify(root.PublicKey(), append([]byte("Roughtime v1 delegation signature\x00"), certificate[TagDELE]...), certificate[TagSIG], &mldsa.Options{}); err != nil {
			t.Fatalf("delegation signature: %v", err)
		}
		if err := mldsa.Verify(online.PublicKey(), append([]byte("Roughtime v1 response signature\x00"), response[TagSREP]...), response[TagSIG], &mldsa.Options{}); err != nil {
			t.Fatalf("response signature: %v", err)
		}
		srep, err := Decode(response[TagSREP])
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(srep[TagVER], testVersionBytes([]Version{VersionMLDSA44})) || !bytes.Equal(srep[TagVERS], srep[TagVER]) ||
			len(srep[TagMIDP]) != 8 || binary.LittleEndian.Uint64(srep[TagMIDP]) != uint64(midpoint.Unix()) ||
			len(srep[TagRADI]) != 4 || binary.LittleEndian.Uint32(srep[TagRADI]) != 1 {
			t.Fatal("incorrect signed version, timestamp, or radius")
		}
		// Reconstruct a multi-leaf RFC path independently of the protocol
		// helpers.
		hash := sha512.Sum512(append([]byte{0}, requests[i].RawPacket...))
		index := binary.LittleEndian.Uint32(response[TagINDX])
		path := response[TagPATH]
		if len(path) != 64 {
			t.Fatal("incorrect three-leaf Merkle path length")
		}
		for len(path) > 0 {
			left, right := hash[:32], path[:32]
			if index&1 != 0 {
				left, right = right, left
			}
			hash = sha512.Sum512(append(append([]byte{1}, left...), right...))
			index >>= 1
			path = path[32:]
		}
		if index != 0 || !bytes.Equal(hash[:32], srep[TagROOT]) {
			t.Fatal("incorrect RFC Merkle ordering")
		}
		got, radius, err := VerifyReplyWithOptions([]Version{VersionMLDSA44}, reply, root.PublicKey().Bytes(), requests[i].Nonce, requests[i].RawPacket, VerifyOptions{Mode: Flex})
		if err != nil || !got.Equal(midpoint) || radius != time.Second {
			t.Fatalf("verification: %v, %v, %v", got, radius, err)
		}
	}
}

// TestMLDSA44RFCValidation checks required fields, request consistency, and
// signature contexts.
func TestMLDSA44RFCValidation(t *testing.T) {
	cert, rootPK := testPQCert(t)
	versions := []Version{VersionMLDSA44}
	nonce, request, err := CreateRequestWithOptions(versions, rand.Reader, nil, RequestOptions{Mode: Flex})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseRequestWithMode(request, Flex)
	if err != nil {
		t.Fatal(err)
	}
	for _, tag := range []uint32{TagNONC, TagVER, TagTYPE} {
		tags, err := Decode(request[12:])
		if err != nil {
			t.Fatal(err)
		}
		delete(tags, tag)
		raw, err := encodeWrapped(tags)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseRequestWithMode(raw, Flex); err == nil {
			t.Fatalf("accepted request without %08x", tag)
		}
	}
	if _, err := ParseRequest(request); err == nil {
		t.Fatal("strict mode accepted the extension")
	}
	changed := *parsed
	changed.HasType = false
	if _, err := CreateRepliesWithOptions(VersionMLDSA44, []Request{changed}, time.Now(), time.Second, cert, ReplyOptions{Mode: Flex}); err == nil {
		t.Fatal("signed request fields inconsistent with the packet")
	}
	replies, err := CreateRepliesWithOptions(VersionMLDSA44, []Request{*parsed}, time.Now(), time.Second, cert, ReplyOptions{Mode: Flex})
	if err != nil {
		t.Fatal(err)
	}
	for _, tag := range []uint32{TagNONC, TagTYPE} {
		reply := corruptReplyTag(t, replies[0], true, func(tags map[uint32][]byte) { delete(tags, tag) })
		if _, _, err := VerifyReplyWithOptions(versions, reply, rootPK, nonce, request, VerifyOptions{Mode: Flex}); err == nil {
			t.Fatalf("accepted response without %08x", tag)
		}
	}
	response, err := Decode(replies[0][12:])
	if err != nil {
		t.Fatal(err)
	}
	// Native FIPS 204 context parameters do not replace the RFC message prefix.
	wrong, err := cert.pqOnlineSK.Sign(nil, response[TagSREP], &mldsa.Options{Context: "Roughtime v1 response signature\x00"})
	if err != nil {
		t.Fatal(err)
	}
	reply := corruptReplyTag(t, replies[0], true, func(tags map[uint32][]byte) { tags[TagSIG] = wrong })
	if _, _, err := VerifyReplyWithOptions(versions, reply, rootPK, nonce, request, VerifyOptions{Mode: Flex}); err == nil {
		t.Fatal("accepted a signature over different input")
	}
}
