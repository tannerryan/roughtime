// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"math"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

// rfcExchange builds RFC requests and signed replies for protocol tests.
func rfcExchange(t *testing.T, count int, midpoint time.Time) (*Certificate, []Request, [][]byte) {
	t.Helper()
	rootSK, onlineSK := testKeys(t)
	cert, err := NewCertificate(midpoint.Add(-time.Hour), midpoint.Add(time.Hour), onlineSK, rootSK)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cert.Wipe)
	requests := make([]Request, count)
	for i := range requests {
		_, packet, err := CreateRequest([]Version{Version1}, rand.Reader, ComputeSRV(cert.edRootPK))
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseRequest(packet)
		if err != nil {
			t.Fatal(err)
		}
		requests[i] = *parsed
	}
	replies, err := CreateReplies(Version1, requests, midpoint, 3*time.Second, cert)
	if err != nil {
		t.Fatal(err)
	}
	return cert, requests, replies
}

// TestRFCSignaturesAndMerklePaths checks contexts, time units, and paths
// independently.
func TestRFCSignaturesAndMerklePaths(t *testing.T) {
	if !slices.Equal(Supported(), []Version{1}) {
		t.Fatalf("strict versions: %v", Supported())
	}
	midpoint := time.Now().Truncate(time.Second)
	cert, requests, replies := rfcExchange(t, 5, midpoint)
	for i, reply := range replies {
		request := requests[i]
		if len(request.RawPacket) != 1036 || len(request.Nonce) != 32 || !request.HasType {
			t.Fatalf("request %d: size=%d nonce=%d TYPE=%t", i, len(request.RawPacket), len(request.Nonce), request.HasType)
		}
		response, err := Decode(reply[12:])
		if err != nil {
			t.Fatal(err)
		}
		certificate, err := Decode(response[TagCERT])
		if err != nil {
			t.Fatal(err)
		}
		delegation, err := Decode(certificate[TagDELE])
		if err != nil {
			t.Fatal(err)
		}
		if !ed25519.Verify(cert.edRootPK, append([]byte("Roughtime v1 delegation signature\x00"), certificate[TagDELE]...), certificate[TagSIG]) {
			t.Fatal("certificate does not use the RFC context")
		}
		if !ed25519.Verify(delegation[TagPUBK], append([]byte("Roughtime v1 response signature\x00"), response[TagSREP]...), response[TagSIG]) {
			t.Fatal("response does not use the RFC context")
		}
		srep, err := Decode(response[TagSREP])
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(srep[TagVER], []byte{1, 0, 0, 0}) || !bytes.Equal(srep[TagVERS], []byte{1, 0, 0, 0}) {
			t.Fatal("incorrect signed versions")
		}
		if binary.LittleEndian.Uint64(srep[TagMIDP]) != uint64(midpoint.Unix()) || binary.LittleEndian.Uint32(srep[TagRADI]) != 3 {
			t.Fatal("incorrect time units")
		}
		// Reconstruct the path with SHA-512 and the RFC's bit order
		// independently.
		hash := sha512.Sum512(append([]byte{0}, request.RawPacket...))
		index := binary.LittleEndian.Uint32(response[TagINDX])
		path := response[TagPATH]
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
			t.Fatalf("invalid RFC Merkle path %d", i)
		}
		got, radius, err := VerifyReply([]Version{1}, reply, cert.edRootPK, request.Nonce, request.RawPacket)
		if err != nil || !got.Equal(midpoint) || radius != 3*time.Second {
			t.Fatalf("verify: %v, %v, %v", got, radius, err)
		}
	}
}

// TestRFCMandatoryFields rejects missing tags and inconsistent request fields.
func TestRFCMandatoryFields(t *testing.T) {
	cert, requests, replies := rfcExchange(t, 1, time.Now().Truncate(time.Second))
	request := requests[0]
	for _, tag := range []uint32{TagNONC, TagVER, TagTYPE} {
		body, _ := Decode(request.RawPacket[12:])
		delete(body, tag)
		packet, _ := encodeWrapped(body)
		if _, err := ParseRequest(packet); err == nil {
			t.Fatalf("accepted request without %x", tag)
		}
	}
	for _, tag := range []uint32{TagSIG, TagNONC, TagTYPE, TagPATH, TagSREP, TagCERT, TagINDX} {
		packet := corruptReplyTag(t, replies[0], true, func(tags map[uint32][]byte) { delete(tags, tag) })
		if _, _, err := VerifyReply([]Version{1}, packet, cert.edRootPK, request.Nonce, request.RawPacket); err == nil {
			t.Fatalf("accepted response without %x", tag)
		}
	}
	for _, tag := range []uint32{TagMIDP, TagRADI, TagROOT, TagVER, TagVERS} {
		packet := corruptReplyTag(t, replies[0], true, func(tags map[uint32][]byte) {
			srep, _ := Decode(tags[TagSREP])
			delete(srep, tag)
			tags[TagSREP], _ = encode(srep)
			tags[TagSIG] = ed25519.Sign(cert.edOnlineSK, append([]byte("Roughtime v1 response signature\x00"), tags[TagSREP]...))
		})
		if _, _, err := VerifyReply([]Version{1}, packet, cert.edRootPK, request.Nonce, request.RawPacket); err == nil {
			t.Fatalf("accepted signed response without %x", tag)
		}
	}
	for _, size := range []int{0, 64} {
		packet := corruptReplyTag(t, replies[0], true, func(tags map[uint32][]byte) { tags[TagNONC] = make([]byte, size) })
		if _, _, err := VerifyReply([]Version{1}, packet, cert.edRootPK, request.Nonce, request.RawPacket); err == nil {
			t.Fatalf("accepted %d-byte echoed nonce", size)
		}
	}
	request.HasType = false
	if _, err := CreateReplies(Version1, []Request{request}, time.Now(), 3*time.Second, cert); err == nil {
		t.Fatal("signed fields inconsistent with request packet")
	}
}

// TestRFCUnknownExtensions accepts unknown tags and offered version numbers.
func TestRFCUnknownExtensions(t *testing.T) {
	cert, requests, _ := rfcExchange(t, 1, time.Now())
	tags, _ := Decode(requests[0].RawPacket[12:])
	tags[TagVER] = testVersionBytes([]Version{0, 1, VersionDraft01, 0xf0000001})
	tags[0x595a5a5a] = []byte{1, 2, 3, 4} // ZZZY, a valid unknown tag.
	packet, _ := encodeWrapped(tags)
	request, err := ParseRequest(packet)
	if err != nil {
		t.Fatalf("unknown offers and tags: %v", err)
	}
	replies, err := CreateReplies(1, []Request{*request}, time.Now(), time.Second, cert)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyReply([]Version{1}, replies[0], cert.edRootPK, request.Nonce, packet); err != nil {
		t.Fatal(err)
	}
}

// TestRFCRejectsMalformedFields checks tag lengths, version lists, and Merkle
// paths.
func TestRFCRejectsMalformedFields(t *testing.T) {
	cert, requests, replies := rfcExchange(t, 2, time.Now())
	request := requests[1]
	for _, tc := range []struct {
		name  string // subtest label
		tag   uint32 // signed response field to replace
		value []byte // malformed field encoding
	}{
		{"zero radius", TagRADI, make([]byte, 4)},
		{"short midpoint", TagMIDP, make([]byte, 4)},
		{"long root", TagROOT, make([]byte, 64)},
		{"duplicate versions", TagVERS, testVersionBytes([]Version{1, 1})},
		{"unsorted versions", TagVERS, testVersionBytes([]Version{2, 1})},
		{"unlisted choice", TagVERS, testVersionBytes([]Version{2})},
		{"too many versions", TagVERS, testVersionBytes(rfcVersionList(33))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			packet := corruptReplyTag(t, replies[1], true, func(tags map[uint32][]byte) {
				srep, _ := Decode(tags[TagSREP])
				srep[tc.tag] = tc.value
				tags[TagSREP], _ = encode(srep)
				tags[TagSIG] = ed25519.Sign(cert.edOnlineSK, append([]byte("Roughtime v1 response signature\x00"), tags[TagSREP]...))
			})
			if _, _, err := VerifyReply([]Version{1}, packet, cert.edRootPK, request.Nonce, request.RawPacket); err == nil {
				t.Fatal("accepted malformed signed response")
			}
		})
	}
	for _, tc := range []struct {
		name  string // subtest label
		tag   uint32 // Merkle proof field to replace
		value []byte // malformed field encoding
	}{
		{"too many hashes", TagPATH, make([]byte, 33*32)},
		{"short hash", TagPATH, make([]byte, 28)},
		{"wrong orientation", TagINDX, make([]byte, 4)},
		{"unused index bits", TagINDX, []byte{3, 0, 0, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			packet := corruptReplyTag(t, replies[1], true, func(tags map[uint32][]byte) { tags[tc.tag] = tc.value })
			for _, mode := range []Mode{Strict, Flex} {
				if _, _, err := VerifyReplyWithOptions([]Version{1}, packet, cert.edRootPK, request.Nonce, request.RawPacket, VerifyOptions{Mode: mode}); err == nil {
					t.Fatal("accepted malformed RFC path")
				}
			}
		})
	}
	for _, tc := range []struct {
		name  string // subtest label
		tag   uint32 // request field to replace
		value []byte // malformed field encoding
	}{
		{"too many offers", TagVER, testVersionBytes(rfcVersionList(33))},
		{"duplicate offers", TagVER, testVersionBytes([]Version{1, 1})},
		{"unsorted offers", TagVER, testVersionBytes([]Version{2, 1})},
		{"short server binding", TagSRV, make([]byte, 28)},
		{"nonzero padding", TagZZZZ, []byte{1, 0, 0, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tags, _ := Decode(request.RawPacket[12:])
			tags[tc.tag] = tc.value
			packet, _ := encodeWrapped(tags)
			for _, mode := range []Mode{Strict, Flex} {
				if _, err := ParseRequestWithMode(packet, mode); err == nil {
					t.Fatal("accepted malformed RFC request")
				}
			}
		})
	}
}

// rfcVersionList returns consecutive version numbers starting at 1.
func rfcVersionList(count int) []Version {
	versions := make([]Version, count)
	for i := range versions {
		versions[i] = Version(i + 1)
	}
	return versions
}

// TestRFCStrictRejectsLegacyProfiles checks strict parsing, building, and
// verification.
func TestRFCStrictRejectsLegacyProfiles(t *testing.T) {
	for _, version := range SupportedWithMode(Flex) {
		if version == Version1 {
			continue
		}
		t.Run(version.ShortString(), func(t *testing.T) {
			_, packet, err := CreateRequestWithOptions([]Version{version}, rand.Reader, nil, RequestOptions{Mode: Flex})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseRequest(packet); err == nil {
				t.Fatal("strict parser accepted legacy request")
			}
			if _, _, err := CreateRequest([]Version{version}, rand.Reader, nil); err == nil {
				t.Fatal("strict builder accepted legacy version")
			}
			if _, _, err := VerifyReply([]Version{version}, nil, nil, nil, nil); err == nil {
				t.Fatal("strict verifier accepted legacy version")
			}
		})
	}
}

// TestRFCUnixEpoch accepts RFC timestamps outside the legacy year bounds.
func TestRFCUnixEpoch(t *testing.T) {
	for _, midpoint := range []time.Time{time.Unix(3600, 0), time.Date(3500, 1, 1, 0, 0, 0, 0, time.UTC)} {
		cert, requests, replies := rfcExchange(t, 1, midpoint)
		if _, _, err := VerifyReply([]Version{1}, replies[0], cert.edRootPK, requests[0].Nonce, requests[0].RawPacket); err != nil {
			t.Fatal(err)
		}
	}
}

// TestRFCTimeRange rejects signed windows that exceed Go's time range.
func TestRFCTimeRange(t *testing.T) {
	maxUnix := int64(math.MaxInt64) + time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
	midpoint := time.Unix(maxUnix, 0)
	cert, requests, replies := rfcExchange(t, 1, midpoint.Add(-time.Hour))
	if _, err := CreateReplies(1, requests, midpoint, time.Nanosecond, cert); err == nil {
		t.Fatal("built an unrepresentable rounded time window")
	}
	reply := corruptReplyTag(t, replies[0], true, func(tags map[uint32][]byte) {
		srep, _ := Decode(tags[TagSREP])
		value := encodeTimestamp(midpoint, groupRFC)
		srep[TagMIDP] = value[:]
		tags[TagSREP], _ = encode(srep)
		tags[TagSIG] = ed25519.Sign(cert.edOnlineSK, append([]byte("Roughtime v1 response signature\x00"), tags[TagSREP]...))
	})
	for _, mode := range []Mode{Strict, Flex} {
		if _, _, err := VerifyReplyWithOptions([]Version{1}, reply, cert.edRootPK, requests[0].Nonce, requests[0].RawPacket, VerifyOptions{Mode: mode}); err == nil {
			t.Fatal("accepted an unrepresentable time window")
		}
	}
}

// TestRFCRadiusAndReport checks radius rounding and RFC report encoding.
func TestRFCRadiusAndReport(t *testing.T) {
	cert, requests, replies := rfcExchange(t, 1, time.Now().Truncate(time.Second))
	for _, tc := range []struct {
		radius time.Duration // input uncertainty
		want   time.Duration // expected rounded uncertainty
	}{
		{time.Nanosecond, time.Second},
		{time.Second, time.Second},
		{1500 * time.Millisecond, 2 * time.Second},
	} {
		replies, err := CreateReplies(1, requests, time.Now().Truncate(time.Second), tc.radius, cert)
		if err != nil {
			t.Fatal(err)
		}
		_, got, err := VerifyReply([]Version{1}, replies[0], cert.edRootPK, requests[0].Nonce, requests[0].RawPacket)
		if err != nil || got != tc.want {
			t.Fatalf("radius %s: %s, %v", tc.radius, got, err)
		}
	}
	chain := &Chain{Links: []ChainLink{{PublicKey: cert.edRootPK, Request: requests[0].RawPacket, Response: replies[0]}}}
	data, err := chain.MalfeasanceReport()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseMalfeasanceReport(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := parsed.Verify(); err != nil {
		t.Fatal(err)
	}
	chain.Links[0].Rand = make([]byte, 64)
	if _, err := chain.MalfeasanceReport(); err == nil {
		t.Fatal("strict report accepted legacy rand")
	}
}

// TestRFCAppendixBContexts checks strict contexts and flex appendix
// verification.
func TestRFCAppendixBContexts(t *testing.T) {
	data, err := os.ReadFile("testdata/rfc10049-appendix-b.json")
	if err != nil {
		t.Fatal(err)
	}
	strict, err := ParseMalfeasanceReport(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := strict.Verify(); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("RFC appendix uses draft contexts: %v", err)
	}
	flex, err := ParseMalfeasanceReportWithMode(data, Flex)
	if err != nil {
		t.Fatal(err)
	}
	if err := flex.Verify(); !errors.Is(err, ErrCausalOrder) {
		t.Fatalf("authenticated appendix contradiction: %v", err)
	}
	for _, link := range flex.Links {
		request, err := ParseRequest(link.Request)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := VerifyReplyWithOptions([]Version{1}, link.Response, link.PublicKey, request.Nonce, link.Request, VerifyOptions{Mode: Flex}); err != nil {
			t.Fatal(err)
		}
	}
}

// TestRFCReportUTF8 rejects malformed text while preserving flex parsing.
func TestRFCReportUTF8(t *testing.T) {
	data, err := os.ReadFile("testdata/rfc10049-appendix-b.json")
	if err != nil {
		t.Fatal(err)
	}
	malformed := append([]byte(`{"extension":"`), 0xff, '"', ',')
	data = append(malformed, data[1:]...)
	if _, err := ParseMalfeasanceReport(data); err == nil {
		t.Fatal("strict parser accepted invalid UTF-8")
	}
	if _, err := ParseMalfeasanceReportWithMode(data, Flex); err != nil {
		t.Fatalf("flex parsing: %v", err)
	}
}
