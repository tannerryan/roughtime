// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"testing"
	"time"
)

// draft07Vector holds an independently encoded and signed exchange. See
// testdata/README.md for its fixed inputs and provenance.
type draft07Vector struct {
	// RootKey authenticates the delegation certificate.
	RootKey []byte
	// Nonce binds the reply to the request.
	Nonce []byte
	// Request is the complete framed request.
	Request []byte
	// Reply contains the certificate, signature, and three-leaf Merkle proof.
	Reply []byte
}

// loadDraft07Vector reads the independent draft 07 fixture.
func loadDraft07Vector(t testing.TB) draft07Vector {
	t.Helper()
	data, err := os.ReadFile("testdata/draft07-independent.json")
	if err != nil {
		t.Fatal(err)
	}
	var v draft07Vector
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// TestDraft07IndependentVector verifies the fixture's signature, Merkle proof,
// and time.
func TestDraft07IndependentVector(t *testing.T) {
	v := loadDraft07Vector(t)
	mid, rad, err := VerifyReplyWithOptions([]Version{VersionDraft07}, v.Reply, v.RootKey, v.Nonce, v.Request, VerifyOptions{Mode: Flex})
	if err != nil || !mid.Equal(time.Date(2024, 11, 15, 12, 0, 0, 0, time.UTC)) || rad != time.Second {
		t.Fatalf("independent draft 07 vector: %v %v %v", mid, rad, err)
	}
}

// TestProfileFinalValueAlignment checks profile-specific rules for an unaligned
// final value.
func TestProfileFinalValueAlignment(t *testing.T) {
	for _, ver := range append([]Version{VersionGoogle}, supportedVersionsEd25519...) {
		t.Run(ver.ShortString(), func(t *testing.T) {
			reply, pk, nonce, request := validReply(t, ver, []Version{ver})
			mode := Flex
			if ver == Version1 {
				mode = Strict
			}
			for n := 0; n < 4; n++ {
				body := request
				if ver != VersionGoogle {
					body = body[PacketHeaderSize:]
				}
				tags, err := Decode(body)
				if err != nil {
					t.Fatal(err)
				}
				if ver == VersionGoogle {
					tags[TagPAD] = append(bytes.Clone(tags[TagPAD]), make([]byte, n)...)
				} else if padding, ok := tags[TagZZZZ]; ok {
					tags[TagZZZZ] = append(bytes.Clone(padding), make([]byte, n)...)
				} else {
					tags[0x595a5a5a] = make([]byte, n)
				} // ZZZY
				encoded, err := encode(tags)
				if err != nil {
					t.Fatal(err)
				}
				if ver != VersionGoogle {
					encoded = wrapPacket(encoded)
				}
				_, err = ParseRequestWithMode(encoded, mode)
				reject := ver == VersionGoogle && n != 0
				if (err != nil) != reject {
					t.Fatalf("request final length %d: %v", n, err)
				}
				extended := corruptReplyTag(t, reply, ver != VersionGoogle, func(m map[uint32][]byte) { m[0x595a5a5a] = make([]byte, n) })
				_, _, err = VerifyReplyWithOptions([]Version{ver}, extended, pk, nonce, request, VerifyOptions{Mode: mode})
				if (err != nil) != reject {
					t.Fatalf("reply final length %d: %v", n, err)
				}
			}
		})
	}
	// A non-final odd value still creates an invalid encoded offset.
	if _, err := encode(map[uint32][]byte{1: {0}, 2: {0, 0, 0, 0}}); err == nil {
		t.Fatal("accepted unaligned intermediate value")
	}
}

// TestGoogleUnknownVersion checks that Google ignores opaque IETF extensions.
func TestGoogleUnknownVersion(t *testing.T) {
	cert, _ := testCert(t)
	for _, v := range [][]byte{nil, {1, 0, 0, 0}, {12, 0, 0, 128}, make([]byte, 8)} {
		tags := map[uint32][]byte{TagNONC: bytes.Repeat([]byte{7}, 64), TagVER: v, TagTYPE: make([]byte, 8), TagSRV: make([]byte, 4), TagPAD: nil}
		tags[TagPAD] = make([]byte, 1024-8*len(tags)-64-len(v)-8-4)
		request, err := encode(tags)
		if err != nil {
			t.Fatal(err)
		}
		req, err := ParseRequestWithMode(request, Flex)
		if err != nil || len(req.Versions) != 0 || len(req.SRV) != 0 || req.HasType {
			t.Fatalf("Google extensions: %v %v", req, err)
		}
		if _, err := ParseRequest(request); err == nil {
			t.Fatal("strict accepted Google")
		}
		replies, err := CreateRepliesWithOptions(VersionGoogle, []Request{*req}, time.Now(), time.Second, cert, ReplyOptions{Mode: Flex})
		if err != nil {
			t.Fatal(err)
		}
		injected := corruptReplyTag(t, replies[0], false, func(m map[uint32][]byte) { m[TagVER] = testVersionBytes([]Version{VersionDraft08}) })
		if _, ok := ExtractVersion(injected); ok {
			t.Fatal("trusted Google VER extension")
		}
		chain := &Chain{Mode: Flex, Links: []ChainLink{{PublicKey: cert.edRootPK, Request: request, Response: injected}}}
		if err := chain.Verify(); err != nil {
			t.Fatal(err)
		}
		report, err := chain.MalfeasanceReport()
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseMalfeasanceReportWithMode(report, Flex)
		if err != nil {
			t.Fatal(err)
		}
		if err := parsed.Verify(); err != nil {
			t.Fatalf("Google report lost authenticated profile: %v", err)
		}
	}
}

// TestMidpointQuantizationPreservesUncertainty checks that rounding preserves
// the input window.
func TestMidpointQuantizationPreservesUncertainty(t *testing.T) {
	cert, _ := testCert(t)
	for _, ver := range []Version{Version1, VersionDraft08, VersionDraft10, VersionDraft12, VersionGoogle, VersionDraft07} {
		for _, fraction := range []time.Duration{0, 900 * time.Millisecond} {
			nonce, request, err := CreateRequestWithOptions([]Version{ver}, rand.Reader, nil, RequestOptions{Mode: Flex})
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := ParseRequestWithMode(request, Flex)
			if err != nil {
				t.Fatal(err)
			}
			mid := time.Now().Truncate(time.Second).Add(fraction)
			replies, err := CreateRepliesWithOptions(ver, []Request{*parsed}, mid, 3*time.Second, cert, ReplyOptions{Mode: Flex})
			if err != nil {
				t.Fatal(err)
			}
			got, radius, err := VerifyReplyWithOptions([]Version{ver}, replies[0], cert.edRootPK, nonce, request, VerifyOptions{Mode: Flex})
			if err != nil {
				t.Fatal(err)
			}
			if got.Add(radius).Before(mid.Add(3*time.Second)) || got.Add(-radius).After(mid.Add(-3*time.Second)) {
				t.Fatalf("%s lost uncertainty: %v +/- %v around %v", ver, got, radius, mid)
			}
		}
	}
}

// reverseEncoding writes unique tags and their values in descending order,
// independently of the implementation's canonical encoder.
func reverseEncoding(m map[uint32][]byte) []byte {
	keys := make([]uint32, 0, len(m))
	size := 8 * len(m)
	for tag, value := range m {
		keys = append(keys, tag)
		size += len(value)
	}
	slices.Sort(keys)
	slices.Reverse(keys)
	raw := make([]byte, size)
	binary.LittleEndian.PutUint32(raw, uint32(len(keys)))
	off := 0
	for i, tag := range keys {
		if i > 0 {
			binary.LittleEndian.PutUint32(raw[4*i:], uint32(off))
		}
		binary.LittleEndian.PutUint32(raw[4*len(keys)+4*i:], tag)
		copy(raw[8*len(keys)+off:], m[tag])
		off += len(m[tag])
	}
	return raw
}

// TestDraft01UnsortedSignedExchange accepts unique unsorted tags only for draft
// 01.
func TestDraft01UnsortedSignedExchange(t *testing.T) {
	cert, rootSK := testCert(t)
	request := wrapPacket(reverseEncoding(map[uint32][]byte{TagNONC: bytes.Repeat([]byte{7}, 64), TagVER: testVersionBytes([]Version{VersionDraft01}), tagPADIETF: make([]byte, 932)}))
	req, err := ParseRequestWithMode(request, Flex)
	if err != nil {
		t.Fatal(err)
	}
	replies, err := CreateRepliesWithOptions(VersionDraft01, []Request{*req}, time.Now(), time.Second, cert, ReplyOptions{Mode: Flex})
	if err != nil {
		t.Fatal(err)
	}
	resp, _ := Decode(replies[0][12:])
	srep, _ := Decode(resp[TagSREP])
	cm, _ := Decode(resp[TagCERT])
	dele, _ := Decode(cm[TagDELE])
	cm[TagDELE] = reverseEncoding(dele)
	cm[TagSIG] = signEd25519(rootSK, cm[TagDELE], delegationContext(groupD01))
	resp[TagCERT] = reverseEncoding(cm)
	resp[TagSREP] = reverseEncoding(srep)
	resp[TagSIG] = signEd25519(cert.edOnlineSK, resp[TagSREP], responseCtx)
	reply := wrapPacket(reverseEncoding(resp))
	if _, _, err := VerifyReplyWithOptions([]Version{VersionDraft01}, reply, cert.edRootPK, req.Nonce, request, VerifyOptions{Mode: Flex}); err != nil {
		t.Fatal(err)
	}
	// Draft 02 already requires numeric order.
	tags := map[uint32][]byte{TagNONC: req.Nonce, TagVER: testVersionBytes([]Version{VersionDraft02})}
	if _, err := ParseRequestWithMode(wrapPacket(reverseEncoding(tags)), Flex); err == nil {
		t.Fatal("draft 02 accepted unsorted tags")
	}
	// Unsorted input must not admit duplicate tags.
	duplicate := bytes.Clone(request)
	n := int(binary.LittleEndian.Uint32(duplicate[12:]))
	copy(duplicate[12+4*n+4:], duplicate[12+4*n:12+4*n+4])
	if _, err := ParseRequestWithMode(duplicate, Flex); err == nil {
		t.Fatal("draft 01 accepted duplicate tags")
	}
}

// TestOptionalTimeFieldSyntax checks early drafts' DUT1, DTAI, and LEAP
// encodings.
func TestOptionalTimeFieldSyntax(t *testing.T) {
	cert, _ := testCert(t)
	for _, ver := range []Version{VersionDraft01, VersionDraft02, VersionDraft03, VersionDraft04, VersionDraft05, VersionDraft06, VersionDraft07, VersionDraft08} {
		nonce, request, err := CreateRequestWithOptions([]Version{ver}, rand.Reader, nil, RequestOptions{Mode: Flex})
		if err != nil {
			t.Fatal(err)
		}
		req, err := ParseRequestWithMode(request, Flex)
		if err != nil {
			t.Fatal(err)
		}
		replies, err := CreateRepliesWithOptions(ver, []Request{*req}, time.Now(), time.Second, cert, ReplyOptions{Mode: Flex})
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			tag   uint32 // optional signed time field
			value []byte // candidate field encoding
			valid bool   // expected acceptance in drafts 01-07
		}{{tagDUT1, []byte{0, 0, 0, 128}, false}, {tagDTAI, make([]byte, 8), false}, {tagLEAP, []byte{1, 0, 0, 0, 2, 0, 0, 0}, false}, {tagLEAP, []byte{2, 0, 0, 128, 1, 0, 0, 0}, true}, {tagLEAP, nil, true}} {
			reply := resignSREP(t, replies[0], cert.edOnlineSK, func(s map[uint32][]byte) { s[tc.tag] = tc.value })
			_, _, err := VerifyReplyWithOptions([]Version{ver}, reply, cert.edRootPK, nonce, request, VerifyOptions{Mode: Flex})
			reject := !tc.valid && ver != VersionDraft08
			if (err != nil) != reject {
				t.Fatalf("%s optional %08x valid=%v: %v", ver, tc.tag, tc.valid, err)
			}
		}
	}
}

// TestMJDLeapDelegationAndCausality checks native delegation bounds and
// leap-second uncertainty.
func TestMJDLeapDelegationAndCausality(t *testing.T) {
	for _, ver := range []Version{VersionDraft01, VersionDraft02, VersionDraft03, VersionDraft04, VersionDraft05, VersionDraft06, VersionDraft07} {
		t.Run(ver.ShortString(), func(t *testing.T) {
			rootSK, onlineSK := testKeys(t)
			pk := rootSK.Public().(ed25519.PublicKey)
			midnight := time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC)
			cert, err := NewCertificateWithVersions(midnight.Add(-24*time.Hour), midnight.Add(24*time.Hour), onlineSK, rootSK, []Version{ver})
			if err != nil {
				t.Fatal(err)
			}
			defer cert.Wipe()
			chain := &Chain{Mode: Flex}
			for _, rawMIDP := range []uint64{uint64(57753)<<40 | 86_400_900_000, uint64(57754)<<40 | 100_000} {
				link, err := chain.NextRequest([]Version{ver}, pk, rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				req, err := ParseRequestWithMode(link.Request, Flex)
				if err != nil {
					t.Fatal(err)
				}
				replies, err := CreateRepliesWithOptions(ver, []Request{*req}, midnight, 100*time.Microsecond, cert, ReplyOptions{Mode: Flex})
				if err != nil {
					t.Fatal(err)
				}
				link.Response = resignSREP(t, replies[0], onlineSK, func(m map[uint32][]byte) {
					b := make([]byte, 8)
					binary.LittleEndian.PutUint64(b, rawMIDP)
					m[TagMIDP] = b
				})
				chain.Append(link)
			}
			if err := chain.Verify(); err != nil {
				t.Fatalf("honest leap-second chain: %v", err)
			}
			// Recertify the first response with MINT after its native leap
			// second.
			certAfter, err := NewCertificateWithVersions(midnight, midnight.Add(time.Hour), onlineSK, rootSK, []Version{ver})
			if err != nil {
				t.Fatal(err)
			}
			defer certAfter.Wipe()
			bad := corruptReplyTag(t, chain.Links[0].Response, true, func(m map[uint32][]byte) { m[TagCERT] = certAfter.certBytes(wireGroupOf(ver, false)) })
			link := chain.Links[0]
			if _, _, err := VerifyReplyWithOptions([]Version{ver}, bad, pk, link.Nonce, link.Request, VerifyOptions{Mode: Flex}); !errors.Is(err, ErrDelegationWindow) {
				t.Fatalf("accepted MIDP before native MINT: %v", err)
			}
		})
	}
}

// TestGoogleOldSingleHashProof preserves verification of this library's older
// Google chains.
func TestGoogleOldSingleHashProof(t *testing.T) {
	chain, servers := buildChain(t, VersionGoogle, 1)
	blind := bytes.Repeat([]byte{0x42}, 64)
	h := sha512.New()
	_, _ = h.Write(chain.Links[0].Response)
	_, _ = h.Write(blind)
	nonce := h.Sum(nil)
	request, err := CreateRequestWithNonceOptions([]Version{VersionGoogle}, nonce, nil, RequestOptions{Mode: Flex})
	if err != nil {
		t.Fatal(err)
	}
	chain.Append(ChainLink{PublicKey: servers[0].rootPK, Request: request, Nonce: nonce, Rand: blind, Response: servers[0].respond(t, request)})
	if err := chain.Verify(); err != nil {
		t.Fatalf("old Google proof no longer verifies: %v", err)
	}
}

// TestProfileTagSyntax checks tag grammar in requests, replies, and nested
// signed messages.
func TestProfileTagSyntax(t *testing.T) {
	cert, rootSK := testCert(t)
	for _, ver := range []Version{Version1, VersionDraft10, VersionDraft11, VersionDraft12} {
		nonce, request, err := CreateRequestWithOptions([]Version{ver}, rand.Reader, nil, RequestOptions{Mode: Flex})
		if err != nil {
			t.Fatal(err)
		}
		req, err := ParseRequestWithMode(request, Flex)
		if err != nil {
			t.Fatal(err)
		}
		replies, err := CreateRepliesWithOptions(ver, []Request{*req}, time.Now(), time.Second, cert, ReplyOptions{Mode: Flex})
		if err != nil {
			t.Fatal(err)
		}
		mode := Flex
		if ver == Version1 {
			mode = Strict
		}
		g := wireGroupOf(ver, req.HasType)
		for _, tag := range []uint32{0x00415a5a, 0, 0x01020304, 0x61616161, 0x00410041} {
			reject := tag != 0x00415a5a && ver != VersionDraft10
			requestTags, _ := Decode(request[12:])
			requestTags[tag] = make([]byte, 4)
			modified, err := encodeWrapped(requestTags)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseRequestWithMode(modified, mode); (err != nil) != reject {
				t.Fatalf("%s request tag %08x: %v", ver, tag, err)
			}
			for _, where := range []string{"outer", "SREP", "CERT", "DELE"} {
				resp, _ := Decode(replies[0][12:])
				switch where {
				case "outer":
					resp[tag] = make([]byte, 4)
				case "SREP":
					m, _ := Decode(resp[TagSREP])
					m[tag] = make([]byte, 4)
					resp[TagSREP], err = encode(m)
					if err != nil {
						t.Fatal(err)
					}
					resp[TagSIG] = signEd25519(cert.edOnlineSK, resp[TagSREP], responseContext(g))
				case "CERT", "DELE":
					m, _ := Decode(resp[TagCERT])
					if where == "DELE" {
						dele, _ := Decode(m[TagDELE])
						dele[tag] = make([]byte, 4)
						m[TagDELE], err = encode(dele)
						if err != nil {
							t.Fatal(err)
						}
						m[TagSIG] = signEd25519(rootSK, m[TagDELE], delegationContext(g))
					} else {
						m[tag] = make([]byte, 4)
					}
					resp[TagCERT], err = encode(m)
					if err != nil {
						t.Fatal(err)
					}
				}
				modified, err := encodeWrapped(resp)
				if err != nil {
					t.Fatal(err)
				}
				if _, _, err := VerifyReplyWithOptions([]Version{ver}, modified, cert.edRootPK, nonce, request, VerifyOptions{Mode: mode}); (err != nil) != reject {
					t.Fatalf("%s %s tag %08x: %v", ver, where, tag, err)
				}
			}
		}
	}
}
