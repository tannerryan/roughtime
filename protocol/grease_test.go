// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

// TestGreaseDoesNotPanic verifies Grease handles repeated invocations across
// versions without panicking.
func TestGreaseDoesNotPanic(t *testing.T) {
	for _, ver := range []Version{VersionGoogle, VersionDraft08, VersionDraft12} {
		t.Run(ver.String(), func(t *testing.T) {
			reply, _, _, _ := validReply(t, ver, []Version{ver})
			for range 200 {
				cp := make([]byte, len(reply))
				copy(cp, reply)
				Grease(cp, ver)
			}
		})
	}
}

// TestGreaseCorruptSig verifies greaseCorruptSig produces replies that fail
// VerifyReply.
func TestGreaseCorruptSig(t *testing.T) {
	for _, ver := range []Version{VersionGoogle, VersionDraft08, VersionDraft12} {
		t.Run(ver.String(), func(t *testing.T) {
			reply, rootPK, nonce, req := validReply(t, ver, []Version{ver})
			for range 50 {
				cp := make([]byte, len(reply))
				copy(cp, reply)
				greaseCorruptSig(cp, ver)
				if _, _, err := VerifyReply([]Version{ver}, cp, rootPK, nonce, req); err == nil {
					t.Fatal("greaseCorruptSig produced a reply that still verifies")
				}
			}
		})
	}
}

// TestGreaseDropTag verifies greaseDropTag produces replies that fail
// VerifyReply.
func TestGreaseDropTag(t *testing.T) {
	for _, ver := range []Version{VersionGoogle, VersionDraft08, VersionDraft12} {
		t.Run(ver.String(), func(t *testing.T) {
			reply, rootPK, nonce, req := validReply(t, ver, []Version{ver})
			out := greaseDropTag(reply, ver)
			if out == nil {
				t.Fatal("greaseDropTag returned nil")
			}
			if _, _, err := VerifyReply([]Version{ver}, out, rootPK, nonce, req); err == nil {
				t.Fatal("expected verification failure after dropping a mandatory tag")
			}
		})
	}
}

// TestGreaseWrongVersion verifies greaseWrongVersion produces a reply that
// fails VerifyReply.
func TestGreaseWrongVersion(t *testing.T) {
	reply, rootPK, nonce, req := validReply(t, VersionDraft08, []Version{VersionDraft08})
	out := greaseWrongVersion(reply, VersionDraft08)
	if out == nil {
		t.Fatal("greaseWrongVersion returned nil for draft08")
	}
	if _, _, err := VerifyReply([]Version{VersionDraft08}, out, rootPK, nonce, req); err == nil {
		t.Fatal("expected verification failure for wrong version")
	}
}

// TestGreaseWrongVersionNilForGoogle verifies greaseWrongVersion returns nil
// for Google (no top-level VER).
func TestGreaseWrongVersionNilForGoogle(t *testing.T) {
	reply, _, _, _ := validReply(t, VersionGoogle, []Version{VersionGoogle})
	if out := greaseWrongVersion(reply, VersionGoogle); out != nil {
		t.Fatal("expected nil for Google version (no top-level VER)")
	}
}

// TestGreaseWrongVersionNilForDraft12 verifies greaseWrongVersion returns nil
// for draft-12 (no top-level VER).
func TestGreaseWrongVersionNilForDraft12(t *testing.T) {
	reply, _, _, _ := validReply(t, VersionDraft12, []Version{VersionDraft12})
	if out := greaseWrongVersion(reply, VersionDraft12); out != nil {
		t.Fatal("expected nil for draft12 (no top-level VER)")
	}
}

// TestGreaseUndefinedTag verifies replies with an unknown grease tag still
// verify.
func TestGreaseUndefinedTag(t *testing.T) {
	for _, ver := range []Version{VersionGoogle, VersionDraft08, VersionDraft12} {
		t.Run(ver.String(), func(t *testing.T) {
			reply, rootPK, nonce, req := validReply(t, ver, []Version{ver})
			out := greaseUndefinedTag(reply, ver)
			if out == nil {
				t.Fatal("greaseUndefinedTag returned nil")
			}
			if len(out) <= len(reply) {
				t.Fatal("expected greased reply to be larger (added tag)")
			}
			if _, _, err := VerifyReply([]Version{ver}, out, rootPK, nonce, req); err != nil {
				t.Fatalf("undefined tag should not break verification: %v", err)
			}
		})
	}
}

// TestGreaseAllModesReachable verifies all four grease modes fire.
func TestGreaseAllModesReachable(t *testing.T) {
	reply, rootPK, nonce, req := validReply(t, VersionDraft08, []Version{VersionDraft08})

	var sigCorrupt, tagDrop, wrongVer, undefinedTag int
	for range 1000 {
		cp := make([]byte, len(reply))
		copy(cp, reply)
		out := Grease(cp, VersionDraft08)

		_, _, err := VerifyReply([]Version{VersionDraft08}, out, rootPK, nonce, req)
		switch {
		case err == nil:
			undefinedTag++
		case len(out) < len(reply):
			tagDrop++
		default:
			// distinguish sig corruption from wrong-version by inspecting VER
			_, body := greaseSplit(out, VersionDraft08)
			if body != nil {
				if lo, hi, ok := findTagRange(body, TagVER); ok && hi-lo == 4 {
					v := binary.LittleEndian.Uint32(body[lo:])
					if v == 0xFFFFFFFF {
						wrongVer++
						continue
					}
				}
			}
			sigCorrupt++
		}
	}

	if sigCorrupt == 0 {
		t.Error("signature corruption mode never fired")
	}
	if tagDrop == 0 {
		t.Error("tag drop mode never fired")
	}
	if wrongVer == 0 {
		t.Error("wrong version mode never fired")
	}
	if undefinedTag == 0 {
		t.Error("undefined tag mode never fired")
	}
	t.Logf("distribution: sig=%d drop=%d ver=%d undef=%d", sigCorrupt, tagDrop, wrongVer, undefinedTag)
}

// TestGreaseNeverProducesSentinels verifies Grease never surfaces
// ErrMerkleMismatch or ErrDelegationWindow.
func TestGreaseNeverProducesSentinels(t *testing.T) {
	for _, ver := range []Version{VersionGoogle, VersionDraft08, VersionDraft12} {
		t.Run(ver.ShortString(), func(t *testing.T) {
			reply, rootPK, nonce, req := validReply(t, ver, []Version{ver})
			for range 500 {
				cp := make([]byte, len(reply))
				copy(cp, reply)
				out := Grease(cp, ver)
				_, _, err := VerifyReply([]Version{ver}, out, rootPK, nonce, req)
				if err == nil {
					continue
				}
				if errors.Is(err, ErrMerkleMismatch) || errors.Is(err, ErrDelegationWindow) {
					t.Fatalf("grease produced sentinel error: %v", err)
				}
			}
		})
	}
}

// TestGreaseMalformedInput verifies Grease tolerates malformed inputs without
// panicking.
func TestGreaseMalformedInput(t *testing.T) {
	for _, ver := range []Version{VersionGoogle, VersionDraft08, VersionDraft12} {
		t.Run(ver.String(), func(t *testing.T) {
			for _, input := range [][]byte{nil, {}, {0x00}, make([]byte, 11)} {
				Grease(input, ver)
			}
		})
	}
}

// FuzzGrease fuzzes Grease for panic-safety on arbitrary inputs.
func FuzzGrease(f *testing.F) {
	_, rootSK, _ := ed25519.GenerateKey(rand.Reader)
	_, onlineSK, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	cert, _ := NewCertificate(now.Add(-time.Hour), now.Add(time.Hour), onlineSK, rootSK)

	for _, ver := range []Version{VersionGoogle, VersionDraft08, VersionDraft12} {
		_, req, err := CreateRequest([]Version{ver}, rand.Reader, nil)
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
		f.Add(replies[0], uint32(ver))
	}
	f.Add([]byte{}, uint32(0))
	f.Add([]byte{0xff}, uint32(VersionDraft08))

	f.Fuzz(func(t *testing.T, data []byte, verRaw uint32) {
		Grease(data, Version(verRaw))
	})
}

// TestGreaseDropTagOnGarbageBody verifies greaseDropTag returns nil for an
// unparseable body.
func TestGreaseDropTagOnGarbageBody(t *testing.T) {
	header := make([]byte, 12)
	copy(header[:8], []byte("ROUGHTIM"))
	binary.LittleEndian.PutUint32(header[8:12], 4)
	reply := append(header, []byte{0xff, 0xff, 0xff, 0xff}...)
	if got := greaseDropTag(reply, VersionDraft08); got != nil {
		t.Fatalf("expected nil for garbage body, got %d bytes", len(got))
	}
}

// TestGreaseDropTagNoCandidates verifies greaseDropTag returns nil when no
// candidate tags are present.
func TestGreaseDropTagNoCandidates(t *testing.T) {
	body, err := encode(map[uint32][]byte{TagNONC: make([]byte, 32)})
	if err != nil {
		t.Fatal(err)
	}
	header := make([]byte, 12)
	copy(header[:8], []byte("ROUGHTIM"))
	binary.LittleEndian.PutUint32(header[8:12], uint32(len(body)))
	reply := append(header, body...)
	if got := greaseDropTag(reply, VersionDraft08); got != nil {
		t.Fatalf("expected nil when no candidate tags exist, got %d bytes", len(got))
	}
}

// TestGreaseDropTagSubTagsReachable verifies greaseDropTag drops both top-level
// tags and SREP/CERT sub-tags.
func TestGreaseDropTagSubTagsReachable(t *testing.T) {
	reply, _, _, _ := validReply(t, VersionDraft12, []Version{VersionDraft12})

	var topOnly, subTag int
	origBody, _ := unwrapPacket(reply)
	origMsg, _ := Decode(origBody)
	origSREP := origMsg[TagSREP]
	origCERT := origMsg[TagCERT]

	for range 500 {
		cp := make([]byte, len(reply))
		copy(cp, reply)
		out := greaseDropTag(cp, VersionDraft12)
		if out == nil {
			t.Fatal("greaseDropTag returned nil")
		}
		outBody, err := unwrapPacket(out)
		if err != nil {
			t.Fatalf("unwrap grease output: %v", err)
		}
		outMsg, err := Decode(outBody)
		if err != nil {
			t.Fatalf("decode grease output: %v", err)
		}
		// changed SREP/CERT = sub-tag drop; missing = top-level
		switch {
		case outMsg[TagSREP] == nil, outMsg[TagCERT] == nil,
			outMsg[TagPATH] == nil && origMsg[TagPATH] != nil,
			len(outMsg) < len(origMsg):
			topOnly++
		case !bytes.Equal(outMsg[TagSREP], origSREP), !bytes.Equal(outMsg[TagCERT], origCERT):
			subTag++
		default:
			topOnly++
		}
	}
	if subTag == 0 {
		t.Error("sub-tag drop mode never fired (SREP/CERT sub-tag drop unreachable)")
	}
	if topOnly == 0 {
		t.Error("top-level drop mode never fired")
	}
	t.Logf("distribution: top-level=%d sub-tag=%d", topOnly, subTag)
}

// TestGreaseDoesNotPanicMLDSA44 verifies Grease handles ML-DSA-44 replies
// without panicking.
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
	for range 50 {
		Grease(replies[0], VersionMLDSA44)
	}
}

// TestGreaseCorruptSigNoSig verifies greaseCorruptSig leaves the reply
// unchanged when SIG is absent.
func TestGreaseCorruptSigNoSig(t *testing.T) {
	body, err := encode(map[uint32][]byte{TagNONC: make([]byte, 32)})
	if err != nil {
		t.Fatal(err)
	}
	header := make([]byte, 12)
	copy(header[:8], []byte("ROUGHTIM"))
	binary.LittleEndian.PutUint32(header[8:12], uint32(len(body)))
	reply := append(header, body...)
	orig := append([]byte(nil), reply...)
	if greaseCorruptSig(reply, VersionDraft08) {
		t.Fatal("greaseCorruptSig returned true with no SIG present")
	}
	if !bytes.Equal(reply, orig) {
		t.Fatal("greaseCorruptSig mutated reply when no SIG was present")
	}
}
