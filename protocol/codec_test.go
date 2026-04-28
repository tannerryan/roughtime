// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// TestParsePacketHeader verifies ParsePacketHeader on valid, bad-magic, and
// short inputs.
func TestParsePacketHeader(t *testing.T) {
	var good [12]byte
	copy(good[:8], []byte("ROUGHTIM"))
	binary.LittleEndian.PutUint32(good[8:], 1024)
	if n, err := ParsePacketHeader(good[:]); err != nil || n != 1024 {
		t.Fatalf("good: n=%d err=%v", n, err)
	}

	var bad [12]byte
	copy(bad[:8], []byte("NOTMAGIC"))
	if _, err := ParsePacketHeader(bad[:]); err == nil {
		t.Fatal("accepted bad magic")
	}

	if _, err := ParsePacketHeader(good[:5]); err == nil {
		t.Fatal("accepted short header")
	}
}

// FuzzParsePacketHeader fuzzes ParsePacketHeader for panic-safety on arbitrary
// bytes.
func FuzzParsePacketHeader(f *testing.F) {
	var good [12]byte
	copy(good[:8], []byte("ROUGHTIM"))
	binary.LittleEndian.PutUint32(good[8:], 1024)
	f.Add(good[:])
	f.Add([]byte("NOTMAGIC\x00\x00\x00\x00"))
	f.Add([]byte{})
	f.Add([]byte("ROUG"))
	f.Fuzz(func(t *testing.T, in []byte) {
		if _, err := ParsePacketHeader(in); err == nil {
			if len(in) < PacketHeaderSize || !bytes.Equal(in[:8], []byte("ROUGHTIM")) {
				t.Fatalf("accepted invalid header: len=%d prefix=%x", len(in), in[:min(8, len(in))])
			}
		}
	})
}

// TestEncodeDecodeRoundTrip verifies a multi-tag message round-trips through
// encode/Decode.
func TestEncodeDecodeRoundTrip(t *testing.T) {
	msg := map[uint32][]byte{
		0x0001: {0x10, 0x20, 0x30, 0x40},
		0x0002: {0x50, 0x60, 0x70, 0x80, 0xa0, 0xb0, 0xc0, 0xd0},
		0x0003: {},
	}
	encoded, err := encode(msg)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	for tag, val := range msg {
		got, ok := decoded[tag]
		if !ok {
			t.Fatalf("missing tag %#x", tag)
		}
		if !bytes.Equal(got, val) {
			t.Fatalf("tag %#x: got %x, want %x", tag, got, val)
		}
	}
}

// TestEncodeSingleTag verifies encode handles a single-tag message.
func TestEncodeSingleTag(t *testing.T) {
	encoded, err := encode(map[uint32][]byte{TagNONC: make([]byte, 32)})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 1 {
		t.Fatalf("expected 1 tag, got %d", len(decoded))
	}
}

// TestEncodeTagOrder verifies encode emits tags in ascending order.
func TestEncodeTagOrder(t *testing.T) {
	encoded, err := encode(map[uint32][]byte{
		0x0003: make([]byte, 4),
		0x0001: make([]byte, 4),
		0x0002: make([]byte, 4),
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		tag := binary.LittleEndian.Uint32(encoded[12+4*i : 12+4*i+4])
		if tag != uint32(i+1) {
			t.Fatalf("tag %d: got %#x, want %#x", i, tag, i+1)
		}
	}
}

// TestEncodeRejectsEmpty verifies encode rejects an empty tag map.
func TestEncodeRejectsEmpty(t *testing.T) {
	if _, err := encode(map[uint32][]byte{}); err == nil {
		t.Fatal("expected error")
	}
}

// TestEncodeRejectsNonAlignedValue verifies encode rejects values whose length
// is not a multiple of 4.
func TestEncodeRejectsNonAlignedValue(t *testing.T) {
	if _, err := encode(map[uint32][]byte{0x0001: {1, 2, 3}}); err == nil {
		t.Fatal("expected error")
	}
}

// TestEncodeRejectsExcessiveTags verifies encode rejects more than
// maxEncodeTags entries.
func TestEncodeRejectsExcessiveTags(t *testing.T) {
	msg := make(map[uint32][]byte, maxEncodeTags+1)
	for i := range maxEncodeTags + 1 {
		msg[uint32(i+1)] = make([]byte, 4)
	}
	if _, err := encode(msg); err == nil {
		t.Fatal("expected error")
	}
}

// TestDecodeRejectsTooShort verifies Decode rejects input smaller than the tag
// count word.
func TestDecodeRejectsTooShort(t *testing.T) {
	if _, err := Decode([]byte{1, 2}); err == nil {
		t.Fatal("expected error")
	}
}

// TestDecodeZeroTags verifies Decode accepts the empty zero-tag message.
func TestDecodeZeroTags(t *testing.T) {
	msg, err := Decode([]byte{0, 0, 0, 0})
	if err != nil {
		t.Fatalf("zero-tag message should be valid: %v", err)
	}
	if len(msg) != 0 {
		t.Fatalf("expected empty map, got %d entries", len(msg))
	}
}

// TestDecodeZeroTagsTrailingData verifies Decode rejects trailing bytes after a
// zero-tag message.
func TestDecodeZeroTagsTrailingData(t *testing.T) {
	if _, err := Decode([]byte{0, 0, 0, 0, 0xff}); err == nil {
		t.Fatal("expected error for trailing data")
	}
}

// TestDecodeRejectsExcessiveTags verifies Decode rejects tag counts above
// maxDecodeTags.
func TestDecodeRejectsExcessiveTags(t *testing.T) {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, maxDecodeTags+1)
	if _, err := Decode(buf); err == nil {
		t.Fatal("expected error")
	}
}

// TestDecodeRejectsTruncatedHeader verifies Decode rejects a header smaller
// than the declared size.
func TestDecodeRejectsTruncatedHeader(t *testing.T) {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, 5)
	if _, err := Decode(buf); err == nil {
		t.Fatal("expected error")
	}
}

// TestDecodeRejectsNonAscendingTags verifies Decode rejects tags not in
// strictly ascending order.
func TestDecodeRejectsNonAscendingTags(t *testing.T) {
	encoded, _ := encode(map[uint32][]byte{
		0x0001: make([]byte, 4),
		0x0002: make([]byte, 4),
	})
	for i := range 4 {
		encoded[8+i], encoded[12+i] = encoded[12+i], encoded[8+i]
	}
	if _, err := Decode(encoded); err == nil {
		t.Fatal("expected error")
	}
}

// TestDecodeRejectsBadOffset verifies Decode rejects misaligned offsets.
func TestDecodeRejectsBadOffset(t *testing.T) {
	encoded, _ := encode(map[uint32][]byte{
		0x0001: make([]byte, 4),
		0x0002: make([]byte, 4),
	})
	binary.LittleEndian.PutUint32(encoded[4:8], 3)
	if _, err := Decode(encoded); err == nil {
		t.Fatal("expected error")
	}
}

// TestDecodeRejectsOutOfBoundsOffset verifies Decode rejects offsets pointing
// outside the message.
func TestDecodeRejectsOutOfBoundsOffset(t *testing.T) {
	encoded, _ := encode(map[uint32][]byte{
		0x0001: make([]byte, 4),
		0x0002: make([]byte, 4),
	})
	binary.LittleEndian.PutUint32(encoded[4:8], 9999)
	if _, err := Decode(encoded); err == nil {
		t.Fatal("expected error")
	}
}

// TestWrapUnwrapRoundTrip verifies wrapPacket and unwrapPacket round-trip a
// body.
func TestWrapUnwrapRoundTrip(t *testing.T) {
	msg := []byte("hello world!")
	got, err := unwrapPacket(wrapPacket(msg))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatal("round-trip mismatch")
	}
}

// TestWrapPacketHeader verifies wrapPacket emits the ROUGHTIM magic and body
// length.
func TestWrapPacketHeader(t *testing.T) {
	pkt := wrapPacket(make([]byte, 20))
	if !bytes.Equal(pkt[:8], packetMagic[:]) {
		t.Fatal("bad magic")
	}
	if binary.LittleEndian.Uint32(pkt[8:12]) != 20 {
		t.Fatal("bad message length")
	}
}

// TestUnwrapRejectsTooShort verifies unwrapPacket rejects input smaller than
// the header.
func TestUnwrapRejectsTooShort(t *testing.T) {
	if _, err := unwrapPacket([]byte{1, 2}); err == nil {
		t.Fatal("expected error")
	}
}

// TestUnwrapRejectsBadMagic verifies unwrapPacket rejects packets without the
// ROUGHTIM magic.
func TestUnwrapRejectsBadMagic(t *testing.T) {
	pkt := make([]byte, 16)
	copy(pkt[:8], []byte("BADMAGIC"))
	if _, err := unwrapPacket(pkt); err == nil {
		t.Fatal("expected error")
	}
}

// TestUnwrapRejectsTruncatedMessage verifies unwrapPacket rejects a body
// shorter than the declared length.
func TestUnwrapRejectsTruncatedMessage(t *testing.T) {
	if _, err := unwrapPacket(wrapPacket(make([]byte, 20))[:16]); err == nil {
		t.Fatal("expected error")
	}
}

// TestUnwrapPacketBoundary verifies mlen == len(pkt)-12 is accepted.
func TestUnwrapPacketBoundary(t *testing.T) {
	msg := bytes.Repeat([]byte{0xab}, 20)
	got, err := unwrapPacket(wrapPacket(msg))
	if err != nil {
		t.Fatalf("boundary case: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatal("boundary case: body mismatch")
	}
}

// TestUnwrapReplyRejectsGoogleWithHeader verifies unwrapReply rejects Google
// replies that include a ROUGHTIM header.
func TestUnwrapReplyRejectsGoogleWithHeader(t *testing.T) {
	pkt := wrapPacket(make([]byte, 20))
	if _, err := unwrapReply(pkt, groupGoogle); err == nil {
		t.Fatal("expected error for Google reply with ROUGHTIM header")
	}
}

// TestDecodeRejectsValueOutOfBounds verifies Decode rejects a value range that
// exceeds message length.
func TestDecodeRejectsValueOutOfBounds(t *testing.T) {
	encoded, _ := encode(map[uint32][]byte{
		0x0001: make([]byte, 8),
		0x0002: make([]byte, 4),
	})
	binary.LittleEndian.PutUint32(encoded[4:8], 4)
	if _, err := Decode(encoded[:16]); err == nil {
		t.Fatal("expected error for value out of bounds")
	}
}

// TestDecodeRejectsOversizedInput verifies Decode rejects messages larger than
// maxMessageSize.
func TestDecodeRejectsOversizedInput(t *testing.T) {
	if _, err := Decode(make([]byte, maxMessageSize+1)); err == nil {
		t.Fatal("expected error for oversized message")
	}
}

// FuzzDecode fuzzes Decode for panic-safety and round-trip stability.
func FuzzDecode(f *testing.F) {
	valid, _ := encode(map[uint32][]byte{TagNONC: make([]byte, 32)})
	f.Add(valid)

	multi, _ := encode(map[uint32][]byte{
		TagNONC: make([]byte, 32),
		TagVER:  {0x0c, 0x00, 0x00, 0x80},
		TagZZZZ: make([]byte, 64),
	})
	f.Add(multi)

	f.Add([]byte{0x00, 0x00, 0x00, 0x00})
	f.Add([]byte{})
	f.Add([]byte{0x01})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		msg, err := Decode(data)
		if err != nil {
			return
		}
		reencoded, err := encode(msg)
		if err != nil {
			return
		}
		msg2, err := Decode(reencoded)
		if err != nil {
			t.Fatalf("re-decode failed: %v", err)
		}
		if len(msg) != len(msg2) {
			t.Fatalf("tag count mismatch: %d vs %d", len(msg), len(msg2))
		}
		for tag, val := range msg {
			if !bytes.Equal(val, msg2[tag]) {
				t.Fatalf("value mismatch for tag %#x", tag)
			}
		}
	})
}

// FuzzEncode fuzzes encode followed by Decode for round-trip stability.
func FuzzEncode(f *testing.F) {
	f.Add(uint32(1), []byte{0x00, 0x00, 0x00, 0x00})
	f.Add(uint32(3), make([]byte, 256))

	f.Fuzz(func(t *testing.T, numTags uint32, valTemplate []byte) {
		n := int(numTags%64) + 1
		if len(valTemplate)%4 != 0 {
			aligned := len(valTemplate) &^ 3
			if aligned == 0 {
				valTemplate = []byte{0, 0, 0, 0}
			} else {
				valTemplate = valTemplate[:aligned]
			}
		}
		if len(valTemplate) == 0 {
			valTemplate = []byte{0, 0, 0, 0}
		}

		msg := make(map[uint32][]byte, n)
		for i := range n {
			tag := uint32(i * 0x01010101)
			msg[tag] = valTemplate
		}

		encoded, err := encode(msg)
		if err != nil {
			return
		}
		if len(encoded) > maxMessageSize {
			return
		}
		decoded, err := Decode(encoded)
		if err != nil {
			t.Fatalf("round-trip decode failed: %v", err)
		}
		if len(decoded) != len(msg) {
			t.Fatalf("tag count mismatch: got %d, want %d", len(decoded), len(msg))
		}
		for tag, val := range msg {
			if !bytes.Equal(val, decoded[tag]) {
				t.Fatalf("value mismatch for tag %#x", tag)
			}
		}
	})
}

// TestFindTagRangeMalformed verifies findTagRange handles malformed inputs and
// missing tags.
func TestFindTagRangeMalformed(t *testing.T) {
	t.Run("too short", func(t *testing.T) {
		if _, _, ok := findTagRange([]byte{1, 2, 3}, TagNONC); ok {
			t.Fatal("expected ok=false for <4 byte msg")
		}
	})
	t.Run("zero tag count", func(t *testing.T) {
		msg := make([]byte, 4)
		if _, _, ok := findTagRange(msg, TagNONC); ok {
			t.Fatal("expected ok=false for zero tag count")
		}
	})
	t.Run("oversized tag count", func(t *testing.T) {
		msg := make([]byte, 4)
		binary.LittleEndian.PutUint32(msg, 513)
		if _, _, ok := findTagRange(msg, TagNONC); ok {
			t.Fatal("expected ok=false for tag count > 512")
		}
	})
	t.Run("truncated header", func(t *testing.T) {
		msg := make([]byte, 8)
		binary.LittleEndian.PutUint32(msg, 2)
		if _, _, ok := findTagRange(msg, TagNONC); ok {
			t.Fatal("expected ok=false for truncated header")
		}
	})
	t.Run("tag not found", func(t *testing.T) {
		msg := make([]byte, 8)
		binary.LittleEndian.PutUint32(msg, 1)
		binary.LittleEndian.PutUint32(msg[4:], TagNONC)
		if _, _, ok := findTagRange(msg, TagSIG); ok {
			t.Fatal("expected ok=false when tag absent")
		}
	})
	t.Run("last tag with values", func(t *testing.T) {
		body, err := encode(map[uint32][]byte{
			TagNONC: bytes.Repeat([]byte{0x11}, 32),
			TagPAD:  bytes.Repeat([]byte{0x22}, 8),
		})
		if err != nil {
			t.Fatal(err)
		}
		lo, hi, ok := findTagRange(body, TagPAD)
		if !ok {
			t.Fatal("expected to find PAD")
		}
		if hi-lo != 8 {
			t.Fatalf("PAD length = %d, want 8", hi-lo)
		}
		if !bytes.Equal(body[lo:hi], bytes.Repeat([]byte{0x22}, 8)) {
			t.Fatal("PAD value mismatch")
		}
	})
}

// TestEncodeWrappedRejectsBadInput verifies encodeWrapped surfaces encode
// errors.
func TestEncodeWrappedRejectsBadInput(t *testing.T) {
	if _, err := encodeWrapped(map[uint32][]byte{TagNONC: {1, 2, 3}}); err == nil {
		t.Fatal("expected error for non-aligned value")
	}
}

// TestEncodeWrappedHeader verifies encodeWrapped emits the ROUGHTIM magic and
// correct body length.
func TestEncodeWrappedHeader(t *testing.T) {
	out, err := encodeWrapped(map[uint32][]byte{TagNONC: make([]byte, 32)})
	if err != nil {
		t.Fatalf("encodeWrapped: %v", err)
	}
	if !bytes.Equal(out[:8], packetMagic[:]) {
		t.Fatal("missing ROUGHTIM magic")
	}
	if got, want := binary.LittleEndian.Uint32(out[8:12]), uint32(len(out)-12); got != want {
		t.Fatalf("body length = %d, want %d", got, want)
	}
}

// TestNonceOffsetInRequest verifies NonceOffsetInRequest locates NONC for
// framed and unframed requests.
func TestNonceOffsetInRequest(t *testing.T) {
	nonce := bytes.Repeat([]byte{0x42}, 32)

	framed, err := CreateRequestWithNonce([]Version{VersionDraft12}, nonce, nil)
	if err != nil {
		t.Fatalf("CreateRequestWithNonce: %v", err)
	}
	off, err := NonceOffsetInRequest(framed)
	if err != nil {
		t.Fatalf("framed: %v", err)
	}
	if !bytes.Equal(framed[off:off+32], nonce) {
		t.Fatalf("framed: slice at offset %d does not match nonce", off)
	}

	raw := framed[12:]
	off, err = NonceOffsetInRequest(raw)
	if err != nil {
		t.Fatalf("unframed: %v", err)
	}
	if !bytes.Equal(raw[off:off+32], nonce) {
		t.Fatalf("unframed: slice at offset %d does not match nonce", off)
	}

	noNONC, err := encode(map[uint32][]byte{TagPAD: make([]byte, 32)})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, err := NonceOffsetInRequest(noNONC); err == nil {
		t.Fatal("expected error for message without NONC")
	}

	for _, bad := range [][]byte{nil, {}, {0x01}, {0x00, 0x00, 0x00}} {
		if _, err := NonceOffsetInRequest(bad); err == nil {
			t.Fatalf("expected error for malformed input %x", bad)
		}
	}

	// framed but truncated body — exercises unwrapRequest error path
	pkt := make([]byte, 12)
	copy(pkt[:8], packetMagic[:])
	binary.LittleEndian.PutUint32(pkt[8:12], 9999)
	if _, err := NonceOffsetInRequest(pkt); err == nil {
		t.Fatal("expected error for framed but truncated request")
	}

	// NONC tag with zero-length value at end-of-buffer must not yield an
	// out-of-bounds offset.
	crafted := []byte("\x04\x00\x00\x00\x00\x00\x00\x0000000000NONC000000000000")
	if _, err := NonceOffsetInRequest(crafted); err == nil {
		t.Fatal("expected error for NONC with invalid length")
	}
}

// FuzzNonceOffsetInRequest fuzzes NonceOffsetInRequest for panic-safety and
// bounds.
func FuzzNonceOffsetInRequest(f *testing.F) {
	if req, err := CreateRequestWithNonce([]Version{VersionDraft12}, bytes.Repeat([]byte{0xaa}, 32), nil); err == nil {
		f.Add(req)
		f.Add(req[12:])
	}
	f.Add([]byte{})
	f.Add([]byte{0x01, 0x00, 0x00, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		off, err := NonceOffsetInRequest(data)
		if err != nil {
			return
		}
		if off < 0 || off >= len(data) {
			t.Fatalf("offset %d out of bounds (len=%d)", off, len(data))
		}
	})
}

// FuzzFindTagRange fuzzes findTagRange for panic-safety and bounds invariants.
func FuzzFindTagRange(f *testing.F) {
	f.Add([]byte{}, uint32(0))
	f.Add([]byte{0x01, 0x00, 0x00, 0x00}, uint32(TagSIG))
	if req, err := CreateRequestWithNonce([]Version{VersionDraft12}, bytes.Repeat([]byte{0xaa}, 32), nil); err == nil {
		f.Add(req[12:], uint32(TagNONC))
		f.Add(req[12:], uint32(TagVER))
	}
	f.Fuzz(func(t *testing.T, msg []byte, tag uint32) {
		lo, hi, ok := findTagRange(msg, tag)
		if !ok {
			return
		}
		if lo > hi {
			t.Fatalf("ok but lo=%d > hi=%d", lo, hi)
		}
		if uint64(hi) > uint64(len(msg)) {
			t.Fatalf("hi=%d exceeds len(msg)=%d", hi, len(msg))
		}
	})
}

// TestNonceOffsetInRequestAliasing verifies rewriting the nonce at the returned
// offset surfaces in ParseRequest.
func TestNonceOffsetInRequestAliasing(t *testing.T) {
	srv := bytes.Repeat([]byte{0x42}, 32)
	nonce := bytes.Repeat([]byte{0xaa}, 32)
	request, err := CreateRequestWithNonce([]Version{VersionDraft12}, nonce, srv)
	if err != nil {
		t.Fatalf("CreateRequestWithNonce: %v", err)
	}
	off, err := NonceOffsetInRequest(request)
	if err != nil {
		t.Fatalf("NonceOffsetInRequest: %v", err)
	}
	rewritten := bytes.Repeat([]byte{0x77}, len(nonce))
	copy(request[off:off+len(rewritten)], rewritten)
	parsed, err := ParseRequest(request)
	if err != nil {
		t.Fatalf("ParseRequest after rewrite: %v", err)
	}
	if !bytes.Equal(parsed.Nonce, rewritten) {
		t.Fatalf("nonce rewrite did not surface in ParseRequest: got %x, want %x", parsed.Nonce, rewritten)
	}
}

// TestTagZZZZValue locks TagZZZZ to the universal 0x5a5a5a5a value used by
// drafts 10+.
func TestTagZZZZValue(t *testing.T) {
	if TagZZZZ != 0x5a5a5a5a {
		t.Fatalf("TagZZZZ = 0x%08x, want 0x5a5a5a5a (drafts 10+ value used universally)", TagZZZZ)
	}
}

// TestDecodeRejectsEqualTags verifies Decode rejects duplicate tags.
func TestDecodeRejectsEqualTags(t *testing.T) {
	msg := make([]byte, 4+4+8)
	binary.LittleEndian.PutUint32(msg[0:4], 2)
	binary.LittleEndian.PutUint32(msg[4:8], 0)
	binary.LittleEndian.PutUint32(msg[8:12], TagNONC)
	binary.LittleEndian.PutUint32(msg[12:16], TagNONC)
	if _, err := Decode(msg); err == nil {
		t.Fatal("Decode accepted message with duplicate tags")
	}
}

// TestFindTagRangeZeroLength verifies findTagRange accepts zero-length values.
func TestFindTagRangeZeroLength(t *testing.T) {
	body, err := encode(map[uint32][]byte{
		TagNONC: bytes.Repeat([]byte{0x11}, 32),
		TagPAD:  nil,
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	lo, hi, ok := findTagRange(body, TagPAD)
	if !ok {
		t.Fatal("findTagRange returned ok=false for zero-length tag")
	}
	if hi != lo {
		t.Fatalf("zero-length tag: hi=%d lo=%d, want equal", hi, lo)
	}
}
