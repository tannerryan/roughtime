// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// TestParsePacketHeader covers framed-header validation.
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

// TestEncodeDecodeRoundTrip covers tag-map serialization.
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

// TestEncodeTagOrder covers canonical tag ordering.
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

// TestDecodeRejectsNonAscendingTags covers noncanonical ordering.
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

// TestWrapUnwrapRoundTrip covers ROUGHTIM framing.
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

// TestUnwrapPacketBoundary covers an exactly framed body.
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

// FuzzDecode exercises arbitrary tag-value messages.
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

// TestNonceOffsetInRequest covers nonce location across request forms.
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

	// framed but truncated body, exercises the unwrapRequest error path
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

// TestTagZZZZValue covers the numeric ZZZZ tag value.
func TestTagZZZZValue(t *testing.T) {
	if TagZZZZ != 0x5a5a5a5a {
		t.Fatalf("TagZZZZ = 0x%08x, want 0x5a5a5a5a (drafts 10+ value used universally)", TagZZZZ)
	}
}
