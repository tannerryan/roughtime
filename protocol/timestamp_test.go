// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"encoding/binary"
	"math"
	"testing"
	"time"
)

// TestEncodeTimestampGoogle covers the Google midpoint epoch.
func TestEncodeTimestampGoogle(t *testing.T) {
	ts := time.Unix(1700000000, 500000000)
	buf := encodeTimestamp(ts, groupGoogle)
	if binary.LittleEndian.Uint64(buf[:]) != uint64(ts.UnixMicro()) {
		t.Fatal("Google timestamp mismatch")
	}
}

// TestEncodeTimestampUnixSeconds covers second-resolution Unix encoding.
func TestEncodeTimestampUnixSeconds(t *testing.T) {
	buf := encodeTimestamp(time.Unix(1700000000, 999999999), groupD08)
	if binary.LittleEndian.Uint64(buf[:]) != 1700000000 {
		t.Fatal("Unix seconds should truncate sub-second")
	}
}

// TestEncodeTimestampMJDEpoch covers modified-Julian encoding.
func TestEncodeTimestampMJDEpoch(t *testing.T) {
	buf := encodeTimestamp(time.Unix(0, 0).UTC(), groupD01)
	got := binary.LittleEndian.Uint64(buf[:])
	if got>>40 != 40587 || got&0xFFFFFFFFFF != 0 {
		t.Fatal("MJD epoch mismatch")
	}
}

// TestDecodeTimestampGoogle covers Google midpoint decoding.
func TestDecodeTimestampGoogle(t *testing.T) {
	ts := time.Unix(1700000000, 500000000).UTC()
	buf := encodeTimestamp(ts, groupGoogle)
	got, err := decodeTimestamp(buf[:], groupGoogle)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(ts) {
		t.Fatalf("got %v, want %v", got, ts)
	}
}

// TestDecodeTimestampMJD covers modified-Julian decoding.
func TestDecodeTimestampMJD(t *testing.T) {
	ts := time.Date(2024, 11, 15, 10, 30, 0, 0, time.UTC)
	buf := encodeTimestamp(ts, groupD01)
	got, err := decodeTimestamp(buf[:], groupD01)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(ts) {
		t.Fatalf("got %v, want %v", got, ts)
	}
}

// TestDecodeTimestampUnixSeconds covers Unix-second decoding.
func TestDecodeTimestampUnixSeconds(t *testing.T) {
	ts := time.Unix(1700000000, 0).UTC()
	buf := encodeTimestamp(ts, groupD08)
	got, err := decodeTimestamp(buf[:], groupD08)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(ts) {
		t.Fatalf("got %v, want %v", got, ts)
	}
}

// TestDecodeTimestampPublic covers the exported decoder's validation and
// version-specific dispatch.
func TestDecodeTimestampPublic(t *testing.T) {
	ts := time.Unix(1700000000, 0).UTC()
	buf := encodeTimestamp(ts, groupD08)
	got, err := DecodeTimestamp(VersionDraft08, buf[:])
	if err != nil || !got.Equal(ts) {
		t.Fatalf("DecodeTimestamp = %v, %v, want %v", got, err, ts)
	}
	if _, err := DecodeTimestamp(VersionDraft08, buf[:7]); err == nil {
		t.Fatal("DecodeTimestamp accepted a short timestamp")
	}
	if _, err := DecodeTimestamp(Version(0xdeadbeef), buf[:]); err == nil {
		t.Fatal("DecodeTimestamp accepted an unknown version")
	}
}

// TestMJDMicroRoundTrip covers microsecond MJD precision.
func TestMJDMicroRoundTrip(t *testing.T) {
	ts := time.Date(2024, 11, 15, 10, 30, 0, 0, time.UTC)
	decoded, err := mjdMicroToTime(timeToMJDMicro(ts))
	if err != nil {
		t.Fatal(err)
	}
	if !decoded.Equal(ts) {
		t.Fatalf("round-trip failed: got %v, want %v", decoded, ts)
	}
}

// TestMJDMicroToTimeRejectsOverflow covers invalid MJD sub-day fields.
func TestMJDMicroToTimeRejectsOverflow(t *testing.T) {
	v := (uint64(40587) << 40) | uint64(microsPerPositiveLeapDay)
	if _, err := mjdMicroToTime(v); err == nil {
		t.Fatal("expected error at the positive-leap-day limit")
	}
	v = (uint64(40587) << 40) | 0xFFFFFFFFFF
	if _, err := mjdMicroToTime(v); err == nil {
		t.Fatal("expected error for 40-bit-max sub-day µs")
	}
}

// TestRadiMicroseconds covers microsecond RADI rounding and limits.
func TestRadiMicroseconds(t *testing.T) {
	if got, err := radiMicroseconds(time.Second); err != nil || got != 1_000_000 {
		t.Fatal("1s should be 1000000 µs")
	}
	if got, err := radiMicroseconds(0); err != nil || got != 1 {
		t.Fatal("0 should clamp to 1")
	}
	if got, err := radiMicroseconds(-time.Second); err != nil || got != 1 {
		t.Fatal("negative should clamp to 1")
	}
	if _, err := radiMicroseconds(time.Duration(math.MaxInt64)); err == nil {
		t.Fatal("overflow should fail")
	}
}

// TestRadiSeconds covers second RADI rounding and limits.
func TestRadiSeconds(t *testing.T) {
	if got, err := radiSeconds(500 * time.Millisecond); err != nil || got != 3 {
		t.Fatal("sub-second should clamp to 3")
	}
	if got, err := radiSeconds(2 * time.Second); err != nil || got != 3 {
		t.Fatal("2s should clamp to 3")
	}
	if got, err := radiSeconds(3 * time.Second); err != nil || got != 3 {
		t.Fatal("3s should be 3")
	}
	if got, err := radiSeconds(5 * time.Second); err != nil || got != 5 {
		t.Fatal("5s should be 5")
	}
	if _, err := radiSeconds(time.Duration(math.MaxInt64)); err == nil {
		t.Fatal("overflow should fail")
	}
}

// TestDecodeRadiusRejectsShort covers truncated RADI values.
func TestDecodeRadiusRejectsShort(t *testing.T) {
	if _, err := decodeRadius([]byte{1, 2}, groupGoogle); err == nil {
		t.Fatal("expected error")
	}
}
