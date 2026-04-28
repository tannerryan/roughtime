// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"encoding/binary"
	"math"
	"testing"
	"time"
)

// TestEncodeTimestampGoogle verifies encodeTimestamp uses Unix-µs for
// Google-Roughtime.
func TestEncodeTimestampGoogle(t *testing.T) {
	ts := time.Unix(1700000000, 500000000)
	buf := encodeTimestamp(ts, groupGoogle)
	if binary.LittleEndian.Uint64(buf[:]) != uint64(ts.UnixMicro()) {
		t.Fatal("Google timestamp mismatch")
	}
}

// TestEncodeTimestampUnixSeconds verifies encodeTimestamp truncates sub-second
// precision for drafts 08+.
func TestEncodeTimestampUnixSeconds(t *testing.T) {
	buf := encodeTimestamp(time.Unix(1700000000, 999999999), groupD08)
	if binary.LittleEndian.Uint64(buf[:]) != 1700000000 {
		t.Fatal("Unix seconds should truncate sub-second")
	}
}

// TestEncodeTimestampMJDEpoch verifies encodeTimestamp encodes the Unix epoch
// as MJD 40587.
func TestEncodeTimestampMJDEpoch(t *testing.T) {
	buf := encodeTimestamp(time.Unix(0, 0).UTC(), groupD01)
	got := binary.LittleEndian.Uint64(buf[:])
	if got>>40 != 40587 || got&0xFFFFFFFFFF != 0 {
		t.Fatal("MJD epoch mismatch")
	}
}

// TestEncodeTimestampMJDNoon verifies encodeTimestamp encodes noon as 12 hours
// of µs in the MJD sub-day field.
func TestEncodeTimestampMJDNoon(t *testing.T) {
	buf := encodeTimestamp(time.Unix(43200, 0).UTC(), groupD05)
	got := binary.LittleEndian.Uint64(buf[:])
	if got>>40 != 40587 || got&0xFFFFFFFFFF != uint64(12*3600_000_000) {
		t.Fatal("MJD noon mismatch")
	}
}

// TestTimeToMJDMicroKnownDate verifies timeToMJDMicro on a known date.
func TestTimeToMJDMicroKnownDate(t *testing.T) {
	ts := time.Date(2024, 11, 15, 10, 30, 0, 0, time.UTC)
	got := timeToMJDMicro(ts)
	wantMJD := uint64(40587 + ts.Unix()/86400)
	wantUs := uint64(10*3600_000_000 + 30*60_000_000)
	if got>>40 != wantMJD || got&0xFFFFFFFFFF != wantUs {
		t.Fatal("MJD known date mismatch")
	}
}

// TestDecodeTimestampGoogle verifies decodeTimestamp round-trips Unix-µs
// timestamps for Google.
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

// TestDecodeTimestampMJD verifies decodeTimestamp round-trips MJD-µs timestamps
// for drafts 01-07.
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

// TestDecodeTimestampUnixSeconds verifies decodeTimestamp round-trips
// Unix-second timestamps for drafts 08+.
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

// TestDecodeTimestampRejectsShort verifies decodeTimestamp rejects buffers
// under 8 bytes.
func TestDecodeTimestampRejectsShort(t *testing.T) {
	if _, err := decodeTimestamp([]byte{1, 2, 3}, groupGoogle); err == nil {
		t.Fatal("expected error")
	}
}

// TestDecodeTimestampPublic verifies DecodeTimestamp dispatches by version.
func TestDecodeTimestampPublic(t *testing.T) {
	tests := []struct {
		name string
		ver  Version
		g    wireGroup
		ts   time.Time
	}{
		{"Google", VersionGoogle, groupGoogle, time.Unix(1700000000, 500000000).UTC()},
		{"MJD", VersionDraft01, groupD01, time.Date(2024, 11, 15, 10, 30, 0, 0, time.UTC)},
		{"UnixSec", VersionDraft08, groupD08, time.Unix(1700000000, 0).UTC()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := encodeTimestamp(tt.ts, tt.g)
			got, err := DecodeTimestamp(tt.ver, buf[:])
			if err != nil {
				t.Fatal(err)
			}
			if !got.Equal(tt.ts) {
				t.Fatalf("got %v, want %v", got, tt.ts)
			}
		})
	}
}

// TestDecodeTimestampZero verifies DecodeTimestamp accepts a zero MIDP across
// versions.
func TestDecodeTimestampZero(t *testing.T) {
	zero := make([]byte, 8)
	for _, ver := range []Version{VersionGoogle, VersionDraft01, VersionDraft08, VersionDraft12} {
		t.Run(ver.String(), func(t *testing.T) {
			if _, err := DecodeTimestamp(ver, zero); err != nil {
				t.Fatalf("zero MIDP rejected for %s: %v", ver, err)
			}
		})
	}
}

// TestDecodeTimestampPublicRejectsShort verifies DecodeTimestamp rejects
// buffers under 8 bytes.
func TestDecodeTimestampPublicRejectsShort(t *testing.T) {
	if _, err := DecodeTimestamp(VersionGoogle, []byte{1, 2, 3}); err == nil {
		t.Fatal("expected error")
	}
}

// TestMJDMicroToTimeEpoch verifies mjdMicroToTime maps MJD 40587 to the Unix
// epoch.
func TestMJDMicroToTimeEpoch(t *testing.T) {
	got, err := mjdMicroToTime(uint64(40587) << 40)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(time.Unix(0, 0).UTC()) {
		t.Fatalf("got %v, want Unix epoch", got)
	}
}

// TestMJDMicroToTimeNoon verifies mjdMicroToTime maps MJD 40587 plus 12h µs to
// the Unix epoch noon.
func TestMJDMicroToTimeNoon(t *testing.T) {
	v := (uint64(40587) << 40) | uint64(12*3600_000_000)
	got, err := mjdMicroToTime(v)
	if err != nil {
		t.Fatal(err)
	}
	want := time.Unix(43200, 0).UTC()
	if !got.Equal(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// TestMJDMicroRoundTrip verifies timeToMJDMicro and mjdMicroToTime round-trip a
// known date.
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

// TestMJDMicroToTimeRejectsOverflow verifies mjdMicroToTime rejects sub-day µs
// >= microsPerDay.
func TestMJDMicroToTimeRejectsOverflow(t *testing.T) {
	v := (uint64(40587) << 40) | uint64(microsPerDay)
	if _, err := mjdMicroToTime(v); err == nil {
		t.Fatal("expected error for sub-day µs >= 86400_000_000")
	}
	v = (uint64(40587) << 40) | 0xFFFFFFFFFF
	if _, err := mjdMicroToTime(v); err == nil {
		t.Fatal("expected error for 40-bit-max sub-day µs")
	}
}

// TestRadiMicroseconds verifies radiMicroseconds clamps to [1, MaxUint32].
func TestRadiMicroseconds(t *testing.T) {
	if radiMicroseconds(time.Second) != 1_000_000 {
		t.Fatal("1s should be 1000000 µs")
	}
	if radiMicroseconds(0) != 1 {
		t.Fatal("0 should clamp to 1")
	}
	if radiMicroseconds(-time.Second) != 1 {
		t.Fatal("negative should clamp to 1")
	}
	if radiMicroseconds(time.Duration(math.MaxInt64)) != math.MaxUint32 {
		t.Fatal("overflow should clamp to MaxUint32")
	}
}

// TestRadiSeconds verifies radiSeconds clamps with a floor of 3 seconds.
func TestRadiSeconds(t *testing.T) {
	if radiSeconds(500*time.Millisecond) != 3 {
		t.Fatal("sub-second should clamp to 3")
	}
	if radiSeconds(2*time.Second) != 3 {
		t.Fatal("2s should clamp to 3")
	}
	if radiSeconds(3*time.Second) != 3 {
		t.Fatal("3s should be 3")
	}
	if radiSeconds(5*time.Second) != 5 {
		t.Fatal("5s should be 5")
	}
	if radiSeconds(time.Duration(math.MaxInt64)) != math.MaxUint32 {
		t.Fatal("overflow should clamp to MaxUint32")
	}
}

// TestDecodeRadiusMicroseconds verifies decodeRadius returns µs durations for
// Google.
func TestDecodeRadiusMicroseconds(t *testing.T) {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], 1_000_000)
	got, err := decodeRadius(buf[:], groupGoogle)
	if err != nil {
		t.Fatal(err)
	}
	if got != time.Second {
		t.Fatalf("got %v, want %v", got, time.Second)
	}
}

// TestDecodeRadiusSeconds verifies decodeRadius returns second durations for
// drafts 08+.
func TestDecodeRadiusSeconds(t *testing.T) {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], 5)
	got, err := decodeRadius(buf[:], groupD10)
	if err != nil {
		t.Fatal(err)
	}
	if got != 5*time.Second {
		t.Fatalf("got %v, want %v", got, 5*time.Second)
	}
}

// TestDecodeRadiusRejectsShort verifies decodeRadius rejects buffers under 4
// bytes.
func TestDecodeRadiusRejectsShort(t *testing.T) {
	if _, err := decodeRadius([]byte{1, 2}, groupGoogle); err == nil {
		t.Fatal("expected error")
	}
}

// TestDecodeRadiusAcceptsZero verifies decodeRadius accepts RADI=0 across wire
// groups.
func TestDecodeRadiusAcceptsZero(t *testing.T) {
	for _, g := range []wireGroup{groupGoogle, groupD01, groupD05, groupD07, groupD08, groupD10, groupD12, groupD14} {
		if _, err := decodeRadius(make([]byte, 4), g); err != nil {
			t.Fatalf("RADI=0 should be accepted for group %d: %v", g, err)
		}
	}
}

// TestDecodeRadiusMJDMicroseconds verifies decodeRadius returns µs durations
// for drafts 01-07.
func TestDecodeRadiusMJDMicroseconds(t *testing.T) {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, 1000000)
	for _, g := range []wireGroup{groupD01, groupD02, groupD03, groupD05, groupD07} {
		d, err := decodeRadius(buf, g)
		if err != nil {
			t.Fatalf("group %d: %v", g, err)
		}
		if d != time.Second {
			t.Fatalf("group %d: radius = %v, want 1s", g, d)
		}
	}
}

// TestRadiSecondsFloor verifies radiSeconds applies a 3-second floor.
func TestRadiSecondsFloor(t *testing.T) {
	got := radiSeconds(time.Second)
	if got != 3 {
		t.Fatalf("radiSeconds(1s) = %d, want 3", got)
	}
	got = radiSeconds(500 * time.Millisecond)
	if got != 3 {
		t.Fatalf("radiSeconds(500ms) = %d, want 3", got)
	}
	got = radiSeconds(10 * time.Second)
	if got != 10 {
		t.Fatalf("radiSeconds(10s) = %d, want 10", got)
	}
}

// TestDecodeRadiusToleratesShortRadii verifies decodeRadius accepts RADI < 3.
func TestDecodeRadiusToleratesShortRadii(t *testing.T) {
	enc := func(v uint32) []byte {
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, v)
		return b
	}
	for _, g := range []wireGroup{groupGoogle, groupD01, groupD05, groupD08, groupD10, groupD12, groupD14} {
		for _, v := range []uint32{0, 1, 2, 3} {
			if _, err := decodeRadius(enc(v), g); err != nil {
				t.Errorf("group %v RADI=%d: unexpected error: %v", g, v, err)
			}
		}
	}
}

// TestDecodeTimestampRejectsOverflow verifies decodeTimestamp rejects values
// exceeding MaxInt64.
func TestDecodeTimestampRejectsOverflow(t *testing.T) {
	overflow := make([]byte, 8)
	binary.LittleEndian.PutUint64(overflow, math.MaxInt64+1)
	if _, err := decodeTimestamp(overflow, groupGoogle); err == nil {
		t.Fatal("Google decode accepted >MaxInt64")
	}
	if _, err := decodeTimestamp(overflow, groupD08); err == nil {
		t.Fatal("Unix-seconds decode accepted >MaxInt64")
	}
}

// FuzzDecodeTimestamp fuzzes DecodeTimestamp for panic-safety on arbitrary
// bytes.
func FuzzDecodeTimestamp(f *testing.F) {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], uint64(time.Now().UnixMicro()))
	f.Add(buf[:], byte(0))
	f.Add(buf[:], byte(1))
	f.Add([]byte{}, byte(0))
	f.Add([]byte{0x01, 0x02, 0x03}, byte(5))
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, byte(0))

	versions := []Version{
		VersionGoogle, VersionDraft01, VersionDraft05, VersionDraft08, VersionDraft12,
	}

	f.Fuzz(func(t *testing.T, data []byte, verHint byte) {
		idx := int(verHint) % len(versions)
		DecodeTimestamp(versions[idx], data) //nolint:errcheck // fuzz target tests for panics
	})
}
