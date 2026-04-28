// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"time"
)

// microsPerDay is µs in a non-leap UTC day, used to validate MJD-µs sub-day
// fields.
const microsPerDay int64 = 86_400 * 1_000_000

// timeToMJDMicro encodes a time as an MJD-µs timestamp for drafts 01-07.
func timeToMJDMicro(t time.Time) uint64 {
	utc := t.UTC()
	year, month, day := utc.Date()
	hour, min, sec := utc.Clock()
	nsec := utc.Nanosecond()

	a := (14 - int(month)) / 12
	y := year + 4800 - a
	m := int(month) + 12*a - 3
	jdn := day + (153*m+2)/5 + 365*y + y/4 - y/100 + y/400 - 32045

	// MJD at midnight: JDN_noon - 2400001 (1 Jan 1970 = MJD 40587)
	mjd := uint64(jdn - 2400001)

	usInDay := uint64(hour)*3600_000_000 +
		uint64(min)*60_000_000 +
		uint64(sec)*1_000_000 +
		uint64(nsec)/1000

	return (mjd << 40) | (usInDay & 0xFFFFFFFFFF)
}

// encodeTimestamp encodes a time per the wire group's timestamp format.
func encodeTimestamp(t time.Time, g wireGroup) [8]byte {
	var buf [8]byte
	switch {
	case g == groupGoogle:
		binary.LittleEndian.PutUint64(buf[:], uint64(t.UnixMicro()))
	case usesMJDMicroseconds(g):
		binary.LittleEndian.PutUint64(buf[:], timeToMJDMicro(t))
	default:
		binary.LittleEndian.PutUint64(buf[:], uint64(t.Unix()))
	}
	return buf
}

// radiMicroseconds encodes a RADI value in µs, clamped to [1, MaxUint32].
func radiMicroseconds(d time.Duration) uint32 {
	return uint32(min(max(d.Microseconds(), 1), math.MaxUint32))
}

// radiSeconds encodes a RADI value in seconds with a 3-second floor.
func radiSeconds(d time.Duration) uint32 {
	sec := int64(d / time.Second)
	const floor = int64(3)
	return uint32(min(max(sec, floor), math.MaxUint32))
}

// mjdMicroToTime converts an MJD-µs timestamp to a [time.Time].
func mjdMicroToTime(v uint64) (time.Time, error) {
	mjd := int64(v >> 40)
	usInDay := int64(v & 0xFFFFFFFFFF)
	if usInDay >= microsPerDay {
		return time.Time{}, fmt.Errorf("protocol: MJD sub-day µs %d >= %d (invalid)", usInDay, microsPerDay)
	}

	unixDays := mjd - 40587
	sec := unixDays*86400 + usInDay/1_000_000
	nsec := (usInDay % 1_000_000) * 1000
	return time.Unix(sec, nsec).UTC(), nil
}

// decodeTimestamp converts a wire timestamp to a [time.Time].
func decodeTimestamp(buf []byte, g wireGroup) (time.Time, error) {
	if len(buf) != 8 {
		return time.Time{}, errors.New("protocol: timestamp must be 8 bytes")
	}
	v := binary.LittleEndian.Uint64(buf)
	switch {
	case g == groupGoogle:
		if v > math.MaxInt64 {
			return time.Time{}, fmt.Errorf("protocol: Google timestamp 0x%x exceeds int64", v)
		}
		return time.UnixMicro(int64(v)).UTC(), nil
	case usesMJDMicroseconds(g):
		return mjdMicroToTime(v)
	default:
		if v > math.MaxInt64 {
			return time.Time{}, fmt.Errorf("protocol: timestamp 0x%x exceeds int64", v)
		}
		return time.Unix(int64(v), 0).UTC(), nil
	}
}

// decodeRadius converts a wire RADI value to a [time.Duration].
func decodeRadius(buf []byte, g wireGroup) (time.Duration, error) {
	if len(buf) != 4 {
		return 0, errors.New("protocol: RADI must be 4 bytes")
	}
	v := binary.LittleEndian.Uint32(buf)
	if g == groupGoogle || usesMJDMicroseconds(g) {
		return time.Duration(v) * time.Microsecond, nil
	}
	return time.Duration(v) * time.Second, nil
}

// DecodeTimestamp decodes an 8-byte wire timestamp per ver's encoding rules.
func DecodeTimestamp(ver Version, buf []byte) (time.Time, error) {
	return decodeTimestamp(buf, wireGroupOf(ver, false))
}
