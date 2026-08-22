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

// microsPerPositiveLeapDay is the exclusive upper bound for the sub-day field
// on a UTC day containing a positive leap second. The old MJD format cannot be
// validated more precisely without an external leap-second table.
const microsPerPositiveLeapDay int64 = 86_401 * 1_000_000

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

// validateTimestampEncoding rejects values that cannot round-trip through a
// wire group's unsigned timestamp representation.
func validateTimestampEncoding(t time.Time, g wireGroup) error {
	sec := t.Unix()
	switch {
	case g == groupGoogle:
		if sec < 0 || sec > math.MaxInt64/1_000_000 ||
			(sec == math.MaxInt64/1_000_000 && int64(t.Nanosecond()/1_000) > math.MaxInt64%1_000_000) {
			return errors.New("protocol: timestamp outside Google microsecond range")
		}
	case usesMJDMicroseconds(g):
		v := timeToMJDMicro(t)
		// Detect a negative/pre-MJD time or overflow of the 24-bit day field by
		// round-tripping the encoding.
		decoded, err := mjdMicroToTime(v)
		if err != nil || !decoded.Equal(t.Truncate(time.Microsecond)) {
			return errors.New("protocol: timestamp outside 24-bit MJD microsecond range")
		}
	default:
		if sec < 0 {
			return errors.New("protocol: timestamp precedes Unix epoch")
		}
	}
	return nil
}

// radiMicroseconds encodes RADI in µs, rounding up with a one-microsecond
// floor.
func radiMicroseconds(d time.Duration) (uint32, error) {
	units := ceilDurationUnits(d, time.Microsecond)
	units = max(units, 1)
	if units > math.MaxUint32 {
		return 0, errors.New("protocol: radius exceeds 32-bit microsecond range")
	}
	return uint32(units), nil
}

// radiSeconds encodes RADI in seconds, rounding up with a three-second floor.
func radiSeconds(d time.Duration) (uint32, error) {
	units := ceilDurationUnits(d, time.Second)
	units = max(units, 3)
	if units > math.MaxUint32 {
		return 0, errors.New("protocol: radius exceeds 32-bit second range")
	}
	return uint32(units), nil
}

// ceilDurationUnits rounds a positive duration up to whole units.
func ceilDurationUnits(d, unit time.Duration) uint64 {
	if d <= 0 {
		return 0
	}
	units := uint64(d / unit)
	if d%unit != 0 {
		units++
	}
	return units
}

// encodeRadius applies the wire group's RADI unit and floor.
func encodeRadius(d time.Duration, g wireGroup) (uint32, error) {
	if g == groupGoogle || usesMJDMicroseconds(g) {
		return radiMicroseconds(d)
	}
	return radiSeconds(d)
}

// mjdMicroToTime converts an MJD-µs timestamp to a [time.Time].
func mjdMicroToTime(v uint64) (time.Time, error) {
	mjd := int64(v >> 40)
	usInDay := int64(v & 0xFFFFFFFFFF)
	if usInDay >= microsPerPositiveLeapDay {
		return time.Time{}, fmt.Errorf("protocol: MJD sub-day µs %d >= %d (invalid)", usInDay, microsPerPositiveLeapDay)
	}

	// time.Time cannot represent second 60. Normalize a positive-leap-second
	// field into the first second of the following nominal Unix day while
	// preserving its fractional microseconds.
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
	if !isRecognizedVersion(ver) {
		return time.Time{}, fmt.Errorf("protocol: unsupported timestamp version %s", ver)
	}
	return decodeTimestamp(buf, wireGroupOf(ver, false))
}
