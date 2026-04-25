// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

// Package protocol implements the Roughtime wire protocol for Google-Roughtime
// and IETF drafts 01-19, plus an experimental ML-DSA-44 post-quantum variant
// ([VersionMLDSA44]); see README.md for the PQ caveats.
//
// Drafts 12-19 share wire version 0x8000000c, disambiguated by [TagTYPE] (draft
// 14+). Multi-request batches to draft 14-15 peers are not strictly conformant
// (node-first vs hash-first Merkle ordering); single-request replies are
// unaffected.
package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	mrand "math/rand/v2"
	"slices"
	"sync"
	"time"

	"filippo.io/mldsa"
)

// Version is a Roughtime protocol version number. The zero value represents
// Google-Roughtime (no VER tag on the wire).
type Version uint32

const (
	VersionGoogle  Version = 0          // Google-Roughtime (no VER tag)
	VersionDraft01 Version = 0x80000001 // draft-ietf-ntp-roughtime-01
	VersionDraft02 Version = 0x80000002 // draft-ietf-ntp-roughtime-02
	VersionDraft03 Version = 0x80000003 // draft-ietf-ntp-roughtime-03
	VersionDraft04 Version = 0x80000004 // draft-ietf-ntp-roughtime-04
	VersionDraft05 Version = 0x80000005 // draft-ietf-ntp-roughtime-05
	VersionDraft06 Version = 0x80000006 // draft-ietf-ntp-roughtime-06
	VersionDraft07 Version = 0x80000007 // draft-ietf-ntp-roughtime-07
	VersionDraft08 Version = 0x80000008 // draft-ietf-ntp-roughtime-08
	VersionDraft09 Version = 0x80000009 // draft-ietf-ntp-roughtime-09
	VersionDraft10 Version = 0x8000000a // draft-ietf-ntp-roughtime-10
	VersionDraft11 Version = 0x8000000b // draft-ietf-ntp-roughtime-11
	VersionDraft12 Version = 0x8000000c // drafts 12-19

	// VersionMLDSA44 is an experimental post-quantum wire version that signs
	// with ML-DSA-44 (FIPS 204) over TCP only. See README.md.
	VersionMLDSA44 Version = 0x90000001
)

// String returns the IETF draft name or a hex representation for unknown
// values. Drafts 12-19 all report draft-12.
func (v Version) String() string {
	switch v {
	case VersionGoogle:
		return "Google-Roughtime"
	case VersionDraft01:
		return "draft-ietf-ntp-roughtime-01"
	case VersionDraft02:
		return "draft-ietf-ntp-roughtime-02"
	case VersionDraft03:
		return "draft-ietf-ntp-roughtime-03"
	case VersionDraft04:
		return "draft-ietf-ntp-roughtime-04"
	case VersionDraft05:
		return "draft-ietf-ntp-roughtime-05"
	case VersionDraft06:
		return "draft-ietf-ntp-roughtime-06"
	case VersionDraft07:
		return "draft-ietf-ntp-roughtime-07"
	case VersionDraft08:
		return "draft-ietf-ntp-roughtime-08"
	case VersionDraft09:
		return "draft-ietf-ntp-roughtime-09"
	case VersionDraft10:
		return "draft-ietf-ntp-roughtime-10"
	case VersionDraft11:
		return "draft-ietf-ntp-roughtime-11"
	case VersionDraft12:
		return "draft-ietf-ntp-roughtime-12"
	case VersionMLDSA44:
		return "roughtime-ml-dsa-44"
	default:
		return fmt.Sprintf("Version(0x%08x)", uint32(v))
	}
}

// ShortString returns a compact version label (e.g. "Google", "draft-08").
func (v Version) ShortString() string {
	switch v {
	case VersionGoogle:
		return "Google"
	case VersionDraft12:
		return "draft-12"
	case VersionMLDSA44:
		return "ml-dsa-44"
	default:
		if v > VersionGoogle && v <= VersionDraft12 {
			return fmt.Sprintf("draft-%02d", uint32(v)-0x80000000)
		}
		return fmt.Sprintf("0x%08x", uint32(v))
	}
}

// ParseShortVersion is the inverse of [Version.ShortString] over [Supported].
func ParseShortVersion(s string) (Version, error) {
	for _, v := range Supported() {
		if v.ShortString() == s {
			return v, nil
		}
	}
	return 0, fmt.Errorf("protocol: unknown version %q", s)
}

// wireGroup identifies a set of drafts that share on-wire behaviour.
type wireGroup int

const (
	groupGoogle wireGroup = iota // Google-Roughtime (no header, no VER)
	groupD01                     // draft 01 (SHA-512, NONC in SREP, 64B nonce)
	groupD02                     // draft 02 (SHA-512/256, NONC in SREP, 64B nonce)
	groupD03                     // drafts 03-04 (NONC top-level, 64B nonce)
	groupD05                     // drafts 05-06 (32B nonce, MJD-µs)
	groupD07                     // draft 07 (SHA-512/256, delegation ctx no hyphens)
	groupD08                     // drafts 08-09 (Unix seconds, ZZZZ padding)
	groupD10                     // drafts 10-11 (RADI ≥ 3, SRV tag)
	groupD12                     // drafts 12-13; fallback for 14-19 without TYPE
	groupD14                     // drafts 14-19 with TYPE
	groupPQ                      // ML-DSA-44 over TCP, draft-14-style wire
)

// wireGroupOf returns the wire group for a version and TYPE presence.
func wireGroupOf(v Version, hasType bool) wireGroup {
	switch {
	case v == VersionGoogle:
		return groupGoogle
	case v == VersionMLDSA44:
		return groupPQ
	case v == VersionDraft01:
		return groupD01
	case v == VersionDraft02:
		return groupD02
	case v <= VersionDraft04:
		return groupD03
	case v <= VersionDraft06:
		return groupD05
	case v == VersionDraft07:
		return groupD07
	case v <= VersionDraft09:
		return groupD08
	case v <= VersionDraft11:
		return groupD10
	default:
		if hasType {
			return groupD14
		}
		return groupD12
	}
}

// Tag constants from the IANA Roughtime tag registry.
const (
	TagSIG  uint32 = 0x00474953 // SIG\0
	TagVER  uint32 = 0x00524556 // VER\0
	TagSRV  uint32 = 0x00565253 // SRV\0
	TagNONC uint32 = 0x434e4f4e // NONC
	TagDELE uint32 = 0x454c4544 // DELE
	TagTYPE uint32 = 0x45505954 // TYPE
	TagPATH uint32 = 0x48544150 // PATH
	TagRADI uint32 = 0x49444152 // RADI
	TagPUBK uint32 = 0x4b425550 // PUBK
	TagMIDP uint32 = 0x5044494d // MIDP
	TagSREP uint32 = 0x50455253 // SREP
	TagVERS uint32 = 0x53524556 // VERS
	TagROOT uint32 = 0x544f4f52 // ROOT
	TagCERT uint32 = 0x54524543 // CERT
	TagMINT uint32 = 0x544e494d // MINT
	TagMAXT uint32 = 0x5458414d // MAXT
	TagINDX uint32 = 0x58444e49 // INDX
	// TagZZZZ uses the drafts 10+ value universally (drafts 08-09 registered
	// 0x7a7a7a7a).
	TagZZZZ uint32 = 0x5a5a5a5a // ZZZZ client padding (drafts 08+)
	TagPAD  uint32 = 0xff444150 // PAD\xff Google-Roughtime client padding

	tagPADIETF uint32 = 0x00444150 // PAD\0 client padding (drafts 01-07)
)

// Wire-format limits.
const (
	maxMessageSize = 65535
	maxEncodeTags  = 512
	maxDecodeTags  = 512
	maxVersionList = 32
)

// packetMagic is the 8-byte prefix of the ROUGHTIM packet header.
var packetMagic = [8]byte{'R', 'O', 'U', 'G', 'H', 'T', 'I', 'M'}

// PacketHeaderSize is the length of the ROUGHTIM packet header: 8 bytes of
// magic followed by a little-endian uint32 body length.
const PacketHeaderSize = 12

// ParsePacketHeader validates the ROUGHTIM magic in hdr and returns the
// declared body length. hdr must be at least [PacketHeaderSize] bytes.
func ParsePacketHeader(hdr []byte) (bodyLen uint32, err error) {
	if len(hdr) < PacketHeaderSize {
		return 0, errors.New("protocol: header too short")
	}
	if !bytes.Equal(hdr[:8], packetMagic[:]) {
		return 0, errors.New("protocol: bad magic")
	}
	return binary.LittleEndian.Uint32(hdr[8:PacketHeaderSize]), nil
}

// hashSize returns the Merkle hash output length: 64 for Google, 32 for IETF.
func hashSize(g wireGroup) int {
	if g == groupGoogle {
		return 64
	}
	return 32
}

// usesRoughtimHeader reports whether packets use the 12-byte ROUGHTIM header.
func usesRoughtimHeader(g wireGroup) bool { return g >= groupD01 }

// usesMJDMicroseconds reports whether timestamps use MJD-µs encoding (drafts
// 01-07). Google uses Unix-µs; drafts 08+ use Unix seconds.
func usesMJDMicroseconds(g wireGroup) bool { return g >= groupD01 && g <= groupD07 }

// usesFullPacketLeaf reports whether the Merkle leaf is the full request packet
// (drafts 12+) rather than the nonce.
func usesFullPacketLeaf(g wireGroup) bool { return g >= groupD12 }

// noncInSREP reports whether NONC sits inside SREP (drafts 01-02).
func noncInSREP(g wireGroup) bool { return g == groupD01 || g == groupD02 }

// NoncInSREP reports whether ver+hasType places NONC inside SREP (drafts
// 01-02).
func NoncInSREP(ver Version, hasType bool) bool { return noncInSREP(wireGroupOf(ver, hasType)) }

// hasResponseVER reports whether the response carries a top-level VER tag
// (drafts 01-11; 12+ moved it into SREP).
func hasResponseVER(g wireGroup) bool { return g >= groupD01 && g < groupD12 }

// hasResponseNONC reports whether the response echoes NONC at top level (drafts
// 03+).
func hasResponseNONC(g wireGroup) bool { return g >= groupD03 }

// hasSREPVERS reports whether SREP carries VER and VERS (drafts 12+).
func hasSREPVERS(g wireGroup) bool { return g >= groupD12 }

// usesSHA512_256 reports whether the hash is SHA-512/256 (drafts 02 and 07);
// otherwise SHA-512 (truncated to 32 bytes for IETF, full 64 for Google).
func usesSHA512_256(g wireGroup) bool { return g == groupD02 || g == groupD07 }

// nonceSize returns the nonce length: 64 for Google and drafts 01-04, 32 for
// drafts 05+.
func nonceSize(g wireGroup) int {
	if g <= groupD03 {
		return 64
	}
	return 32
}

// Signature context strings.
var (
	delegationCtxOld = []byte("RoughTime v1 delegation signature--\x00") // Google, drafts 01-06, 08-11
	delegationCtxNew = []byte("RoughTime v1 delegation signature\x00")   // draft 07, drafts 12+
	responseCtx      = []byte("RoughTime v1 response signature\x00")     // all versions
)

// Sentinel errors from [VerifyReply] for faults grease cannot produce.
var (
	ErrMerkleMismatch   = errors.New("protocol: Merkle root mismatch")
	ErrDelegationWindow = errors.New("protocol: midpoint outside delegation window")
)

// delegationContext returns the delegation signature context. Draft 07 and
// drafts 12+ use the shorter context without trailing hyphens.
func delegationContext(g wireGroup) []byte {
	if g == groupD07 || g >= groupD12 {
		return delegationCtxNew
	}
	return delegationCtxOld
}

// timeToMJDMicro encodes a time as an MJD-µs timestamp (drafts 01-07): upper 3
// bytes are the Modified Julian Date (days since 17 Nov 1858), lower 5 bytes
// are µs since midnight UTC.
func timeToMJDMicro(t time.Time) uint64 {
	utc := t.UTC()
	year, month, day := utc.Date()
	hour, min, sec := utc.Clock()
	nsec := utc.Nanosecond()

	// Julian Day Number
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

// encodeTimestamp encodes a time per the wire group: Unix-µs (Google), MJD-µs
// (drafts 01-07), or Unix seconds (drafts 08+).
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

// radiMicroseconds encodes a RADI value in µs (Google, drafts 01-07), clamped
// to [1, MaxUint32].
func radiMicroseconds(d time.Duration) uint32 {
	return uint32(min(max(d.Microseconds(), 1), math.MaxUint32))
}

// radiSeconds encodes a RADI value in seconds (drafts 08+). The 3-second floor
// satisfies the drafts 10-11 minimum and the drafts 12+ nonzero rule.
func radiSeconds(d time.Duration) uint32 {
	sec := int64(d / time.Second)
	const floor = int64(3)
	return uint32(min(max(sec, floor), math.MaxUint32))
}

// microsPerDay is µs in a UTC day (Roughtime defines MJD in TAI-equivalent
// µs-of-day, no leap seconds).
const microsPerDay int64 = 86_400 * 1_000_000

// mjdMicroToTime converts an MJD-µs timestamp to a [time.Time]. The sub-day µs
// field must be < microsPerDay; the 40-bit mask alone admits ~12.7 days and
// would silently re-map onto a later MJD.
func mjdMicroToTime(v uint64) (time.Time, error) {
	mjd := int64(v >> 40)
	usInDay := int64(v & 0xFFFFFFFFFF)
	if usInDay >= microsPerDay {
		return time.Time{}, fmt.Errorf("protocol: MJD sub-day µs %d >= %d (invalid)", usInDay, microsPerDay)
	}

	// MJD 40587 = 1 Jan 1970
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

// Hasher pools: SHA-512/256 for drafts 02 and 07, SHA-512 otherwise.
var (
	sha512Pool     = sync.Pool{New: func() any { return sha512.New() }}
	sha512_256Pool = sync.Pool{New: func() any { return sha512.New512_256() }}
)

// getHasher returns a reset hasher for g; pair with putHasher.
func getHasher(g wireGroup) hash.Hash {
	var h hash.Hash
	if usesSHA512_256(g) {
		h = sha512_256Pool.Get().(hash.Hash)
	} else {
		h = sha512Pool.Get().(hash.Hash)
	}
	h.Reset()
	return h
}

// putHasher returns h to its pool; caller must not touch h after.
func putHasher(g wireGroup, h hash.Hash) {
	if usesSHA512_256(g) {
		sha512_256Pool.Put(h)
	} else {
		sha512Pool.Put(h)
	}
}

// leafHash computes H(0x00 || data) truncated to the wire group's hash size.
func leafHash(g wireGroup, data []byte) []byte {
	h := getHasher(g)
	defer putHasher(g, h)
	_, _ = h.Write([]byte{0x00})
	_, _ = h.Write(data)
	return h.Sum(nil)[:hashSize(g)]
}

// nodeHash computes H(0x01 || left || right) truncated to the wire group's hash
// size.
func nodeHash(g wireGroup, left, right []byte) []byte {
	h := getHasher(g)
	defer putHasher(g, h)
	_, _ = h.Write([]byte{0x01})
	_, _ = h.Write(left)
	_, _ = h.Write(right)
	return h.Sum(nil)[:hashSize(g)]
}

// encode serializes a tag-value map. Values must be 4-byte aligned; tags are
// emitted in ascending order.
func encode(msg map[uint32][]byte) ([]byte, error) {
	return encodeTo(msg, 0)
}

// encodeTo is [encode] with `prefix` reserved zero bytes at the start of the
// returned slice so [encodeWrapped] can pack the header in one allocation.
func encodeTo(msg map[uint32][]byte, prefix int) ([]byte, error) {
	if len(msg) == 0 {
		return nil, errors.New("protocol: empty message")
	}
	if len(msg) > maxEncodeTags {
		return nil, errors.New("protocol: tag count exceeds limit")
	}
	tags := make([]uint32, 0, len(msg))
	for t := range msg {
		tags = append(tags, t)
	}
	slices.Sort(tags)

	n := uint32(len(tags))
	headerLen := 4 + 4*(n-1) + 4*n // tag count + (n-1) offsets + n tags
	var valsLen uint32
	for _, v := range msg {
		if len(v)%4 != 0 {
			return nil, fmt.Errorf("protocol: value length %d not multiple of 4", len(v))
		}
		next := valsLen + uint32(len(v))
		if next < valsLen {
			return nil, errors.New("protocol: total value size overflow")
		}
		valsLen = next
	}

	totalLen := uint64(headerLen) + uint64(valsLen)
	if totalLen > math.MaxInt-uint64(prefix) {
		return nil, errors.New("protocol: message too large")
	}

	out := make([]byte, uint64(prefix)+totalLen)
	body := out[prefix:]
	binary.LittleEndian.PutUint32(body[0:4], n)

	off := uint32(0)
	for i := uint32(1); i < n; i++ {
		off += uint32(len(msg[tags[i-1]]))
		binary.LittleEndian.PutUint32(body[4+4*(i-1):4+4*i], off)
	}

	tBase := 4 + 4*(n-1) // start of tag section
	for i, t := range tags {
		binary.LittleEndian.PutUint32(body[tBase+uint32(4*i):tBase+uint32(4*i)+4], t)
	}

	pos := headerLen
	for _, t := range tags {
		copy(body[pos:], msg[t])
		pos += uint32(len(msg[t]))
	}
	return out, nil
}

// encodeWrapped encodes msg and prepends the ROUGHTIM header in one allocation.
func encodeWrapped(msg map[uint32][]byte) ([]byte, error) {
	out, err := encodeTo(msg, 12)
	if err != nil {
		return nil, err
	}
	copy(out[0:8], packetMagic[:])
	binary.LittleEndian.PutUint32(out[8:12], uint32(len(out)-12))
	return out, nil
}

// Decode parses a Roughtime message into a tag-value map. Returned slices alias
// data.
func Decode(data []byte) (map[uint32][]byte, error) {
	if len(data) < 4 {
		return nil, errors.New("protocol: message too short")
	}
	if len(data) > maxMessageSize {
		return nil, fmt.Errorf("protocol: message exceeds %d bytes", maxMessageSize)
	}
	if len(data)%4 != 0 {
		return nil, errors.New("protocol: message length not a multiple of 4")
	}
	n := binary.LittleEndian.Uint32(data[0:4])
	if n == 0 {
		if len(data) != 4 {
			return nil, errors.New("protocol: trailing data after zero-tag message")
		}
		return map[uint32][]byte{}, nil
	}
	if n > maxDecodeTags {
		return nil, errors.New("protocol: tag count exceeds limit")
	}

	headerLen := 4 + 4*(n-1) + 4*n // tag count + (n-1) offsets + n tags
	if uint32(len(data)) < headerLen {
		return nil, errors.New("protocol: header truncated")
	}

	offsets := make([]uint32, n)
	for i := uint32(1); i < n; i++ {
		offsets[i] = binary.LittleEndian.Uint32(data[4+4*(i-1) : 4+4*i])
	}
	tBase := 4 + 4*(n-1) // start of tag section
	tags := make([]uint32, n)
	for i := range n {
		tags[i] = binary.LittleEndian.Uint32(data[tBase+4*i : tBase+4*i+4])
	}
	if err := validateHeader(tags, offsets, n); err != nil {
		return nil, err
	}

	return decodeValues(data, tags, offsets, headerLen)
}

// validateHeader checks tags are strictly ascending and offsets are aligned and
// monotonic.
func validateHeader(tags, offsets []uint32, n uint32) error {
	for i := uint32(1); i < n; i++ {
		if tags[i] <= tags[i-1] {
			return errors.New("protocol: tags not strictly ascending")
		}
		if offsets[i]%4 != 0 || offsets[i] < offsets[i-1] {
			return errors.New("protocol: bad offset")
		}
	}
	return nil
}

// decodeValues extracts tag values from the data section.
func decodeValues(data []byte, tags, offsets []uint32, headerLen uint32) (map[uint32][]byte, error) {
	totalVal := uint32(len(data)) - headerLen
	n := uint32(len(tags))
	msg := make(map[uint32][]byte, n)
	for i := range n {
		start := offsets[i]
		end := totalVal
		if i+1 < n {
			end = offsets[i+1]
		}
		if start > totalVal || end > totalVal || start > end {
			return nil, errors.New("protocol: value out of bounds")
		}
		msg[tags[i]] = data[headerLen+start : headerLen+end]
	}
	return msg, nil
}

// unwrapPacket validates and strips the 12-byte ROUGHTIM header.
func unwrapPacket(pkt []byte) ([]byte, error) {
	if len(pkt) < 12 {
		return nil, errors.New("protocol: packet too short")
	}
	if !bytes.Equal(pkt[:8], packetMagic[:]) {
		return nil, errors.New("protocol: bad magic")
	}
	mlen := binary.LittleEndian.Uint32(pkt[8:12])
	if uint32(len(pkt)-12) < mlen {
		return nil, errors.New("protocol: truncated message")
	}
	return pkt[12 : 12+mlen], nil
}

// Request holds the parsed fields of a client request. RawPacket and the
// Nonce/SRV sub-slices alias the caller's buffer; callers pooling the buffer
// must not mutate it while a Request is in use.
type Request struct {
	Nonce     []byte    // 32 bytes (drafts 05+) or 64 bytes (Google, drafts 01-04)
	Versions  []Version // from VER tag; empty for Google-Roughtime
	SRV       []byte    // nil if absent
	HasType   bool      // request had TYPE=0 (drafts 14+)
	RawPacket []byte    // full framed packet for Merkle leaf (drafts 12+)
}

// ParseRequest auto-detects Google vs IETF framing and extracts request fields.
// Nonce and SRV alias raw.
func ParseRequest(raw []byte) (*Request, error) {
	framed := len(raw) >= 12 && bytes.Equal(raw[:8], packetMagic[:])
	req := &Request{RawPacket: raw}

	msgBytes, err := unwrapRequest(raw)
	if err != nil {
		return nil, err
	}

	msg, err := Decode(msgBytes)
	if err != nil {
		return nil, fmt.Errorf("protocol: decode request: %w", err)
	}

	nonce, ok := msg[TagNONC]
	if !ok {
		return nil, errors.New("protocol: missing NONC")
	}
	if len(nonce) != 32 && len(nonce) != 64 {
		return nil, fmt.Errorf("protocol: bad nonce length %d", len(nonce))
	}
	req.Nonce = nonce
	if err := parseOptionalTags(req, msg); err != nil {
		return nil, err
	}

	// framed packets must carry VER, else a malformed framed request could pass
	// as Google
	if framed && len(req.Versions) == 0 {
		return nil, errors.New("protocol: framed request missing VER tag")
	}
	if !framed && len(req.Versions) > 0 {
		return nil, errors.New("protocol: unframed request contains VER tag")
	}
	// VersionGoogle is signalled by VER absence
	if slices.Contains(req.Versions, VersionGoogle) {
		return nil, errors.New("protocol: VER list contains VersionGoogle (0)")
	}

	maxVer := VersionGoogle
	for _, v := range req.Versions {
		if v > maxVer {
			maxVer = v
		}
	}
	maxGroup := wireGroupOf(maxVer, false)

	// drafts 10-11 forbid duplicates; drafts 12+ require strictly ascending
	if maxGroup >= groupD12 {
		for i := 1; i < len(req.Versions); i++ {
			if req.Versions[i] <= req.Versions[i-1] {
				return nil, errors.New("protocol: VER list not strictly ascending")
			}
		}
	} else if maxGroup >= groupD10 {
		seen := make(map[Version]struct{}, len(req.Versions))
		for _, v := range req.Versions {
			if _, dup := seen[v]; dup {
				return nil, errors.New("protocol: VER list contains duplicates")
			}
			seen[v] = struct{}{}
		}
	}

	// mixed-version VER lists can span both nonce sizes (64 for Google/01-04,
	// 32 for 05+); accept if the nonce matches any offered version
	nonceOK := false
	if len(req.Versions) == 0 {
		nonceOK = len(req.Nonce) == nonceSize(groupGoogle)
	} else {
		for _, v := range req.Versions {
			if len(req.Nonce) == nonceSize(wireGroupOf(v, false)) {
				nonceOK = true
				break
			}
		}
	}
	if !nonceOK {
		return nil, fmt.Errorf("protocol: nonce length %d matches no offered version", len(req.Nonce))
	}

	// drafts 10+ require SRV to be exactly 32 bytes
	if req.SRV != nil && maxGroup >= groupD10 && len(req.SRV) != 32 {
		return nil, fmt.Errorf("protocol: SRV length %d invalid for drafts 10+ (want 32)", len(req.SRV))
	}

	// drafts 12+ MUST zero ZZZZ; drafts 01-11 only SHOULD, so non-zero padding
	// is tolerated there for interop
	if maxGroup >= groupD12 {
		if pad, ok := msg[TagZZZZ]; ok {
			for _, b := range pad {
				if b != 0 {
					return nil, errors.New("protocol: ZZZZ padding contains non-zero byte")
				}
			}
		}
	}

	return req, nil
}

// unwrapRequest strips the ROUGHTIM header if present, else returns raw.
func unwrapRequest(raw []byte) ([]byte, error) {
	if len(raw) >= 12 && bytes.Equal(raw[:8], packetMagic[:]) {
		return unwrapPacket(raw)
	}
	return raw, nil
}

// parseOptionalTags extracts VER, SRV, and TYPE; per-version cross-checks
// happen in [ParseRequest].
func parseOptionalTags(req *Request, msg map[uint32][]byte) error {
	if vb, ok := msg[TagVER]; ok {
		if len(vb) == 0 || len(vb)%4 != 0 {
			return errors.New("protocol: VER tag length invalid")
		}
		count := len(vb) / 4
		if count > maxVersionList {
			return fmt.Errorf("protocol: VER tag has %d entries (max %d)", count, maxVersionList)
		}
		req.Versions = make([]Version, 0, count)
		for i := 0; i < len(vb); i += 4 {
			req.Versions = append(req.Versions, Version(binary.LittleEndian.Uint32(vb[i:i+4])))
		}
	}
	if srv, ok := msg[TagSRV]; ok {
		// sanity bounds only; per-version length is enforced in ParseRequest
		if len(srv) == 0 || len(srv) > 64 {
			return fmt.Errorf("protocol: SRV tag length %d invalid", len(srv))
		}
		req.SRV = srv
	}
	if tb, ok := msg[TagTYPE]; ok {
		if len(tb) != 4 {
			return errors.New("protocol: TYPE tag must be 4 bytes")
		}
		if v := binary.LittleEndian.Uint32(tb); v != 0 {
			return fmt.Errorf("protocol: TYPE=%d in request (must be 0)", v)
		}
		req.HasType = true
	}
	// padding zero-fill is version-gated in ParseRequest (drafts 12+ MUST)
	return nil
}

// ServerPreferenceEd25519 lists Ed25519 versions in descending negotiation
// preference.
var ServerPreferenceEd25519 = []Version{
	VersionDraft12,
	VersionDraft11, VersionDraft10,
	VersionDraft09, VersionDraft08,
	VersionDraft07, VersionDraft06,
	VersionDraft05, VersionDraft04, VersionDraft03, VersionDraft02, VersionDraft01,
	VersionGoogle,
}

// ServerPreferenceMLDSA44 is the negotiation preference list for ML-DSA-44.
var ServerPreferenceMLDSA44 = []Version{VersionMLDSA44}

// supportedVersionsEd25519 lists Ed25519 IETF versions in ascending order for
// the VERS tag in SREP (drafts 12+).
var supportedVersionsEd25519 = []Version{
	VersionDraft01, VersionDraft02, VersionDraft03, VersionDraft04,
	VersionDraft05, VersionDraft06, VersionDraft07,
	VersionDraft08, VersionDraft09,
	VersionDraft10, VersionDraft11,
	VersionDraft12,
}

// supportedVersionsMLDSA44 is the scheme-scoped VERS list for ML-DSA-44; a
// single entry binds downgrade protection to the PQ suite.
var supportedVersionsMLDSA44 = []Version{VersionMLDSA44}

// Pre-encoded VERS byte slices for direct inclusion in SREP.
var (
	supportedVersionsEd25519Bytes []byte
	supportedVersionsMLDSA44Bytes []byte
)

func init() {
	encVers := func(vs []Version) []byte {
		out := make([]byte, 4*len(vs))
		for i, v := range vs {
			binary.LittleEndian.PutUint32(out[4*i:4*i+4], uint32(v))
		}
		return out
	}
	supportedVersionsEd25519Bytes = encVers(supportedVersionsEd25519)
	supportedVersionsMLDSA44Bytes = encVers(supportedVersionsMLDSA44)
}

// Supported returns all recognized protocol versions: newest IETF first, Google
// last, then post-quantum.
func Supported() []Version {
	out := slices.Clone(supportedVersionsEd25519)
	slices.Reverse(out)
	out = append(out, VersionGoogle)
	out = append(out, supportedVersionsMLDSA44...)
	return out
}

// ComputeSRV returns the SRV tag value (drafts 10+): the first 32 bytes of
// SHA-512(0xff || rootPK). rootPK must be Ed25519 (32 bytes) or ML-DSA-44 (1312
// bytes); other lengths return nil.
func ComputeSRV(rootPK []byte) []byte {
	if len(rootPK) != ed25519.PublicKeySize && len(rootPK) != mldsa.MLDSA44PublicKeySize {
		return nil
	}
	h := sha512.New()
	_, _ = h.Write([]byte{0xff})
	_, _ = h.Write(rootPK)
	return h.Sum(nil)[:32]
}

// SelectVersion picks the best mutually supported version whose nonce size
// matches nonceLen. serverVersions is the listener's preference list
// (descending). An empty clientVersions signals a Google-Roughtime client.
func SelectVersion(clientVersions []Version, nonceLen int, serverVersions []Version) (Version, error) {
	if len(clientVersions) == 0 {
		if nonceLen == nonceSize(groupGoogle) && slices.Contains(serverVersions, VersionGoogle) {
			return VersionGoogle, nil
		}
		return 0, errors.New("protocol: no supported version")
	}
	for _, sv := range serverVersions {
		if nonceSize(wireGroupOf(sv, false)) != nonceLen {
			continue
		}
		if slices.Contains(clientVersions, sv) {
			return sv, nil
		}
	}
	return 0, errors.New("protocol: no mutually supported version")
}

// Certificate holds a pre-signed online delegation. CERT bytes are built once
// per wire group at construction and reused. Use [NewCertificate] for Ed25519
// and [NewCertificatePQ] for ML-DSA-44.
type Certificate struct {
	scheme sigScheme
	mint   time.Time
	maxt   time.Time

	// populated when scheme == schemeEd25519
	edOnlineSK ed25519.PrivateKey
	edOnlinePK ed25519.PublicKey
	edRootPK   ed25519.PublicKey

	// populated when scheme == schemeMLDSA44
	pqOnlineSK *mldsa.PrivateKey
	pqOnlinePK *mldsa.PublicKey
	pqRootPK   *mldsa.PublicKey

	cache map[certCacheKey][]byte
}

// certCacheKey identifies a unique CERT encoding; wire groups with matching
// delegation context and timestamp encoding share an entry.
type certCacheKey struct {
	ctx   string // delegation signature context
	micro bool   // µs timestamps (Google or MJD)
	mjd   bool   // MJD encoding (else Unix)
}

// NewCertificate creates and signs an Ed25519 delegation certificate for every
// Ed25519 wire group.
func NewCertificate(mint, maxt time.Time, onlineSK, rootSK ed25519.PrivateKey) (*Certificate, error) {
	if len(onlineSK) != ed25519.PrivateKeySize || len(rootSK) != ed25519.PrivateKeySize {
		return nil, errors.New("protocol: invalid key size")
	}
	if !mint.Before(maxt) {
		return nil, errors.New("protocol: MINT must be before MAXT")
	}
	c := &Certificate{
		scheme:     schemeEd25519,
		mint:       mint,
		maxt:       maxt,
		edOnlineSK: onlineSK,
		edOnlinePK: onlineSK.Public().(ed25519.PublicKey),
		edRootPK:   rootSK.Public().(ed25519.PublicKey),
		cache:      make(map[certCacheKey][]byte),
	}
	for _, v := range ServerPreferenceEd25519 {
		g := wireGroupOf(v, false)
		k := c.cacheKeyFor(g)
		if _, ok := c.cache[k]; ok {
			continue
		}
		b, err := c.buildCERT(g, rootSK, nil)
		if err != nil {
			return nil, err
		}
		c.cache[k] = b
	}
	return c, nil
}

// NewCertificatePQ creates and signs an ML-DSA-44 delegation certificate. The
// PQ suite uses a single wire group, so the cache has one entry.
func NewCertificatePQ(mint, maxt time.Time, onlineSK, rootSK *mldsa.PrivateKey) (*Certificate, error) {
	if onlineSK == nil || rootSK == nil {
		return nil, errors.New("protocol: nil ML-DSA key")
	}
	if !mint.Before(maxt) {
		return nil, errors.New("protocol: MINT must be before MAXT")
	}
	c := &Certificate{
		scheme:     schemeMLDSA44,
		mint:       mint,
		maxt:       maxt,
		pqOnlineSK: onlineSK,
		pqOnlinePK: onlineSK.PublicKey(),
		pqRootPK:   rootSK.PublicKey(),
		cache:      make(map[certCacheKey][]byte),
	}
	g := wireGroupOf(VersionMLDSA44, true)
	b, err := c.buildCERT(g, nil, rootSK)
	if err != nil {
		return nil, err
	}
	c.cache[c.cacheKeyFor(g)] = b
	return c, nil
}

// Wipe releases the online signing key; callers must ensure no signing is in
// flight. Ed25519 is zeroed in place; ML-DSA-44 drops the reference (the
// library exposes no zeroizer).
func (c *Certificate) Wipe() {
	if c == nil {
		return
	}
	switch c.scheme {
	case schemeEd25519:
		clear(c.edOnlineSK)
	case schemeMLDSA44:
		c.pqOnlineSK = nil
	}
}

// cacheKeyFor returns the cache key for g's CERT encoding.
func (c *Certificate) cacheKeyFor(g wireGroup) certCacheKey {
	ctx := string(delegationContext(g))
	switch {
	case g == groupGoogle:
		return certCacheKey{ctx: ctx, micro: true, mjd: false}
	case g <= groupD07:
		return certCacheKey{ctx: ctx, micro: true, mjd: true}
	default:
		return certCacheKey{ctx: ctx, micro: false, mjd: false}
	}
}

// certBytes returns the pre-built CERT for g; panics on cache miss (would
// indicate a bug in the pre-compute loop).
func (c *Certificate) certBytes(g wireGroup) []byte {
	b, ok := c.cache[c.cacheKeyFor(g)]
	if !ok {
		panic(fmt.Sprintf("protocol: certificate cache miss for wire group %d", g))
	}
	return b
}

// onlinePublicKey returns the online delegation key in on-wire form.
func (c *Certificate) onlinePublicKey() []byte {
	if c.scheme == schemeMLDSA44 {
		return c.pqOnlinePK.Bytes()
	}
	return []byte(c.edOnlinePK)
}

// buildCERT constructs the CERT message for g; exactly one of edRootSK /
// pqRootSK must be non-nil, matching c.scheme.
func (c *Certificate) buildCERT(g wireGroup, edRootSK ed25519.PrivateKey, pqRootSK *mldsa.PrivateKey) ([]byte, error) {
	mintBuf := encodeTimestamp(c.mint, g)
	maxtBuf := encodeTimestamp(c.maxt, g)

	dele, err := encode(map[uint32][]byte{
		TagPUBK: c.onlinePublicKey(),
		TagMINT: mintBuf[:],
		TagMAXT: maxtBuf[:],
	})
	if err != nil {
		return nil, err
	}

	ctx := delegationContext(g)
	var sig []byte
	switch c.scheme {
	case schemeEd25519:
		sig = signEd25519(edRootSK, dele, ctx)
	case schemeMLDSA44:
		sig, err = signMLDSA44(pqRootSK, dele, ctx)
		if err != nil {
			return nil, fmt.Errorf("protocol: ML-DSA-44 sign DELE: %w", err)
		}
	default:
		return nil, errSchemeNotSupported
	}

	return encode(map[uint32][]byte{TagSIG: sig, TagDELE: dele})
}

// merkleTree holds the pre-computed root and per-leaf paths for a batch of
// requests. The tree is built in a single bottom-up pass at construction time.
type merkleTree struct {
	rootHash []byte     // root of the Merkle tree
	paths    [][][]byte // paths[i] = sibling hashes from leaf i to root
}

// merkleNodeFirst reports whether node precedes hash when INDX bit is 0. Drafts
// 05-13 use node-first; 14+ switched to hash-first (groupD14 follows draft-19).
func merkleNodeFirst(g wireGroup) bool {
	return g >= groupD05 && g <= groupD12
}

// maxMerkleLeaves caps batch size at 2^32 (32-deep tree).
const maxMerkleLeaves = 1 << 32

// newMerkleTree builds the tree and per-leaf paths in one bottom-up pass;
// panics if len(leafInputs) > [maxMerkleLeaves].
func newMerkleTree(g wireGroup, leafInputs [][]byte) *merkleTree {
	n := len(leafInputs)
	hs := hashSize(g)

	if uint64(n) > maxMerkleLeaves {
		panic(fmt.Sprintf("protocol: Merkle tree with %d leaves exceeds 2^32 (PATH > 32 hash values)", n))
	}
	if n == 0 {
		return &merkleTree{rootHash: make([]byte, hs)}
	}

	hashes := make([][]byte, n)
	for i, d := range leafInputs {
		hashes[i] = leafHash(g, d)
	}

	if n == 1 {
		return &merkleTree{rootHash: hashes[0], paths: make([][][]byte, 1)}
	}

	// pad to next power of two by repeating the last hash
	size := 1
	for size < n {
		size *= 2
	}
	level := make([][]byte, size)
	copy(level, hashes)
	for i := n; i < size; i++ {
		level[i] = hashes[n-1]
	}

	indices := make([]int, n)
	paths := make([][][]byte, n)
	for i := range indices {
		indices[i] = i
	}

	for len(level) > 1 {
		for i := range n {
			sib := indices[i] ^ 1
			paths[i] = append(paths[i], level[sib])
			indices[i] /= 2
		}
		// drafts 05-13 use node-first for bit=0; swap argument order to match
		// verification
		next := make([][]byte, len(level)/2)
		for j := 0; j < len(level); j += 2 {
			if merkleNodeFirst(g) {
				next[j/2] = nodeHash(g, level[j+1], level[j])
			} else {
				next[j/2] = nodeHash(g, level[j], level[j+1])
			}
		}
		level = next
	}

	return &merkleTree{rootHash: level[0], paths: paths}
}

// CreateReplies builds signed responses for a batch of requests. A zero
// midpoint is captured just before signing.
func CreateReplies(ver Version, requests []Request, midpoint time.Time, radius time.Duration, cert *Certificate) ([][]byte, error) {
	if len(requests) == 0 {
		return nil, errors.New("protocol: no requests")
	}
	if uint64(len(requests)) > maxMerkleLeaves {
		return nil, fmt.Errorf("protocol: batch size %d exceeds Merkle cap 2^32", len(requests))
	}

	g := wireGroupOf(ver, requests[0].HasType)

	// all requests must share a wire group and have the right nonce size
	ns := nonceSize(g)
	for i := range requests {
		if i > 0 && wireGroupOf(ver, requests[i].HasType) != g {
			return nil, errors.New("protocol: batch contains requests with incompatible wire groups")
		}
		if len(requests[i].Nonce) != ns {
			return nil, fmt.Errorf("protocol: request %d nonce is %d bytes, want %d", i, len(requests[i].Nonce), ns)
		}
	}

	// drafts 01-02 put NONC inside SREP, so only one request per batch
	if noncInSREP(g) && len(requests) > 1 {
		return nil, errors.New("protocol: drafts 01–02 do not support batched responses")
	}

	leafData := make([][]byte, len(requests))
	for i := range requests {
		if usesFullPacketLeaf(g) {
			leafData[i] = requests[i].RawPacket
		} else {
			leafData[i] = requests[i].Nonce
		}
	}
	tree := newMerkleTree(g, leafData)

	if midpoint.IsZero() {
		midpoint = time.Now()
	}

	if schemeOfGroup(g) != cert.scheme {
		return nil, fmt.Errorf("protocol: version %s requires %s cert, have %s",
			ver, schemeOfGroup(g), cert.scheme)
	}

	srepBytes, err := buildSREP(ver, g, requests, midpoint, radius, tree.rootHash)
	if err != nil {
		return nil, err
	}

	var srepSig []byte
	switch cert.scheme {
	case schemeEd25519:
		srepSig = signEd25519(cert.edOnlineSK, srepBytes, responseCtx)
	case schemeMLDSA44:
		srepSig, err = signMLDSA44(cert.pqOnlineSK, srepBytes, responseCtx)
		if err != nil {
			return nil, fmt.Errorf("protocol: ML-DSA-44 sign SREP: %w", err)
		}
	default:
		return nil, errSchemeNotSupported
	}

	certBytes := cert.certBytes(g)

	replies := make([][]byte, len(requests))
	for i := range requests {
		reply, err := buildReply(ver, g, requests[i], i, tree, srepSig, srepBytes, certBytes)
		if err != nil {
			return nil, err
		}
		replies[i] = reply
	}
	return replies, nil
}

// buildSREP constructs the signed response (MIDP, RADI, ROOT, and version
// tags).
func buildSREP(ver Version, g wireGroup, requests []Request, midpoint time.Time, radius time.Duration, rootHash []byte) ([]byte, error) {
	midpBuf := encodeTimestamp(midpoint, g)
	var radiBuf [4]byte
	if g == groupGoogle || usesMJDMicroseconds(g) {
		binary.LittleEndian.PutUint32(radiBuf[:], radiMicroseconds(radius))
	} else {
		binary.LittleEndian.PutUint32(radiBuf[:], radiSeconds(radius))
	}

	srepTags := map[uint32][]byte{
		TagRADI: radiBuf[:],
		TagMIDP: midpBuf[:],
		TagROOT: rootHash,
	}
	// drafts 01-02: NONC is inside SREP; CreateReplies rejects batches here
	if noncInSREP(g) {
		if len(requests) != 1 {
			return nil, fmt.Errorf("protocol: NONC-in-SREP group requires single-request batch, got %d", len(requests))
		}
		srepTags[TagNONC] = requests[0].Nonce
	}
	if hasSREPVERS(g) {
		var vBuf [4]byte
		binary.LittleEndian.PutUint32(vBuf[:], uint32(ver))
		srepTags[TagVER] = vBuf[:]
		srepTags[TagVERS] = suiteSupportedVersionsBytes(schemeOfGroup(g))
	}

	b, err := encode(srepTags)
	if err != nil {
		return nil, fmt.Errorf("protocol: encode SREP: %w", err)
	}
	return b, nil
}

// buildReply constructs a single response message for request i.
func buildReply(ver Version, g wireGroup, req Request, i int, tree *merkleTree, srepSig, srepBytes, certBytes []byte) ([]byte, error) {
	hs := hashSize(g)
	p := tree.paths[i]
	pathBytes := make([]byte, hs*len(p))
	for j, h := range p {
		copy(pathBytes[j*hs:], h)
	}

	var indxBuf [4]byte
	binary.LittleEndian.PutUint32(indxBuf[:], uint32(i))

	resp := map[uint32][]byte{
		TagSIG:  srepSig,
		TagSREP: srepBytes,
		TagCERT: certBytes,
		TagPATH: pathBytes,
		TagINDX: indxBuf[:],
	}
	if hasResponseVER(g) {
		var vBuf [4]byte
		binary.LittleEndian.PutUint32(vBuf[:], uint32(ver))
		resp[TagVER] = vBuf[:]
	}
	if hasResponseNONC(g) {
		resp[TagNONC] = req.Nonce
	}
	if g >= groupD14 {
		var tBuf [4]byte
		binary.LittleEndian.PutUint32(tBuf[:], 1)
		resp[TagTYPE] = tBuf[:]
	}

	var replyMsg []byte
	var err error
	if usesRoughtimHeader(g) {
		replyMsg, err = encodeWrapped(resp)
	} else {
		replyMsg, err = encode(resp)
	}
	if err != nil {
		return nil, fmt.Errorf("protocol: encode reply %d: %w", i, err)
	}
	return replyMsg, nil
}

// clientVersionPreference returns the highest version and its wire group.
func clientVersionPreference(versions []Version) (Version, wireGroup, error) {
	if len(versions) == 0 {
		return 0, 0, errors.New("protocol: empty version list")
	}
	best := slices.Max(versions)
	// hasType=true selects groupD14 for drafts 12+; wireGroupOf ignores it for
	// pre-draft-12
	return best, wireGroupOf(best, true), nil
}

// CreateRequest builds a Roughtime request; the returned nonce is needed to
// verify the reply. srv (optional) is the SRV tag from [ComputeSRV] for drafts
// 10+.
func CreateRequest(versions []Version, entropy io.Reader, srv []byte) (nonce, request []byte, err error) {
	_, g, err := clientVersionPreference(versions)
	if err != nil {
		return nil, nil, err
	}

	ns := nonceSize(g)
	nonce = make([]byte, ns)
	if _, err := io.ReadFull(entropy, nonce); err != nil {
		return nil, nil, fmt.Errorf("protocol: read entropy: %w", err)
	}

	request, err = createRequestFromNonce(g, versions, nonce, srv)
	return nonce, request, err
}

// CreateRequestWithNonce builds a request using a caller-supplied nonce (e.g. a
// hash of a payload, for document timestamping). nonce must match the
// negotiated version's nonce size.
func CreateRequestWithNonce(versions []Version, nonce []byte, srv []byte) ([]byte, error) {
	_, g, err := clientVersionPreference(versions)
	if err != nil {
		return nil, err
	}
	if len(nonce) != nonceSize(g) {
		return nil, fmt.Errorf("protocol: nonce length %d, want %d", len(nonce), nonceSize(g))
	}
	return createRequestFromNonce(g, versions, nonce, srv)
}

// createRequestFromNonce assembles a request packet from a pre-built nonce.
func createRequestFromNonce(g wireGroup, versions []Version, nonce, srv []byte) ([]byte, error) {
	tags := map[uint32][]byte{TagNONC: nonce}

	if g != groupGoogle {
		sorted := make([]Version, 0, len(versions))
		for _, v := range versions {
			if v == VersionGoogle {
				continue
			}
			sorted = append(sorted, v)
		}
		slices.Sort(sorted)
		// drafts 12+ require strictly ascending VER
		sorted = slices.Compact(sorted)
		vb := make([]byte, 4*len(sorted))
		for i, v := range sorted {
			binary.LittleEndian.PutUint32(vb[4*i:], uint32(v))
		}
		tags[TagVER] = vb

		if g >= groupD14 {
			tags[TagTYPE] = make([]byte, 4) // TYPE=0 = request
		}
		if len(srv) > 0 && g >= groupD10 {
			tags[TagSRV] = srv
		}
	}

	// IETF wire size is 1024 including the 12-byte header; Google has no header
	target := 1024
	if usesRoughtimHeader(g) {
		target = 1012
	}

	n := uint32(len(tags))
	headerWithPad := 4 + 4*n + 4*(n+1) // header size after adding the pad tag
	var bodySize uint32
	for _, v := range tags {
		bodySize += uint32(len(v))
	}
	shortfall := target - int(headerWithPad+bodySize)
	if shortfall > 0 {
		padTag := TagPAD // Google PAD\xff
		if g >= groupD08 {
			padTag = TagZZZZ // drafts 08+
		} else if g >= groupD01 {
			padTag = tagPADIETF // drafts 01-07 PAD\0
		}
		padLen := shortfall
		padLen -= padLen % 4 // 4-byte align
		tags[padTag] = make([]byte, padLen)
	}

	if usesRoughtimHeader(g) {
		msg, err := encodeWrapped(tags)
		if err != nil {
			return nil, fmt.Errorf("protocol: encode request: %w", err)
		}
		return msg, nil
	}
	msg, err := encode(tags)
	if err != nil {
		return nil, fmt.Errorf("protocol: encode request: %w", err)
	}
	return msg, nil
}

// VerifyReply authenticates a server response and returns the midpoint and
// radius. versions must match the list passed to [CreateRequest]. For drafts
// 12+, requestBytes must be the full request packet; earlier versions may pass
// nil.
func VerifyReply(versions []Version, reply, rootPK, nonce, requestBytes []byte) (midpoint time.Time, radius time.Duration, err error) {
	bestVer, bestG, err := clientVersionPreference(versions)
	if err != nil {
		return time.Time{}, 0, err
	}
	if want := publicKeySize(schemeOfGroup(bestG)); len(rootPK) != want {
		return time.Time{}, 0, fmt.Errorf("protocol: root key is %d bytes, want %d for %s",
			len(rootPK), want, schemeOfGroup(bestG))
	}

	// unwrap with the client's best version, refine once server VER is known
	respBytes, err := unwrapReply(reply, bestG)
	if err != nil {
		return time.Time{}, 0, err
	}

	resp, err := Decode(respBytes)
	if err != nil {
		return time.Time{}, 0, fmt.Errorf("protocol: decode reply: %w", err)
	}

	// decode SREP once and reuse; missing SREP is reported by verifyReplySigs
	var srep map[uint32][]byte
	if srepBytes, ok := resp[TagSREP]; ok {
		s, derr := Decode(srepBytes)
		if derr != nil {
			return time.Time{}, 0, fmt.Errorf("protocol: decode SREP: %w", derr)
		}
		srep = s
	}

	// resolve the server's negotiated version, fall back to client's best
	g := bestG
	if bestVer != VersionGoogle {
		if respVer, ok := extractResponseVER(resp, srep); ok {
			if !versionOffered(respVer, versions) {
				return time.Time{}, 0, errors.New("protocol: server chose version not offered by client")
			}
			respTypeBytes, hasRespType := resp[TagTYPE]
			if hasRespType {
				if len(respTypeBytes) != 4 || binary.LittleEndian.Uint32(respTypeBytes) != 1 {
					return time.Time{}, 0, errors.New("protocol: response TYPE must be 1")
				}
			}
			g = wireGroupOf(respVer, hasRespType)
		}
	}

	// drafts 01-11 require top-level VER (4 bytes); 12+ moved it into SREP
	// (checked by verifyNoVersionDowngrade)
	if hasResponseVER(g) {
		vb, ok := resp[TagVER]
		if !ok {
			return time.Time{}, 0, errors.New("protocol: missing VER in response")
		}
		if len(vb) != 4 {
			return time.Time{}, 0, fmt.Errorf("protocol: top-level VER must be 4 bytes, got %d", len(vb))
		}
	}

	_, mintBuf, maxtBuf, err := verifyReplySigs(resp, rootPK, g)
	if err != nil {
		return time.Time{}, 0, err
	}

	midpoint, radius, err = verifyReplySREP(srep, resp, nonce, requestBytes, g)
	if err != nil {
		return time.Time{}, 0, err
	}

	// drafts 12+: SREP signs VERS for the no-downgrade check
	if g >= groupD12 {
		if err := verifyNoVersionDowngrade(srep, versions); err != nil {
			return time.Time{}, 0, err
		}
	}

	return validateDelegationWindow(midpoint, radius, mintBuf, maxtBuf, g)
}

// verifyNoVersionDowngrade confirms the signed SREP.VER is the highest version
// mutually supported by the client and the signed VERS (drafts 12+).
func verifyNoVersionDowngrade(srep map[uint32][]byte, clientVersions []Version) error {
	if srep == nil {
		return errors.New("protocol: missing SREP for downgrade check")
	}
	verBytes, ok := srep[TagVER]
	if !ok || len(verBytes) != 4 {
		return errors.New("protocol: missing VER in SREP")
	}
	chosen := Version(binary.LittleEndian.Uint32(verBytes))
	versBytes, ok := srep[TagVERS]
	if !ok || len(versBytes) == 0 || len(versBytes)%4 != 0 {
		return errors.New("protocol: missing or malformed VERS in SREP")
	}
	nv := len(versBytes) / 4
	if nv > maxVersionList {
		return fmt.Errorf("protocol: VERS has %d entries (max %d)", nv, maxVersionList)
	}
	serverSupports := make(map[Version]bool, nv)
	var prev Version
	for i := 0; i < len(versBytes); i += 4 {
		v := Version(binary.LittleEndian.Uint32(versBytes[i : i+4]))
		if i > 0 && v <= prev {
			return errors.New("protocol: VERS not sorted in ascending order")
		}
		prev = v
		serverSupports[v] = true
	}
	// drafts 12+: VERS must contain the chosen VER
	if !serverSupports[chosen] {
		return fmt.Errorf("protocol: server chose version %s not present in signed VERS list", chosen)
	}
	var best Version
	var found bool
	for _, v := range clientVersions {
		if serverSupports[v] && (!found || v > best) {
			best, found = v, true
		}
	}
	if !found {
		return errors.New("protocol: no mutually supported version (VERS check)")
	}
	if chosen != best {
		return fmt.Errorf("protocol: version downgrade detected: server chose %s, expected %s", chosen, best)
	}
	return nil
}

// extractResponseVER returns the negotiated version, preferring signed VER in
// SREP (drafts 12+) over unsigned top-level VER to close a downgrade vector.
// srep may be nil.
func extractResponseVER(resp, srep map[uint32][]byte) (Version, bool) {
	if srep != nil {
		if vb, ok := srep[TagVER]; ok && len(vb) == 4 {
			return Version(binary.LittleEndian.Uint32(vb)), true
		}
	}
	if vb, ok := resp[TagVER]; ok && len(vb) == 4 {
		return Version(binary.LittleEndian.Uint32(vb)), true
	}
	return 0, false
}

// ExtractVersion returns the negotiated version from a raw server reply.
func ExtractVersion(reply []byte) (Version, bool) {
	msg := reply
	if len(reply) >= 12 {
		if inner, err := unwrapPacket(reply); err == nil {
			msg = inner
		}
	}
	resp, err := Decode(msg)
	if err != nil {
		return 0, false
	}
	var srep map[uint32][]byte
	if srepBytes, ok := resp[TagSREP]; ok {
		if s, derr := Decode(srepBytes); derr == nil {
			srep = s
		}
	}
	return extractResponseVER(resp, srep)
}

// versionOffered reports whether ver appears in the client's version list.
func versionOffered(ver Version, versions []Version) bool {
	return slices.Contains(versions, ver)
}

// unwrapReply strips the ROUGHTIM header for IETF versions; for Google it
// validates the header is absent.
func unwrapReply(reply []byte, g wireGroup) ([]byte, error) {
	if usesRoughtimHeader(g) {
		return unwrapPacket(reply)
	}
	if len(reply) >= 8 && bytes.Equal(reply[:8], packetMagic[:]) {
		return nil, errors.New("protocol: unexpected ROUGHTIM header for Google-Roughtime")
	}
	return reply, nil
}

// verifyReplySigs verifies CERT against rootPK and SREP against the online key;
// returns the online key bytes and raw MINT/MAXT from DELE.
func verifyReplySigs(resp map[uint32][]byte, rootPK []byte, g wireGroup) ([]byte, []byte, []byte, error) {
	scheme := schemeOfGroup(g)
	if len(rootPK) != publicKeySize(scheme) {
		return nil, nil, nil, fmt.Errorf("protocol: root key is %d bytes, want %d for %s",
			len(rootPK), publicKeySize(scheme), scheme)
	}
	srepBytes, ok := resp[TagSREP]
	if !ok {
		return nil, nil, nil, errors.New("protocol: missing SREP")
	}
	srepSig, ok := resp[TagSIG]
	if !ok || len(srepSig) != signatureSize(scheme) {
		return nil, nil, nil, errors.New("protocol: missing or invalid SIG")
	}
	certBytes, ok := resp[TagCERT]
	if !ok {
		return nil, nil, nil, errors.New("protocol: missing CERT")
	}

	onlinePK, mintBuf, maxtBuf, err := verifyCert(certBytes, rootPK, g)
	if err != nil {
		return nil, nil, nil, err
	}

	switch scheme {
	case schemeEd25519:
		if !verifyEd25519(ed25519.PublicKey(onlinePK), srepBytes, responseCtx, srepSig) {
			return nil, nil, nil, errors.New("protocol: SREP signature verification failed")
		}
	case schemeMLDSA44:
		pk, err := mldsa.NewPublicKey(mldsa.MLDSA44(), onlinePK)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("protocol: decode online PUBK: %w", err)
		}
		if !verifyMLDSA44(pk, srepBytes, responseCtx, srepSig) {
			return nil, nil, nil, errors.New("protocol: SREP signature verification failed")
		}
	default:
		return nil, nil, nil, errSchemeNotSupported
	}

	return onlinePK, mintBuf, maxtBuf, nil
}

// verifyReplySREP verifies the Merkle proof and decodes MIDP/RADI from a
// pre-decoded SREP.
func verifyReplySREP(srep, resp map[uint32][]byte, nonce, requestBytes []byte, g wireGroup) (time.Time, time.Duration, error) {
	if srep == nil {
		return time.Time{}, 0, errors.New("protocol: missing SREP")
	}
	midpBytes, ok := srep[TagMIDP]
	if !ok {
		return time.Time{}, 0, errors.New("protocol: missing MIDP")
	}
	radiBytes, ok := srep[TagRADI]
	if !ok {
		return time.Time{}, 0, errors.New("protocol: missing RADI")
	}
	rootHash, ok := srep[TagROOT]
	if !ok || len(rootHash) != hashSize(g) {
		return time.Time{}, 0, errors.New("protocol: missing or invalid ROOT")
	}

	// drafts 01-02 bind nonce only via SREP.NONC; 03+ echo at top-level but the
	// Merkle proof already binds it (echo is optional)
	if noncInSREP(g) {
		srepNonce, ok := srep[TagNONC]
		if !ok {
			return time.Time{}, 0, errors.New("protocol: missing NONC in SREP")
		}
		if !bytes.Equal(srepNonce, nonce) {
			return time.Time{}, 0, errors.New("protocol: NONC in SREP does not match request nonce")
		}
	} else if echoed, ok := resp[TagNONC]; ok {
		if !bytes.Equal(echoed, nonce) {
			return time.Time{}, 0, errors.New("protocol: response NONC does not match request nonce")
		}
	}

	leafData := nonce
	if usesFullPacketLeaf(g) {
		if len(requestBytes) == 0 {
			return time.Time{}, 0, errors.New("protocol: requestBytes required for drafts 12+")
		}
		leafData = requestBytes
	}
	if err := verifyMerkle(resp, leafData, rootHash, g); err != nil {
		return time.Time{}, 0, err
	}

	midpoint, err := decodeTimestamp(midpBytes, g)
	if err != nil {
		return time.Time{}, 0, fmt.Errorf("protocol: decode MIDP: %w", err)
	}
	radius, err := decodeRadius(radiBytes, g)
	if err != nil {
		return time.Time{}, 0, fmt.Errorf("protocol: decode RADI: %w", err)
	}
	// drafts 12+: RADI must be nonzero
	if g >= groupD12 && radius == 0 {
		return time.Time{}, 0, errors.New("protocol: RADI must not be zero")
	}
	return midpoint, radius, nil
}

// validateDelegationWindow checks the midpoint falls within MINT..MAXT.
func validateDelegationWindow(midpoint time.Time, radius time.Duration, mintBuf, maxtBuf []byte, g wireGroup) (time.Time, time.Duration, error) {
	mintTime, err := decodeTimestamp(mintBuf, g)
	if err != nil {
		return time.Time{}, 0, fmt.Errorf("protocol: decode MINT: %w", err)
	}
	maxtTime, err := decodeTimestamp(maxtBuf, g)
	if err != nil {
		return time.Time{}, 0, fmt.Errorf("protocol: decode MAXT: %w", err)
	}
	if midpoint.Before(mintTime) || midpoint.After(maxtTime) {
		return time.Time{}, 0, fmt.Errorf("%w (MIDP=%s, MINT=%s, MAXT=%s)",
			ErrDelegationWindow,
			midpoint.Format(time.RFC3339), mintTime.Format(time.RFC3339), maxtTime.Format(time.RFC3339))
	}
	return midpoint, radius, nil
}

// verifyCert verifies the delegation certificate; returns the online PK and raw
// MINT/MAXT bytes from DELE. Signature scheme is implied by g.
func verifyCert(certBytes []byte, rootPK []byte, g wireGroup) ([]byte, []byte, []byte, error) {
	scheme := schemeOfGroup(g)
	certMsg, err := Decode(certBytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("protocol: decode CERT: %w", err)
	}
	deleBytes, ok := certMsg[TagDELE]
	if !ok {
		return nil, nil, nil, errors.New("protocol: missing DELE in CERT")
	}
	certSig, ok := certMsg[TagSIG]
	if !ok || len(certSig) != signatureSize(scheme) {
		return nil, nil, nil, errors.New("protocol: missing or invalid SIG in CERT")
	}

	ctx := delegationContext(g)
	switch scheme {
	case schemeEd25519:
		if !verifyEd25519(ed25519.PublicKey(rootPK), deleBytes, ctx, certSig) {
			return nil, nil, nil, errors.New("protocol: DELE signature verification failed")
		}
	case schemeMLDSA44:
		pk, perr := mldsa.NewPublicKey(mldsa.MLDSA44(), rootPK)
		if perr != nil {
			return nil, nil, nil, fmt.Errorf("protocol: decode root PUBK: %w", perr)
		}
		if !verifyMLDSA44(pk, deleBytes, ctx, certSig) {
			return nil, nil, nil, errors.New("protocol: DELE signature verification failed")
		}
	default:
		return nil, nil, nil, errSchemeNotSupported
	}

	dele, err := Decode(deleBytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("protocol: decode DELE: %w", err)
	}
	onlinePK, ok := dele[TagPUBK]
	if !ok || len(onlinePK) != publicKeySize(scheme) {
		return nil, nil, nil, errors.New("protocol: missing or invalid PUBK in DELE")
	}
	mintBuf, ok := dele[TagMINT]
	if !ok || len(mintBuf) != 8 {
		return nil, nil, nil, errors.New("protocol: missing or invalid MINT in DELE")
	}
	maxtBuf, ok := dele[TagMAXT]
	if !ok || len(maxtBuf) != 8 {
		return nil, nil, nil, errors.New("protocol: missing or invalid MAXT in DELE")
	}

	return onlinePK, mintBuf, maxtBuf, nil
}

// verifyMerkle verifies the Merkle proof that leafInput is in the tree rooted
// at rootHash.
func verifyMerkle(resp map[uint32][]byte, leafInput, rootHash []byte, g wireGroup) error {
	indexBytes, ok := resp[TagINDX]
	if !ok || len(indexBytes) != 4 {
		return errors.New("protocol: missing or invalid INDX")
	}
	index := binary.LittleEndian.Uint32(indexBytes)

	pathBytes, pathOK := resp[TagPATH] // zero-length valid for single-request batches
	if !pathOK {
		return errors.New("protocol: missing PATH in response")
	}
	hs := hashSize(g)
	if len(pathBytes)%hs != 0 {
		return errors.New("protocol: PATH length not a multiple of hash size")
	}
	if len(pathBytes)/hs > 32 {
		return errors.New("protocol: PATH exceeds 32 hash values")
	}

	hash := leafHash(g, leafInput)
	steps := len(pathBytes) / hs
	nf := merkleNodeFirst(g)
	for i := range steps {
		sibling := pathBytes[i*hs : (i+1)*hs]
		if index&1 == 0 {
			// drafts 05-13: H(0x01 || node || hash); others: H(0x01 || hash ||
			// node)
			if nf {
				hash = nodeHash(g, sibling, hash)
			} else {
				hash = nodeHash(g, hash, sibling)
			}
		} else {
			if nf {
				hash = nodeHash(g, hash, sibling)
			} else {
				hash = nodeHash(g, sibling, hash)
			}
		}
		index >>= 1
	}

	// trailing INDX bits must be zero after consuming PATH
	if index != 0 {
		return errors.New("protocol: INDX has trailing non-zero bits")
	}

	if !bytes.Equal(hash, rootHash) {
		return ErrMerkleMismatch
	}
	return nil
}

// Grease applies a random grease transformation to a signed reply: corrupt a
// signature + MIDP, drop a mandatory tag, rewrite VER, or add an undefined tag.
// Grease may mutate reply in place or return a new buffer; callers must use
// only the returned buffer.
func Grease(reply []byte, ver Version) []byte {
	mode := mrand.IntN(4)
	switch mode {
	case 1:
		if out := greaseDropTag(reply, ver); out != nil {
			return out
		}
	case 2:
		if out := greaseWrongVersion(reply, ver); out != nil {
			return out
		}
	case 3:
		if out := greaseUndefinedTag(reply, ver); out != nil {
			return out
		}
	}
	// mode 0 or fallback
	greaseCorruptSig(reply, ver)
	return reply
}

// greaseSplit separates a reply into its ROUGHTIM header (nil for Google) and
// body; returns nil body on malformed input.
func greaseSplit(reply []byte, ver Version) (header, body []byte) {
	if ver == VersionGoogle {
		return nil, reply
	}
	if len(reply) < 12 {
		return nil, nil
	}
	return reply[:12], reply[12:]
}

// greaseJoin prepends the ROUGHTIM header to a re-encoded body, fixing the
// length field.
func greaseJoin(header, body []byte) []byte {
	if header == nil {
		return body
	}
	out := make([]byte, len(header)+len(body))
	copy(out, header)
	binary.LittleEndian.PutUint32(out[8:12], uint32(len(body)))
	copy(out[len(header):], body)
	return out
}

// greaseCorruptSig corrupts a randomly chosen signature (SREP or DELE) and MIDP
// in place. MIDP is corrupted only when the sig was, since grease forbids
// invalid times with valid signatures.
func greaseCorruptSig(reply []byte, ver Version) {
	_, body := greaseSplit(reply, ver)
	if body == nil {
		return
	}
	base := uint32(len(reply) - len(body))

	sigCorrupted := false
	if mrand.IntN(2) == 0 {
		if certLo, certHi, ok := findTagRange(body, TagCERT); ok && certHi > certLo {
			cert := body[certLo:certHi]
			if sigLo, sigHi, ok := findTagRange(cert, TagSIG); ok && sigHi > sigLo {
				reply[base+certLo+sigLo+uint32(mrand.IntN(int(sigHi-sigLo)))] ^= 0xff
				sigCorrupted = true
			}
		}
	} else {
		if lo, hi, ok := findTagRange(body, TagSIG); ok && hi > lo {
			reply[base+lo+uint32(mrand.IntN(int(hi-lo)))] ^= 0xff
			sigCorrupted = true
		}
	}
	if !sigCorrupted {
		return
	}
	if srepLo, srepHi, ok := findTagRange(body, TagSREP); ok && srepHi > srepLo {
		srep := body[srepLo:srepHi]
		if midpLo, midpHi, ok := findTagRange(srep, TagMIDP); ok && midpHi > midpLo {
			reply[base+srepLo+midpLo+uint32(mrand.IntN(int(midpHi-midpLo)))] ^= 0xff
		}
	}
}

// greaseDropTag removes a randomly chosen mandatory tag from the top-level
// response, SREP, or CERT; returns nil on failure.
func greaseDropTag(reply []byte, ver Version) []byte {
	header, body := greaseSplit(reply, ver)
	if body == nil {
		return nil
	}
	msg, err := Decode(body)
	if err != nil {
		return nil
	}
	scopes := []uint32{0, TagSREP, TagCERT}
	mrand.Shuffle(len(scopes), func(i, j int) { scopes[i], scopes[j] = scopes[j], scopes[i] })
	// drop only tags whose absence breaks verification: NONC echo and TYPE are
	// tolerated/optional, so neither is a valid drop target
	for _, scope := range scopes {
		if scope == 0 {
			candidates := []uint32{TagSIG, TagSREP, TagCERT, TagPATH, TagINDX}
			if out, ok := dropOneTag(msg, candidates); ok {
				encoded, err := encode(out)
				if err != nil {
					return nil
				}
				return greaseJoin(header, encoded)
			}
			continue
		}
		inner, ok := msg[scope]
		if !ok {
			continue
		}
		innerMsg, err := Decode(inner)
		if err != nil {
			continue
		}
		var candidates []uint32
		if scope == TagSREP {
			candidates = []uint32{TagRADI, TagMIDP, TagROOT}
		} else { // TagCERT
			candidates = []uint32{TagSIG, TagDELE}
		}
		modified, ok := dropOneTag(innerMsg, candidates)
		if !ok {
			continue
		}
		reencoded, err := encode(modified)
		if err != nil {
			return nil
		}
		msg[scope] = reencoded
		out, err := encode(msg)
		if err != nil {
			return nil
		}
		return greaseJoin(header, out)
	}
	return nil
}

// dropOneTag removes one randomly chosen candidate tag from msg.
func dropOneTag(msg map[uint32][]byte, candidates []uint32) (map[uint32][]byte, bool) {
	shuffled := append([]uint32(nil), candidates...)
	mrand.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
	for _, tag := range shuffled {
		if _, ok := msg[tag]; ok {
			delete(msg, tag)
			return msg, true
		}
	}
	return nil, false
}

// greaseWrongVersion overwrites top-level VER with an unsupported version;
// returns nil when no top-level VER exists (Google, drafts 12+).
func greaseWrongVersion(reply []byte, ver Version) []byte {
	_, body := greaseSplit(reply, ver)
	if body == nil {
		return nil
	}
	lo, hi, ok := findTagRange(body, TagVER)
	if !ok || hi-lo != 4 {
		return nil
	}
	base := uint32(len(reply) - len(body))
	binary.LittleEndian.PutUint32(reply[base+lo:], 0xFFFFFFFF)
	return reply
}

// greaseUndefinedTag adds an undefined tag with random content; the draft
// requires clients to ignore undefined tags.
func greaseUndefinedTag(reply []byte, ver Version) []byte {
	header, body := greaseSplit(reply, ver)
	if body == nil {
		return nil
	}
	msg, err := Decode(body)
	if err != nil {
		return nil
	}
	// GRSE (0x45535247) is not in the IANA Roughtime tag registry
	const tagGRSE uint32 = 0x45535247
	var val [4]byte
	binary.LittleEndian.PutUint32(val[:], mrand.Uint32())
	msg[tagGRSE] = val[:]
	out, err := encode(msg)
	if err != nil {
		return nil
	}
	return greaseJoin(header, out)
}

// NonceOffsetInRequest returns the byte offset of NONC's value in a raw request
// (framed or unframed), so callers reusing the buffer (load generators) can
// rewrite the nonce in place.
func NonceOffsetInRequest(request []byte) (int, error) {
	msg, err := unwrapRequest(request)
	if err != nil {
		return 0, err
	}
	prefix := len(request) - len(msg)
	lo, _, ok := findTagRange(msg, TagNONC)
	if !ok {
		return 0, errors.New("protocol: NONC tag not found")
	}
	return prefix + int(lo), nil
}

// findTagRange locates the [lo, hi) byte range of a tag's value within a raw
// Roughtime message.
func findTagRange(msg []byte, tag uint32) (lo, hi uint32, ok bool) {
	if len(msg) < 4 {
		return 0, 0, false
	}
	n := binary.LittleEndian.Uint32(msg[:4])
	if n == 0 || n > maxDecodeTags {
		return 0, 0, false
	}

	tagsOff := 4 + (n-1)*4
	valsOff := tagsOff + n*4
	if valsOff < tagsOff || uint32(len(msg)) < valsOff {
		return 0, 0, false
	}

	idx := int(-1)
	for i := range n {
		if binary.LittleEndian.Uint32(msg[tagsOff+i*4:]) == tag {
			idx = int(i)
			break
		}
	}
	if idx < 0 {
		return 0, 0, false
	}

	if idx == 0 {
		lo = 0
	} else {
		lo = binary.LittleEndian.Uint32(msg[4+(idx-1)*4:])
	}
	if idx == int(n)-1 {
		hi = uint32(len(msg)) - valsOff
	} else {
		hi = binary.LittleEndian.Uint32(msg[4+idx*4:])
	}

	lo += valsOff
	hi += valsOff
	if hi > uint32(len(msg)) || lo >= hi {
		return 0, 0, false
	}
	return lo, hi, true
}
