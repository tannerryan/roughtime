// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

// Package protocol implements the Roughtime wire protocol for both server and
// client use. It supports Google-Roughtime and IETF drafts 01-19. Drafts 12-19
// share wire version 0x8000000c but differ in wire behavior: drafts 14-19
// include a TYPE tag, which changes the Merkle leaf hash and delegation context
// group.
package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	mrand "math/rand/v2"
	"slices"
	"time"
)

// Version is a Roughtime protocol version number. The zero value represents
// Google-Roughtime, which does not use a VER tag on the wire.
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
	VersionDraft12 Version = 0x8000000c // draft-ietf-ntp-roughtime-12 through 19
)

// String returns the IETF draft name (e.g. "draft-ietf-ntp-roughtime-08") or a
// hex representation for unknown values. Drafts 12–19 all report draft-12.
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
	default:
		return fmt.Sprintf("Version(0x%08x)", uint32(v))
	}
}

// ShortString returns a compact version label (e.g. "Google", "draft-08",
// "draft-12"). For unknown values it returns the hex wire number.
func (v Version) ShortString() string {
	switch v {
	case VersionGoogle:
		return "Google"
	case VersionDraft12:
		return "draft-12"
	default:
		if v > VersionGoogle && v <= VersionDraft12 {
			return fmt.Sprintf("draft-%02d", uint32(v)-0x80000000)
		}
		return fmt.Sprintf("0x%08x", uint32(v))
	}
}

// wireGroup identifies a set of drafts that share the same on-wire behaviour.
type wireGroup int

const (
	groupGoogle wireGroup = iota // Google-Roughtime (no header, no VER)
	groupD01                     // Draft 01 (SHA-512, NONC in SREP, 64B nonce)
	groupD02                     // Draft 02 (SHA-512/256, NONC in SREP, 64B nonce)
	groupD03                     // Drafts 03–04 (NONC at top-level, 64B nonce)
	groupD05                     // Drafts 05–06 (32B nonce, MJD-µs)
	groupD07                     // Draft 07 (SHA-512/256, delegation ctx without hyphens)
	groupD08                     // Drafts 08–09 (Unix seconds, ZZZZ padding)
	groupD10                     // Drafts 10–11 (RADI ≥ 3, SRV tag)
	groupD12                     // Drafts 12–13 (full-packet leaf, VERS in SREP); also fallback for 14–19 without TYPE
	groupD14                     // Drafts 14–19 with TYPE tag present (changes Merkle leaf and delegation context)
)

// wireGroupOf returns the wire format group for a version and TYPE presence.
func wireGroupOf(v Version, hasType bool) wireGroup {
	switch {
	case v == VersionGoogle:
		return groupGoogle
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

// Tag constants from the IANA Roughtime tag registry. These identify fields in
// Roughtime wire-format messages.
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
	// TagZZZZ: draft 08's registry listed 0x7a7a7a7a (a typo, lowercase
	// "zzzz"); the correct value 0x5a5a5a5a was used from draft 09 onward.
	TagZZZZ uint32 = 0x5a5a5a5a // ZZZZ (client padding, drafts 08+)
	TagPAD  uint32 = 0xff444150 // PAD\xff (Google-Roughtime client padding)

	tagPADIETF uint32 = 0x00444150 // PAD\0 (client padding, drafts 01–07)
)

// Wire-format limits. maxMessageSize bounds adversarial input fed to [Decode];
// maxEncodeTags / maxDecodeTags bound the tag count; maxVersionList bounds the
// VER list a client may advertise (drafts 13+ require ≤ 32).
const (
	maxMessageSize = 65535
	maxEncodeTags  = 512
	maxDecodeTags  = 512
	maxVersionList = 32
)

// packetMagic is the 8-byte ROUGHTIM header present in all IETF draft packets.
var packetMagic = [8]byte{'R', 'O', 'U', 'G', 'H', 'T', 'I', 'M'}

// hashSize returns the Merkle hash output length: 64 for Google (SHA-512), 32
// for all IETF drafts.
func hashSize(g wireGroup) int {
	if g == groupGoogle {
		return 64
	}
	return 32
}

// usesRoughtimHeader reports whether packets use the 12-byte ROUGHTIM header.
// All IETF drafts require it; Google-Roughtime sends bare messages.
func usesRoughtimHeader(g wireGroup) bool { return g >= groupD01 }

// usesMJDMicroseconds reports whether timestamps use MJD microsecond encoding
// (drafts 01–07). Google uses plain Unix microseconds; drafts 08+ use Unix
// seconds.
func usesMJDMicroseconds(g wireGroup) bool { return g >= groupD01 && g <= groupD07 }

// usesFullPacketLeaf reports whether the Merkle tree leaf is computed over the
// full request packet (drafts 12+) rather than just the nonce.
func usesFullPacketLeaf(g wireGroup) bool { return g >= groupD12 }

// noncInSREP reports whether NONC is placed inside SREP (drafts 01–02). Draft
// 03 moved NONC to the top-level response.
func noncInSREP(g wireGroup) bool { return g == groupD01 || g == groupD02 }

// NoncInSREP reports whether the given version and TYPE presence indicate a
// wire group that places NONC inside SREP (drafts 01–02).
func NoncInSREP(ver Version, hasType bool) bool { return noncInSREP(wireGroupOf(ver, hasType)) }

// hasResponseVER reports whether the response includes a top-level VER tag
// (drafts 01–11). Drafts 12+ moved VER inside SREP.
func hasResponseVER(g wireGroup) bool { return g >= groupD01 && g < groupD12 }

// hasResponseNONC reports whether the response includes a top-level NONC echo
// (drafts 03+).
func hasResponseNONC(g wireGroup) bool { return g >= groupD03 }

// hasSREPVERS reports whether SREP includes VER and VERS tags (drafts 12+).
func hasSREPVERS(g wireGroup) bool { return g >= groupD12 }

// usesSHA512_256 reports whether the hash algorithm is SHA-512/256 rather than
// SHA-512 truncated. Drafts 02 and 07 use SHA-512/256; all others use SHA-512
// (truncated to 32 bytes for IETF, full 64 bytes for Google).
func usesSHA512_256(g wireGroup) bool { return g == groupD02 || g == groupD07 }

// nonceSize returns the nonce length for a wire group: 64 bytes for Google and
// drafts 01–04, 32 bytes for drafts 05+.
func nonceSize(g wireGroup) int {
	if g <= groupD03 {
		return 64
	}
	return 32
}

// Signature context strings
var (
	delegationCtxOld = []byte("RoughTime v1 delegation signature--\x00") // Google, drafts 01–06, 08–11
	delegationCtxNew = []byte("RoughTime v1 delegation signature\x00")   // draft 07, drafts 12+
	responseCtx      = []byte("RoughTime v1 response signature\x00")     // all versions
)

// delegationContext returns the delegation signature context for a wire group.
// Draft 07 and drafts 12+ use the shorter context without trailing hyphens.
func delegationContext(g wireGroup) []byte {
	if g == groupD07 || g >= groupD12 {
		return delegationCtxNew
	}
	return delegationCtxOld
}

// timeToMJDMicro encodes a time as an MJD microsecond timestamp (drafts 01–07).
// The upper 3 bytes hold the Modified Julian Date (days since 17 Nov 1858) and
// the lower 5 bytes hold microseconds elapsed since midnight UTC on that day.
func timeToMJDMicro(t time.Time) uint64 {
	utc := t.UTC()
	year, month, day := utc.Date()
	hour, min, sec := utc.Clock()
	nsec := utc.Nanosecond()

	// Julian Day Number for the date
	a := (14 - int(month)) / 12
	y := year + 4800 - a
	m := int(month) + 12*a - 3
	jdn := day + (153*m+2)/5 + 365*y + y/4 - y/100 + y/400 - 32045

	// MJD at midnight: JDN_noon - 2400001. Verified: 1 Jan 1970 = MJD 40587
	mjd := uint64(jdn - 2400001)

	usInDay := uint64(hour)*3600_000_000 +
		uint64(min)*60_000_000 +
		uint64(sec)*1_000_000 +
		uint64(nsec)/1000

	return (mjd << 40) | (usInDay & 0xFFFFFFFFFF)
}

// encodeTimestamp encodes a time in the format appropriate for a wire group:
// Unix microseconds for Google, MJD microseconds for drafts 01–07, or Unix
// seconds for drafts 08+.
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

// radiMicroseconds encodes a duration as a RADI value in microseconds (Google,
// drafts 01–07). The result is clamped to [1, MaxUint32].
func radiMicroseconds(d time.Duration) uint32 {
	return uint32(min(max(d.Microseconds(), 1), math.MaxUint32))
}

// radiSeconds encodes a duration as a RADI value in seconds (drafts 08+). The
// spec requires RADI MUST NOT be zero. Drafts 10–11 require RADI >= 3 (MUST);
// drafts 12+ relax this to SHOULD when the server lacks leap second info.
func radiSeconds(d time.Duration, g wireGroup) uint32 {
	sec := int64(d / time.Second)
	floor := int64(1)
	if g == groupD10 {
		floor = 3 // drafts 10–11 §6.2.5: RADI MUST be at least 3 seconds
	}
	return uint32(min(max(sec, floor), math.MaxUint32))
}

// mjdMicroToTime converts an MJD microsecond timestamp to a [time.Time].
func mjdMicroToTime(v uint64) time.Time {
	mjd := int64(v >> 40)
	usInDay := int64(v & 0xFFFFFFFFFF)

	// MJD 40587 = 1 Jan 1970 (Unix epoch)
	unixDays := mjd - 40587
	sec := unixDays*86400 + usInDay/1_000_000
	nsec := (usInDay % 1_000_000) * 1000
	return time.Unix(sec, nsec).UTC()
}

// decodeTimestamp converts a wire-format timestamp to a [time.Time].
func decodeTimestamp(buf []byte, g wireGroup) (time.Time, error) {
	if len(buf) != 8 {
		return time.Time{}, errors.New("protocol: timestamp must be 8 bytes")
	}
	v := binary.LittleEndian.Uint64(buf)
	switch {
	case g == groupGoogle:
		return time.UnixMicro(int64(v)).UTC(), nil
	case usesMJDMicroseconds(g):
		return mjdMicroToTime(v), nil
	default:
		return time.Unix(int64(v), 0).UTC(), nil
	}
}

// decodeRadius converts a wire-format RADI value to a [time.Duration]. Drafts
// 10+ §6.2.5 say RADI "MUST be at least 3 seconds"; we enforce only the
// non-zero floor to tolerate deployed servers that send 1s–2s radii. Earlier
// drafts and Google-Roughtime do not define a lower bound.
func decodeRadius(buf []byte, g wireGroup) (time.Duration, error) {
	if len(buf) != 4 {
		return 0, errors.New("protocol: RADI must be 4 bytes")
	}
	v := binary.LittleEndian.Uint32(buf)
	if v == 0 && g >= groupD10 {
		return 0, errors.New("protocol: RADI must not be zero")
	}
	if g == groupGoogle || usesMJDMicroseconds(g) {
		return time.Duration(v) * time.Microsecond, nil
	}
	return time.Duration(v) * time.Second, nil
}

// DecodeTimestamp decodes an 8-byte wire-format timestamp using the encoding
// rules for the given version.
func DecodeTimestamp(ver Version, buf []byte) (time.Time, error) {
	return decodeTimestamp(buf, wireGroupOf(ver, false))
}

// newHasher returns the hash function for a wire group: SHA-512/256 for drafts
// 02 and 07, SHA-512 for all others.
func newHasher(g wireGroup) interface {
	Write([]byte) (int, error)
	Sum([]byte) []byte
} {
	if usesSHA512_256(g) {
		return sha512.New512_256()
	}
	return sha512.New()
}

// leafHash computes H(0x00 || data), truncated to the wire group's hash size.
func leafHash(g wireGroup, data []byte) []byte {
	h := newHasher(g)
	_, _ = h.Write([]byte{0x00})
	_, _ = h.Write(data)
	return h.Sum(nil)[:hashSize(g)]
}

// nodeHash computes H(0x01 || left || right), truncated to the wire group's
// hash size.
func nodeHash(g wireGroup, left, right []byte) []byte {
	h := newHasher(g)
	_, _ = h.Write([]byte{0x01})
	_, _ = h.Write(left)
	_, _ = h.Write(right)
	return h.Sum(nil)[:hashSize(g)]
}

// encode serializes a tag-value map into a Roughtime message. All value lengths
// must be multiples of 4 bytes; tags are emitted in ascending order.
func encode(msg map[uint32][]byte) ([]byte, error) {
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
	if totalLen > math.MaxInt {
		return nil, errors.New("protocol: message too large")
	}

	out := make([]byte, totalLen)
	binary.LittleEndian.PutUint32(out[0:4], n)

	off := uint32(0)
	for i := uint32(1); i < n; i++ {
		off += uint32(len(msg[tags[i-1]]))
		binary.LittleEndian.PutUint32(out[4+4*(i-1):4+4*i], off)
	}

	tBase := 4 + 4*(n-1) // start of tag section
	for i, t := range tags {
		binary.LittleEndian.PutUint32(out[tBase+uint32(4*i):tBase+uint32(4*i)+4], t)
	}

	pos := headerLen
	for _, t := range tags {
		copy(out[pos:], msg[t])
		pos += uint32(len(msg[t]))
	}
	return out, nil
}

// Decode parses a Roughtime message into a tag-value map. The returned slices
// alias data.
func Decode(data []byte) (map[uint32][]byte, error) {
	if len(data) < 4 {
		return nil, errors.New("protocol: message too short")
	}
	if len(data) > maxMessageSize {
		return nil, fmt.Errorf("protocol: message exceeds %d bytes", maxMessageSize)
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

// validateHeader checks that tags are strictly ascending and offsets are
// aligned and monotonic.
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

// decodeValues extracts tag values from the data section of a message.
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

// wrapPacket prepends the 12-byte ROUGHTIM header.
func wrapPacket(message []byte) []byte {
	pkt := make([]byte, 12+len(message))
	copy(pkt[0:8], packetMagic[:])
	binary.LittleEndian.PutUint32(pkt[8:12], uint32(len(message)))
	copy(pkt[12:], message)
	return pkt
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
// Nonce/SRV sub-slices share memory with the caller-supplied buffer; callers
// that pool the buffer must not mutate it while a Request is in use.
type Request struct {
	Nonce     []byte    // 32 bytes (IETF drafts 05+) or 64 bytes (Google, drafts 01–04)
	Versions  []Version // from VER tag; empty for Google-Roughtime
	SRV       []byte    // optional; nil if absent
	HasType   bool      // true when request contains TYPE=0 (drafts 14+)
	RawPacket []byte    // complete UDP payload for Merkle leaf (drafts 12+)
}

// ParseRequest auto-detects Google vs IETF framing and extracts request fields.
// The Nonce and SRV fields are sub-slices of raw and share its memory. Framed
// (IETF) requests that omit VER are rejected; the nonce length must match at
// least one offered version; SRV (when present) must be 32 bytes for drafts
// 10+.
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

	// A framed (ROUGHTIM-header) request is by definition an IETF draft 01+
	// packet, which requires a VER tag. Silently falling back to Google on a
	// missing VER would let a malformed framed request be processed as Google.
	if framed && len(req.Versions) == 0 {
		return nil, errors.New("protocol: framed request missing VER tag")
	}

	// Determine the highest declared version for cross-checks. An empty VER
	// list implies Google-Roughtime (unframed; framed case rejected above).
	maxVer := VersionGoogle
	for _, v := range req.Versions {
		if v > maxVer {
			maxVer = v
		}
	}
	maxGroup := wireGroupOf(maxVer, false)

	// Drafts 12+ §5.1.1: VER MUST be strictly ascending and non-repeating.
	// Earlier drafts have no ordering rule, so accept unsorted/duplicate VER.
	if maxGroup >= groupD12 {
		for i := 1; i < len(req.Versions); i++ {
			if req.Versions[i] <= req.Versions[i-1] {
				return nil, errors.New("protocol: VER list not strictly ascending")
			}
		}
	}

	// The nonce size is 64 bytes for Google/drafts 01–04 and 32 bytes for
	// drafts 05+. A client VER list may mix versions with different nonce
	// sizes; accept the request if the nonce length matches at least one of the
	// offered versions (or Google when VER is absent). Version selection later
	// picks a mutually supported version whose nonce size matches.
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

	// Drafts 10+ §6.1.3 define SRV as H(0xff || pubkey) truncated to 32 bytes.
	// Earlier drafts left SRV undefined, so we only enforce length for 10+.
	if req.SRV != nil && maxGroup >= groupD10 && len(req.SRV) != 32 {
		return nil, fmt.Errorf("protocol: SRV length %d invalid for drafts 10+ (want 32)", len(req.SRV))
	}

	return req, nil
}

// unwrapRequest strips the ROUGHTIM header if present, otherwise returns raw.
func unwrapRequest(raw []byte) ([]byte, error) {
	if len(raw) >= 12 && bytes.Equal(raw[:8], packetMagic[:]) {
		return unwrapPacket(raw)
	}
	return raw, nil
}

// parseOptionalTags extracts VER, SRV, and TYPE from a decoded message. The
// caller ([ParseRequest]) performs per-version cross-checks (ascending order,
// SRV length) after this returns.
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
		// Base sanity bounds only; draft-specific length enforcement happens in
		// [ParseRequest] once the highest declared version is known.
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
	return nil
}

// serverPreference lists versions in descending preference for negotiation.
var serverPreference = []Version{
	VersionDraft12,
	VersionDraft11, VersionDraft10,
	VersionDraft09, VersionDraft08,
	VersionDraft07, VersionDraft06,
	VersionDraft05, VersionDraft04, VersionDraft03, VersionDraft02, VersionDraft01,
	VersionGoogle,
}

// supportedVersions contains all IETF version numbers in ascending order for
// the VERS tag in SREP (drafts 12+).
var supportedVersions = []Version{
	VersionDraft01, VersionDraft02, VersionDraft03, VersionDraft04,
	VersionDraft05, VersionDraft06, VersionDraft07,
	VersionDraft08, VersionDraft09,
	VersionDraft10, VersionDraft11,
	VersionDraft12,
}

// supportedVersionsBytes is the pre-encoded wire representation of
// supportedVersions for direct inclusion in SREP.
var supportedVersionsBytes []byte

func init() {
	supportedVersionsBytes = make([]byte, 4*len(supportedVersions))
	for i, v := range supportedVersions {
		binary.LittleEndian.PutUint32(supportedVersionsBytes[4*i:4*i+4], uint32(v))
	}
}

// Supported returns all recognized protocol versions in descending order
// (newest IETF first, Google-Roughtime last).
func Supported() []Version {
	out := slices.Clone(supportedVersions)
	slices.Reverse(out)
	return append(out, VersionGoogle)
}

// ComputeSRV returns the SRV tag value for a server's long-term Ed25519 public
// key as defined in draft-ietf-ntp-roughtime-10 §6.1.3 and later: the first 32
// bytes of SHA-512(0xff || pubkey).
func ComputeSRV(rootPK ed25519.PublicKey) []byte {
	if len(rootPK) != ed25519.PublicKeySize {
		return nil
	}
	h := sha512.New()
	_, _ = h.Write([]byte{0xff})
	_, _ = h.Write(rootPK)
	return h.Sum(nil)[:32]
}

// SelectVersion picks the best mutually supported version. For Google-Roughtime
// clients (no VER tag, 64-byte nonce), pass an empty clientVersions slice.
func SelectVersion(clientVersions []Version, nonceLen int) (Version, error) {
	if len(clientVersions) == 0 {
		if nonceLen == 64 {
			return VersionGoogle, nil
		}
		return 0, errors.New("protocol: no supported version")
	}
	set := make(map[Version]bool, len(clientVersions))
	for _, v := range clientVersions {
		set[v] = true
	}
	for _, sv := range serverPreference {
		if set[sv] {
			return sv, nil
		}
	}
	return 0, errors.New("protocol: no mutually supported version")
}

// Certificate holds a pre-signed online delegation for each wire format group.
// The CERT bytes are computed once at construction and reused across requests.
type Certificate struct {
	onlineSK ed25519.PrivateKey
	onlinePK ed25519.PublicKey
	rootPK   ed25519.PublicKey
	mint     time.Time
	maxt     time.Time
	cache    map[certCacheKey][]byte
}

// certCacheKey identifies a unique CERT encoding. Different wire groups may
// share a CERT if their delegation context and timestamp encoding match.
type certCacheKey struct {
	ctx   string // delegation signature context string
	micro bool   // true for microsecond timestamps (Google or MJD)
	mjd   bool   // true for MJD encoding, false for Unix epoch
}

// NewCertificate creates and signs an online delegation certificate. The CERT
// bytes for every wire format group are pre-computed and cached.
func NewCertificate(mint, maxt time.Time, onlineSK, rootSK ed25519.PrivateKey) (*Certificate, error) {
	if len(onlineSK) != ed25519.PrivateKeySize || len(rootSK) != ed25519.PrivateKeySize {
		return nil, errors.New("protocol: invalid key size")
	}
	if !mint.Before(maxt) {
		return nil, errors.New("protocol: MINT must be before MAXT")
	}
	c := &Certificate{
		onlineSK: onlineSK,
		onlinePK: onlineSK.Public().(ed25519.PublicKey),
		rootPK:   rootSK.Public().(ed25519.PublicKey),
		mint:     mint,
		maxt:     maxt,
		cache:    make(map[certCacheKey][]byte),
	}
	for _, v := range serverPreference {
		g := wireGroupOf(v, false)
		k := c.cacheKeyFor(g)
		if _, ok := c.cache[k]; ok {
			continue
		}
		b, err := c.buildCERT(g, rootSK)
		if err != nil {
			return nil, err
		}
		c.cache[k] = b
	}
	return c, nil
}

// cacheKeyFor returns the cache key for a wire group's CERT encoding.
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

// certBytes returns the pre-built CERT for a wire group. It panics if the cache
// lacks an entry for g, which would indicate a programming error in
// NewCertificate's pre-computation loop rather than runtime input.
func (c *Certificate) certBytes(g wireGroup) []byte {
	b, ok := c.cache[c.cacheKeyFor(g)]
	if !ok {
		panic(fmt.Sprintf("protocol: certificate cache miss for wire group %d", g))
	}
	return b
}

// buildCERT constructs the CERT message for a wire group.
func (c *Certificate) buildCERT(g wireGroup, rootSK ed25519.PrivateKey) ([]byte, error) {
	mintBuf := encodeTimestamp(c.mint, g)
	maxtBuf := encodeTimestamp(c.maxt, g)

	dele, err := encode(map[uint32][]byte{
		TagPUBK: []byte(c.onlinePK),
		TagMINT: mintBuf[:],
		TagMAXT: maxtBuf[:],
	})
	if err != nil {
		return nil, err
	}

	ctx := delegationContext(g)
	toSign := make([]byte, len(ctx)+len(dele))
	copy(toSign, ctx)
	copy(toSign[len(ctx):], dele)
	sig := ed25519.Sign(rootSK, toSign)

	return encode(map[uint32][]byte{TagSIG: sig, TagDELE: dele})
}

// merkleTree holds the pre-computed root and per-leaf paths for a batch of
// requests. The tree is built in a single bottom-up pass at construction time.
type merkleTree struct {
	rootHash []byte     // root of the Merkle tree
	paths    [][][]byte // paths[i] = sibling hashes from leaf i to root
}

// merkleNodeFirst reports whether the spec's Merkle verification algorithm puts
// the sibling node before the current hash when the INDX bit is 0. groupD05
// through groupD12 (drafts 05–13) use H(0x01 || node || hash); all others use
// H(0x01 || hash || node). Drafts 14–15 originally specified node-first but
// 16–19 switched to hash-first; since groupD14 covers all of drafts 14–19, we
// follow the latest spec (draft-19) and use hash-first for that group.
func merkleNodeFirst(g wireGroup) bool {
	return g >= groupD05 && g <= groupD12
}

// newMerkleTree builds the Merkle tree and per-leaf paths in one bottom-up
// pass. The node-hash argument order matches the verification algorithm for
// each wire group: groupD05–groupD12 use (node, hash) when bit=0, all others
// use (hash, node).
func newMerkleTree(g wireGroup, leafInputs [][]byte) *merkleTree {
	n := len(leafInputs)
	hs := hashSize(g)

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

	// Pad to the next power of two by repeating the last hash
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
		// Record each original leaf's sibling at this level
		for i := range n {
			sib := indices[i] ^ 1 // sibling position
			paths[i] = append(paths[i], level[sib])
			indices[i] /= 2 // move to parent position
		}
		// Combine pairs to form the next level. Drafts 05–13 define bit=0 as
		// H(0x01 || node || hash), so the builder must use (right, left) to
		// match the spec's verification algorithm.
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

// CreateReplies builds signed responses for a batch of requests. If midpoint is
// zero, the timestamp is captured after the Merkle tree is built, immediately
// before signing.
func CreateReplies(ver Version, requests []Request, midpoint time.Time, radius time.Duration, cert *Certificate) ([][]byte, error) {
	if len(requests) == 0 {
		return nil, errors.New("protocol: no requests")
	}

	g := wireGroupOf(ver, requests[0].HasType)

	// All requests in a batch must resolve to the same wire group so the shared
	// SREP, CERT, and Merkle tree are consistent.
	for i := 1; i < len(requests); i++ {
		if wireGroupOf(ver, requests[i].HasType) != g {
			return nil, errors.New("protocol: batch contains requests with incompatible wire groups")
		}
	}

	// Drafts 01–02 place NONC inside the signed SREP, which is shared by every
	// reply in a batch. That construction only admits a single nonce, so reject
	// multi-request batches for those wire groups instead of silently producing
	// a non-compliant response that omits NONC.
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

	// Capture time after tree construction, immediately before signing.
	if midpoint.IsZero() {
		midpoint = time.Now()
	}

	srepBytes, err := buildSREP(ver, g, requests, midpoint, radius, tree.rootHash)
	if err != nil {
		return nil, err
	}

	toSign := make([]byte, len(responseCtx)+len(srepBytes))
	copy(toSign, responseCtx)
	copy(toSign[len(responseCtx):], srepBytes)
	srepSig := ed25519.Sign(cert.onlineSK, toSign)

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

// buildSREP constructs the signed response message containing MIDP, RADI, ROOT,
// and version tags.
func buildSREP(ver Version, g wireGroup, requests []Request, midpoint time.Time, radius time.Duration, rootHash []byte) ([]byte, error) {
	midpBuf := encodeTimestamp(midpoint, g)
	var radiBuf [4]byte
	if g == groupGoogle || usesMJDMicroseconds(g) {
		binary.LittleEndian.PutUint32(radiBuf[:], radiMicroseconds(radius))
	} else {
		binary.LittleEndian.PutUint32(radiBuf[:], radiSeconds(radius, g))
	}

	srepTags := map[uint32][]byte{
		TagRADI: radiBuf[:],
		TagMIDP: midpBuf[:],
		TagROOT: rootHash,
	}
	// Drafts 01–02 place NONC inside SREP. CreateReplies rejects multi-request
	// batches for these groups, so requests[0] is the only nonce here.
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
		srepTags[TagVERS] = supportedVersionsBytes
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

	replyMsg, err := encode(resp)
	if err != nil {
		return nil, fmt.Errorf("protocol: encode reply %d: %w", i, err)
	}
	if usesRoughtimHeader(g) {
		replyMsg = wrapPacket(replyMsg)
	}
	return replyMsg, nil
}

// clientVersionPreference returns the highest version from the preference list
// and its wire group. It is used to determine the wire format for client
// requests.
func clientVersionPreference(versions []Version) (Version, wireGroup, error) {
	if len(versions) == 0 {
		return 0, 0, errors.New("protocol: empty version list")
	}
	best := slices.Max(versions)
	// Drafts 12–19 share wire version 0x8000000c. The client includes TYPE=0 in
	// the request (a draft-14+ feature) to signal support. If the server
	// responds without TYPE, verifyReply falls back to groupD12. Passing
	// hasType=true is harmless for pre-draft-12 versions because wireGroupOf
	// only inspects hasType in the default branch (draft-12+).
	return best, wireGroupOf(best, true), nil
}

// CreateRequest builds a Roughtime request for the given version preferences.
// The returned nonce is needed to verify the server's reply. The optional srv
// parameter includes the SRV tag (drafts 10+) computed by [ComputeSRV].
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

// CreateRequestWithNonce builds a request using a caller-supplied nonce instead
// of generating one randomly. The nonce must match the size required by the
// negotiated protocol version. For document timestamping, callers typically set
// this to a cryptographic hash of the payload to be timestamped.
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
		sorted := make([]Version, len(versions))
		copy(sorted, versions)
		slices.Sort(sorted)
		// Drop duplicates: drafts 12+ require strictly ascending VER values.
		sorted = slices.Compact(sorted)
		vb := make([]byte, 4*len(sorted))
		for i, v := range sorted {
			binary.LittleEndian.PutUint32(vb[4*i:], uint32(v))
		}
		tags[TagVER] = vb

		if g >= groupD14 {
			tags[TagTYPE] = make([]byte, 4) // TYPE=0 (request)
		}
		if len(srv) > 0 && g >= groupD10 {
			tags[TagSRV] = srv
		}
	}

	// All IETF drafts (01+) wrap the message in a 12-byte ROUGHTIM header; pad
	// the inner body to 1012 so the total wire size is 1024. Google-Roughtime
	// has no header and pads to 1024.
	target := 1024
	if usesRoughtimHeader(g) {
		target = 1012
	}

	n := uint32(len(tags))
	headerWithPad := 4 + 4*n + 4*(n+1) // header size after adding one more tag
	var bodySize uint32
	for _, v := range tags {
		bodySize += uint32(len(v))
	}
	shortfall := target - int(headerWithPad+bodySize)
	if shortfall > 0 {
		padTag := TagPAD // Google PAD\xff
		if g >= groupD08 {
			padTag = TagZZZZ // IETF drafts 08+
		} else if g >= groupD01 {
			padTag = tagPADIETF // IETF drafts 01–07 PAD\0
		}
		padLen := shortfall
		padLen -= padLen % 4 // round down to 4-byte alignment
		tags[padTag] = make([]byte, padLen)
	}

	msg, err := encode(tags)
	if err != nil {
		return nil, fmt.Errorf("protocol: encode request: %w", err)
	}

	if usesRoughtimHeader(g) {
		return wrapPacket(msg), nil
	}
	return msg, nil
}

// VerifyReply authenticates a server response and returns the midpoint and
// uncertainty radius. The versions slice must match the one passed to
// [CreateRequest]. For drafts 12+, requestBytes must be the complete request
// packet (Merkle leaves cover the full packet); earlier versions may pass nil.
func VerifyReply(versions []Version, reply, rootPK, nonce, requestBytes []byte) (midpoint time.Time, radius time.Duration, err error) {
	if len(rootPK) != ed25519.PublicKeySize {
		return time.Time{}, 0, errors.New("protocol: invalid public key size")
	}

	bestVer, bestG, err := clientVersionPreference(versions)
	if err != nil {
		return time.Time{}, 0, err
	}

	// Unwrap using the client's best version, then refine if the server
	// included a negotiated VER
	respBytes, err := unwrapReply(reply, bestG)
	if err != nil {
		return time.Time{}, 0, err
	}

	resp, err := Decode(respBytes)
	if err != nil {
		return time.Time{}, 0, fmt.Errorf("protocol: decode reply: %w", err)
	}

	// Decode SREP once and reuse across version resolution, Merkle
	// verification, and the downgrade check. If SREP is absent
	// [verifyReplySigs] will surface the missing-tag error below; if it is
	// present but malformed, fail fast here.
	var srep map[uint32][]byte
	if srepBytes, ok := resp[TagSREP]; ok {
		s, derr := Decode(srepBytes)
		if derr != nil {
			return time.Time{}, 0, fmt.Errorf("protocol: decode SREP: %w", derr)
		}
		srep = s
	}

	// Resolve the server's negotiated version from the response VER tag,
	// falling back to the client's preferred version
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

	_, mintBuf, maxtBuf, err := verifyReplySigs(resp, rootPK, g)
	if err != nil {
		return time.Time{}, 0, err
	}

	midpoint, radius, err = verifyReplySREP(srep, resp, nonce, requestBytes, g)
	if err != nil {
		return time.Time{}, 0, err
	}

	// Drafts 12+ §5.2.5: SREP signs the server's VERS list. Verify the
	// negotiated version is the highest common version to detect downgrades.
	if g >= groupD12 {
		if err := verifyNoVersionDowngrade(srep, versions); err != nil {
			return time.Time{}, 0, err
		}
	}

	return validateDelegationWindow(midpoint, radius, mintBuf, maxtBuf, g)
}

// verifyNoVersionDowngrade decodes the signed VERS list inside SREP and
// confirms the chosen version (also inside SREP) is the highest mutually
// supported version. Drafts 12+ only.
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

// extractResponseVER looks for the negotiated version in a decoded response. It
// prefers signed VER inside SREP (canonical for drafts 12+) over the unsigned
// top-level VER (drafts 01-11), closing a downgrade vector. srep may be nil, in
// which case only the top-level VER is consulted.
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

// unwrapReply strips the ROUGHTIM header for IETF versions or validates its
// absence for Google-Roughtime.
func unwrapReply(reply []byte, g wireGroup) ([]byte, error) {
	if usesRoughtimHeader(g) {
		return unwrapPacket(reply)
	}
	if len(reply) >= 8 && bytes.Equal(reply[:8], packetMagic[:]) {
		return nil, errors.New("protocol: unexpected ROUGHTIM header for Google-Roughtime")
	}
	return reply, nil
}

// verifyReplySigs verifies CERT against rootPK and SREP against the online key,
// returning the online key and raw MINT/MAXT from DELE.
func verifyReplySigs(resp map[uint32][]byte, rootPK ed25519.PublicKey, g wireGroup) (ed25519.PublicKey, []byte, []byte, error) {
	srepBytes, ok := resp[TagSREP]
	if !ok {
		return nil, nil, nil, errors.New("protocol: missing SREP")
	}
	srepSig, ok := resp[TagSIG]
	if !ok || len(srepSig) != ed25519.SignatureSize {
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

	toVerify := make([]byte, len(responseCtx)+len(srepBytes))
	copy(toVerify, responseCtx)
	copy(toVerify[len(responseCtx):], srepBytes)
	if !ed25519.Verify(onlinePK, toVerify, srepSig) {
		return nil, nil, nil, errors.New("protocol: SREP signature verification failed")
	}

	return onlinePK, mintBuf, maxtBuf, nil
}

// verifyReplySREP verifies the Merkle proof and decodes the midpoint and radius
// from a pre-decoded SREP. srep must not be nil; the caller is responsible for
// surfacing missing-SREP errors.
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

	// Verify NONC echo: drafts 01–02 embed NONC inside the signed SREP; drafts
	// 03+ echo it at the top level. If present, NONC MUST match the client's
	// nonce. A missing top-level NONC is tolerated because the Merkle proof
	// already binds the nonce to the signed root, and some real-world servers
	// (e.g. Cloudflare) omit it.
	if noncInSREP(g) {
		srepNonce, ok := srep[TagNONC]
		if !ok || !bytes.Equal(srepNonce, nonce) {
			return time.Time{}, 0, errors.New("protocol: NONC in SREP does not match request nonce")
		}
	} else if hasResponseNONC(g) {
		if echoed, ok := resp[TagNONC]; ok && !bytes.Equal(echoed, nonce) {
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
	return midpoint, radius, nil
}

// validateDelegationWindow checks that the midpoint falls within the MINT/MAXT
// delegation window.
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
		return time.Time{}, 0, fmt.Errorf("protocol: midpoint outside delegation window (MIDP=%s, MINT=%s, MAXT=%s)",
			midpoint.Format(time.RFC3339), mintTime.Format(time.RFC3339), maxtTime.Format(time.RFC3339))
	}
	return midpoint, radius, nil
}

// verifyCert verifies the delegation certificate and returns the online public
// key and raw MINT/MAXT bytes from DELE.
func verifyCert(certBytes []byte, rootPK ed25519.PublicKey, g wireGroup) (ed25519.PublicKey, []byte, []byte, error) {
	certMsg, err := Decode(certBytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("protocol: decode CERT: %w", err)
	}
	deleBytes, ok := certMsg[TagDELE]
	if !ok {
		return nil, nil, nil, errors.New("protocol: missing DELE in CERT")
	}
	certSig, ok := certMsg[TagSIG]
	if !ok || len(certSig) != ed25519.SignatureSize {
		return nil, nil, nil, errors.New("protocol: missing or invalid SIG in CERT")
	}

	ctx := delegationContext(g)
	toVerify := make([]byte, len(ctx)+len(deleBytes))
	copy(toVerify, ctx)
	copy(toVerify[len(ctx):], deleBytes)
	if !ed25519.Verify(rootPK, toVerify, certSig) {
		return nil, nil, nil, errors.New("protocol: DELE signature verification failed")
	}

	dele, err := Decode(deleBytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("protocol: decode DELE: %w", err)
	}
	onlinePK, ok := dele[TagPUBK]
	if !ok || len(onlinePK) != ed25519.PublicKeySize {
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

// verifyMerkle verifies the Merkle proof that leafInput (nonce or full request
// packet) is included in the tree whose root is rootHash.
func verifyMerkle(resp map[uint32][]byte, leafInput, rootHash []byte, g wireGroup) error {
	indexBytes, ok := resp[TagINDX]
	if !ok || len(indexBytes) != 4 {
		return errors.New("protocol: missing or invalid INDX")
	}
	index := binary.LittleEndian.Uint32(indexBytes)

	pathBytes, pathOK := resp[TagPATH] // may be zero-length for single-request batches
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
			// Drafts 05–13: H(0x01 || node || hash); others: H(0x01 || hash ||
			// node).
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

	// all remaining INDX bits must be zero after consuming PATH entries
	if index != 0 {
		return errors.New("protocol: INDX has trailing non-zero bits")
	}

	if !bytes.Equal(hash, rootHash) {
		return errors.New("protocol: Merkle root mismatch")
	}
	return nil
}

// Grease applies a random grease transformation to a signed reply per Section
// 7. It corrupts a signature with incorrect times, drops a mandatory tag,
// replaces the version with an unsupported number, or adds an undefined tag.
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
	// Mode 0 or fallback: corrupt a signature and timestamp.
	greaseCorruptSig(reply, ver)
	return reply
}

// greaseSplit separates a reply into its ROUGHTIM header (nil for Google) and
// message body. Returns nil body on malformed input.
func greaseSplit(reply []byte, ver Version) (header, body []byte) {
	if ver == VersionGoogle {
		return nil, reply
	}
	if len(reply) < 12 {
		return nil, nil
	}
	return reply[:12], reply[12:]
}

// greaseJoin prepends the ROUGHTIM header to a re-encoded body, updating the
// length field to match the new body size.
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

// greaseCorruptSig corrupts a randomly chosen signature (SREP or DELE) and the
// MIDP timestamp in place. MIDP is only corrupted when the signature was, since
// the spec forbids incorrect times with valid signatures.
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
// response message. Returns the modified reply or nil on failure.
func greaseDropTag(reply []byte, ver Version) []byte {
	header, body := greaseSplit(reply, ver)
	if body == nil {
		return nil
	}
	msg, err := Decode(body)
	if err != nil {
		return nil
	}
	candidates := []uint32{TagSIG, TagSREP, TagCERT, TagPATH, TagINDX}
	mrand.Shuffle(len(candidates), func(i, j int) { candidates[i], candidates[j] = candidates[j], candidates[i] })
	for _, tag := range candidates {
		if _, ok := msg[tag]; ok {
			delete(msg, tag)
			out, err := encode(msg)
			if err != nil {
				return nil
			}
			return greaseJoin(header, out)
		}
	}
	return nil
}

// greaseWrongVersion overwrites the top-level VER tag with an unsupported
// version number. Returns nil if no top-level VER exists (Google, drafts 12+).
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

// greaseUndefinedTag adds an undefined tag with random content to the top-level
// response. Clients MUST ignore undefined tags per Section 7.
func greaseUndefinedTag(reply []byte, ver Version) []byte {
	header, body := greaseSplit(reply, ver)
	if body == nil {
		return nil
	}
	msg, err := Decode(body)
	if err != nil {
		return nil
	}
	// GRSE (0x45535247) — not in the IANA Roughtime tag registry.
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

// findTagRange locates the byte range [lo, hi) of a tag's value within a raw
// Roughtime message. Returns false if the tag is not found or the message is
// malformed.
func findTagRange(msg []byte, tag uint32) (lo, hi uint32, ok bool) {
	if len(msg) < 4 {
		return 0, 0, false
	}
	n := binary.LittleEndian.Uint32(msg[:4])
	if n == 0 || n > 512 {
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
