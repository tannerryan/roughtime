// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

// Package protocol implements the Roughtime wire protocol for server-side use.
//
// Supported versions:
//
//	Google-Roughtime                        (no version number)
//	draft-ietf-ntp-roughtime-00             0x80000001
//	draft-ietf-ntp-roughtime-01             0x80000001
//	draft-ietf-ntp-roughtime-02             0x80000002
//	draft-ietf-ntp-roughtime-03             0x80000003
//	draft-ietf-ntp-roughtime-04             0x80000004
//	draft-ietf-ntp-roughtime-05             0x80000005
//	draft-ietf-ntp-roughtime-06             0x80000006
//	draft-ietf-ntp-roughtime-07             0x80000007
//	draft-ietf-ntp-roughtime-08             0x80000008
//	draft-ietf-ntp-roughtime-09             0x80000009
//	draft-ietf-ntp-roughtime-10             0x8000000a
//	draft-ietf-ntp-roughtime-11             0x8000000b
//	draft-ietf-ntp-roughtime-12             0x8000000c
//	draft-ietf-ntp-roughtime-13             0x8000000c
//	draft-ietf-ntp-roughtime-14             0x8000000c
//	draft-ietf-ntp-roughtime-15             0x8000000c
//	draft-ietf-ntp-roughtime-16             0x8000000c
//	draft-ietf-ntp-roughtime-17             0x8000000c
//	draft-ietf-ntp-roughtime-18             0x8000000c
//	draft-ietf-ntp-roughtime-19             0x8000000c
package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"slices"
	"time"
)

// Version is a Roughtime protocol version number. The zero value represents
// Google-Roughtime, which does not use a VER tag on the wire.
type Version uint32

const (
	VersionGoogle  Version = 0          // Google-Roughtime (no VER tag)
	VersionDraft01 Version = 0x80000001 // draft-ietf-ntp-roughtime-01
	VersionDraft02 Version = 0x80000002 // editorial revision of 01
	VersionDraft03 Version = 0x80000003 // editorial revision of 01
	VersionDraft04 Version = 0x80000004 // editorial revision of 01
	VersionDraft05 Version = 0x80000005 // draft-ietf-ntp-roughtime-05
	VersionDraft06 Version = 0x80000006 // draft-ietf-ntp-roughtime-06
	VersionDraft07 Version = 0x80000007 // draft-ietf-ntp-roughtime-07
	VersionDraft08 Version = 0x80000008 // draft-ietf-ntp-roughtime-08
	VersionDraft09 Version = 0x80000009 // editorial revision of 08
	VersionDraft10 Version = 0x8000000a // draft-ietf-ntp-roughtime-10
	VersionDraft11 Version = 0x8000000b // editorial revision of 10
	VersionDraft12 Version = 0x8000000c // draft-ietf-ntp-roughtime-12 through 19
)

// wireGroup identifies a set of drafts that share the same on-wire behaviour.
type wireGroup int

const (
	groupGoogle wireGroup = iota // Google-Roughtime
	groupD01                     // Drafts 01–04
	groupD06                     // Drafts 05–07
	groupD08                     // Drafts 08–09
	groupD10                     // Drafts 10–11
	groupD12                     // Drafts 12–13 (0x8000000c, no TYPE)
	groupD14                     // Drafts 14–19 (0x8000000c, TYPE present)
)

// wireGroupOf returns the wire format group for a version and TYPE presence.
func wireGroupOf(v Version, hasType bool) wireGroup {
	switch {
	case v == VersionGoogle:
		return groupGoogle
	case v <= VersionDraft04:
		return groupD01
	case v <= VersionDraft07:
		return groupD06
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

// Tag constants from IANA Roughtime tag registry.
const (
	tagSIG  uint32 = 0x00474953 // SIG\0
	tagVER  uint32 = 0x00524556 // VER\0
	tagSRV  uint32 = 0x00565253 // SRV\0
	tagNONC uint32 = 0x434e4f4e // NONC
	tagDELE uint32 = 0x454c4544 // DELE
	tagTYPE uint32 = 0x45505954 // TYPE
	tagPATH uint32 = 0x48544150 // PATH
	tagRADI uint32 = 0x49444152 // RADI
	tagPUBK uint32 = 0x4b425550 // PUBK
	tagMIDP uint32 = 0x5044494d // MIDP
	tagSREP uint32 = 0x50455253 // SREP
	tagVERS uint32 = 0x53524556 // VERS
	tagROOT uint32 = 0x544f4f52 // ROOT
	tagCERT uint32 = 0x54524543 // CERT
	tagMINT uint32 = 0x544e494d // MINT
	tagMAXT uint32 = 0x5458414d // MAXT
	tagINDX uint32 = 0x58444e49 // INDX
	tagZZZZ uint32 = 0x5a5a5a5a // ZZZZ (client padding; unused by server)
)

// packetMagic is the 8-byte ROUGHTIM header present in all IETF draft packets.
var packetMagic = [8]byte{'R', 'O', 'U', 'G', 'H', 'T', 'I', 'M'}

// hashSize returns the Merkle hash output length: 64 for Google (SHA-512), 32
// for all IETF drafts (SHA-512 truncated to 256 bits).
func hashSize(g wireGroup) int {
	if g == groupGoogle {
		return 64
	}
	return 32
}

// usesRoughtimHeader reports whether packets use the 12-byte ROUGHTIM header.
func usesRoughtimHeader(g wireGroup) bool { return g != groupGoogle }

// usesMJDMicroseconds reports whether timestamps use MJD microsecond encoding
// (drafts 01–06). Google uses plain Unix microseconds; drafts 08+ use Unix
// seconds.
func usesMJDMicroseconds(g wireGroup) bool { return g >= groupD01 && g <= groupD06 }

// usesFullPacketLeaf reports whether the Merkle tree leaf is computed over the
// full request packet (drafts 12+) rather than just the nonce.
func usesFullPacketLeaf(g wireGroup) bool { return g >= groupD12 }

// noncInSREP reports whether NONC is placed inside SREP (drafts 01–04). Drafts
// 06+ moved NONC to the top-level response.
func noncInSREP(g wireGroup) bool { return g == groupD01 }

// hasResponseVER reports whether the response includes a top-level VER tag.
func hasResponseVER(g wireGroup) bool { return g >= groupD01 }

// hasResponseNONC reports whether the response includes a top-level NONC echo.
func hasResponseNONC(g wireGroup) bool { return g >= groupD06 }

// hasSREPVERS reports whether SREP includes VER and VERS tags (drafts 12+).
func hasSREPVERS(g wireGroup) bool { return g >= groupD12 }

// Signature context strings.
var (
	delegationCtxOld = []byte("RoughTime v1 delegation signature--\x00") // Google through draft 11
	delegationCtxNew = []byte("RoughTime v1 delegation signature\x00")   // drafts 12+
	responseCtx      = []byte("RoughTime v1 response signature\x00")     // all versions
)

// delegationContext returns the delegation signature context for a wire group.
func delegationContext(g wireGroup) []byte {
	if g >= groupD12 {
		return delegationCtxNew
	}
	return delegationCtxOld
}

// timeToMJDMicro encodes a time as an MJD microsecond timestamp (drafts 01–06).
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

	return (mjd << 40) | usInDay
}

// encodeTimestamp encodes a time in the format appropriate for a wire group:
// Unix microseconds for Google, MJD microseconds for drafts 01–06, or Unix
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
// drafts 01–06). The result is clamped to [1, MaxUint32].
func radiMicroseconds(d time.Duration) uint32 {
	us := d.Microseconds()
	if us > math.MaxUint32 {
		return math.MaxUint32
	}
	if us < 1 {
		return 1
	}
	return uint32(us)
}

// radiSeconds encodes a duration as a RADI value in seconds (drafts 08+).
// Drafts 10+ require RADI >= 3; earlier drafts clamp to >= 1.
func radiSeconds(d time.Duration, g wireGroup) uint32 {
	sec := int64(d / time.Second)
	if sec > math.MaxUint32 {
		return math.MaxUint32
	}
	if g >= groupD10 {
		if sec < 3 {
			return 3
		}
	} else {
		if sec < 1 {
			return 1
		}
	}
	return uint32(sec)
}

// leafHash computes H(0x00 || data). It streams into the hasher to avoid
// allocating and copying the full input (which can be up to 1280 bytes for
// draft-12+ full-packet leaves).
func leafHash(g wireGroup, data []byte) []byte {
	h := sha512.New()
	h.Write([]byte{0x00})
	h.Write(data)
	return h.Sum(nil)[:hashSize(g)]
}

// nodeHash computes H(0x01 || left || right). It streams into the hasher to
// avoid allocating a temporary concatenation buffer.
func nodeHash(g wireGroup, left, right []byte) []byte {
	h := sha512.New()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)[:hashSize(g)]
}

// Encode serializes a tag-value map into a Roughtime message. All values must
// have lengths that are multiples of 4 bytes. Tags are emitted in ascending
// numeric order as required by the wire format.
func Encode(msg map[uint32][]byte) ([]byte, error) {
	if len(msg) == 0 {
		return nil, errors.New("protocol: empty message")
	}
	tags := make([]uint32, 0, len(msg))
	for t := range msg {
		tags = append(tags, t)
	}
	slices.Sort(tags)

	n := uint32(len(tags))
	headerLen := 4 + 4*(n-1) + 4*n
	var valsLen uint32
	for _, v := range msg {
		if len(v)%4 != 0 {
			return nil, fmt.Errorf("protocol: value length %d not multiple of 4", len(v))
		}
		valsLen += uint32(len(v))
	}

	out := make([]byte, headerLen+valsLen)
	binary.LittleEndian.PutUint32(out[0:4], n)

	off := uint32(0)
	for i := uint32(1); i < n; i++ {
		off += uint32(len(msg[tags[i-1]]))
		binary.LittleEndian.PutUint32(out[4+4*(i-1):4+4*i], off)
	}

	tBase := 4 + 4*(n-1)
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

// maxDecodeTags limits the tag count accepted by [Decode] to prevent integer
// overflow in header length calculations and excessive memory allocation from
// untrusted input.
const maxDecodeTags = 512

// Decode parses a Roughtime message into a tag-value map. The returned byte
// slices are sub-slices of data and share its underlying memory.
func Decode(data []byte) (map[uint32][]byte, error) {
	if len(data) < 4 {
		return nil, errors.New("protocol: message too short")
	}
	n := binary.LittleEndian.Uint32(data[0:4])
	if n == 0 {
		return nil, errors.New("protocol: zero tags")
	}
	if n > maxDecodeTags {
		return nil, errors.New("protocol: tag count exceeds limit")
	}

	headerLen := 4 + 4*(n-1) + 4*n
	if uint32(len(data)) < headerLen {
		return nil, errors.New("protocol: header truncated")
	}

	offsets := make([]uint32, n)
	for i := uint32(1); i < n; i++ {
		offsets[i] = binary.LittleEndian.Uint32(data[4+4*(i-1) : 4+4*i])
	}
	tBase := 4 + 4*(n-1)
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

// WrapPacket prepends the 12-byte ROUGHTIM header (8-byte magic + 4-byte
// message length).
func WrapPacket(message []byte) []byte {
	pkt := make([]byte, 12+len(message))
	copy(pkt[0:8], packetMagic[:])
	binary.LittleEndian.PutUint32(pkt[8:12], uint32(len(message)))
	copy(pkt[12:], message)
	return pkt
}

// UnwrapPacket validates and strips the 12-byte ROUGHTIM header.
func UnwrapPacket(pkt []byte) ([]byte, error) {
	if len(pkt) < 12 {
		return nil, errors.New("protocol: packet too short")
	}
	for i := range 8 {
		if pkt[i] != packetMagic[i] {
			return nil, errors.New("protocol: bad magic")
		}
	}
	mlen := binary.LittleEndian.Uint32(pkt[8:12])
	if uint32(len(pkt)-12) < mlen {
		return nil, errors.New("protocol: truncated message")
	}
	return pkt[12 : 12+mlen], nil
}

// Request holds the parsed fields of a client request.
type Request struct {
	Nonce     []byte    // 32 bytes (IETF draft 06+) or 64 bytes (Google, drafts 01–04)
	Versions  []Version // from VER tag; empty for Google/draft-00
	SRV       []byte    // optional; nil if absent
	HasType   bool      // true when request contains TYPE=0 (drafts 14+)
	RawPacket []byte    // complete UDP payload for Merkle leaf (drafts 12+)
}

// ParseRequest auto-detects Google vs IETF framing and extracts request fields.
// The Nonce and SRV fields are sub-slices of raw and share its memory.
func ParseRequest(raw []byte) (*Request, error) {
	req := &Request{RawPacket: raw}

	msgBytes, err := unwrapRequest(raw)
	if err != nil {
		return nil, err
	}

	msg, err := Decode(msgBytes)
	if err != nil {
		return nil, fmt.Errorf("protocol: decode request: %w", err)
	}

	nonce, ok := msg[tagNONC]
	if !ok {
		return nil, errors.New("protocol: missing NONC")
	}
	if len(nonce) != 32 && len(nonce) != 64 {
		return nil, fmt.Errorf("protocol: bad nonce length %d", len(nonce))
	}
	req.Nonce = nonce
	parseOptionalTags(req, msg)

	return req, nil
}

// unwrapRequest strips the ROUGHTIM header if present, otherwise returns raw.
func unwrapRequest(raw []byte) ([]byte, error) {
	if len(raw) >= 12 && bytes.Equal(raw[:8], packetMagic[:]) {
		return UnwrapPacket(raw)
	}
	return raw, nil
}

// parseOptionalTags extracts VER, SRV, and TYPE from a decoded message.
func parseOptionalTags(req *Request, msg map[uint32][]byte) {
	if vb, ok := msg[tagVER]; ok && len(vb) >= 4 && len(vb)%4 == 0 {
		for i := 0; i < len(vb); i += 4 {
			req.Versions = append(req.Versions, Version(binary.LittleEndian.Uint32(vb[i:i+4])))
		}
	}
	if srv, ok := msg[tagSRV]; ok {
		req.SRV = srv
	}
	if tb, ok := msg[tagTYPE]; ok && len(tb) == 4 && binary.LittleEndian.Uint32(tb) == 0 {
		req.HasType = true
	}
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

// SupportedVersions returns all IETF version numbers in ascending order.
func SupportedVersions() []Version {
	return supportedVersions
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
	case g <= groupD06:
		return certCacheKey{ctx: ctx, micro: true, mjd: true}
	default:
		return certCacheKey{ctx: ctx, micro: false, mjd: false}
	}
}

// certBytes returns the pre-built CERT for a wire group.
func (c *Certificate) certBytes(g wireGroup) []byte {
	return c.cache[c.cacheKeyFor(g)]
}

// buildCERT constructs the CERT message for a wire group.
func (c *Certificate) buildCERT(g wireGroup, rootSK ed25519.PrivateKey) ([]byte, error) {
	mintBuf := encodeTimestamp(c.mint, g)
	maxtBuf := encodeTimestamp(c.maxt, g)

	dele, err := Encode(map[uint32][]byte{
		tagPUBK: []byte(c.onlinePK),
		tagMINT: mintBuf[:],
		tagMAXT: maxtBuf[:],
	})
	if err != nil {
		return nil, err
	}

	ctx := delegationContext(g)
	toSign := make([]byte, len(ctx)+len(dele))
	copy(toSign, ctx)
	copy(toSign[len(ctx):], dele)
	sig := ed25519.Sign(rootSK, toSign)

	return Encode(map[uint32][]byte{tagSIG: sig, tagDELE: dele})
}

// merkleTree holds the pre-computed root and per-leaf paths for a batch of
// requests. The tree is built in a single bottom-up pass at construction time.
type merkleTree struct {
	rootHash []byte     // root of the Merkle tree
	paths    [][][]byte // paths[i] = sibling hashes from leaf i to root
}

// newMerkleTree builds the Merkle tree and extracts the root and all paths in a
// single pass. Client verification walks INDX bits from LSB: if bit is 0, hash
// = H(0x01 || hash || node); otherwise hash = H(0x01 || node || hash).
func newMerkleTree(g wireGroup, leafInputs [][]byte) *merkleTree {
	n := len(leafInputs)
	hs := hashSize(g)

	if n == 0 {
		return &merkleTree{rootHash: make([]byte, hs)}
	}

	level := make([][]byte, n)
	for i, d := range leafInputs {
		level[i] = leafHash(g, d)
	}

	if n == 1 {
		return &merkleTree{rootHash: level[0], paths: make([][][]byte, 1)}
	}

	indices := make([]int, n)
	paths := make([][][]byte, n)
	for i := range indices {
		indices[i] = i
	}

	for len(level) > 1 {
		for i := range n {
			sib := indices[i] ^ 1
			if sib < len(level) {
				paths[i] = append(paths[i], level[sib])
			}
			indices[i] /= 2
		}
		next := make([][]byte, 0, (len(level)+1)/2)
		for j := 0; j < len(level); j += 2 {
			if j+1 < len(level) {
				next = append(next, nodeHash(g, level[j], level[j+1]))
			} else {
				next = append(next, level[j])
			}
		}
		level = next
	}

	return &merkleTree{rootHash: level[0], paths: paths}
}

// CreateReplies builds signed responses for a batch of requests.
func CreateReplies(ver Version, requests []Request, midpoint time.Time, radius time.Duration, cert *Certificate) ([][]byte, error) {
	if len(requests) == 0 {
		return nil, errors.New("protocol: no requests")
	}

	g := wireGroupOf(ver, requests[0].HasType)

	// Build Merkle tree
	leafData := make([][]byte, len(requests))
	for i := range requests {
		if usesFullPacketLeaf(g) {
			leafData[i] = requests[i].RawPacket
		} else {
			leafData[i] = requests[i].Nonce
		}
	}
	tree := newMerkleTree(g, leafData)

	srepBytes, err := buildSREP(ver, g, requests, midpoint, radius, tree.rootHash)
	if err != nil {
		return nil, err
	}

	// Sign SREP
	toSign := make([]byte, len(responseCtx)+len(srepBytes))
	copy(toSign, responseCtx)
	copy(toSign[len(responseCtx):], srepBytes)
	srepSig := ed25519.Sign(cert.onlineSK, toSign)

	certBytes := cert.certBytes(g)

	// Build per-request responses
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
		tagRADI: radiBuf[:],
		tagMIDP: midpBuf[:],
		tagROOT: rootHash,
	}
	if noncInSREP(g) && len(requests) == 1 {
		srepTags[tagNONC] = requests[0].Nonce
	}
	if hasSREPVERS(g) {
		var vBuf [4]byte
		binary.LittleEndian.PutUint32(vBuf[:], uint32(ver))
		srepTags[tagVER] = vBuf[:]
		srepTags[tagVERS] = supportedVersionsBytes
	}

	b, err := Encode(srepTags)
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
		tagSIG:  srepSig,
		tagSREP: srepBytes,
		tagCERT: certBytes,
		tagPATH: pathBytes,
		tagINDX: indxBuf[:],
	}
	if hasResponseVER(g) {
		var vBuf [4]byte
		binary.LittleEndian.PutUint32(vBuf[:], uint32(ver))
		resp[tagVER] = vBuf[:]
	}
	if hasResponseNONC(g) {
		resp[tagNONC] = req.Nonce
	}
	if req.HasType {
		var tBuf [4]byte
		binary.LittleEndian.PutUint32(tBuf[:], 1)
		resp[tagTYPE] = tBuf[:]
	}

	replyMsg, err := Encode(resp)
	if err != nil {
		return nil, fmt.Errorf("protocol: encode reply %d: %w", i, err)
	}
	if usesRoughtimHeader(g) {
		replyMsg = WrapPacket(replyMsg)
	}
	return replyMsg, nil
}
