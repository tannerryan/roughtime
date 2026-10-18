// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"slices"
)

// Parsing and encoding limits.
const (
	// maxMessageSize is the largest accepted Roughtime message in bytes.
	maxMessageSize = 65535
	// maxEncodeTags caps the tag count in encode.
	maxEncodeTags = 512
	// maxDecodeTags caps the tag count accepted by Decode.
	maxDecodeTags = 512
	// maxVersionList caps generated VER/VERS lists and modern typed input.
	// Historical and untyped draft-12 input remains bounded by maxMessageSize.
	maxVersionList = 32
)

// packetMagic is the 8-byte prefix of the ROUGHTIM packet header.
var packetMagic = [8]byte{'R', 'O', 'U', 'G', 'H', 'T', 'I', 'M'}

// PacketHeaderSize is the length of the ROUGHTIM packet header.
const PacketHeaderSize = 12

// ParsePacketHeader validates the ROUGHTIM magic and returns the declared body
// length.
func ParsePacketHeader(hdr []byte) (bodyLen uint32, err error) {
	if len(hdr) < PacketHeaderSize {
		return 0, errors.New("protocol: header too short")
	}
	if !bytes.Equal(hdr[:8], packetMagic[:]) {
		return 0, errors.New("protocol: bad magic")
	}
	return binary.LittleEndian.Uint32(hdr[8:PacketHeaderSize]), nil
}

// encode serializes a tag-value map with aligned value offsets and tags in
// ascending order. The final value may have any byte length.
func encode(msg map[uint32][]byte) ([]byte, error) {
	return encodeTo(msg, 0)
}

// encodeTo is encode with prefix reserved bytes at the start of the returned
// slice.
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

	// len(msg) > 0 guarded above, so n-1 cannot underflow
	n := uint32(len(tags))
	headerLen := 4 + 4*(n-1) + 4*n
	var valsLen uint32
	for i, tag := range tags {
		v := msg[tag]
		if len(v) > maxMessageSize {
			return nil, fmt.Errorf("protocol: encoded message exceeds %d bytes", maxMessageSize)
		}
		if i < len(tags)-1 && len(v)%4 != 0 {
			return nil, fmt.Errorf("protocol: value length %d not multiple of 4", len(v))
		}
		next := valsLen + uint32(len(v))
		if next < valsLen {
			return nil, errors.New("protocol: total value size overflow")
		}
		valsLen = next
	}

	totalLen := uint64(headerLen) + uint64(valsLen)
	// cap symmetrically with Decode. This also keeps the uint32 accumulators
	// below from wrapping
	if totalLen > maxMessageSize {
		return nil, fmt.Errorf("protocol: encoded message exceeds %d bytes", maxMessageSize)
	}
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

	tBase := 4 + 4*(n-1)
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
	out, err := encodeTo(msg, PacketHeaderSize)
	if err != nil {
		return nil, err
	}
	copy(out[0:len(packetMagic)], packetMagic[:])
	binary.LittleEndian.PutUint32(out[len(packetMagic):PacketHeaderSize], uint32(len(out)-PacketHeaderSize))
	return out, nil
}

// Decode parses a Roughtime message into a tag-value map. Returned slices alias
// data.
func Decode(data []byte) (map[uint32][]byte, error) {
	return decodeMessage(data, false)
}

// DecodeWithVersion parses an unframed message using the version's tag rules.
// Draft 01 allows unique unsorted tags. Returned slices alias data.
func DecodeWithVersion(data []byte, version Version) (map[uint32][]byte, error) {
	if !isRecognizedVersion(version) {
		return nil, fmt.Errorf("protocol: unsupported version %s", version)
	}
	return decodeProfile(data, wireGroupOf(version, true))
}

// decodeMessage permits unsorted unique tags only while identifying draft 01.
func decodeMessage(data []byte, allowUnsorted bool) (map[uint32][]byte, error) {
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

	// n >= 1 guaranteed by the n == 0 branch above
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
	if err := validateHeader(tags, offsets, n, allowUnsorted); err != nil {
		return nil, err
	}

	return decodeValues(data, tags, offsets, headerLen)
}

// validateHeader checks tag uniqueness and aligned monotonic offsets. Except
// for draft 01 discovery, tags must also be strictly ascending.
func validateHeader(tags, offsets []uint32, n uint32, allowUnsorted bool) error {
	if allowUnsorted {
		seen := make(map[uint32]bool, n)
		for _, tag := range tags {
			if seen[tag] {
				return errors.New("protocol: duplicate tag")
			}
			seen[tag] = true
		}
	}
	for i := uint32(1); i < n; i++ {
		if !allowUnsorted && tags[i] <= tags[i-1] {
			return errors.New("protocol: tags not strictly ascending")
		}
		if offsets[i]%4 != 0 || offsets[i] < offsets[i-1] {
			return errors.New("protocol: bad offset")
		}
	}
	return nil
}

// validateMessage applies the selected profile's rules to an already decoded map.
func validateMessage(data []byte, msg map[uint32][]byte, g wireGroup) error {
	n := len(msg)
	if g != groupD01 {
		for i := 1; i < n; i++ {
			if binary.LittleEndian.Uint32(data[4*n+4*i:]) <= binary.LittleEndian.Uint32(data[4*n+4*(i-1):]) {
				return errors.New("protocol: tags not strictly ascending")
			}
		}
	}
	for tag, value := range msg {
		if g == groupGoogle && len(value)%4 != 0 {
			return errors.New("protocol: Google value length not multiple of 4")
		}
		if g >= groupD11 {
			padding := false
			for i := range 4 {
				b := byte(tag >> (8 * i))
				if b == 0 && i > 0 {
					padding = true
				} else if padding || b < 'A' || b > 'Z' {
					return fmt.Errorf("protocol: invalid tag 0x%08x", tag)
				}
			}
		}
	}
	return nil
}

// decodeProfile decodes a message and enforces the selected profile's tag rules.
func decodeProfile(data []byte, g wireGroup) (map[uint32][]byte, error) {
	msg, err := decodeMessage(data, g == groupD01)
	if err == nil {
		err = validateMessage(data, msg, g)
	}
	return msg, err
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

// unwrapPacket validates and strips the ROUGHTIM header.
func unwrapPacket(pkt []byte) ([]byte, error) {
	if len(pkt) < PacketHeaderSize {
		return nil, errors.New("protocol: packet too short")
	}
	if !bytes.Equal(pkt[:len(packetMagic)], packetMagic[:]) {
		return nil, errors.New("protocol: bad magic")
	}
	mlen := binary.LittleEndian.Uint32(pkt[len(packetMagic):PacketHeaderSize])
	bodyLen := uint64(len(pkt) - PacketHeaderSize)
	if bodyLen < uint64(mlen) {
		return nil, errors.New("protocol: truncated message")
	}
	if bodyLen > uint64(mlen) {
		return nil, errors.New("protocol: trailing data after framed message")
	}
	return pkt[PacketHeaderSize : PacketHeaderSize+mlen], nil
}

// unwrapRequest strips the ROUGHTIM header if present, else returns raw.
func unwrapRequest(raw []byte) ([]byte, error) {
	if len(raw) >= PacketHeaderSize && bytes.Equal(raw[:len(packetMagic)], packetMagic[:]) {
		return unwrapPacket(raw)
	}
	return raw, nil
}

// NonceOffsetInRequest returns the byte offset of a 32- or 64-byte NONC value
// in a raw request. Framing is validated, but the inner message is only
// inspected enough to locate NONC. Callers that accept untrusted requests
// should use [ParseRequest] for full validation.
func NonceOffsetInRequest(request []byte) (int, error) {
	msg, err := unwrapRequest(request)
	if err != nil {
		return 0, err
	}
	prefix := len(request) - len(msg)
	lo, hi, ok := findTagRange(msg, TagNONC)
	if !ok {
		return 0, errors.New("protocol: NONC tag not found")
	}
	if n := hi - lo; n != 32 && n != 64 {
		return 0, errors.New("protocol: NONC value has invalid length")
	}
	return prefix + int(lo), nil
}

// findTagRange locates the [lo, hi) byte range of a tag's value within a raw
// message.
func findTagRange(msg []byte, tag uint32) (lo, hi uint32, ok bool) {
	if len(msg) < 4 {
		return 0, 0, false
	}
	n := binary.LittleEndian.Uint32(msg[:4])
	if n == 0 || n > maxDecodeTags {
		return 0, 0, false
	}

	// n != 0 guaranteed above, so (n-1)*4 cannot underflow
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

	// uint64 arithmetic so a crafted offset near 2^32 cannot wrap past the
	// bounds check. Zero-length values are spec-legal, so loAbs may equal hiAbs
	loAbs := uint64(lo) + uint64(valsOff)
	hiAbs := uint64(hi) + uint64(valsOff)
	if hiAbs > uint64(len(msg)) || loAbs > hiAbs {
		return 0, 0, false
	}
	return uint32(loAbs), uint32(hiAbs), true
}
