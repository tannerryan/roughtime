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

// Wire-format limits.
const (
	// maxMessageSize is the largest accepted Roughtime message in bytes.
	maxMessageSize = 65535
	// maxEncodeTags caps the tag count in encode.
	maxEncodeTags = 512
	// maxDecodeTags caps the tag count accepted by Decode.
	maxDecodeTags = 512
	// maxVersionList caps VER/VERS list length.
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

// encode serializes a tag-value map with values 4-byte aligned and tags in
// ascending order.
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
	out, err := encodeTo(msg, 12)
	if err != nil {
		return nil, err
	}
	copy(out[0:8], packetMagic[:])
	binary.LittleEndian.PutUint32(out[8:12], uint32(len(out)-12))
	return out, nil
}

// Decode parses a Roughtime message into a tag-value map; returned slices alias
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
	if err := validateHeader(tags, offsets, n); err != nil {
		return nil, err
	}

	return decodeValues(data, tags, offsets, headerLen)
}

// validateHeader checks tags are strictly ascending and offsets aligned and
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

// unwrapRequest strips the ROUGHTIM header if present, else returns raw.
func unwrapRequest(raw []byte) ([]byte, error) {
	if len(raw) >= 12 && bytes.Equal(raw[:8], packetMagic[:]) {
		return unwrapPacket(raw)
	}
	return raw, nil
}

// NonceOffsetInRequest returns the byte offset of a 32- or 64-byte NONC value
// in a raw request.
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
	// bounds check; zero-length values are spec-legal so loAbs may equal hiAbs
	loAbs := uint64(lo) + uint64(valsOff)
	hiAbs := uint64(hi) + uint64(valsOff)
	if hiAbs > uint64(len(msg)) || loAbs > hiAbs {
		return 0, 0, false
	}
	return uint32(loAbs), uint32(hiAbs), true
}
