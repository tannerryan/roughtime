// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// responseCtx is the SREP signature context.
var responseCtx = []byte("RoughTime v1 response signature\x00")

// CreateReplies builds signed responses for a batch of requests.
func CreateReplies(ver Version, requests []Request, midpoint time.Time, radius time.Duration, cert *Certificate) ([][]byte, error) {
	if len(requests) == 0 {
		return nil, errors.New("protocol: no requests")
	}
	if uint64(len(requests)) > maxMerkleLeaves {
		return nil, fmt.Errorf("protocol: batch size %d exceeds Merkle cap 2^32", len(requests))
	}

	g := wireGroupOf(ver, requests[0].HasType)

	ns := nonceSize(g)
	for i := range requests {
		if i > 0 && wireGroupOf(ver, requests[i].HasType) != g {
			return nil, errors.New("protocol: batch contains requests with incompatible wire groups")
		}
		if len(requests[i].Nonce) != ns {
			return nil, fmt.Errorf("protocol: request %d nonce is %d bytes, want %d", i, len(requests[i].Nonce), ns)
		}
	}

	// drafts 01-02 put NONC inside SREP, allowing only one request per batch
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

	// zero midpoint uses the moment of signing; tests and replays needing
	// deterministic output must pass a non-zero midpoint
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

// buildSREP constructs the signed response carrying MIDP, RADI, ROOT, and
// version tags.
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
