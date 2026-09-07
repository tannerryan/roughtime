// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"time"
)

// responseCtx is the SREP signature context.
var responseCtx = []byte("RoughTime v1 response signature\x00")

// ReplyOptions controls wire choices that cannot be inferred from the shared
// version number.
type ReplyOptions struct {
	// Draft14NodeFirst emits the node-first Merkle convention specified by
	// drafts 14-15. Drafts 16-19 use hash-first under the same VersionDraft12
	// and TYPE=1 identifiers, which remains the default for compatibility.
	Draft14NodeFirst bool
}

// CreateReplies builds signed responses for a batch of requests. A zero
// midpoint uses the current time. Radius is rounded up to the wire unit and its
// required floor. Midpoints outside years 2000–3000 are rejected. For the
// ambiguous TYPE=1 wire group it emits the draft-16+ hash-first Merkle form.
// Use [CreateRepliesWithOptions] for a draft-14/15 peer.
func CreateReplies(ver Version, requests []Request, midpoint time.Time, radius time.Duration, cert *Certificate) ([][]byte, error) {
	return CreateRepliesWithOptions(ver, requests, midpoint, radius, cert, ReplyOptions{})
}

// CreateRepliesWithOptions builds signed responses with explicit choices for
// wire behavior that the negotiated version cannot disambiguate.
func CreateRepliesWithOptions(ver Version, requests []Request, midpoint time.Time, radius time.Duration, cert *Certificate, opts ReplyOptions) ([][]byte, error) {
	if len(requests) == 0 {
		return nil, errors.New("protocol: no requests")
	}
	if cert == nil {
		return nil, errors.New("protocol: nil certificate")
	}
	if !isRecognizedVersion(ver) {
		return nil, fmt.Errorf("protocol: unsupported response version %s", ver)
	}
	if uint64(len(requests)) > maxMerkleLeaves {
		return nil, fmt.Errorf("protocol: batch size %d exceeds Merkle cap 2^32", len(requests))
	}

	g := wireGroupOf(ver, requests[0].HasType)
	if opts.Draft14NodeFirst && g != groupD14 {
		return nil, errors.New("protocol: Draft14NodeFirst requires VersionDraft12 with TYPE")
	}
	if !cert.supportsVersion(ver) {
		return nil, fmt.Errorf("protocol: certificate is not configured for version %s", ver)
	}

	ns := nonceSize(g)
	for i := range requests {
		if i > 0 && wireGroupOf(ver, requests[i].HasType) != g {
			return nil, errors.New("protocol: batch contains requests with incompatible wire groups")
		}
		if len(requests[i].Nonce) != ns {
			return nil, fmt.Errorf("protocol: request %d nonce is %d bytes, want %d", i, len(requests[i].Nonce), ns)
		}
		if err := validateRequestForReply(ver, requests[i], cert); err != nil {
			return nil, fmt.Errorf("protocol: request %d: %w", i, err)
		}
	}

	// drafts 01-02 put NONC inside SREP, allowing only one request per batch
	if noncInSREP(g) && len(requests) > 1 {
		return nil, errors.New("protocol: drafts 01-02 do not support batched responses")
	}

	// reject a cert/version scheme mismatch before doing tree work
	if schemeOfGroup(g) != cert.scheme {
		return nil, fmt.Errorf("protocol: version %s requires %s cert, have %s",
			ver, schemeOfGroup(g), cert.scheme)
	}

	// A zero midpoint requests self-timestamping. Validate all explicit and
	// generated values before signing so this function cannot emit a reply its
	// own verifier rejects.
	if midpoint.IsZero() {
		midpoint = time.Now()
	}
	if err := validateTimestampEncoding(midpoint, g); err != nil {
		return nil, fmt.Errorf("protocol: invalid midpoint: %w", err)
	}
	if midpoint.Before(minPlausibleMidpoint) || midpoint.After(maxPlausibleMidpoint) {
		return nil, errors.New("protocol: midpoint outside plausible calendar range")
	}
	if radius < 0 {
		return nil, errors.New("protocol: radius must not be negative")
	}
	if g >= groupD10 && radius == 0 {
		return nil, errors.New("protocol: radius must not be zero for drafts 10+")
	}
	if _, err := encodeRadius(radius, g); err != nil {
		return nil, err
	}
	certMint := encodeTimestamp(cert.mint, g)
	certMaxt := encodeTimestamp(cert.maxt, g)
	if _, _, err := validateDelegationWindow(midpoint, radius, certMint[:], certMaxt[:], g); err != nil {
		return nil, fmt.Errorf("protocol: refusing to sign unverifiable midpoint: %w", err)
	}

	leafData := make([][]byte, len(requests))
	for i := range requests {
		if usesFullPacketLeaf(g) {
			leafData[i] = requests[i].RawPacket
		} else {
			leafData[i] = requests[i].Nonce
		}
	}
	tree := newMerkleTreeWithOrder(g, leafData, merkleNodeFirst(g) || opts.Draft14NodeFirst)

	srepBytes, err := buildSREP(ver, g, requests, midpoint, radius, tree.rootHash, cert.signedVERS())
	if err != nil {
		return nil, err
	}

	var srepSig []byte
	switch cert.scheme {
	case schemeEd25519:
		if len(cert.edOnlineSK) != ed25519.PrivateKeySize {
			return nil, errors.New("protocol: invalid Ed25519 online signing key")
		}
		srepSig = signEd25519(cert.edOnlineSK, srepBytes, responseCtx)
	case schemeMLDSA44:
		if cert.pqOnlineSK == nil {
			return nil, errors.New("protocol: nil ML-DSA-44 online signing key")
		}
		srepSig, err = signMLDSA44(cert.pqOnlineSK, srepBytes, responseCtx)
		if err != nil {
			return nil, fmt.Errorf("protocol: ML-DSA-44 sign SREP: %w", err)
		}
	default:
		return nil, errSchemeNotSupported
	}

	certBytes := cert.certBytes(g)
	if len(certBytes) == 0 {
		return nil, fmt.Errorf("protocol: certificate unavailable for wire group %d", g)
	}

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
func buildSREP(ver Version, g wireGroup, requests []Request, midpoint time.Time, radius time.Duration, rootHash, supportedVERS []byte) ([]byte, error) {
	midpBuf := encodeTimestamp(midpoint, g)
	var radiBuf [4]byte
	wireRadius, err := encodeRadius(radius, g)
	if err != nil {
		return nil, err
	}
	binary.LittleEndian.PutUint32(radiBuf[:], wireRadius)

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
		if len(supportedVERS) == 0 || len(supportedVERS)%4 != 0 {
			return nil, errors.New("protocol: empty or malformed configured VERS")
		}
		var vBuf [4]byte
		binary.LittleEndian.PutUint32(vBuf[:], uint32(ver))
		srepTags[TagVER] = vBuf[:]
		srepTags[TagVERS] = supportedVERS
	}

	b, err := encode(srepTags)
	if err != nil {
		return nil, fmt.Errorf("protocol: encode SREP: %w", err)
	}
	return b, nil
}

// validateRequestForReply checks the fields needed to build a valid reply.
func validateRequestForReply(ver Version, req Request, cert *Certificate) error {
	if wireGroupOf(ver, req.HasType) >= groupD10 && len(req.SRV) != 0 && !bytes.Equal(req.SRV, ComputeSRV(cert.rootPublicKey())) {
		return errors.New("request SRV does not identify this certificate root")
	}
	if len(req.RawPacket) == 0 {
		// Before draft 12 the Merkle leaf is the nonce, so the historical API
		// permitted callers to construct Request values without retaining the
		// encoded packet. Drafts 12+ authenticate the full packet and must have
		// it.
		if usesFullPacketLeaf(wireGroupOf(ver, req.HasType)) {
			return errors.New("missing RawPacket for full-packet Merkle leaf")
		}
		if ver == VersionGoogle {
			if len(req.Versions) != 0 {
				return errors.New("google-format request unexpectedly contains versions")
			}
			return nil
		}
		// Historically Request{Nonce: ...} was sufficient for nonce-leaf IETF
		// versions. If a caller supplies an offer list, keep validating it.
		if len(req.Versions) > 0 && !slices.Contains(req.Versions, ver) {
			return fmt.Errorf("selected version %s was not offered", ver)
		}
		return nil
	}
	if ver == VersionGoogle {
		if len(req.Versions) != 0 {
			return errors.New("google-format request unexpectedly contains versions")
		}
	} else if !slices.Contains(req.Versions, ver) {
		return fmt.Errorf("selected version %s was not offered", ver)
	}
	return nil
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
