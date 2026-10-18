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

// responseCtx is the draft and Google SREP signature context.
var responseCtx = []byte("RoughTime v1 response signature\x00")

// ReplyOptions selects compatibility mode, advertised versions, and draft Merkle ordering.
type ReplyOptions struct {
	// Mode selects strict or flex protocol support.
	Mode Mode
	// SupportedVersions restricts signed VERS to a nonempty subset of the
	// certificate's versions that includes the selected version. Nil uses the
	// certificate's full set. This supports listeners with different profiles
	// sharing one delegation.
	SupportedVersions []Version
	// Draft14NodeFirst emits the node-first Merkle convention specified by
	// drafts 14-15. Drafts 16-19 use hash-first under the same VersionDraft12
	// and TYPE=1 identifiers. This option requires flex mode.
	Draft14NodeFirst bool
}

// CreateReplies builds signed responses for a batch of requests. A zero
// midpoint uses the current time. Radius includes midpoint rounding and is
// rounded up to whole seconds. The input radius must be positive.
// This function accepts only RFC version 1. Use
// [CreateRepliesWithOptions] for flex draft replies.
func CreateReplies(ver Version, requests []Request, midpoint time.Time, radius time.Duration, cert *Certificate) ([][]byte, error) {
	return CreateRepliesWithOptions(ver, requests, midpoint, radius, cert, ReplyOptions{})
}

// CreateRepliesWithOptions builds signed responses with explicit choices for
// wire behavior that the negotiated version cannot disambiguate.
func CreateRepliesWithOptions(ver Version, requests []Request, midpoint time.Time, radius time.Duration, cert *Certificate, opts ReplyOptions) ([][]byte, error) {
	if err := checkVersions(opts.Mode, []Version{ver}); err != nil {
		return nil, err
	}
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
	supportedVERS := cert.signedVERS()
	if opts.SupportedVersions != nil {
		versions, err := normalizeCertificateVersions(opts.SupportedVersions, cert.scheme)
		if err != nil {
			return nil, err
		}
		if !slices.Contains(versions, ver) {
			return nil, errors.New("protocol: advertised versions exclude selected version")
		}
		for _, v := range versions {
			if !cert.supportsVersion(v) {
				return nil, fmt.Errorf("protocol: advertised version %s is not configured", v)
			}
		}
		supportedVERS = encodeCertificateVERS(versions)
	}

	ns := nonceSize(g)
	for i := range requests {
		if usesFullPacketLeaf(g) {
			parsed, err := ParseRequestWithMode(requests[i].RawPacket, opts.Mode)
			if err != nil {
				return nil, fmt.Errorf("protocol: request %d: %w", i, err)
			}
			if !bytes.Equal(parsed.Nonce, requests[i].Nonce) || !slices.Equal(parsed.Versions, requests[i].Versions) || !bytes.Equal(parsed.SRV, requests[i].SRV) || parsed.HasType != requests[i].HasType {
				return nil, fmt.Errorf("protocol: request %d fields do not match packet", i)
			}
		}
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
	if !usesRFCFormat(g) && (midpoint.Before(minPlausibleMidpoint) || midpoint.After(maxPlausibleMidpoint)) {
		return nil, errors.New("protocol: midpoint outside plausible calendar range")
	}
	if radius < 0 {
		return nil, errors.New("protocol: radius must not be negative")
	}
	if g >= groupD10 && radius == 0 {
		return nil, errors.New("protocol: second-based radius must not be zero")
	}
	timeUnit := time.Second
	if g == groupGoogle || usesMJDMicroseconds(g) {
		timeUnit = time.Microsecond
	}
	loss := midpoint.Sub(midpoint.Truncate(timeUnit))
	if radius > time.Duration(1<<63-1)-loss {
		return nil, errors.New("protocol: radius overflow after midpoint rounding")
	}
	wireRadius, err := encodeRadius(radius+loss, g)
	if err != nil {
		return nil, err
	}
	encodedMidpoint := encodeTimestamp(midpoint, g)
	certMint := encodeTimestamp(cert.mint, g)
	certMaxt := encodeTimestamp(cert.maxt, g)
	if _, _, err := validateDelegationWindow(midpoint.Truncate(timeUnit), time.Duration(wireRadius)*timeUnit, encodedMidpoint[:], certMint[:], certMaxt[:], g); err != nil {
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

	srepBytes, err := buildSREP(ver, g, requests, midpoint, wireRadius, tree.rootHash, supportedVERS)
	if err != nil {
		return nil, err
	}

	var srepSig []byte
	switch cert.scheme {
	case schemeEd25519:
		if len(cert.edOnlineSK) != ed25519.PrivateKeySize {
			return nil, errors.New("protocol: invalid Ed25519 online signing key")
		}
		srepSig = signEd25519(cert.edOnlineSK, srepBytes, responseContext(g))
	case schemeMLDSA44:
		if cert.pqOnlineSK == nil {
			return nil, errors.New("protocol: nil ML-DSA-44 online signing key")
		}
		srepSig, err = signMLDSA44(cert.pqOnlineSK, srepBytes, responseContext(g))
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
func buildSREP(ver Version, g wireGroup, requests []Request, midpoint time.Time, radius uint32, rootHash, supportedVERS []byte) ([]byte, error) {
	midpBuf := encodeTimestamp(midpoint, g)
	var radiBuf [4]byte
	binary.LittleEndian.PutUint32(radiBuf[:], radius)

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
		// Nonce-leaf profiles allow caller-built requests without RawPacket.
		if usesFullPacketLeaf(wireGroupOf(ver, req.HasType)) {
			return errors.New("missing RawPacket for full-packet Merkle leaf")
		}
		if ver == VersionGoogle {
			if len(req.Versions) != 0 {
				return errors.New("google-format request unexpectedly contains versions")
			}
			return nil
		}
		// An optional offer list must include the selected nonce-leaf version.
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
