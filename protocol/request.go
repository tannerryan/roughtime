// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"
)

// Request holds the parsed fields of a client request. Sub-slices alias
// RawPacket.
type Request struct {
	// Nonce is the request nonce.
	Nonce []byte
	// Versions lists the client's offered versions. It is empty for Google and
	// may be omitted on caller-built pre-draft-12 Request values passed
	// directly to CreateReplies for backward compatibility.
	Versions []Version
	// SRV is the optional 32-byte server identifier (drafts 10+ and ML-DSA-44).
	SRV []byte
	// HasType reports whether the request carries TYPE=0.
	HasType bool
	// RawPacket is the framed or unframed request. CreateReplies requires it
	// for drafts 12+ and ML-DSA-44. Earlier nonce-leaf versions retain support
	// for caller-built values.
	RawPacket []byte
}

// RequestOptions controls request encoding and legacy packet sizing.
type RequestOptions struct {
	// OmitTYPE emits the draft-12/13 request form without TYPE. The default
	// includes TYPE=0 for draft-14+ compatibility.
	OmitTYPE bool
	// LegacyPacketSize pads framed requests to a historical total size: 1024
	// bytes, or 8192 for ML-DSA-44. The default pads the body to that size. Use
	// this only for deployed legacy interoperability.
	LegacyPacketSize bool
}

// ParseRequest auto-detects Google vs IETF framing and extracts request fields.
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
	if slices.Contains(req.Versions, VersionGoogle) {
		return nil, errors.New("protocol: VER list contains VersionGoogle (0)")
	}

	maxVer := VersionGoogle
	hasKnownVersion := false
	for _, v := range req.Versions {
		if isRecognizedVersion(v) && v > maxVer {
			maxVer = v
			hasKnownVersion = true
		}
	}
	maxGroup := wireGroupOf(maxVer, false)

	// drafts 10-11 forbid duplicates, drafts 12+ require strictly ascending
	if hasKnownVersion && maxGroup >= groupD12 {
		for i := 1; i < len(req.Versions); i++ {
			if req.Versions[i] <= req.Versions[i-1] {
				return nil, errors.New("protocol: VER list not strictly ascending")
			}
		}
	} else if hasKnownVersion && maxGroup >= groupD10 {
		seen := make(map[Version]struct{}, len(req.Versions))
		for _, v := range req.Versions {
			if _, dup := seen[v]; dup {
				return nil, errors.New("protocol: VER list contains duplicates")
			}
			seen[v] = struct{}{}
		}
	}

	// Every recognized offered version must be compatible with the request's
	// nonce size. Signature schemes may coexist because SRV selects the server
	// identity and therefore the applicable scheme.
	nonceOK := false
	if len(req.Versions) == 0 {
		nonceOK = len(req.Nonce) == nonceSize(groupGoogle)
	} else if !hasKnownVersion {
		// Preserve forward-compatible parsing. A server will ignore an offer
		// containing no implemented version, but parsing must not guess an
		// unknown version's nonce rules.
		nonceOK = true
	} else if hasKnownVersion {
		nonceOK = true
		for _, v := range req.Versions {
			if !isRecognizedVersion(v) {
				continue
			}
			if v == VersionGoogle || len(req.Nonce) != nonceSize(wireGroupOf(v, false)) {
				nonceOK = false
				break
			}
		}
	}
	if !nonceOK {
		return nil, fmt.Errorf("protocol: nonce length %d matches no offered version", len(req.Nonce))
	}

	// Drafts 10+ require a present SRV to be 32 bytes. Older drafts ignore it.
	if hasKnownVersion && maxGroup >= groupD10 {
		if req.SRV != nil && len(req.SRV) != 32 {
			return nil, fmt.Errorf("protocol: SRV length %d invalid for drafts 10+ (want 32)", len(req.SRV))
		}
	} else {
		req.SRV = nil
	}

	// Drafts 10+ require ZZZZ to contain only zero bytes. Drafts 08-09 merely
	// recommend zero padding, so tolerate other contents for those versions.
	if hasKnownVersion && maxGroup >= groupD10 {
		if pad, ok := msg[TagZZZZ]; ok {
			for _, b := range pad {
				if b != 0 {
					return nil, errors.New("protocol: ZZZZ padding contains non-zero byte")
				}
			}
		}
	}

	// Draft 14 introduced TYPE under the shared draft-12 wire version. Ignore
	// it for older and unknown versions.
	if slices.Contains(req.Versions, VersionDraft12) || slices.Contains(req.Versions, VersionMLDSA44) {
		if tb, ok := msg[TagTYPE]; ok {
			if len(tb) != 4 {
				return nil, errors.New("protocol: TYPE tag must be 4 bytes")
			}
			if v := binary.LittleEndian.Uint32(tb); v != 0 {
				return nil, fmt.Errorf("protocol: TYPE=%d in request (must be 0)", v)
			}
			req.HasType = true
		}
	}
	// Draft 13 introduced the 32-entry limit, but shares its untyped wire
	// identifier with draft 12. Accept longer untyped lists for historical
	// interoperability. TYPE identifies modern input where the limit applies.
	if req.HasType && len(req.Versions) > maxVersionList {
		return nil, fmt.Errorf("protocol: VER tag has %d entries (max %d)", len(req.Versions), maxVersionList)
	}

	return req, nil
}

// parseOptionalTags extracts VER and SRV into req. ParseRequest interprets TYPE
// only after it knows whether an applicable version was offered.
func parseOptionalTags(req *Request, msg map[uint32][]byte) error {
	if vb, ok := msg[TagVER]; ok {
		if len(vb) == 0 || len(vb)%4 != 0 {
			return errors.New("protocol: VER tag length invalid")
		}
		count := len(vb) / 4
		req.Versions = make([]Version, 0, count)
		for i := 0; i < len(vb); i += 4 {
			req.Versions = append(req.Versions, Version(binary.LittleEndian.Uint32(vb[i:i+4])))
		}
	}
	if srv, ok := msg[TagSRV]; ok {
		req.SRV = srv
	}
	return nil
}

// ComputeSRV returns the SRV tag value, the first 32 bytes of SHA-512(0xff ||
// rootPK). It returns nil unless rootPK is an Ed25519 or ML-DSA-44 key.
func ComputeSRV(rootPK []byte) []byte {
	if len(rootPK) != ed25519.PublicKeySize && len(rootPK) != mldsa.MLDSA44PublicKeySize {
		return nil
	}
	h := sha512.New()
	_, _ = h.Write([]byte{0xff})
	_, _ = h.Write(rootPK)
	return h.Sum(nil)[:32]
}

// CreateRequest builds a Roughtime request and returns the nonce needed to
// verify the reply. Versions whose nonce size is incompatible with the highest
// preferred version are omitted from the encoded offer.
func CreateRequest(versions []Version, entropy io.Reader, srv []byte) (nonce, request []byte, err error) {
	return CreateRequestWithOptions(versions, entropy, srv, RequestOptions{})
}

// CreateRequestWithOptions builds a request using opts.
func CreateRequestWithOptions(versions []Version, entropy io.Reader, srv []byte, opts RequestOptions) (nonce, request []byte, err error) {
	best, g, err := clientVersionPreference(versions)
	if err != nil {
		return nil, nil, err
	}
	if opts.OmitTYPE && best != VersionDraft12 {
		return nil, nil, errors.New("protocol: OmitTYPE requires VersionDraft12 as the preferred version")
	}
	if entropy == nil {
		return nil, nil, errors.New("protocol: nil entropy reader")
	}

	ns := nonceSize(g)
	nonce = make([]byte, ns)
	if _, err := io.ReadFull(entropy, nonce); err != nil {
		return nil, nil, fmt.Errorf("protocol: read entropy: %w", err)
	}

	request, err = createRequestFromNonce(g, versions, nonce, srv, opts)
	return nonce, request, err
}

// CreateRequestWithNonce builds a request with a caller-supplied nonce.
// Versions incompatible with the nonce length are omitted.
func CreateRequestWithNonce(versions []Version, nonce []byte, srv []byte) ([]byte, error) {
	return CreateRequestWithNonceOptions(versions, nonce, srv, RequestOptions{})
}

// CreateRequestWithNonceOptions builds a caller-nonce request using opts.
func CreateRequestWithNonceOptions(versions []Version, nonce []byte, srv []byte, opts RequestOptions) ([]byte, error) {
	best, g, err := clientVersionPreference(versions)
	if err != nil {
		return nil, err
	}
	if opts.OmitTYPE && best != VersionDraft12 {
		return nil, errors.New("protocol: OmitTYPE requires VersionDraft12 as the preferred version")
	}
	if len(nonce) != nonceSize(g) {
		return nil, fmt.Errorf("protocol: nonce length %d, want %d", len(nonce), nonceSize(g))
	}
	return createRequestFromNonce(g, versions, nonce, srv, opts)
}

// createRequestFromNonce assembles a request packet from a pre-built nonce.
func createRequestFromNonce(g wireGroup, versions []Version, nonce, srv []byte, opts RequestOptions) ([]byte, error) {
	if g >= groupD10 && len(srv) != 0 && len(srv) != 32 {
		return nil, fmt.Errorf("protocol: SRV length %d invalid for drafts 10+ (want 32)", len(srv))
	}
	tags := map[uint32][]byte{TagNONC: nonce}

	if g != groupGoogle {
		sorted := make([]Version, 0, len(versions))
		for _, v := range versions {
			if v == VersionGoogle || nonceSize(wireGroupOf(v, true)) != nonceSize(g) {
				continue
			}
			sorted = append(sorted, v)
		}
		slices.Sort(sorted)
		sorted = slices.Compact(sorted)
		if len(sorted) > maxVersionList {
			return nil, fmt.Errorf("protocol: VER list has %d entries (max %d)", len(sorted), maxVersionList)
		}
		vb := make([]byte, 4*len(sorted))
		for i, v := range sorted {
			binary.LittleEndian.PutUint32(vb[4*i:], uint32(v))
		}
		tags[TagVER] = vb

		if g >= groupD14 && !opts.OmitTYPE {
			tags[TagTYPE] = make([]byte, 4)
		}
		if len(srv) > 0 && g >= groupD10 {
			tags[TagSRV] = srv
		}
	}

	// IETF request messages are padded to at least 1024 bytes. The ROUGHTIM
	// framing header is additional. ML-DSA-44 replies are much larger, so an
	// offer containing it uses the full 8192-byte request-body cap.
	target := 1024
	if pqOffered(versions) {
		target = 8192
	}
	if opts.LegacyPacketSize && usesRoughtimHeader(g) {
		target -= PacketHeaderSize
	}

	n := uint32(len(tags))
	headerWithPad := 4 + 4*n + 4*(n+1)
	var bodySize uint32
	for _, v := range tags {
		bodySize += uint32(len(v))
	}
	shortfall := target - int(headerWithPad+bodySize)
	if shortfall > 0 {
		padTag := TagPAD
		if g >= groupD08 {
			padTag = TagZZZZ
		} else if g >= groupD01 {
			padTag = tagPADIETF
		}
		padLen := shortfall
		padLen -= padLen % 4
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

// pqOffered reports whether the non-Google offer set includes ML-DSA-44.
func pqOffered(versions []Version) bool {
	return slices.Contains(versions, VersionMLDSA44)
}
