// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"

	"filippo.io/mldsa"
)

// Request holds the parsed fields of a client request; sub-slices alias
// RawPacket.
type Request struct {
	// Nonce is the request nonce.
	Nonce []byte
	// Versions lists the client's offered versions (empty for Google).
	Versions []Version
	// SRV is the optional server-identifier tag (drafts 10+).
	SRV []byte
	// HasType reports whether the request carries a TYPE tag (drafts 14+).
	HasType bool
	// RawPacket is the framed or unframed request bytes.
	RawPacket []byte
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

	// mixed-version VER lists can span both nonce sizes (64 for drafts 01-04,
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

	// drafts 10+ require SRV to be exactly 32 bytes; older drafts MUST ignore
	if maxGroup >= groupD10 {
		if req.SRV != nil && len(req.SRV) != 32 {
			return nil, fmt.Errorf("protocol: SRV length %d invalid for drafts 10+ (want 32)", len(req.SRV))
		}
	} else {
		req.SRV = nil
	}

	// drafts 10+ require ZZZZ to be zero; enforced only on drafts 12+ so
	// non-conformant 10-11 peers still interop
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

// parseOptionalTags extracts VER, SRV, and TYPE into req.
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

// ComputeSRV returns the SRV tag value, the first 32 bytes of SHA-512(0xff ||
// rootPK).
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
// verify the reply.
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

// CreateRequestWithNonce builds a request with a caller-supplied nonce.
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
		sorted = slices.Compact(sorted)
		vb := make([]byte, 4*len(sorted))
		for i, v := range sorted {
			binary.LittleEndian.PutUint32(vb[4*i:], uint32(v))
		}
		tags[TagVER] = vb

		if g >= groupD14 {
			tags[TagTYPE] = make([]byte, 4)
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
