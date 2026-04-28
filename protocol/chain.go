// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"bytes"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"io"
	"time"
)

var (
	// ErrChainNonce indicates a nonce linkage failure in [Chain.Verify].
	ErrChainNonce = errors.New("protocol: chain nonce mismatch")

	// ErrCausalOrder indicates a causal ordering violation in [Chain.Verify].
	ErrCausalOrder = errors.New("protocol: causal ordering violation")
)

// maxChainLinks caps the link count of a parsed malfeasance report.
const maxChainLinks = 1024

// ChainLink is one server query in a Roughtime measurement chain.
type ChainLink struct {
	// Rand is the blind, nil for the first link.
	Rand []byte
	// PublicKey is the server's long-term key.
	PublicKey []byte
	// Nonce is the nonce sent in Request; not serialized.
	Nonce []byte
	// Request is the full request packet.
	Request []byte
	// Response is the full response packet.
	Response []byte
}

// Chain accumulates sequential Roughtime queries for causal ordering and
// malfeasance reporting; not safe for concurrent use.
type Chain struct {
	// Links holds the chain's queries in order.
	Links []ChainLink
}

// ChainNonce derives the next link's nonce, returning random bytes for the
// first link or H(prevResponse || rand) thereafter.
func ChainNonce(prevResponse []byte, entropy io.Reader, versions []Version) (nonce, rand []byte, err error) {
	_, g, err := clientVersionPreference(versions)
	if err != nil {
		return nil, nil, err
	}
	ns := nonceSize(g)

	if prevResponse == nil {
		nonce = make([]byte, ns)
		if _, err = io.ReadFull(entropy, nonce); err != nil {
			return nil, nil, fmt.Errorf("protocol: read entropy: %w", err)
		}
		return nonce, nil, nil
	}
	rand = make([]byte, ns)
	if _, err = io.ReadFull(entropy, rand); err != nil {
		return nil, nil, fmt.Errorf("protocol: read entropy: %w", err)
	}
	h := chainHasher(g)
	h.Write(prevResponse)
	h.Write(rand)
	nonce = h.Sum(nil)[:ns]
	return nonce, rand, nil
}

// chainHasher returns the chain-nonce hasher; SHA-512 is used for every group
// since drafts 01-04 require up to 64 bytes.
func chainHasher(_ wireGroup) hash.Hash {
	return sha512.New()
}

// NextRequest creates the next chained request with Rand, PublicKey, Nonce, and
// Request populated.
func (c *Chain) NextRequest(versions []Version, rootPK []byte, entropy io.Reader) (ChainLink, error) {
	var prevResp []byte
	if n := len(c.Links); n > 0 {
		prevResp = c.Links[n-1].Response
		if len(prevResp) == 0 {
			return ChainLink{}, errors.New("protocol: previous chain link has no response")
		}
	}

	nonce, blind, err := ChainNonce(prevResp, entropy, versions)
	if err != nil {
		return ChainLink{}, err
	}

	srv := ComputeSRV(rootPK)
	_, request, err := CreateRequest(versions, bytes.NewReader(nonce), srv)
	if err != nil {
		return ChainLink{}, fmt.Errorf("protocol: create chained request: %w", err)
	}

	return ChainLink{
		Rand:      blind,
		PublicKey: append([]byte(nil), rootPK...),
		Nonce:     nonce,
		Request:   request,
	}, nil
}

// NextRequestWithNonce creates the first chained request with a caller-supplied
// nonce.
func (c *Chain) NextRequestWithNonce(versions []Version, rootPK, nonce []byte) (ChainLink, error) {
	if len(c.Links) > 0 {
		return ChainLink{}, errors.New("protocol: NextRequestWithNonce only valid for the first chain link")
	}
	srv := ComputeSRV(rootPK)
	request, err := CreateRequestWithNonce(versions, nonce, srv)
	if err != nil {
		return ChainLink{}, fmt.Errorf("protocol: create chained request: %w", err)
	}
	return ChainLink{
		PublicKey: append([]byte(nil), rootPK...),
		Nonce:     append([]byte(nil), nonce...),
		Request:   request,
	}, nil
}

// Append adds a completed link to the chain.
func (c *Chain) Append(link ChainLink) {
	c.Links = append(c.Links, link)
}

// Verify checks nonce linkage, signature validity, and causal ordering across
// the chain.
func (c *Chain) Verify() error {
	if len(c.Links) == 0 {
		return errors.New("protocol: empty chain")
	}
	if len(c.Links) > maxChainLinks {
		return fmt.Errorf("protocol: chain has %d links (max %d)", len(c.Links), maxChainLinks)
	}

	type timeResult struct {
		lower time.Time // MIDP - RADI
		upper time.Time // MIDP + RADI
	}
	results := make([]timeResult, len(c.Links))

	for i := range c.Links {
		link := &c.Links[i]
		req, err := ParseRequest(link.Request)
		if err != nil {
			return fmt.Errorf("protocol: chain link %d: parse request: %w", i, err)
		}

		versions := req.Versions
		if len(versions) == 0 {
			versions = []Version{VersionGoogle}
		}

		if i > 0 {
			_, g, err := clientVersionPreference(versions)
			if err != nil {
				return fmt.Errorf("protocol: chain link %d: %w", i, err)
			}
			ns := len(req.Nonce)
			if len(link.Rand) != ns {
				return fmt.Errorf("protocol: chain link %d: %w: rand is %d bytes, want %d", i, ErrChainNonce, len(link.Rand), ns)
			}
			h := chainHasher(g)
			h.Write(c.Links[i-1].Response)
			h.Write(link.Rand)
			want := h.Sum(nil)[:ns]
			if !bytes.Equal(req.Nonce, want) {
				return fmt.Errorf("protocol: chain link %d: %w", i, ErrChainNonce)
			}
		}

		midpoint, radius, err := VerifyReply(versions, link.Response, link.PublicKey, req.Nonce, link.Request)
		if err != nil {
			return fmt.Errorf("protocol: chain link %d: verify: %w", i, err)
		}

		results[i] = timeResult{
			lower: midpoint.Add(-radius),
			upper: midpoint.Add(radius),
		}
	}

	// require lower[i] <= upper[j] for all i < j; running max of lower keeps
	// this O(n)
	maxLowerIdx := 0
	for j := 1; j < len(results); j++ {
		if results[maxLowerIdx].lower.After(results[j].upper) {
			return fmt.Errorf("protocol: chain links %d and %d: %w", maxLowerIdx, j, ErrCausalOrder)
		}
		if results[j].lower.After(results[maxLowerIdx].lower) {
			maxLowerIdx = j
		}
	}

	return nil
}
