// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"bytes"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"
	"time"
)

var (
	// ErrChainNonce indicates a nonce linkage failure in [Chain.Verify].
	ErrChainNonce = errors.New("protocol: chain nonce mismatch")

	// ErrCausalOrder indicates a causal ordering violation in [Chain.Verify].
	ErrCausalOrder = errors.New("protocol: causal ordering violation")
)

// MaxChainLinks is the maximum accepted by verification and report processing.
const MaxChainLinks = 1024

// ChainLink is one server query in a Roughtime measurement chain.
type ChainLink struct {
	// Rand is the blind, nil for the first link.
	Rand []byte
	// PublicKey is the server's long-term key.
	PublicKey []byte
	// Nonce caches the nonce from Request; reports do not serialize it separately.
	Nonce []byte
	// Request is the full request packet.
	Request []byte
	// Response is the full response packet.
	Response []byte
}

// Chain accumulates sequential Roughtime queries for causal ordering and
// malfeasance reporting. It is not safe for concurrent use.
type Chain struct {
	// Links holds the chain's queries in order.
	Links []ChainLink
}

// ChainNonce derives the next link's nonce, returning random bytes for the
// first link. Later links use H(prevResponse || rand), except draft-01, which
// specifies H(H(prevResponse) || rand).
func ChainNonce(prevResponse []byte, entropy io.Reader, versions []Version) (nonce, rand []byte, err error) {
	_, g, err := clientVersionPreference(versions)
	if err != nil {
		return nil, nil, err
	}
	if entropy == nil {
		return nil, nil, errors.New("protocol: nil entropy reader")
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
	nonce = deriveChainNonce(prevResponse, rand, g, ns)
	return nonce, rand, nil
}

// deriveChainNonce applies the version-specific chain hash.
func deriveChainNonce(response, blind []byte, group wireGroup, size int) []byte {
	h := sha512.New()
	if group == groupD01 {
		sum := sha512.Sum512(response)
		_, _ = h.Write(sum[:])
	} else {
		_, _ = h.Write(response)
	}
	_, _ = h.Write(blind)
	return h.Sum(nil)[:size]
}

// NextRequest creates the next chained request. It populates PublicKey, Nonce,
// Request, and Rand for non-first links.
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
	if srv == nil {
		return ChainLink{}, errors.New("protocol: unsupported root key length")
	}
	request, err := CreateRequestWithNonce(versions, nonce, srv)
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
	if srv == nil {
		return ChainLink{}, errors.New("protocol: unsupported root key length")
	}
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

// Bound is the verified midpoint and radius for one chain link.
type Bound struct {
	// Midpoint is the authenticated center of the server's time interval.
	Midpoint time.Time
	// Radius is the authenticated uncertainty around Midpoint.
	Radius time.Duration
}

// Verify checks nonce linkage, signature validity, and causal ordering across
// the chain.
func (c *Chain) Verify() error {
	_, err := c.VerifyBounds()
	return err
}

// VerifyBounds runs the same checks as Verify and returns each link's verified
// midpoint and radius, letting callers avoid a second verification pass.
func (c *Chain) VerifyBounds() ([]Bound, error) {
	if len(c.Links) == 0 {
		return nil, errors.New("protocol: empty chain")
	}
	if len(c.Links) > MaxChainLinks {
		return nil, fmt.Errorf("protocol: chain has %d links (max %d)", len(c.Links), MaxChainLinks)
	}

	bounds := make([]Bound, len(c.Links))

	for i := range c.Links {
		link := &c.Links[i]
		req, err := ParseRequest(link.Request)
		if err != nil {
			return nil, fmt.Errorf("protocol: chain link %d: parse request: %w", i, err)
		}

		versions := req.Versions
		if len(versions) == 0 {
			versions = []Version{VersionGoogle}
		}

		if i > 0 {
			_, g, err := clientVersionPreference(versions)
			if err != nil {
				return nil, fmt.Errorf("protocol: chain link %d: %w", i, err)
			}
			ns := len(req.Nonce)
			if len(link.Rand) != ns {
				return nil, fmt.Errorf("protocol: chain link %d: %w: rand is %d bytes, want %d", i, ErrChainNonce, len(link.Rand), ns)
			}
			want := deriveChainNonce(c.Links[i-1].Response, link.Rand, g, ns)
			if !bytes.Equal(req.Nonce, want) {
				return nil, fmt.Errorf("protocol: chain link %d: %w", i, ErrChainNonce)
			}
		}

		midpoint, radius, err := VerifyReply(versions, link.Response, link.PublicKey, req.Nonce, link.Request)
		if err != nil {
			return nil, fmt.Errorf("protocol: chain link %d: verify: %w", i, err)
		}

		bounds[i] = Bound{Midpoint: midpoint, Radius: radius}
	}

	// require lower[i] <= upper[j] for all i < j. A running max of lower keeps
	// this O(n)
	lower := func(b Bound) time.Time { return b.Midpoint.Add(-b.Radius) }
	maxLowerIdx := 0
	for j := 1; j < len(bounds); j++ {
		if lower(bounds[maxLowerIdx]).After(bounds[j].Midpoint.Add(bounds[j].Radius)) {
			return nil, fmt.Errorf("protocol: chain links %d and %d: %w", maxLowerIdx, j, ErrCausalOrder)
		}
		if lower(bounds[j]).After(lower(bounds[maxLowerIdx])) {
			maxLowerIdx = j
		}
	}

	return bounds, nil
}
