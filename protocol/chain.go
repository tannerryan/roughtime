// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// Sentinel errors returned by [Chain.Verify].
var (
	// ErrChainNonce indicates a nonce linkage failure: the chain is corrupted
	// or forged, not that a server misbehaved.
	ErrChainNonce = errors.New("protocol: chain nonce mismatch")

	// ErrCausalOrder indicates a causal ordering violation (Section 8.2). This
	// is evidence of server malfeasance.
	ErrCausalOrder = errors.New("protocol: causal ordering violation")
)

// ChainLink is one server query in a Roughtime measurement chain (Section
// 8.4.1). The fields map 1:1 to the malfeasance report JSON format.
type ChainLink struct {
	Rand      []byte // 32-byte blind; nil for the first link
	PublicKey []byte // server's long-term Ed25519 public key
	Request   []byte // full request packet including ROUGHTIM header
	Response  []byte // full response packet including ROUGHTIM header
}

// Chain accumulates sequential Roughtime queries for causal ordering
// verification and malfeasance reporting (Sections 8.2, 8.4).
type Chain struct {
	Links []ChainLink
}

// ChainNonce derives the nonce for the next link in a chain (Section 8.2). For
// the first link (prevResponse nil), it returns a random 32-byte nonce with nil
// rand. For subsequent links it returns H(prevResponse || rand) and the 32-byte
// rand, where H is the first 32 bytes of SHA-512.
func ChainNonce(prevResponse []byte, entropy io.Reader) (nonce, rand []byte, err error) {
	if prevResponse == nil {
		nonce = make([]byte, 32)
		if _, err = io.ReadFull(entropy, nonce); err != nil {
			return nil, nil, fmt.Errorf("protocol: read entropy: %w", err)
		}
		return nonce, nil, nil
	}
	rand = make([]byte, 32)
	if _, err = io.ReadFull(entropy, rand); err != nil {
		return nil, nil, fmt.Errorf("protocol: read entropy: %w", err)
	}
	h := sha512.New()
	h.Write(prevResponse)
	h.Write(rand)
	nonce = h.Sum(nil)[:32]
	return nonce, rand, nil
}

// NextRequest creates the next chained request. The returned ChainLink has
// Rand, PublicKey, and Request populated; the caller must set Response after
// the round-trip, then pass the link to [Chain.Append].
func (c *Chain) NextRequest(versions []Version, rootPK ed25519.PublicKey, entropy io.Reader) (ChainLink, error) {
	var prevResp []byte
	if n := len(c.Links); n > 0 {
		prevResp = c.Links[n-1].Response
		if len(prevResp) == 0 {
			return ChainLink{}, errors.New("protocol: previous chain link has no response")
		}
	}

	nonce, blind, err := ChainNonce(prevResp, entropy)
	if err != nil {
		return ChainLink{}, err
	}

	srv := ComputeSRV(rootPK)
	_, request, err := CreateRequestWithSRV(versions, bytes.NewReader(nonce), srv)
	if err != nil {
		return ChainLink{}, fmt.Errorf("protocol: create chained request: %w", err)
	}

	return ChainLink{
		Rand:      blind,
		PublicKey: append([]byte(nil), rootPK...),
		Request:   request,
	}, nil
}

// Append adds a completed link to the chain.
func (c *Chain) Append(link ChainLink) {
	c.Links = append(c.Links, link)
}

// Verify checks nonce linkage, signature validity, and causal ordering (Section
// 8.2). Nonce or signature failures return a plain error. Causal ordering
// failures wrap [ErrCausalOrder].
func (c *Chain) Verify() error {
	if len(c.Links) == 0 {
		return errors.New("protocol: empty chain")
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

		// Verify nonce linkage for all links after the first.
		if i > 0 {
			if len(link.Rand) != 32 {
				return fmt.Errorf("protocol: chain link %d: %w: rand is %d bytes, want 32", i, ErrChainNonce, len(link.Rand))
			}
			h := sha512.New()
			h.Write(c.Links[i-1].Response)
			h.Write(link.Rand)
			want := h.Sum(nil)[:32]
			if !bytes.Equal(req.Nonce, want) {
				return fmt.Errorf("protocol: chain link %d: %w", i, ErrChainNonce)
			}
		}

		// Determine versions for VerifyReply. An empty VER list in the request
		// indicates Google-Roughtime.
		versions := req.Versions
		if len(versions) == 0 {
			versions = []Version{VersionGoogle}
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

	// Check causal ordering for all pairs (i, j) where i < j.
	for i := range len(results) {
		for j := i + 1; j < len(results); j++ {
			if results[i].lower.After(results[j].upper) {
				return fmt.Errorf("protocol: chain links %d and %d: %w", i, j, ErrCausalOrder)
			}
		}
	}

	return nil
}

// malfeasanceReport is the JSON structure for Section 8.4.1.
type malfeasanceReport struct {
	Responses []malfeasanceLink `json:"responses"`
}

// malfeasanceLink is one entry in a malfeasance report.
type malfeasanceLink struct {
	Rand      string `json:"rand,omitempty"`
	PublicKey string `json:"publicKey"`
	Request   string `json:"request"`
	Response  string `json:"response"`
}

// MalfeasanceReport serializes the chain as JSON per Section 8.4.1 (media type
// application/roughtime-malfeasance+json).
func (c *Chain) MalfeasanceReport() ([]byte, error) {
	if len(c.Links) == 0 {
		return nil, errors.New("protocol: empty chain")
	}
	report := malfeasanceReport{
		Responses: make([]malfeasanceLink, len(c.Links)),
	}
	for i, link := range c.Links {
		ml := malfeasanceLink{
			PublicKey: base64.StdEncoding.EncodeToString(link.PublicKey),
			Request:   base64.StdEncoding.EncodeToString(link.Request),
			Response:  base64.StdEncoding.EncodeToString(link.Response),
		}
		if link.Rand != nil {
			ml.Rand = base64.StdEncoding.EncodeToString(link.Rand)
		}
		report.Responses[i] = ml
	}
	return json.Marshal(report)
}

// ParseMalfeasanceReport deserializes a JSON malfeasance report (Section 8.4.1)
// into a Chain for verification.
func ParseMalfeasanceReport(data []byte) (*Chain, error) {
	const maxChainLinks = 1024

	var report malfeasanceReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("protocol: parse malfeasance report: %w", err)
	}
	if len(report.Responses) == 0 {
		return nil, errors.New("protocol: malfeasance report has no responses")
	}
	if len(report.Responses) > maxChainLinks {
		return nil, fmt.Errorf("protocol: malfeasance report has %d links (max %d)", len(report.Responses), maxChainLinks)
	}

	c := &Chain{Links: make([]ChainLink, len(report.Responses))}
	for i, ml := range report.Responses {
		var err error

		if ml.Rand != "" {
			if c.Links[i].Rand, err = base64.StdEncoding.DecodeString(ml.Rand); err != nil {
				return nil, fmt.Errorf("protocol: report link %d: decode rand: %w", i, err)
			}
		}
		if c.Links[i].PublicKey, err = base64.StdEncoding.DecodeString(ml.PublicKey); err != nil {
			return nil, fmt.Errorf("protocol: report link %d: decode publicKey: %w", i, err)
		}
		if c.Links[i].Request, err = base64.StdEncoding.DecodeString(ml.Request); err != nil {
			return nil, fmt.Errorf("protocol: report link %d: decode request: %w", i, err)
		}
		if c.Links[i].Response, err = base64.StdEncoding.DecodeString(ml.Response); err != nil {
			return nil, fmt.Errorf("protocol: report link %d: decode response: %w", i, err)
		}
	}

	return c, nil
}
