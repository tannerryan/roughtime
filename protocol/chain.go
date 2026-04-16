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
	"hash"
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

// maxChainLinks caps the per-chain link count to prevent CPU-DoS on Verify.
const maxChainLinks = 1024

// ChainLink is one server query in a Roughtime measurement chain (Section 8.4).
// The fields map 1:1 to the malfeasance report JSON format.
type ChainLink struct {
	Rand      []byte // blind (size matches the version's nonce length); nil for the first link
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
// the first link (prevResponse nil), it returns a random nonce with nil rand.
// For subsequent links it returns H(prevResponse || rand) and the rand blind.
// The versions slice selects the nonce size. See [chainHasher] for the hash
// choice.
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

// chainHasher returns the hash function for chain nonce derivation. The chain
// hash always uses SHA-512 because it must produce enough bytes to fill the
// nonce (up to 64 bytes for Google and drafts 01–04). Drafts 02 and 07 use
// SHA-512/256 for Merkle tree hashes, but SHA-512/256 only produces 32 bytes
// which is insufficient for 64-byte nonces.
func chainHasher(_ wireGroup) hash.Hash {
	return sha512.New()
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
		Request:   request,
	}, nil
}

// Append adds a completed link to the chain.
func (c *Chain) Append(link ChainLink) {
	c.Links = append(c.Links, link)
}

// Verify checks nonce linkage, signature validity, and causal ordering (Section
// 8.2). Nonce failures wrap [ErrChainNonce], causal ordering failures wrap
// [ErrCausalOrder], and signature failures return an unwrapped error.
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

		// Determine versions for VerifyReply. An empty VER list in the request
		// indicates Google-Roughtime.
		versions := req.Versions
		if len(versions) == 0 {
			versions = []Version{VersionGoogle}
		}

		// Verify nonce linkage for all links after the first.
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

	// Causal ordering (Section 8.2): lower[i] <= upper[j] for all i < j.
	// Tracking the running max of lower[] makes this O(n).
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

// malfeasanceReport is the JSON structure for malfeasance reporting in drafts
// 12+ (Section 8.4). Drafts 10–11 used a simpler {nonces, responses} format
// (Section 9.3); see malfeasanceReportLegacy.
type malfeasanceReport struct {
	Responses []malfeasanceLink `json:"responses"`
}

// malfeasanceLink is one entry in a drafts-12+ malfeasance report.
type malfeasanceLink struct {
	Rand      string `json:"rand,omitempty"`
	PublicKey string `json:"publicKey"`
	Request   string `json:"request"`
	Response  string `json:"response"`
}

// malfeasanceReportLegacy is the drafts 10–11 format (Section 9.3): parallel
// arrays of rand values and response packets. No request or publicKey fields.
type malfeasanceReportLegacy struct {
	Nonces    []string `json:"nonces"`
	Responses []string `json:"responses"`
}

// MalfeasanceReport serializes the chain as JSON per Section 8.4 (media type
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

// ParseMalfeasanceReport deserializes a JSON malfeasance report into a Chain.
// Both the drafts 12+ format (Section 8.4) and the legacy drafts 10–11 format
// (Section 9.3) are accepted. Legacy reports yield links with Rand and Response
// populated but no Request or PublicKey, so [Chain.Verify] cannot be used on
// them.
func ParseMalfeasanceReport(data []byte) (*Chain, error) {
	// Detect format: the drafts 12+ format has an object in responses[0]; the
	// legacy format has a string in responses[0] and a top-level "nonces" key.
	var probe struct {
		Nonces    json.RawMessage   `json:"nonces"`
		Responses []json.RawMessage `json:"responses"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("protocol: parse malfeasance report: %w", err)
	}
	if len(probe.Responses) == 0 {
		return nil, errors.New("protocol: malfeasance report has no responses")
	}
	if len(probe.Responses) > maxChainLinks {
		return nil, fmt.Errorf("protocol: malfeasance report has %d links (max %d)", len(probe.Responses), maxChainLinks)
	}
	legacy := len(probe.Nonces) > 0 && len(probe.Responses[0]) > 0 && probe.Responses[0][0] == '"'

	if legacy {
		var report malfeasanceReportLegacy
		if err := json.Unmarshal(data, &report); err != nil {
			return nil, fmt.Errorf("protocol: parse legacy malfeasance report: %w", err)
		}
		if len(report.Nonces) != len(report.Responses) {
			return nil, fmt.Errorf("protocol: legacy report nonces/responses length mismatch (%d vs %d)", len(report.Nonces), len(report.Responses))
		}
		c := &Chain{Links: make([]ChainLink, len(report.Responses))}
		for i := range report.Responses {
			var err error
			if report.Nonces[i] != "" {
				if c.Links[i].Rand, err = base64.StdEncoding.DecodeString(report.Nonces[i]); err != nil {
					return nil, fmt.Errorf("protocol: legacy report link %d: decode nonce: %w", i, err)
				}
			}
			if c.Links[i].Response, err = base64.StdEncoding.DecodeString(report.Responses[i]); err != nil {
				return nil, fmt.Errorf("protocol: legacy report link %d: decode response: %w", i, err)
			}
		}
		return c, nil
	}

	var report malfeasanceReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("protocol: parse malfeasance report: %w", err)
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
