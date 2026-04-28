// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package roughtime

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/tannerryan/roughtime/protocol"
)

// MaxProofBytes caps both the on-disk and decompressed proof size.
const MaxProofBytes = 4 * 1024 * 1024

// gzipMagic is the gzip header (RFC 1952 §2.3).
var gzipMagic = []byte{0x1f, 0x8b}

// Proof is a verifiable Roughtime timestamp proof formed by a causal chain of
// signed witness queries.
type Proof struct {
	chain *protocol.Chain
}

// ProofLink is the per-witness attestation data exposed by [(*Proof).Links].
type ProofLink struct {
	// PublicKey is the witness's Ed25519 or experimental ML-DSA-44 root key.
	PublicKey []byte
	// Version is the negotiated wire version.
	Version protocol.Version
	// Nonce is the signed nonce, equal to the seed for link 0.
	Nonce []byte
	// Midpoint is the verified server midpoint timestamp.
	Midpoint time.Time
	// Radius is the verified server uncertainty half-width.
	Radius time.Duration
}

// Window returns [Midpoint-Radius, Midpoint+Radius].
func (l ProofLink) Window() (lower, upper time.Time) {
	return l.Midpoint.Add(-l.Radius), l.Midpoint.Add(l.Radius)
}

// ParseProof loads a stored proof from gzipped or raw malfeasance-report JSON.
func ParseProof(data []byte) (*Proof, error) {
	if len(data) > MaxProofBytes {
		return nil, fmt.Errorf("roughtime: proof is %d bytes (max %d)", len(data), MaxProofBytes)
	}
	if bytes.HasPrefix(data, gzipMagic) {
		gr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("roughtime: proof gunzip: %w", err)
		}
		defer gr.Close()
		inflated, err := io.ReadAll(io.LimitReader(gr, MaxProofBytes+1))
		if err != nil {
			return nil, fmt.Errorf("roughtime: proof gunzip: %w", err)
		}
		if len(inflated) > MaxProofBytes {
			return nil, fmt.Errorf("roughtime: decompressed proof exceeds %d bytes", MaxProofBytes)
		}
		data = inflated
	}
	chain, err := protocol.ParseMalfeasanceReport(data)
	if err != nil {
		return nil, fmt.Errorf("roughtime: %w", err)
	}
	return &Proof{chain: chain}, nil
}

// MarshalGzip returns the proof as gzipped malfeasance JSON that round-trips
// through [ParseProof].
func (p *Proof) MarshalGzip() ([]byte, error) {
	if p == nil || p.chain == nil {
		return nil, errors.New("roughtime: nil proof")
	}
	report, err := p.chain.MalfeasanceReport()
	if err != nil {
		return nil, fmt.Errorf("roughtime: %w", err)
	}
	// gzip-to-buffer cannot fail
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	_, _ = gw.Write(report)
	_ = gw.Close()
	return buf.Bytes(), nil
}

// MarshalJSON returns the proof as raw malfeasance JSON satisfying
// [encoding/json.Marshaler].
func (p *Proof) MarshalJSON() ([]byte, error) {
	if p == nil || p.chain == nil {
		return nil, errors.New("roughtime: nil proof")
	}
	return p.chain.MalfeasanceReport()
}

// Verify checks signatures, nonce linkage, and causal ordering across the
// chain.
func (p *Proof) Verify() error {
	if p == nil || p.chain == nil {
		return errors.New("roughtime: nil proof")
	}
	return p.chain.Verify()
}

// Len returns the number of chain links, or 0 for a nil proof.
func (p *Proof) Len() int {
	if p == nil || p.chain == nil {
		return 0
	}
	return len(p.chain.Links)
}

// Links returns per-link attestation data with verified midpoint and radius.
func (p *Proof) Links() ([]ProofLink, error) {
	if p == nil || p.chain == nil {
		return nil, errors.New("roughtime: nil proof")
	}
	out := make([]ProofLink, len(p.chain.Links))
	for i, link := range p.chain.Links {
		req, err := protocol.ParseRequest(link.Request)
		if err != nil {
			return nil, fmt.Errorf("roughtime: link %d: parse request: %w", i, err)
		}
		midpoint, radius, err := protocol.VerifyReply(linkVersions(req), link.Response, link.PublicKey, req.Nonce, link.Request)
		if err != nil {
			return nil, fmt.Errorf("roughtime: link %d: %w", i, err)
		}
		// Google replies have no VER tag; zero equals protocol.VersionGoogle.
		ver, _ := protocol.ExtractVersion(link.Response)
		out[i] = ProofLink{
			PublicKey: append([]byte(nil), link.PublicKey...),
			Version:   ver,
			Nonce:     append([]byte(nil), req.Nonce...),
			Midpoint:  midpoint,
			Radius:    radius,
		}
	}
	return out, nil
}

// Trust errors if any link is signed by a key not in trusted.
func (p *Proof) Trust(trusted []Server) error {
	if p == nil || p.chain == nil {
		return errors.New("roughtime: nil proof")
	}
	known := make(map[string]struct{}, len(trusted))
	for _, s := range trusted {
		known[string(s.PublicKey)] = struct{}{}
	}
	for i, link := range p.chain.Links {
		if _, ok := known[string(link.PublicKey)]; !ok {
			return fmt.Errorf("roughtime: link %d signed by untrusted key", i)
		}
	}
	return nil
}

// SeedNonce returns the first link's nonce, the value bound to the timestamped
// payload.
func (p *Proof) SeedNonce() ([]byte, error) {
	if p == nil || p.chain == nil {
		return nil, errors.New("roughtime: nil proof")
	}
	req, err := protocol.ParseRequest(p.chain.Links[0].Request)
	if err != nil {
		return nil, fmt.Errorf("roughtime: parse seed link: %w", err)
	}
	return append([]byte(nil), req.Nonce...), nil
}

// AttestationBound returns the existence interval the chain proves for the
// seed.
func (p *Proof) AttestationBound() (earliest, latest time.Time, err error) {
	if p == nil || p.chain == nil {
		return time.Time{}, time.Time{}, errors.New("roughtime: nil proof")
	}
	bounds, err := p.linkBounds()
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	earliest = bounds[0].midpoint.Add(-bounds[0].radius)
	latest = bounds[0].midpoint.Add(bounds[0].radius)
	for _, b := range bounds[1:] {
		if hi := b.midpoint.Add(b.radius); hi.Before(latest) {
			latest = hi
		}
	}
	return earliest, latest, nil
}

// linkBound is the verified (midpoint, radius) for one chain link.
type linkBound struct {
	midpoint time.Time
	radius   time.Duration
}

// linkBounds verifies each link and returns its midpoint and radius without
// per-link byte copies.
func (p *Proof) linkBounds() ([]linkBound, error) {
	out := make([]linkBound, len(p.chain.Links))
	for i, link := range p.chain.Links {
		req, err := protocol.ParseRequest(link.Request)
		if err != nil {
			return nil, fmt.Errorf("roughtime: link %d: parse request: %w", i, err)
		}
		mid, rad, err := protocol.VerifyReply(linkVersions(req), link.Response, link.PublicKey, req.Nonce, link.Request)
		if err != nil {
			return nil, fmt.Errorf("roughtime: link %d: %w", i, err)
		}
		out[i] = linkBound{midpoint: mid, radius: rad}
	}
	return out, nil
}

// linkVersions falls back to VersionGoogle for VER-less requests, matching
// [protocol.Chain.Verify].
func linkVersions(req *protocol.Request) []protocol.Version {
	if len(req.Versions) == 0 {
		return []protocol.Version{protocol.VersionGoogle}
	}
	return req.Versions
}
