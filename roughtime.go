// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

// Package roughtime is the high-level Roughtime client for Go applications.
// Most callers want this package; the protocol package is the low-level wire
// layer used internally and by diagnostic tools.
//
// Covers draft-ietf-ntp-roughtime 01–19, Google-Roughtime, and an experimental
// ML-DSA-44 post-quantum wire variant.
//
// The zero [Client] is usable and safe for concurrent use:
//
//	var c roughtime.Client
//	resp, err := c.Query(ctx, roughtime.Server{
//	    Name:      "time.txryan.com",
//	    PublicKey: pk,
//	    Addresses: []roughtime.Address{{Transport: "udp", Address: "time.txryan.com:2002"}},
//	})
//
// [Client.QueryAll] fans out concurrently; [Client.QueryChain] runs causal-
// chained queries; [Client.QueryChainWithNonce] seeds the chain for document
// timestamping. [(*ChainResult).Proof] yields a [*Proof] for offline audit via
// [(*Proof).MarshalGzip] / [(*Proof).MarshalJSON] and [ParseProof]. [Verify]
// re-validates a single stored request/reply pair; [ParseEcosystem] decodes the
// ecosystem JSON.
package roughtime

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/tannerryan/roughtime/protocol"
)

// Scheme identifies the signature suite of a server's root key.
type Scheme int

const (
	// SchemeEd25519 is the classical signature suite used by the Google and
	// IETF wire versions.
	SchemeEd25519 Scheme = iota
	// SchemeMLDSA44 is the experimental ML-DSA-44 post-quantum signature suite
	// (TCP only).
	SchemeMLDSA44
)

// Server describes one Roughtime server: a trust root plus one or more
// (transport, address) pairs to try.
type Server struct {
	// Name identifies the server for logs and error messages. Optional.
	Name string
	// Version is an optional ecosystem label. "Google-Roughtime" restricts the
	// advertised VER list to [protocol.VersionGoogle].
	Version string
	// PublicKey is the server's long-term root public key. 32 bytes selects
	// Ed25519; 1312 bytes selects ML-DSA-44.
	PublicKey []byte
	// Addresses is the list of (transport, host:port) pairs for this server.
	Addresses []Address
}

// Address is a single transport endpoint. Transport is matched
// case-insensitively; only "udp" and "tcp" are recognized.
type Address struct {
	Transport string // "udp" or "tcp"
	Address   string // host:port
}

// String renders the address as "<transport>://<host:port>". Wrap with
// [SanitizeForDisplay] when rendering an untrusted source to a terminal.
func (a Address) String() string {
	return a.Transport + "://" + a.Address
}

// Response is the verified outcome of a single query. Request and Reply hold
// the raw on-wire bytes for callers that need to store or forward the proof
// artifact (e.g. document timestamping).
type Response struct {
	Server          Server
	Address         Address          // endpoint dialed
	Version         protocol.Version // negotiated wire version
	Midpoint        time.Time        // server's claimed midpoint
	Radius          time.Duration    // half-width of uncertainty window
	RTT             time.Duration    // measured round-trip time
	LocalNow        time.Time        // local wall clock at reply receipt
	Request         []byte           // verified request bytes (includes nonce)
	Reply           []byte           // verified reply bytes
	AmplificationOK bool             // UDP: reply size ≤ request size; always true on TCP
}

// Drift reports the signed offset between the server's midpoint and the
// client's RTT-corrected local clock (LocalNow − RTT/2).
func (r *Response) Drift() time.Duration {
	ref := r.LocalNow.Add(-r.RTT / 2)
	return r.Midpoint.Sub(ref)
}

// InSync reports whether |Drift| is within the server's uncertainty Radius.
func (r *Response) InSync() bool {
	d := r.Drift()
	if d < 0 {
		d = -d
	}
	return d <= r.Radius
}

// Result is the outcome of one server's query in a multi-server batch. Exactly
// one of Response and Err is non-nil.
type Result struct {
	Server   Server
	Address  Address // zero if resolution or dial failed
	Response *Response
	Err      error
}

// ChainResult is the outcome of a chained multi-server query. Results is
// slot-aligned with the input servers; the chain is exposed via
// [(*ChainResult).Proof].
type ChainResult struct {
	Results []Result
	chain   *protocol.Chain
}

// Proof returns a [*Proof] view of the chain, or an error if no link succeeded.
func (cr *ChainResult) Proof() (*Proof, error) {
	if cr == nil || cr.chain == nil {
		return nil, errors.New("roughtime: no chain")
	}
	if len(cr.chain.Links) == 0 {
		return nil, errors.New("roughtime: empty chain")
	}
	return &Proof{chain: cr.chain}, nil
}

// MaxProofBytes caps both the on-disk and decompressed proof size.
const MaxProofBytes = 4 * 1024 * 1024

// gzipMagic is the gzip header (RFC 1952 §2.3) for [ParseProof] sniffing.
var gzipMagic = []byte{0x1f, 0x8b}

// Proof is a verifiable Roughtime timestamp proof: a causal chain of signed
// witness queries whose first link's nonce binds an arbitrary payload. Obtain
// one from [(*ChainResult).Proof] or [ParseProof]. Safe for concurrent reads.
type Proof struct {
	chain *protocol.Chain
}

// ProofLink is the per-witness attestation data exposed by [(*Proof).Links].
type ProofLink struct {
	PublicKey []byte           // Ed25519 or experimental ML-DSA-44
	Version   protocol.Version // negotiated wire version
	Nonce     []byte           // signed nonce (seed for link 0)
	Midpoint  time.Time
	Radius    time.Duration
}

// Window returns [Midpoint-Radius, Midpoint+Radius].
func (l ProofLink) Window() (lower, upper time.Time) {
	return l.Midpoint.Add(-l.Radius), l.Midpoint.Add(l.Radius)
}

// ParseProof loads a stored proof — gzipped or raw drafts-12+ malfeasance JSON.
// Legacy drafts-10/11 reports parse but cannot be verified (no keys).
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

// MarshalGzip returns the proof as gzipped drafts-12+ malfeasance JSON, the
// canonical persistence form. Round-trips through [ParseProof].
func (p *Proof) MarshalGzip() ([]byte, error) {
	if p == nil || p.chain == nil {
		return nil, errors.New("roughtime: nil proof")
	}
	// chain non-empty by construction; gzip-to-buffer cannot fail
	report, _ := p.chain.MalfeasanceReport()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	_, _ = gw.Write(report)
	_ = gw.Close()
	return buf.Bytes(), nil
}

// MarshalJSON returns the proof as raw drafts-12+ malfeasance JSON, satisfying
// [encoding/json.Marshaler]. Round-trips through [ParseProof].
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
// IETF wire versions only; Google-Roughtime chains surface a verify error.
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
		midpoint, radius, err := protocol.VerifyReply(req.Versions, link.Response, link.PublicKey, req.Nonce, link.Request)
		if err != nil {
			return nil, fmt.Errorf("roughtime: link %d: %w", i, err)
		}
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

// SeedNonce returns the first link's nonce — the value bound to the timestamped
// payload (e.g. SHA-256(document)).
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

// AttestationBound returns the interval the chain proves the seed existed in:
// earliest = link 0 lower bound; latest = smallest upper bound across all
// links. Later witnesses can only tighten the upper bound.
func (p *Proof) AttestationBound() (earliest, latest time.Time, err error) {
	links, err := p.Links()
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	earliest, latest = links[0].Window()
	for _, l := range links[1:] {
		if _, hi := l.Window(); hi.Before(latest) {
			latest = hi
		}
	}
	return earliest, latest, nil
}

// ConsensusReport summarizes drift across the successful subset of a
// [Client.QueryAll] result slice. Samples is zero when no result succeeded.
type ConsensusReport struct {
	Median  time.Duration
	Min     time.Duration
	Max     time.Duration
	Samples int
}

// Consensus computes drift statistics across results, considering only entries
// with Err == nil and a non-nil Response.
func Consensus(results []Result) ConsensusReport {
	drifts := make([]time.Duration, 0, len(results))
	for _, r := range results {
		if r.Err == nil && r.Response != nil {
			drifts = append(drifts, r.Response.Drift())
		}
	}
	if len(drifts) == 0 {
		return ConsensusReport{}
	}
	slices.Sort(drifts)
	return ConsensusReport{
		Median:  drifts[len(drifts)/2],
		Min:     drifts[0],
		Max:     drifts[len(drifts)-1],
		Samples: len(drifts),
	}
}

// Client runs Roughtime queries. The zero value is usable and safe for
// concurrent use.
type Client struct {
	// Timeout bounds each request/response exchange. Zero uses
	// [DefaultTimeout].
	Timeout time.Duration
	// Retries is the maximum number of attempts per server (not additional
	// retries). Zero or one means a single attempt. Backoff is 1s × 1.5^(n-1),
	// capped at 24h.
	Retries int
	// Concurrency caps in-flight queries in [Client.QueryAll]. Zero defaults to
	// [MaxQueryAllConcurrency].
	Concurrency int
}

// Re-exported error sentinels from the protocol package for use with
// [errors.Is].
var (
	// ErrPeerClosedNoReply indicates the peer closed the connection without
	// replying, typically because the offered version, scheme, or transport is
	// unsupported.
	ErrPeerClosedNoReply = protocol.ErrPeerClosedNoReply
	// ErrChainNonce indicates a chain link's nonce did not derive from the
	// previous response. Not evidence of server misbehavior.
	ErrChainNonce = protocol.ErrChainNonce
	// ErrCausalOrder indicates two chain links report time intervals that
	// cannot be reconciled. Evidence of server malfeasance.
	ErrCausalOrder = protocol.ErrCausalOrder
	// ErrMerkleMismatch indicates a reply's Merkle path does not authenticate
	// the request under the signed root.
	ErrMerkleMismatch = protocol.ErrMerkleMismatch
	// ErrDelegationWindow indicates the server's midpoint falls outside its
	// delegation certificate's validity window.
	ErrDelegationWindow = protocol.ErrDelegationWindow
)

// DefaultTimeout is used when [Client.Timeout] is zero.
const DefaultTimeout = 2 * time.Second

// MaxQueryAllConcurrency is the default cap on in-flight queries in
// [Client.QueryAll].
const MaxQueryAllConcurrency = 64

// Retry backoff per the draft: 1s start, 1.5× per failure, capped at 24h
const (
	retryBackoffInitial = 1 * time.Second
	retryBackoffMax     = 24 * time.Hour
	retryBackoffFactor  = 1.5
)

// Query performs a one-shot query against s. Retries honor [Client.Retries]
// with exponential backoff.
func (c *Client) Query(ctx context.Context, s Server) (*Response, error) {
	plan, err := resolveServer(s)
	if err != nil {
		return nil, err
	}
	return c.queryPlanned(ctx, s, plan)
}

// queryPlanned dispatches a fresh-nonce query against a pre-resolved plan.
func (c *Client) queryPlanned(ctx context.Context, s Server, plan serverPlan) (*Response, error) {
	srvHash := protocol.ComputeSRV(s.PublicKey)
	nonce, request, err := protocol.CreateRequest(plan.versions, rand.Reader, srvHash)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	return c.runQuery(ctx, s, plan, nonce, request)
}

// QueryWithNonce performs a one-shot query using a caller-supplied nonce,
// typically a hash of a payload to notarize. The nonce length must match the
// negotiated wire version: 32 bytes for drafts 05+ and ML-DSA-44, 64 bytes for
// Google-Roughtime and drafts 01-04.
func (c *Client) QueryWithNonce(ctx context.Context, s Server, nonce []byte) (*Response, error) {
	plan, err := resolveServer(s)
	if err != nil {
		return nil, err
	}
	srvHash := protocol.ComputeSRV(s.PublicKey)
	request, err := protocol.CreateRequestWithNonce(plan.versions, nonce, srvHash)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	return c.runQuery(ctx, s, plan, nonce, request)
}

// runQuery dispatches the prepared request, verifies the reply, and assembles a
// Response.
func (c *Client) runQuery(ctx context.Context, s Server, plan serverPlan, nonce, request []byte) (*Response, error) {
	reply, rtt, localNow, err := c.sendWithRetry(ctx, plan.address, request)
	if err != nil {
		return nil, err
	}
	midpoint, radius, err := protocol.VerifyReply(plan.versions, reply, s.PublicKey, nonce, request)
	if err != nil {
		return nil, fmt.Errorf("verification: %w", err)
	}
	return buildResponse(s, plan.address, request, reply, midpoint, radius, rtt, localNow), nil
}

// Query is a package-level convenience equivalent to a zero-[Client]'s
// [Client.Query].
func Query(ctx context.Context, s Server) (*Response, error) {
	var c Client
	return c.Query(ctx, s)
}

// QueryWithNonce is a package-level convenience equivalent to a zero-[Client]'s
// [Client.QueryWithNonce].
func QueryWithNonce(ctx context.Context, s Server, nonce []byte) (*Response, error) {
	var c Client
	return c.QueryWithNonce(ctx, s, nonce)
}

// Verify re-validates a stored Roughtime proof: that reply was a legitimate
// response to request from a server with the given long-term public key.
func Verify(pubkey, request, reply []byte) (midpoint time.Time, radius time.Duration, err error) {
	ver, ok := protocol.ExtractVersion(reply)
	if !ok {
		return time.Time{}, 0, errors.New("roughtime: cannot determine reply version")
	}
	parsed, err := protocol.ParseRequest(request)
	if err != nil {
		return time.Time{}, 0, fmt.Errorf("roughtime: parse request: %w", err)
	}
	return protocol.VerifyReply([]protocol.Version{ver}, reply, pubkey, parsed.Nonce, request)
}

// QueryAll queries each server concurrently and returns one Result per input
// server, slot-aligned with servers. Per-server errors land in Result.Err.
// Fan-out is capped by [Client.Concurrency] (or [MaxQueryAllConcurrency] if
// zero). Result.Address is populated whenever address resolution succeeds, even
// if the subsequent query fails.
func (c *Client) QueryAll(ctx context.Context, servers []Server) []Result {
	out := make([]Result, len(servers))
	for i, s := range servers {
		out[i].Server = s
	}
	cap := c.Concurrency
	if cap <= 0 {
		cap = MaxQueryAllConcurrency
	}
	sem := make(chan struct{}, cap)
	var wg sync.WaitGroup
	for i := range servers {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			out[i].Err = ctx.Err()
			continue
		}
		wg.Go(func() {
			defer func() { <-sem }()
			plan, err := resolveServer(out[i].Server)
			if err != nil {
				out[i].Err = err
				return
			}
			out[i].Address = plan.address
			resp, err := c.queryPlanned(ctx, out[i].Server, plan)
			out[i].Response = resp
			out[i].Err = err
		})
	}
	wg.Wait()
	return out
}

// QueryChain queries servers sequentially with causal chaining: each nonce
// derives from the previous successful response, making the ordering
// cryptographically provable. Per-server errors land in Results; a
// nonce-derivation failure aborts the chain and is returned as the top-level
// error. Failed links are not appended to Chain.Links.
func (c *Client) QueryChain(ctx context.Context, servers []Server) (*ChainResult, error) {
	return c.queryChain(ctx, servers, nil)
}

// QueryChainWithNonce is [Client.QueryChain] with the first successful link's
// nonce set to seed (e.g. a hash of a document to timestamp). Seed length must
// match the wire's nonce size: 32 bytes for drafts 05+ and ML-DSA-44, 64 bytes
// for Google-Roughtime / drafts 01-04.
func (c *Client) QueryChainWithNonce(ctx context.Context, servers []Server, seed []byte) (*ChainResult, error) {
	return c.queryChain(ctx, servers, seed)
}

// queryChain is the shared implementation of QueryChain and
// QueryChainWithNonce. firstNonce, when non-nil, sets the first link's nonce.
func (c *Client) queryChain(ctx context.Context, servers []Server, firstNonce []byte) (*ChainResult, error) {
	chain := &protocol.Chain{}
	results := make([]Result, len(servers))
	for i, s := range servers {
		results[i].Server = s
		if err := ctx.Err(); err != nil {
			results[i].Err = err
			continue
		}
		plan, err := resolveServer(s)
		if err != nil {
			results[i].Err = err
			continue
		}
		results[i].Address = plan.address

		var link protocol.ChainLink
		if len(chain.Links) == 0 && firstNonce != nil {
			link, err = chain.NextRequestWithNonce(plan.versions, s.PublicKey, firstNonce)
		} else {
			link, err = chain.NextRequest(plan.versions, s.PublicKey, rand.Reader)
		}
		if err != nil {
			results[i].Err = fmt.Errorf("chained request: %w", err)
			return &ChainResult{Results: results, chain: chain}, err
		}

		reply, rtt, localNow, err := c.sendWithRetry(ctx, plan.address, link.Request)
		if err != nil {
			results[i].Err = err
			continue
		}
		midpoint, radius, err := protocol.VerifyReply(plan.versions, reply, s.PublicKey, link.Nonce, link.Request)
		if err != nil {
			results[i].Err = fmt.Errorf("verification: %w", err)
			continue
		}
		link.Response = reply
		chain.Append(link)
		results[i].Response = buildResponse(s, plan.address, link.Request, reply, midpoint, radius, rtt, localNow)
	}
	return &ChainResult{Results: results, chain: chain}, nil
}

// sendWithRetry dispatches request to addr, retrying up to Retries with
// exponential backoff.
func (c *Client) sendWithRetry(ctx context.Context, addr Address, request []byte) (reply []byte, rtt time.Duration, localNow time.Time, err error) {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	attempts := max(c.Retries, 1)
	sleep := retryBackoffInitial
	for i := range attempts {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, 0, time.Time{}, ctxErr
		}
		reply, rtt, localNow, err = roundTrip(ctx, addr, request, timeout)
		if err == nil {
			return reply, rtt, localNow, nil
		}
		if i == attempts-1 {
			return nil, 0, time.Time{}, err
		}
		if !sleepCtx(ctx, sleep) {
			return nil, 0, time.Time{}, ctx.Err()
		}
		sleep = nextBackoff(sleep)
	}
	return nil, 0, time.Time{}, err
}

// roundTrip dispatches to the UDP or TCP transport primitive for addr.
func roundTrip(ctx context.Context, addr Address, request []byte, timeout time.Duration) ([]byte, time.Duration, time.Time, error) {
	switch strings.ToLower(addr.Transport) {
	case "udp":
		return protocol.RoundTripUDP(ctx, addr.Address, request, timeout)
	case "tcp":
		return protocol.RoundTripTCP(ctx, addr.Address, request, timeout)
	default:
		return nil, 0, time.Time{}, fmt.Errorf("unsupported transport %q", addr.Transport)
	}
}

// sleepCtx sleeps for d, returning false if ctx is cancelled first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// nextBackoff returns the next retry interval per the draft's schedule.
func nextBackoff(cur time.Duration) time.Duration {
	next := time.Duration(float64(cur) * retryBackoffFactor)
	if next > retryBackoffMax {
		return retryBackoffMax
	}
	return next
}

// serverPlan is the resolved (scheme, address, versions) tuple for a single
// query attempt.
type serverPlan struct {
	scheme   Scheme
	address  Address
	versions []protocol.Version
}

// resolveServer picks the scheme from PublicKey, selects an address, and
// returns the VER list to advertise.
func resolveServer(s Server) (serverPlan, error) {
	if len(s.Addresses) == 0 {
		return serverPlan{}, errors.New("roughtime: server has no addresses")
	}
	sch, err := SchemeOfKey(s.PublicKey)
	if err != nil {
		return serverPlan{}, err
	}
	addr, err := pickAddress(s, sch)
	if err != nil {
		return serverPlan{}, err
	}
	return serverPlan{scheme: sch, address: addr, versions: versionsForServer(s, sch)}, nil
}

// pickAddress selects an address: ML-DSA-44 requires TCP, Google-Roughtime
// requires UDP, Ed25519 prefers UDP then TCP.
func pickAddress(s Server, sch Scheme) (Address, error) {
	googleOnly := strings.EqualFold(s.Version, "Google-Roughtime")
	var udp, tcp Address
	for _, a := range s.Addresses {
		switch strings.ToLower(a.Transport) {
		case "udp":
			if udp.Address == "" {
				udp = a
			}
		case "tcp":
			if tcp.Address == "" {
				tcp = a
			}
		}
	}
	switch {
	case sch == SchemeMLDSA44:
		if tcp.Address == "" {
			return Address{}, errors.New("roughtime: ML-DSA-44 server has no tcp address")
		}
		return tcp, nil
	case googleOnly:
		if udp.Address == "" {
			return Address{}, errors.New("roughtime: Google-Roughtime server has no udp address")
		}
		return udp, nil
	case udp.Address != "":
		return udp, nil
	case tcp.Address != "":
		return tcp, nil
	default:
		return Address{}, errors.New("roughtime: no usable address")
	}
}

// VersionsForScheme returns the wire-version preference list to advertise for a
// server in the given scheme. SchemeEd25519 yields every IETF Ed25519 draft
// newest-first; Google-Roughtime is omitted because it's signalled by VER
// absence.
func VersionsForScheme(sch Scheme) []protocol.Version {
	if sch == SchemeMLDSA44 {
		return []protocol.Version{protocol.VersionMLDSA44}
	}
	out := make([]protocol.Version, 0)
	for _, v := range protocol.Supported() {
		if v == protocol.VersionGoogle || v == protocol.VersionMLDSA44 {
			continue
		}
		out = append(out, v)
	}
	return out
}

// versionsForServer returns the VER list for s, honoring the
// Server.Version=="Google-Roughtime" special case.
func versionsForServer(s Server, sch Scheme) []protocol.Version {
	if sch == SchemeEd25519 && strings.EqualFold(s.Version, "Google-Roughtime") {
		return []protocol.Version{protocol.VersionGoogle}
	}
	return VersionsForScheme(sch)
}

// buildResponse assembles a [Response] from a successful verification. When the
// reply has no VER tag (Google-Roughtime), Version is left at the zero value,
// which equals [protocol.VersionGoogle].
func buildResponse(s Server, addr Address, request, reply []byte, midpoint time.Time, radius time.Duration, rtt time.Duration, localNow time.Time) *Response {
	r := &Response{
		Server:          s,
		Address:         addr,
		Midpoint:        midpoint,
		Radius:          radius,
		RTT:             rtt,
		LocalNow:        localNow,
		Request:         request,
		Reply:           reply,
		AmplificationOK: !strings.EqualFold(addr.Transport, "udp") || len(reply) <= len(request),
	}
	if ver, ok := protocol.ExtractVersion(reply); ok {
		r.Version = ver
	}
	return r
}

// SchemeOfKey returns the scheme implied by pk's length: 32 → Ed25519, 1312 →
// ML-DSA-44.
func SchemeOfKey(pk []byte) (Scheme, error) {
	switch len(pk) {
	case ed25519.PublicKeySize:
		return SchemeEd25519, nil
	case protocol.MLDSA44PublicKeySize:
		return SchemeMLDSA44, nil
	default:
		return 0, fmt.Errorf("roughtime: unexpected public key length %d", len(pk))
	}
}

// DecodePublicKey decodes a root public key from base64 (std or URL, padded or
// raw) or hex. Accepts 32 bytes (Ed25519) or 1312 bytes (ML-DSA-44).
func DecodePublicKey(s string) ([]byte, error) {
	for _, dec := range []func(string) ([]byte, error){
		base64.StdEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		base64.RawURLEncoding.DecodeString,
		hex.DecodeString,
	} {
		if b, err := dec(s); err == nil && (len(b) == ed25519.PublicKeySize || len(b) == protocol.MLDSA44PublicKeySize) {
			return b, nil
		}
	}
	return nil, fmt.Errorf("roughtime: public key %q is not a 32-byte Ed25519 or 1312-byte ML-DSA-44 key in base64 or hex", truncateForErr(s))
}

// truncateForErr bounds an attacker-controlled string before embedding it in an
// error message.
func truncateForErr(s string) string {
	const limit = 64
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "..."
}

type ecosystemFile struct {
	Servers []ecosystemServer `json:"servers"`
}

type ecosystemServer struct {
	Name          string             `json:"name"`
	Version       flexString         `json:"version"`
	PublicKeyType string             `json:"publicKeyType"`
	PublicKey     string             `json:"publicKey"`
	Addresses     []ecosystemAddress `json:"addresses"`
}

type ecosystemAddress struct {
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
}

// flexString decodes a JSON field that may be either a string or an integer
// (ecosystem files in the wild use both).
type flexString string

func (v *flexString) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*v = flexString(s)
		return nil
	}
	var n uint32
	if err := json.Unmarshal(b, &n); err == nil {
		*v = flexString(fmt.Sprintf("%d", n))
		return nil
	}
	return fmt.Errorf("version must be a string or integer, got %s", string(b))
}

// MaxEcosystemServers caps the size of a parsed ecosystem file.
const MaxEcosystemServers = 1024

// ParseEcosystem decodes a JSON server list into [Server] values with decoded
// public keys and sanitized strings. When present, publicKeyType must agree
// with the decoded key length ("ed25519" or "ml-dsa-44").
func ParseEcosystem(data []byte) ([]Server, error) {
	var f ecosystemFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("roughtime: parsing ecosystem: %w", err)
	}
	if len(f.Servers) == 0 {
		return nil, errors.New("roughtime: ecosystem has no servers")
	}
	if len(f.Servers) > MaxEcosystemServers {
		return nil, fmt.Errorf("roughtime: ecosystem has %d entries (max %d)", len(f.Servers), MaxEcosystemServers)
	}
	out := make([]Server, 0, len(f.Servers))
	for i, es := range f.Servers {
		pk, err := DecodePublicKey(es.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("roughtime: server %d (%s): %w", i, SanitizeForDisplay(es.Name), err)
		}
		if es.PublicKeyType != "" {
			sch, _ := SchemeOfKey(pk)
			want := publicKeyTypeFor(sch)
			if !strings.EqualFold(es.PublicKeyType, want) {
				return nil, fmt.Errorf("roughtime: server %d (%s): publicKeyType %q does not match decoded key (expected %q)",
					i, SanitizeForDisplay(es.Name), SanitizeForDisplay(es.PublicKeyType), want)
			}
		}
		if len(es.Addresses) == 0 {
			return nil, fmt.Errorf("roughtime: server %d (%s): no addresses", i, SanitizeForDisplay(es.Name))
		}
		addrs := make([]Address, 0, len(es.Addresses))
		for _, a := range es.Addresses {
			t := strings.ToLower(a.Protocol)
			if t != "udp" && t != "tcp" {
				return nil, fmt.Errorf("roughtime: server %d (%s): unsupported transport %q", i, SanitizeForDisplay(es.Name), SanitizeForDisplay(a.Protocol))
			}
			addrs = append(addrs, Address{Transport: t, Address: SanitizeForDisplay(a.Address)})
		}
		out = append(out, Server{
			Name:      SanitizeForDisplay(es.Name),
			Version:   string(es.Version),
			PublicKey: pk,
			Addresses: addrs,
		})
	}
	return out, nil
}

// publicKeyTypeFor returns the ecosystem-file label for sch.
func publicKeyTypeFor(sch Scheme) string {
	switch sch {
	case SchemeMLDSA44:
		return "ml-dsa-44"
	default:
		return "ed25519"
	}
}

// MarshalEcosystem serializes servers as ecosystem JSON. PublicKey is
// std-base64; publicKeyType is derived from key length. Output round-trips
// through [ParseEcosystem].
func MarshalEcosystem(servers []Server) ([]byte, error) {
	if len(servers) > MaxEcosystemServers {
		return nil, fmt.Errorf("roughtime: %d servers exceeds max %d", len(servers), MaxEcosystemServers)
	}
	out := ecosystemFile{Servers: make([]ecosystemServer, 0, len(servers))}
	for i, s := range servers {
		sch, err := SchemeOfKey(s.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("roughtime: server %d (%s): %w", i, SanitizeForDisplay(s.Name), err)
		}
		addrs := make([]ecosystemAddress, 0, len(s.Addresses))
		for _, a := range s.Addresses {
			addrs = append(addrs, ecosystemAddress{Protocol: a.Transport, Address: SanitizeForDisplay(a.Address)})
		}
		out.Servers = append(out.Servers, ecosystemServer{
			Name:          SanitizeForDisplay(s.Name),
			Version:       flexString(s.Version),
			PublicKeyType: publicKeyTypeFor(sch),
			PublicKey:     base64.StdEncoding.EncodeToString(s.PublicKey),
			Addresses:     addrs,
		})
	}
	return json.MarshalIndent(out, "", "  ")
}

// SanitizeForDisplay strips control characters and bidi format codes to defeat
// Trojan-Source display attacks in untrusted strings (e.g. server names from an
// ecosystem file).
func SanitizeForDisplay(s string) string {
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		if (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) {
			return -1
		}
		return r
	}, s)
}
