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
// [Client.QueryAll] fans out concurrently; [Consensus] aggregates drift across
// the result slice. [Client.QueryChain] runs causal-chained queries;
// [Client.QueryChainWithNonce] seeds the chain for document timestamping.
// [(*ChainResult).Proof] yields a [*Proof] for offline audit via
// [(*Proof).MarshalGzip] / [(*Proof).MarshalJSON] and [ParseProof]. [Verify]
// re-validates a single stored request/reply pair; [ParseEcosystem] decodes the
// ecosystem JSON.
package roughtime

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/tannerryan/roughtime/protocol"
)

// Server describes one Roughtime server with a trust root and one or more
// transport endpoints.
type Server struct {
	// Name identifies the server for logs and error messages.
	Name string
	// Version is an optional ecosystem label, with [VersionLabelGoogle]
	// selecting the Google variant.
	Version string
	// PublicKey is the server's long-term root public key (32 bytes Ed25519 or
	// 1312 bytes ML-DSA-44).
	PublicKey []byte
	// Addresses lists (transport, host:port) pairs for this server.
	Addresses []Address
}

// Address is a single transport endpoint with case-insensitive Transport ("udp"
// or "tcp").
type Address struct {
	// Transport is the case-insensitive transport label ("udp" or "tcp").
	Transport string
	// Address is the host:port endpoint.
	Address string
}

// String renders the address as "<transport>://<host:port>".
func (a Address) String() string {
	return a.Transport + "://" + a.Address
}

// Result is the outcome of one server's query in a multi-server batch with
// exactly one of Response and Err non-nil.
type Result struct {
	// Server is the input server description.
	Server Server
	// Address is the resolved transport endpoint, or zero if resolution failed.
	Address Address
	// Response is the verified outcome on success.
	Response *Response
	// Err is the per-server failure.
	Err error
}

// ChainResult is the outcome of a chained multi-server query, slot-aligned with
// the input servers.
type ChainResult struct {
	// Results is per-server outcomes slot-aligned with the input servers.
	Results []Result
	chain   *protocol.Chain
}

// Proof returns a [*Proof] view of the chain or an error if no link succeeded.
func (cr *ChainResult) Proof() (*Proof, error) {
	if cr == nil || cr.chain == nil {
		return nil, errors.New("roughtime: no chain")
	}
	if len(cr.chain.Links) == 0 {
		return nil, errors.New("roughtime: empty chain")
	}
	return &Proof{chain: cr.chain}, nil
}

// Client runs Roughtime queries and is safe for concurrent use with a usable
// zero value.
type Client struct {
	// Timeout bounds each request/response exchange and defaults to
	// [DefaultTimeout] when zero.
	Timeout time.Duration
	// MaxAttempts is the per-server attempt cap with 1s by 1.5^(n-1) backoff
	// capped at 24h.
	MaxAttempts int
	// Concurrency caps in-flight queries in [Client.QueryAll] and defaults to
	// [MaxQueryAllConcurrency] when zero.
	Concurrency int
}

// Error sentinels re-exported from the protocol package for use with
// [errors.Is].
var (
	// ErrPeerClosedNoReply indicates the peer closed the connection without
	// replying.
	ErrPeerClosedNoReply = protocol.ErrPeerClosedNoReply
	// ErrChainNonce indicates a chain link's nonce did not derive from the
	// previous response.
	ErrChainNonce = protocol.ErrChainNonce
	// ErrCausalOrder indicates two chain links report intervals that cannot be
	// reconciled.
	ErrCausalOrder = protocol.ErrCausalOrder
	// ErrMerkleMismatch indicates a reply's Merkle path does not authenticate
	// the request under the signed root.
	ErrMerkleMismatch = protocol.ErrMerkleMismatch
	// ErrDelegationWindow indicates the server's midpoint falls outside the
	// delegation certificate's validity window.
	ErrDelegationWindow = protocol.ErrDelegationWindow
)

// VersionLabelGoogle is the [Server.Version] string that selects the
// Google-Roughtime wire variant.
const VersionLabelGoogle = "Google-Roughtime"

// DefaultTimeout is the per-exchange timeout used when [Client.Timeout] is
// zero.
const DefaultTimeout = 2 * time.Second

// MaxQueryAllConcurrency is the default cap on in-flight queries in
// [Client.QueryAll].
const MaxQueryAllConcurrency = 64

// Retry backoff schedule per draft-ietf-ntp-roughtime §10 (Repeated Queries).
const (
	// retryBackoffInitial is the first backoff interval.
	retryBackoffInitial = 1 * time.Second
	// retryBackoffMax caps the backoff interval.
	retryBackoffMax = 24 * time.Hour
	// retryBackoffFactor multiplies the interval after each failure.
	retryBackoffFactor = 1.5
)

// Query performs a one-shot query against s with up to [Client.MaxAttempts]
// tries and exponential backoff.
func (c *Client) Query(ctx context.Context, s Server) (*Response, error) {
	plan, err := resolveServer(s)
	if err != nil {
		return nil, err
	}
	return c.queryPlanned(ctx, s, plan)
}

// queryPlanned dispatches a fresh-nonce query against a pre-resolved plan.
func (c *Client) queryPlanned(ctx context.Context, s Server, plan serverPlan) (*Response, error) {
	// Google-Roughtime drops the SRV tag.
	var srvHash []byte
	if !isGoogleOnly(plan.versions) {
		srvHash = protocol.ComputeSRV(s.PublicKey)
	}
	nonce, request, err := protocol.CreateRequest(plan.versions, rand.Reader, srvHash)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	return c.runQuery(ctx, s, plan, nonce, request)
}

// QueryWithNonce performs a one-shot query using a caller-supplied nonce (32
// bytes IETF, 64 bytes Google-Roughtime).
func (c *Client) QueryWithNonce(ctx context.Context, s Server, nonce []byte) (*Response, error) {
	plan, err := resolveServer(s)
	if err != nil {
		return nil, err
	}
	var srvHash []byte
	if !isGoogleOnly(plan.versions) {
		srvHash = protocol.ComputeSRV(s.PublicKey)
	}
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

// Verify re-validates a stored request/reply pair against the server's
// long-term public key.
func Verify(pubkey, request, reply []byte) (midpoint time.Time, radius time.Duration, err error) {
	parsed, err := protocol.ParseRequest(request)
	if err != nil {
		return time.Time{}, 0, fmt.Errorf("roughtime: parse request: %w", err)
	}
	// Pass the request's offered list so [protocol.VerifyReply] enforces
	// versionOffered and (drafts 12+) the signed-VERS downgrade check.
	versions := parsed.Versions
	if len(versions) == 0 {
		versions = []protocol.Version{protocol.VersionGoogle}
	}
	return protocol.VerifyReply(versions, reply, pubkey, parsed.Nonce, request)
}

// QueryAll queries each server concurrently and returns slot-aligned Results
// capped by [Client.Concurrency].
func (c *Client) QueryAll(ctx context.Context, servers []Server) []Result {
	out := make([]Result, len(servers))
	for i, s := range servers {
		out[i].Server = s
	}
	limit := c.Concurrency
	if limit <= 0 {
		limit = MaxQueryAllConcurrency
	}
	sem := make(chan struct{}, limit)
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

// QueryChain queries servers sequentially with causal nonce chaining and
// per-server errors landing in Results.
func (c *Client) QueryChain(ctx context.Context, servers []Server) (*ChainResult, error) {
	return c.queryChain(ctx, servers, nil)
}

// QueryChainWithNonce is [Client.QueryChain] with the first link's nonce set to
// seed for document timestamping.
func (c *Client) QueryChainWithNonce(ctx context.Context, servers []Server, seed []byte) (*ChainResult, error) {
	return c.queryChain(ctx, servers, seed)
}

// queryChain is the shared implementation of QueryChain and
// QueryChainWithNonce.
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

// sendWithRetry dispatches request to addr with up to MaxAttempts tries and
// exponential backoff between them.
func (c *Client) sendWithRetry(ctx context.Context, addr Address, request []byte) (reply []byte, rtt time.Duration, localNow time.Time, err error) {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	attempts := max(c.MaxAttempts, 1)
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

// serverPlan is the resolved (address, versions) tuple for a single query
// attempt.
type serverPlan struct {
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
	return serverPlan{address: addr, versions: versionsForServer(s, sch)}, nil
}

// pickAddress selects an address per scheme rules (ML-DSA-44 requires TCP,
// Google requires UDP, Ed25519 prefers UDP).
func pickAddress(s Server, sch Scheme) (Address, error) {
	googleOnly := strings.EqualFold(s.Version, VersionLabelGoogle)
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

// isGoogleOnly reports whether vs is exactly [VersionGoogle].
func isGoogleOnly(vs []protocol.Version) bool {
	return len(vs) == 1 && vs[0] == protocol.VersionGoogle
}

// versionsForServer returns the VER list for s, honoring [VersionLabelGoogle]
// for Ed25519.
func versionsForServer(s Server, sch Scheme) []protocol.Version {
	if sch == SchemeEd25519 && strings.EqualFold(s.Version, VersionLabelGoogle) {
		return []protocol.Version{protocol.VersionGoogle}
	}
	return VersionsForScheme(sch)
}
