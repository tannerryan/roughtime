// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

// Package roughtime is a high-level Roughtime client for Go applications. It
// covers draft-ietf-ntp-roughtime 01–19, Google-Roughtime, and an experimental
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
// Use [Client.QueryAll] for concurrent fan-out and [Client.QueryChain] for
// causal-chained queries. See [ParseEcosystem] for the ecosystem JSON format
// and the protocol package for low-level wire primitives.
package roughtime

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"filippo.io/mldsa"
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
	// Version is an optional ecosystem label. "Google-Roughtime" restricts
	// the advertised VER list to [protocol.VersionGoogle].
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
	AmplificationOK bool             // reply size ≤ request size
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

// Result is the outcome of one server's query in a multi-server batch.
// Exactly one of Response and Err is non-nil.
type Result struct {
	Server   Server
	Address  Address // zero if resolution or dial failed
	Response *Response
	Err      error
}

// ChainResult is the outcome of a chained multi-server query. Results is
// slot-aligned with the input servers; Chain is retained even when some links
// failed.
type ChainResult struct {
	Results []Result
	Chain   *protocol.Chain
}

// MalfeasanceReport serializes the underlying [protocol.Chain] as the
// drafts-12+ JSON malfeasance report.
func (cr *ChainResult) MalfeasanceReport() ([]byte, error) {
	if cr == nil || cr.Chain == nil {
		return nil, errors.New("roughtime: no chain to report on")
	}
	return cr.Chain.MalfeasanceReport()
}

// Client runs Roughtime queries. The zero value is usable and safe for
// concurrent use.
type Client struct {
	// Timeout bounds each request/response exchange. Zero uses [DefaultTimeout].
	Timeout time.Duration
	// Retries is the maximum number of attempts per server (not additional
	// retries). Zero or one means a single attempt. Backoff is 1s × 1.5^(n-1),
	// capped at 24h.
	Retries int
	// Concurrency caps in-flight queries in [Client.QueryAll]. Zero defaults
	// to [MaxQueryAllConcurrency].
	Concurrency int
}

// Re-exported error sentinels from the protocol package for use with
// [errors.Is].
var (
	// ErrPeerClosedNoReply indicates the peer closed the connection without
	// replying, typically because the offered version, scheme, or transport
	// is unsupported.
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
	srvHash := protocol.ComputeSRV(s.PublicKey)
	nonce, request, err := protocol.CreateRequest(plan.versions, rand.Reader, srvHash)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	return c.runQuery(ctx, s, plan, nonce, request)
}

// QueryWithNonce performs a one-shot query using a caller-supplied nonce,
// typically a hash of a payload to notarize. The nonce length must match the
// negotiated wire version: 32 bytes for drafts 05+ and ML-DSA-44, 64 bytes
// for Google-Roughtime and drafts 01-04.
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

// runQuery dispatches the prepared request, verifies the reply, and assembles
// a Response.
func (c *Client) runQuery(ctx context.Context, s Server, plan serverPlan, nonce, request []byte) (*Response, error) {
	reply, rtt, localNow, err := c.sendWithRetry(ctx, plan.address, request)
	if err != nil {
		return nil, err
	}
	midpoint, radius, err := protocol.VerifyReply(plan.versions, reply, s.PublicKey, nonce, request)
	if err != nil {
		return nil, fmt.Errorf("verification: %w", err)
	}
	return buildResponse(s, plan.address, request, reply, plan.versions, midpoint, radius, rtt, localNow), nil
}

// Query is a package-level convenience equivalent to a zero-[Client]'s
// [Client.Query].
func Query(ctx context.Context, s Server) (*Response, error) {
	var c Client
	return c.Query(ctx, s)
}

// QueryWithNonce is a package-level convenience equivalent to a
// zero-[Client]'s [Client.QueryWithNonce].
func QueryWithNonce(ctx context.Context, s Server, nonce []byte) (*Response, error) {
	var c Client
	return c.QueryWithNonce(ctx, s, nonce)
}

// QueryAll queries each server concurrently and returns one Result per input
// server, slot-aligned with servers. Per-server errors land in Result.Err.
// Fan-out is capped by [Client.Concurrency] (or [MaxQueryAllConcurrency] if
// zero).
func (c *Client) QueryAll(ctx context.Context, servers []Server) []Result {
	out := make([]Result, len(servers))
	cap := c.Concurrency
	if cap <= 0 {
		cap = MaxQueryAllConcurrency
	}
	sem := make(chan struct{}, cap)
	var wg sync.WaitGroup
	wg.Add(len(servers))
	for i, s := range servers {
		go func(i int, s Server) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			resp, err := c.Query(ctx, s)
			r := Result{Server: s, Err: err, Response: resp}
			if resp != nil {
				r.Address = resp.Address
			}
			out[i] = r
		}(i, s)
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

		link, err := chain.NextRequest(plan.versions, s.PublicKey, rand.Reader)
		if err != nil {
			results[i].Err = fmt.Errorf("chained request: %w", err)
			return &ChainResult{Results: results, Chain: chain}, err
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
		results[i].Response = buildResponse(s, plan.address, link.Request, reply, plan.versions, midpoint, radius, rtt, localNow)
	}
	return &ChainResult{Results: results, Chain: chain}, nil
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

// VersionsForScheme returns the wire-version preference list to advertise
// for a server in the given scheme. SchemeEd25519 yields every IETF Ed25519
// draft newest-first; Google-Roughtime is omitted because it's signalled by
// VER absence.
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

// buildResponse assembles a [Response] from a successful verification.
// r.Version comes from the reply's VER tag when present, otherwise falls back
// to the single offered version or to VersionGoogle when offered.
func buildResponse(s Server, addr Address, request, reply []byte, versions []protocol.Version, midpoint time.Time, radius time.Duration, rtt time.Duration, localNow time.Time) *Response {
	r := &Response{
		Server:          s,
		Address:         addr,
		Midpoint:        midpoint,
		Radius:          radius,
		RTT:             rtt,
		LocalNow:        localNow,
		Request:         request,
		Reply:           reply,
		AmplificationOK: len(reply) <= len(request),
	}
	if ver, ok := protocol.ExtractVersion(reply); ok {
		r.Version = ver
	} else if len(versions) == 1 {
		r.Version = versions[0]
	} else if slices.Contains(versions, protocol.VersionGoogle) {
		r.Version = protocol.VersionGoogle
	}
	return r
}

// SchemeOfKey returns the scheme implied by pk's length: 32 → Ed25519,
// 1312 → ML-DSA-44.
func SchemeOfKey(pk []byte) (Scheme, error) {
	switch len(pk) {
	case ed25519.PublicKeySize:
		return SchemeEd25519, nil
	case mldsa.MLDSA44PublicKeySize:
		return SchemeMLDSA44, nil
	default:
		return 0, fmt.Errorf("roughtime: unexpected public key length %d", len(pk))
	}
}

// DecodePublicKey decodes a root public key from base64 (std or URL, padded
// or raw) or hex. Accepts 32 bytes (Ed25519) or 1312 bytes (ML-DSA-44).
func DecodePublicKey(s string) ([]byte, error) {
	for _, dec := range []func(string) ([]byte, error){
		base64.StdEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		base64.RawURLEncoding.DecodeString,
		hex.DecodeString,
	} {
		if b, err := dec(s); err == nil && (len(b) == ed25519.PublicKeySize || len(b) == mldsa.MLDSA44PublicKeySize) {
			return b, nil
		}
	}
	return nil, fmt.Errorf("roughtime: public key %q is not a 32-byte Ed25519 or 1312-byte ML-DSA-44 key in base64 or hex", truncateForErr(s))
}

// truncateForErr bounds an attacker-controlled string before embedding it in
// an error message.
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

// ParseEcosystem decodes a JSON server list into [Server] values with
// decoded public keys and sanitized strings. When present, publicKeyType
// must agree with the decoded key length ("ed25519" or "ml-dsa-44").
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
			return nil, fmt.Errorf("roughtime: server %d (%s): %w", i, sanitize(es.Name), err)
		}
		if es.PublicKeyType != "" {
			sch, _ := SchemeOfKey(pk)
			want := publicKeyTypeFor(sch)
			if !strings.EqualFold(es.PublicKeyType, want) {
				return nil, fmt.Errorf("roughtime: server %d (%s): publicKeyType %q does not match decoded key (expected %q)",
					i, sanitize(es.Name), sanitize(es.PublicKeyType), want)
			}
		}
		addrs := make([]Address, 0, len(es.Addresses))
		for _, a := range es.Addresses {
			addrs = append(addrs, Address{Transport: strings.ToLower(a.Protocol), Address: sanitize(a.Address)})
		}
		out = append(out, Server{
			Name:      sanitize(es.Name),
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
			return nil, fmt.Errorf("roughtime: server %d (%s): %w", i, sanitize(s.Name), err)
		}
		addrs := make([]ecosystemAddress, 0, len(s.Addresses))
		for _, a := range s.Addresses {
			addrs = append(addrs, ecosystemAddress{Protocol: a.Transport, Address: a.Address})
		}
		out.Servers = append(out.Servers, ecosystemServer{
			Name:          s.Name,
			Version:       flexString(s.Version),
			PublicKeyType: publicKeyTypeFor(sch),
			PublicKey:     base64.StdEncoding.EncodeToString(s.PublicKey),
			Addresses:     addrs,
		})
	}
	return json.MarshalIndent(out, "", "  ")
}

// sanitize strips control characters and bidi format codes to defeat
// Trojan-Source display attacks in ecosystem-supplied strings.
func sanitize(s string) string {
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
