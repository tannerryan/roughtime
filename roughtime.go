// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

// Package roughtime provides a concurrent high-level Roughtime client,
// multi-server consensus and causal chains, ecosystem parsing, and offline
// timestamp proofs. The zero [Client] is ready for use. Wire-level callers
// should use the protocol subpackage.
package roughtime

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tannerryan/roughtime/protocol"
)

// errChainAborted marks chain links never attempted after an earlier link
// failed.
var errChainAborted = errors.New("roughtime: chained request aborted")

// defaultClient preserves the protocol-mandated per-server retry state for
// package-level convenience queries.
var defaultClient Client

// retryInitMu serializes lazy tracker installation without making Client values
// themselves non-copyable.
var retryInitMu sync.Mutex

// Server describes one Roughtime server with a trust root and one or more
// transport endpoints.
type Server struct {
	// Name identifies the server for logs and error messages.
	Name string
	// Version is an optional ecosystem label. [VersionLabelGoogle] and the
	// numeric Google ecosystem version select Google-Roughtime. Other numeric
	// values cap advertised scheme-compatible versions.
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
	// Address is the successful transport endpoint, or zero on failure.
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
	// [DefaultTimeout] when non-positive.
	Timeout time.Duration
	// MaxAttempts caps attempts per query. Backoff starts at 1s, grows by 1.5,
	// persists by root key across calls, and resets after a verified response.
	// Zero tries each configured endpoint once. Negative values mean one
	// attempt.
	MaxAttempts int
	// Concurrency caps in-flight queries in [Client.QueryAll] and defaults to
	// [MaxQueryAllConcurrency] when non-positive.
	Concurrency int
	// StandardPacketSize pads framed requests to a 1024-byte message body plus
	// the 12-byte header (an 8192-byte body for ML-DSA-44). The default false
	// value retains the historical 1024-byte total packet size, or 8192-byte
	// total for ML-DSA-44, for deployed interoperability.
	StandardPacketSize bool

	retry *retryTracker
}

// retryState is the persistent per-server backoff recommended by drafts 16-17
// and required by drafts 18-19.
type retryState struct {
	interval   time.Duration
	notBefore  time.Time
	probing    bool
	generation uint64
	active     int
	changed    chan struct{}
}

// retryAttempt identifies one exchange admitted by the per-root tracker.
// Generations prevent concurrent failures from multiplying one shared penalty
// and prevent a stale failure from reinstating backoff after a verified reply.
type retryAttempt struct {
	key        string
	state      *retryState
	generation uint64
	probe      bool
}

// retryTracker is shared by copies of an initialized Client.
type retryTracker struct {
	mu      sync.Mutex
	retries map[string]*retryState
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

// VersionLabelGoogle is the textual [Server.Version] value that selects
// Google-Roughtime. Ecosystem files may also use its numeric version value.
const VersionLabelGoogle = "Google-Roughtime"

// DefaultTimeout is the per-exchange timeout used when [Client.Timeout] is
// non-positive.
const DefaultTimeout = 2 * time.Second

// MaxQueryAllConcurrency is the default cap on in-flight queries in
// [Client.QueryAll].
const MaxQueryAllConcurrency = 64

// Retry backoff schedule from the drafts 16-19 transport guidance.
const (
	// retryBackoffInitial is the first backoff interval.
	retryBackoffInitial = 1 * time.Second
	// retryBackoffMax caps the backoff interval.
	retryBackoffMax = 24 * time.Hour
	// retryBackoffFactor multiplies the interval after each failure.
	retryBackoffFactor = 1.5
)

// Query queries s using the client's retry policy.
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
	nonce, request, err := protocol.CreateRequestWithOptions(plan.versions, rand.Reader, srvHash, c.requestOptions())
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	return c.runQuery(ctx, s, plan, nonce, request)
}

// QueryWithNonce queries using a caller-supplied nonce (32 bytes IETF, 64 bytes
// Google-Roughtime).
func (c *Client) QueryWithNonce(ctx context.Context, s Server, nonce []byte) (*Response, error) {
	plan, err := resolveServer(s)
	if err != nil {
		return nil, err
	}
	var srvHash []byte
	if !isGoogleOnly(plan.versions) {
		srvHash = protocol.ComputeSRV(s.PublicKey)
	}
	request, err := protocol.CreateRequestWithNonceOptions(plan.versions, nonce, srvHash, c.requestOptions())
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	return c.runQuery(ctx, s, plan, nonce, request)
}

// runQuery dispatches the prepared request, verifies the reply, and assembles a
// Response.
func (c *Client) runQuery(ctx context.Context, s Server, plan serverPlan, nonce, request []byte) (*Response, error) {
	addr, reply, rtt, localNow, midpoint, radius, err := c.sendWithRetry(ctx, s, plan, request, func(reply []byte) (time.Time, time.Duration, error) {
		return protocol.VerifyReply(plan.versions, reply, s.PublicKey, nonce, request)
	})
	if err != nil {
		return nil, err
	}
	return buildResponse(s, addr, request, reply, midpoint, radius, rtt, localNow), nil
}

// Query is a package-level convenience backed by a shared zero-configured
// [Client]. The shared client preserves protocol-mandated retry state across
// calls.
func Query(ctx context.Context, s Server) (*Response, error) {
	return defaultClient.Query(ctx, s)
}

// QueryWithNonce is the caller-nonce form of [Query] and uses the same shared
// client.
func QueryWithNonce(ctx context.Context, s Server, nonce []byte) (*Response, error) {
	return defaultClient.QueryWithNonce(ctx, s, nonce)
}

// requestOptions preserves legacy packet sizing for Client's zero value.
func (c *Client) requestOptions() protocol.RequestOptions {
	return protocol.RequestOptions{LegacyPacketSize: !c.StandardPacketSize}
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
	if len(servers) == 0 {
		return out
	}
	limit := c.Concurrency
	if limit <= 0 {
		limit = MaxQueryAllConcurrency
	}
	limit = min(limit, len(servers))
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
			resp, err := c.queryPlanned(ctx, out[i].Server, plan)
			out[i].Response = resp
			out[i].Err = err
			if resp != nil {
				out[i].Address = resp.Address
			}
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

// QueryChainWithNonce is [Client.QueryChain] with the first successful link's
// nonce set to seed for document timestamping. The seed must be 32 bytes for
// IETF versions or 64 bytes for Google-Roughtime. Before that link, an
// otherwise usable server incompatible with the seed aborts the remaining
// chain.
func (c *Client) QueryChainWithNonce(ctx context.Context, servers []Server, seed []byte) (*ChainResult, error) {
	if len(seed) == 0 {
		return nil, errors.New("roughtime: chain seed nonce is empty")
	}
	return c.queryChain(ctx, servers, seed)
}

// queryChain is the shared implementation of QueryChain and
// QueryChainWithNonce.
func (c *Client) queryChain(ctx context.Context, servers []Server, firstNonce []byte) (*ChainResult, error) {
	if len(servers) > protocol.MaxChainLinks {
		return nil, fmt.Errorf("roughtime: %d servers exceeds max chain length %d", len(servers), protocol.MaxChainLinks)
	}
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
		var link protocol.ChainLink
		if len(chain.Links) == 0 && firstNonce != nil {
			link.Nonce = append([]byte(nil), firstNonce...)
		} else {
			var previous []byte
			if len(chain.Links) > 0 {
				previous = chain.Links[len(chain.Links)-1].Response
			}
			link.Nonce, link.Rand, err = protocol.ChainNonce(previous, rand.Reader, plan.versions)
		}
		if err == nil {
			link.PublicKey = append([]byte(nil), s.PublicKey...)
			link.Request, err = protocol.CreateRequestWithNonceOptions(plan.versions, link.Nonce, protocol.ComputeSRV(s.PublicKey), c.requestOptions())
		}
		if err != nil {
			results[i].Err = fmt.Errorf("chained request: %w", err)
			// preserve the per-slot invariant for links never attempted
			for j := i + 1; j < len(servers); j++ {
				results[j].Server = servers[j]
				results[j].Err = errChainAborted
			}
			return &ChainResult{Results: results, chain: chain}, err
		}

		addr, reply, rtt, localNow, midpoint, radius, err := c.sendWithRetry(ctx, s, plan, link.Request, func(reply []byte) (time.Time, time.Duration, error) {
			return protocol.VerifyReply(plan.versions, reply, s.PublicKey, link.Nonce, link.Request)
		})
		if err != nil {
			results[i].Err = err
			continue
		}
		results[i].Address = addr
		link.Response = reply
		chain.Append(link)
		results[i].Response = buildResponse(s, addr, link.Request, reply, midpoint, radius, rtt, localNow)
	}
	return &ChainResult{Results: results, chain: chain}, nil
}

// sendWithRetry dispatches and verifies request under the configured retry
// policy. Backoff persists across calls and resets after a verified response.
func (c *Client) sendWithRetry(ctx context.Context, s Server, plan serverPlan, request []byte, verify func([]byte) (time.Time, time.Duration, error)) (addr Address, reply []byte, rtt time.Duration, localNow, midpoint time.Time, radius time.Duration, err error) {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	attempts := c.MaxAttempts
	if attempts == 0 {
		attempts = len(plan.addresses)
	} else if attempts < 0 {
		attempts = 1
	}
	key := string(s.PublicKey)
	for i := range attempts {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return Address{}, nil, 0, time.Time{}, time.Time{}, 0, ctxErr
		}
		attempt, ok := c.waitForRetry(ctx, key)
		if !ok {
			return Address{}, nil, 0, time.Time{}, time.Time{}, 0, ctx.Err()
		}
		addr = plan.addresses[i%len(plan.addresses)]
		reply, rtt, localNow, err = roundTrip(ctx, addr, request, timeout)
		if err == nil {
			midpoint, radius, err = verify(reply)
			if err == nil {
				c.resetRetry(attempt)
				return addr, reply, rtt, localNow, midpoint, radius, nil
			}
			err = fmt.Errorf("verification: %w", err)
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			c.releaseRetry(attempt)
			return addr, nil, 0, time.Time{}, time.Time{}, 0, ctxErr
		}
		c.recordRetryFailure(attempt)
		if i == attempts-1 {
			return addr, nil, 0, time.Time{}, time.Time{}, 0, err
		}
	}
	return addr, nil, 0, time.Time{}, time.Time{}, 0, err
}

// waitForRetry waits until the server's persistent retry interval has elapsed
// and, after a failure, reserves the sole next probe for this root. With no
// active penalty it admits independent exchanges in parallel.
func (c *Client) waitForRetry(ctx context.Context, key string) (retryAttempt, bool) {
	tracker := c.retryTracker()
	for {
		tracker.mu.Lock()
		if tracker.retries == nil {
			tracker.retries = make(map[string]*retryState)
		}
		state := tracker.retries[key]
		if state == nil {
			state = &retryState{changed: make(chan struct{})}
			tracker.retries[key] = state
		}
		if state.interval == 0 {
			state.active++
			attempt := retryAttempt{key: key, state: state, generation: state.generation}
			tracker.mu.Unlock()
			return attempt, true
		}
		if !state.probing {
			d := time.Until(state.notBefore)
			if d <= 0 {
				state.probing = true
				state.active++
				attempt := retryAttempt{key: key, state: state, generation: state.generation, probe: true}
				tracker.mu.Unlock()
				return attempt, true
			}
			changed := state.changed
			tracker.mu.Unlock()
			timer := time.NewTimer(d)
			select {
			case <-timer.C:
			case <-changed:
			case <-ctx.Done():
				timer.Stop()
				return retryAttempt{}, false
			}
			timer.Stop()
			continue
		}
		changed := state.changed
		tracker.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return retryAttempt{}, false
		}
	}
}

// recordRetryFailure advances the persistent per-server retry schedule.
func (c *Client) recordRetryFailure(attempt retryAttempt) {
	tracker := c.retryTracker()
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	state := tracker.retries[attempt.key]
	if state != attempt.state {
		return
	}
	state.active--
	if state.generation != attempt.generation {
		c.cleanupRetryLocked(tracker, attempt.key, state)
		return
	}
	if state.interval == 0 {
		state.interval = retryBackoffInitial
	} else {
		state.interval = nextBackoff(state.interval)
	}
	state.notBefore = time.Now().Add(state.interval)
	state.probing = false
	state.generation++
	notifyRetryWaiters(state)
}

// resetRetry clears a server's backoff after a properly signed response.
func (c *Client) resetRetry(attempt retryAttempt) {
	tracker := c.retryTracker()
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	state := tracker.retries[attempt.key]
	if state != attempt.state {
		return
	}
	state.active--
	state.interval = 0
	state.notBefore = time.Time{}
	state.probing = false
	state.generation++
	notifyRetryWaiters(state)
	c.cleanupRetryLocked(tracker, attempt.key, state)
}

// releaseRetry relinquishes an admitted attempt without treating caller
// cancellation as a server failure. A canceled reserved probe wakes one of the
// other waiters to take its place.
func (c *Client) releaseRetry(attempt retryAttempt) {
	tracker := c.retryTracker()
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	state := tracker.retries[attempt.key]
	if state != attempt.state {
		return
	}
	state.active--
	if attempt.probe && state.generation == attempt.generation && state.probing {
		state.probing = false
		notifyRetryWaiters(state)
	}
	c.cleanupRetryLocked(tracker, attempt.key, state)
}

// cleanupRetryLocked drops idle healthy entries while retaining failed roots.
func (c *Client) cleanupRetryLocked(tracker *retryTracker, key string, state *retryState) {
	if state.active == 0 && state.interval == 0 {
		delete(tracker.retries, key)
	}
}

// notifyRetryWaiters broadcasts a state transition and installs the next
// generation's wait channel. tracker.mu must be held.
func notifyRetryWaiters(state *retryState) {
	close(state.changed)
	state.changed = make(chan struct{})
}

// retryTracker returns c's lazily installed tracker. Copies made after first
// use retain the same pointer and therefore the same lock and retry schedule.
func (c *Client) retryTracker() *retryTracker {
	retryInitMu.Lock()
	defer retryInitMu.Unlock()
	if c.retry == nil {
		c.retry = new(retryTracker)
	}
	return c.retry
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

// nextBackoff returns the next retry interval per the draft's schedule.
func nextBackoff(cur time.Duration) time.Duration {
	next := time.Duration(float64(cur) * retryBackoffFactor)
	if next > retryBackoffMax {
		return retryBackoffMax
	}
	return next
}

// serverPlan is the ordered endpoint and version plan for one server.
type serverPlan struct {
	addresses []Address
	versions  []protocol.Version
}

// NormalizeServer checks client compatibility without network I/O. It returns
// a copy with usable addresses ordered as [Client.Query] will try them.
// The address slice is cloned, but PublicKey still shares the input's storage.
func NormalizeServer(s Server) (Server, error) {
	plan, err := resolveServer(s)
	if err != nil {
		return Server{}, err
	}
	out := s
	out.Addresses = slices.Clone(plan.addresses)
	return out, nil
}

// resolveServer derives the scheme, orders usable addresses, and returns the
// VER list to advertise.
func resolveServer(s Server) (serverPlan, error) {
	if len(s.Addresses) == 0 {
		return serverPlan{}, errors.New("roughtime: server has no addresses")
	}
	sch, err := SchemeOfKey(s.PublicKey)
	if err != nil {
		return serverPlan{}, err
	}
	addrs, err := pickAddresses(s, sch)
	if err != nil {
		return serverPlan{}, err
	}
	versions, err := versionsForServer(s, sch)
	if err != nil {
		return serverPlan{}, err
	}
	return serverPlan{addresses: addrs, versions: versions}, nil
}

// pickAddresses orders endpoints per scheme rules (ML-DSA-44 requires TCP,
// Google requires UDP, and IETF Ed25519 orders UDP before TCP).
func pickAddresses(s Server, sch Scheme) ([]Address, error) {
	googleOnly := isGoogleEcosystemVersion(s.Version)
	if googleOnly && sch != SchemeEd25519 {
		return nil, errors.New("roughtime: Google-Roughtime requires an Ed25519 key")
	}
	var udp, tcp []Address
	for _, a := range s.Addresses {
		switch strings.ToLower(a.Transport) {
		case "udp":
			udp = append(udp, a)
		case "tcp":
			tcp = append(tcp, a)
		default:
			return nil, fmt.Errorf("roughtime: unsupported transport %q", a.Transport)
		}
	}
	switch {
	case sch == SchemeMLDSA44:
		if len(tcp) == 0 {
			return nil, errors.New("roughtime: ML-DSA-44 server has no tcp address")
		}
		return tcp, nil
	case googleOnly:
		if len(udp) == 0 {
			return nil, errors.New("roughtime: Google-Roughtime server has no udp address")
		}
		return udp, nil
	case len(udp)+len(tcp) > 0:
		return append(udp, tcp...), nil
	default:
		return nil, errors.New("roughtime: no usable address")
	}
}

// isGoogleOnly reports whether vs is exactly [protocol.VersionGoogle].
func isGoogleOnly(vs []protocol.Version) bool {
	return len(vs) == 1 && vs[0] == protocol.VersionGoogle
}

// versionsForServer returns s's VER list, honoring textual and numeric Google
// labels and numeric version caps.
func versionsForServer(s Server, sch Scheme) ([]protocol.Version, error) {
	if sch == SchemeEd25519 && isGoogleEcosystemVersion(s.Version) {
		return []protocol.Version{protocol.VersionGoogle}, nil
	}
	versions := VersionsForScheme(sch)
	limit, err := strconv.ParseUint(s.Version, 10, 32)
	if err != nil {
		return versions, nil
	}
	versions = slices.DeleteFunc(versions, func(v protocol.Version) bool { return uint64(v) > limit })
	if len(versions) == 0 {
		return nil, fmt.Errorf("roughtime: server version %d has no supported compatible wire version", limit)
	}
	return versions, nil
}
