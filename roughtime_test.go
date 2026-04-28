// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package roughtime_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tannerryan/roughtime"
	"github.com/tannerryan/roughtime/protocol"
	"go.uber.org/goleak"
)

// TestMain runs the package tests under goleak to surface goroutine leaks.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// fakeServer is a minimal UDP/TCP responder for end-to-end client tests.
type fakeServer struct {
	t         *testing.T
	rootPK    ed25519.PublicKey
	cert      *protocol.Certificate
	udpAddr   string
	tcpAddr   string
	udpConn   *net.UDPConn
	tcpLis    net.Listener
	wg        sync.WaitGroup
	mu        sync.Mutex
	dropCount int           // >0 drops the next N requests
	hook      func()        // optional pre-handle hook
	radius    time.Duration // signed time-uncertainty radius
}

// newFakeServer returns a default fakeServer with a 1s radius and no pre-reply
// hook.
func newFakeServer(t *testing.T) *fakeServer {
	return newFakeServerOpts(t, nil, time.Second)
}

// newFakeServerWithRadius returns a fakeServer that signs replies with the
// given uncertainty radius.
func newFakeServerWithRadius(t *testing.T, radius time.Duration) *fakeServer {
	return newFakeServerOpts(t, nil, radius)
}

// newFakeServerWithHook returns a fakeServer that runs hook before each reply
// for concurrency gating.
func newFakeServerWithHook(t *testing.T, hook func()) *fakeServer {
	return newFakeServerOpts(t, hook, time.Second)
}

// newFakeServerOpts is the underlying constructor that wires up UDP and TCP
// listeners with the given options.
func newFakeServerOpts(t *testing.T, hook func(), radius time.Duration) *fakeServer {
	t.Helper()
	rootPK, rootSK, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 root: %v", err)
	}
	_, onlineSK, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 online: %v", err)
	}
	now := time.Now()
	cert, err := protocol.NewCertificate(now.Add(-time.Hour), now.Add(time.Hour), onlineSK, rootSK)
	if err != nil {
		t.Fatalf("NewCertificate: %v", err)
	}

	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		t.Fatalf("udp listen: %v", err)
	}
	tl, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		_ = uc.Close()
		t.Fatalf("tcp listen: %v", err)
	}
	f := &fakeServer{
		t:       t,
		rootPK:  rootPK,
		cert:    cert,
		udpAddr: uc.LocalAddr().String(),
		tcpAddr: tl.Addr().String(),
		udpConn: uc,
		tcpLis:  tl,
		hook:    hook,
		radius:  radius,
	}
	f.wg.Add(2)
	go f.serveUDP()
	go f.serveTCP()
	return f
}

// Close shuts down the UDP and TCP listeners and waits for the serve goroutines
// to exit.
func (f *fakeServer) Close() {
	_ = f.udpConn.Close()
	_ = f.tcpLis.Close()
	f.wg.Wait()
}

// dropNext arms the server to drop the next n requests on either transport.
func (f *fakeServer) dropNext(n int) {
	f.mu.Lock()
	f.dropCount = n
	f.mu.Unlock()
}

// shouldDrop reports whether the next request should be dropped, decrementing
// the drop counter.
func (f *fakeServer) shouldDrop() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.dropCount > 0 {
		f.dropCount--
		return true
	}
	return false
}

// serveUDP handles UDP requests until the listener is closed.
func (f *fakeServer) serveUDP() {
	defer f.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, peer, err := f.udpConn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if f.shouldDrop() {
			continue
		}
		if f.hook != nil {
			f.hook()
		}
		reply, err := f.handle(buf[:n])
		if err != nil {
			continue
		}
		_, _ = f.udpConn.WriteToUDP(reply, peer)
	}
}

// serveTCP accepts TCP connections and dispatches each to serveTCPConn.
func (f *fakeServer) serveTCP() {
	defer f.wg.Done()
	for {
		conn, err := f.tcpLis.Accept()
		if err != nil {
			return
		}
		go f.serveTCPConn(conn)
	}
}

// serveTCPConn reads one framed request from conn, generates a reply, and
// writes it back.
func (f *fakeServer) serveTCPConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	var hdr [protocol.PacketHeaderSize]byte
	if _, err := readFull(conn, hdr[:]); err != nil {
		return
	}
	bodyLen, err := protocol.ParsePacketHeader(hdr[:])
	if err != nil || bodyLen == 0 || bodyLen > 8192 {
		return
	}
	pkt := make([]byte, protocol.PacketHeaderSize+int(bodyLen))
	copy(pkt[:protocol.PacketHeaderSize], hdr[:])
	if _, err := readFull(conn, pkt[protocol.PacketHeaderSize:]); err != nil {
		return
	}
	if f.shouldDrop() {
		return
	}
	if f.hook != nil {
		f.hook()
	}
	reply, err := f.handle(pkt)
	if err != nil {
		return
	}
	_, _ = conn.Write(reply)
}

// handle parses a request, negotiates a version, and returns a signed reply.
func (f *fakeServer) handle(raw []byte) ([]byte, error) {
	req, err := protocol.ParseRequest(raw)
	if err != nil {
		return nil, err
	}
	prefs := []protocol.Version{protocol.VersionDraft12, protocol.VersionDraft11, protocol.VersionDraft10}
	ver, err := protocol.SelectVersion(req.Versions, len(req.Nonce), prefs)
	if err != nil {
		return nil, err
	}
	replies, err := protocol.CreateReplies(ver, []protocol.Request{*req}, time.Now(), f.radius, f.cert)
	if err != nil {
		return nil, err
	}
	return replies[0], nil
}

// readFull reads len(b) bytes from conn into b, returning early on error.
func readFull(conn net.Conn, b []byte) (int, error) {
	total := 0
	for total < len(b) {
		n, err := conn.Read(b[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// server returns a roughtime.Server description for f's UDP and TCP endpoints.
func (f *fakeServer) server() roughtime.Server {
	uh, up, _ := net.SplitHostPort(f.udpAddr)
	th, tp, _ := net.SplitHostPort(f.tcpAddr)
	return roughtime.Server{
		Name:      "fake",
		Version:   "draft-ietf-ntp-roughtime-12",
		PublicKey: f.rootPK,
		Addresses: []roughtime.Address{
			{Transport: "udp", Address: net.JoinHostPort(uh, up)},
			{Transport: "tcp", Address: net.JoinHostPort(th, tp)},
		},
	}
}

// TestClientQueryUDP verifies a default Client.Query goes over UDP and returns
// a positive RTT and Radius.
func TestClientQueryUDP(t *testing.T) {
	f := newFakeServer(t)
	defer f.Close()

	var c roughtime.Client
	resp, err := c.Query(context.Background(), f.server())
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if resp.Address.Transport != "udp" {
		t.Fatalf("expected UDP, got %q", resp.Address.Transport)
	}
	if resp.RTT <= 0 {
		t.Fatalf("RTT = %s; want > 0", resp.RTT)
	}
	if resp.Radius <= 0 {
		t.Fatalf("Radius = %s; want > 0", resp.Radius)
	}
}

// TestClientQueryTCP verifies Client.Query falls back to TCP when only TCP is
// offered.
func TestClientQueryTCP(t *testing.T) {
	f := newFakeServer(t)
	defer f.Close()

	s := f.server()
	s.Addresses = s.Addresses[1:] // TCP only

	var c roughtime.Client
	resp, err := c.Query(context.Background(), s)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if resp.Address.Transport != "tcp" {
		t.Fatalf("expected TCP, got %q", resp.Address.Transport)
	}
}

// TestClientRetryOnDrop verifies Client retries succeed after the server drops
// one request.
func TestClientRetryOnDrop(t *testing.T) {
	f := newFakeServer(t)
	defer f.Close()
	f.dropNext(1)

	c := roughtime.Client{Timeout: 200 * time.Millisecond, MaxAttempts: 3}
	_, err := c.Query(context.Background(), f.server())
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
}

// TestClientQueryAllConcurrent verifies QueryAll returns one verified Result
// per server.
func TestClientQueryAllConcurrent(t *testing.T) {
	f1 := newFakeServer(t)
	defer f1.Close()
	f2 := newFakeServer(t)
	defer f2.Close()

	var c roughtime.Client
	results := c.QueryAll(context.Background(), []roughtime.Server{f1.server(), f2.server()})
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	for i, r := range results {
		if r.Err != nil {
			t.Fatalf("result[%d]: %v", i, r.Err)
		}
		if r.Response == nil || r.Response.Midpoint.IsZero() {
			t.Fatalf("result[%d]: no midpoint", i)
		}
	}
}

// TestClientQueryChainVerified verifies a three-link QueryChain produces a
// Proof that re-verifies.
func TestClientQueryChainVerified(t *testing.T) {
	f := newFakeServer(t)
	defer f.Close()
	s := f.server()

	var c roughtime.Client
	cr, err := c.QueryChain(context.Background(), []roughtime.Server{s, s, s})
	if err != nil {
		t.Fatalf("QueryChain: %v", err)
	}
	if len(cr.Results) != 3 {
		t.Fatalf("got %d links, want 3", len(cr.Results))
	}
	for i, r := range cr.Results {
		if r.Err != nil {
			t.Fatalf("link[%d]: %v", i, r.Err)
		}
	}
	proof, err := cr.Proof()
	if err != nil {
		t.Fatalf("cr.Proof: %v", err)
	}
	if err := proof.Verify(); err != nil {
		t.Fatalf("proof Verify: %v", err)
	}
}

// TestClientQueryChainWithNonceBindsSeed verifies link 0 nonce equals the seed
// and later links derive causally.
func TestClientQueryChainWithNonceBindsSeed(t *testing.T) {
	f := newFakeServer(t)
	defer f.Close()
	s := f.server()

	seed := bytes.Repeat([]byte{0xA5}, 32) // simulates SHA-256(document)
	var c roughtime.Client
	cr, err := c.QueryChainWithNonce(context.Background(), []roughtime.Server{s, s, s}, seed)
	if err != nil {
		t.Fatalf("QueryChainWithNonce: %v", err)
	}
	proof, err := cr.Proof()
	if err != nil {
		t.Fatalf("cr.Proof: %v", err)
	}
	if proof.Len() != 3 {
		t.Fatalf("got %d links, want 3", proof.Len())
	}
	got, err := proof.SeedNonce()
	if err != nil {
		t.Fatalf("SeedNonce: %v", err)
	}
	if !bytes.Equal(got, seed) {
		t.Fatalf("seed nonce = %x, want %x", got, seed)
	}
	links, err := proof.Links()
	if err != nil {
		t.Fatalf("Links: %v", err)
	}
	for i := 1; i < len(links); i++ {
		if bytes.Equal(links[i].Nonce, seed) {
			t.Fatalf("link[%d] nonce should not equal seed", i)
		}
	}
	if err := proof.Verify(); err != nil {
		t.Fatalf("proof Verify: %v", err)
	}
}

// TestPickAddressMLDSARequiresTCP verifies an ML-DSA-44 server with only UDP
// fails address selection.
func TestPickAddressMLDSARequiresTCP(t *testing.T) {
	pk := make([]byte, 1312) // ML-DSA-44 length
	s := roughtime.Server{
		Name:      "pq",
		PublicKey: pk,
		Addresses: []roughtime.Address{{Transport: "udp", Address: "example.com:2002"}},
	}
	var c roughtime.Client
	_, err := c.Query(context.Background(), s)
	if err == nil || !strings.Contains(err.Error(), "tcp address") {
		t.Fatalf("Query: %v; want 'no tcp address'", err)
	}
}

// TestQueryRejectsEmptyAddresses verifies Query rejects a Server with no
// Addresses.
func TestQueryRejectsEmptyAddresses(t *testing.T) {
	var c roughtime.Client
	_, err := c.Query(context.Background(), roughtime.Server{
		PublicKey: make([]byte, ed25519.PublicKeySize),
	})
	if err == nil || !strings.Contains(err.Error(), "no addresses") {
		t.Fatalf("Query: %v; want 'no addresses' error", err)
	}
}

// TestQueryRejectsBadKeyLength verifies Query rejects a public key that is
// neither 32 nor 1312 bytes.
func TestQueryRejectsBadKeyLength(t *testing.T) {
	var c roughtime.Client
	_, err := c.Query(context.Background(), roughtime.Server{
		PublicKey: make([]byte, 7),
		Addresses: []roughtime.Address{{Transport: "udp", Address: "example.com:2002"}},
	})
	if err == nil || !strings.Contains(err.Error(), "public key length") {
		t.Fatalf("Query: %v; want 'public key length' error", err)
	}
}

// TestQueryRejectsUnsupportedTransport verifies Query rejects transports other
// than udp or tcp.
func TestQueryRejectsUnsupportedTransport(t *testing.T) {
	var c roughtime.Client
	_, err := c.Query(context.Background(), roughtime.Server{
		PublicKey: make([]byte, ed25519.PublicKeySize),
		Addresses: []roughtime.Address{{Transport: "sctp", Address: "example.com:2002"}},
	})
	if err == nil {
		t.Fatal("Query accepted unsupported transport")
	}
}

// TestPickAddressGoogleRequiresUDP verifies a Google-Roughtime server with only
// TCP fails address selection.
func TestPickAddressGoogleRequiresUDP(t *testing.T) {
	s := roughtime.Server{
		Name:      "google-tcp-only",
		Version:   "Google-Roughtime",
		PublicKey: make([]byte, ed25519.PublicKeySize),
		Addresses: []roughtime.Address{{Transport: "tcp", Address: "example.com:2002"}},
	}
	var c roughtime.Client
	_, err := c.Query(context.Background(), s)
	if err == nil || !strings.Contains(err.Error(), "udp address") {
		t.Fatalf("Query: %v; want 'no udp address' error", err)
	}
}

// TestPickAddressEd25519PrefersUDP verifies an Ed25519 server with both
// transports prefers UDP.
func TestPickAddressEd25519PrefersUDP(t *testing.T) {
	f := newFakeServer(t)
	defer f.Close()
	s := f.server()
	var c roughtime.Client
	resp, err := c.Query(context.Background(), s)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if resp.Address.Transport != "udp" {
		t.Fatalf("Address.Transport = %q; Ed25519 should prefer udp", resp.Address.Transport)
	}
}

// TestQueryAllSemaphoreCap verifies QueryAll never exceeds the default
// concurrency cap.
func TestQueryAllSemaphoreCap(t *testing.T) {
	const total = roughtime.MaxQueryAllConcurrency * 2
	servers := make([]roughtime.Server, total)
	closers := make([]func(), total)
	var inFlight, peak atomic.Int32
	gate := make(chan struct{})
	hold := make(chan struct{})
	for i := range total {
		f := newFakeServerWithHook(t, func() {
			n := inFlight.Add(1)
			for {
				p := peak.Load()
				if n <= p || peak.CompareAndSwap(p, n) {
					break
				}
			}
			gate <- struct{}{}
			<-hold
			inFlight.Add(-1)
		})
		servers[i] = f.server()
		closers[i] = f.Close
	}
	defer func() {
		for _, cl := range closers {
			cl()
		}
	}()
	// release hooks on t.Fatalf so the closers above don't deadlock on wg.Wait
	var holdOnce sync.Once
	closeHold := func() { holdOnce.Do(func() { close(hold) }) }
	defer closeHold()

	var c roughtime.Client
	done := make(chan []roughtime.Result, 1)
	go func() {
		done <- c.QueryAll(context.Background(), servers)
	}()

	// fill the cap, assert peak, then release
	for range roughtime.MaxQueryAllConcurrency {
		<-gate
	}
	if got := peak.Load(); got > roughtime.MaxQueryAllConcurrency {
		t.Fatalf("peak concurrency = %d > cap %d", got, roughtime.MaxQueryAllConcurrency)
	}
	go func() {
		// drain remaining gates as later waves acquire the semaphore
		for range total - roughtime.MaxQueryAllConcurrency {
			<-gate
		}
	}()
	closeHold()
	results := <-done
	if len(results) != total {
		t.Fatalf("got %d results, want %d", len(results), total)
	}
	if peak.Load() > roughtime.MaxQueryAllConcurrency {
		t.Fatalf("final peak %d > cap %d", peak.Load(), roughtime.MaxQueryAllConcurrency)
	}
}

// TestQueryAllPreservesOrder verifies QueryAll returns Results in the same
// order as the input servers.
func TestQueryAllPreservesOrder(t *testing.T) {
	f := newFakeServer(t)
	defer f.Close()
	const n = 5
	servers := make([]roughtime.Server, n)
	for i := range n {
		s := f.server()
		s.Name = fmt.Sprintf("idx-%d", i)
		servers[i] = s
	}
	var c roughtime.Client
	results := c.QueryAll(context.Background(), servers)
	for i, r := range results {
		if r.Server.Name != fmt.Sprintf("idx-%d", i) {
			t.Fatalf("result[%d] has Name %q; out of order", i, r.Server.Name)
		}
	}
}

// TestClientRetriesExhausted verifies Query surfaces an error after all retries
// are dropped.
func TestClientRetriesExhausted(t *testing.T) {
	f := newFakeServer(t)
	defer f.Close()
	f.dropNext(100)
	c := roughtime.Client{Timeout: 50 * time.Millisecond, MaxAttempts: 2}
	// large context budget so the surfaced error is the per-attempt timeout,
	// not ctx cancel
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := c.Query(ctx, f.server())
	if err == nil {
		t.Fatal("Query succeeded despite drops")
	}
}

// TestClientRespectsContextCancel verifies Query unblocks promptly when the
// context is cancelled.
func TestClientRespectsContextCancel(t *testing.T) {
	// closed port so Dial/Read hangs on an unreachable peer
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	s := roughtime.Server{
		PublicKey: make([]byte, 32),
		Addresses: []roughtime.Address{{Transport: "udp", Address: addr}},
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	c := roughtime.Client{Timeout: 5 * time.Second}
	start := time.Now()
	_, err = c.Query(ctx, s)
	if err == nil {
		t.Fatal("expected error on cancel")
	}
	if time.Since(start) > time.Second {
		t.Fatalf("Query took %s after cancel; should unblock promptly", time.Since(start))
	}
}

// TestQueryWithNonceUsesCallerNonce verifies QueryWithNonce embeds the supplied
// nonce in the request.
func TestQueryWithNonceUsesCallerNonce(t *testing.T) {
	f := newFakeServer(t)
	defer f.Close()

	nonce := bytes.Repeat([]byte{0xAB}, 32)
	var c roughtime.Client
	resp, err := c.QueryWithNonce(context.Background(), f.server(), nonce)
	if err != nil {
		t.Fatalf("QueryWithNonce: %v", err)
	}
	if len(resp.Request) == 0 {
		t.Fatal("Response.Request not populated")
	}
	if len(resp.Reply) == 0 {
		t.Fatal("Response.Reply not populated")
	}
	if !bytes.Contains(resp.Request, nonce) {
		t.Fatal("supplied nonce not embedded in request bytes")
	}
}

// TestQueryWithNonceRejectsBadLength verifies QueryWithNonce rejects nonces of
// the wrong length.
func TestQueryWithNonceRejectsBadLength(t *testing.T) {
	f := newFakeServer(t)
	defer f.Close()

	var c roughtime.Client
	_, err := c.QueryWithNonce(context.Background(), f.server(), []byte("too short"))
	if err == nil {
		t.Fatal("QueryWithNonce accepted short nonce")
	}
	if !strings.Contains(err.Error(), "nonce length") {
		t.Fatalf("error %q; want 'nonce length' message", err)
	}
}

// TestPackageLevelQuery verifies the package-level Query helper succeeds
// against a fake server.
func TestPackageLevelQuery(t *testing.T) {
	f := newFakeServer(t)
	defer f.Close()

	resp, err := roughtime.Query(context.Background(), f.server())
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if resp.Midpoint.IsZero() {
		t.Fatal("no midpoint on package-level Query")
	}
}

// TestPackageLevelQueryWithNonce verifies the package-level QueryWithNonce
// helper embeds the nonce.
func TestPackageLevelQueryWithNonce(t *testing.T) {
	f := newFakeServer(t)
	defer f.Close()

	nonce := bytes.Repeat([]byte{0xCD}, 32)
	resp, err := roughtime.QueryWithNonce(context.Background(), f.server(), nonce)
	if err != nil {
		t.Fatalf("QueryWithNonce: %v", err)
	}
	if !bytes.Contains(resp.Request, nonce) {
		t.Fatal("nonce not in request")
	}
}

// TestAddressString verifies Address.String renders as
// "<transport>://<host:port>".
func TestAddressString(t *testing.T) {
	a := roughtime.Address{Transport: "udp", Address: "time.example.com:2002"}
	if got, want := a.String(), "udp://time.example.com:2002"; got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}

// TestClientConcurrencyOverride verifies a custom Client.Concurrency caps
// in-flight QueryAll fan-out.
func TestClientConcurrencyOverride(t *testing.T) {
	const cap = 4
	const total = cap * 3
	servers := make([]roughtime.Server, total)
	closers := make([]func(), total)
	var inFlight, peak atomic.Int32
	gate := make(chan struct{})
	hold := make(chan struct{})
	for i := range total {
		f := newFakeServerWithHook(t, func() {
			n := inFlight.Add(1)
			for {
				p := peak.Load()
				if n <= p || peak.CompareAndSwap(p, n) {
					break
				}
			}
			gate <- struct{}{}
			<-hold
			inFlight.Add(-1)
		})
		servers[i] = f.server()
		closers[i] = f.Close
	}
	defer func() {
		for _, cl := range closers {
			cl()
		}
	}()
	// release hooks on t.Fatalf so the closers above don't deadlock on wg.Wait
	var holdOnce sync.Once
	closeHold := func() { holdOnce.Do(func() { close(hold) }) }
	defer closeHold()

	c := roughtime.Client{Concurrency: cap}
	done := make(chan []roughtime.Result, 1)
	go func() {
		done <- c.QueryAll(context.Background(), servers)
	}()
	for range cap {
		<-gate
	}
	if got := peak.Load(); got > int32(cap) {
		t.Fatalf("peak %d > cap %d", got, cap)
	}
	go func() {
		for range total - cap {
			<-gate
		}
	}()
	closeHold()
	<-done
}

// TestErrorSentinelsReExported verifies each top-level error sentinel matches
// its protocol counterpart via errors.Is.
func TestErrorSentinelsReExported(t *testing.T) {
	pairs := []struct {
		name      string
		highLevel error
		lowLevel  error
	}{
		{"ErrPeerClosedNoReply", roughtime.ErrPeerClosedNoReply, protocol.ErrPeerClosedNoReply},
		{"ErrChainNonce", roughtime.ErrChainNonce, protocol.ErrChainNonce},
		{"ErrCausalOrder", roughtime.ErrCausalOrder, protocol.ErrCausalOrder},
		{"ErrMerkleMismatch", roughtime.ErrMerkleMismatch, protocol.ErrMerkleMismatch},
		{"ErrDelegationWindow", roughtime.ErrDelegationWindow, protocol.ErrDelegationWindow},
	}
	for _, p := range pairs {
		if !errors.Is(p.highLevel, p.lowLevel) {
			t.Errorf("%s: roughtime sentinel does not match protocol sentinel", p.name)
		}
	}
}

// TestQueryWithNonceRejectsEmptyAddresses verifies QueryWithNonce rejects a
// Server with no Addresses.
func TestQueryWithNonceRejectsEmptyAddresses(t *testing.T) {
	var c roughtime.Client
	_, err := c.QueryWithNonce(context.Background(), roughtime.Server{
		PublicKey: make([]byte, ed25519.PublicKeySize),
	}, bytes.Repeat([]byte{0}, 32))
	if err == nil || !strings.Contains(err.Error(), "no addresses") {
		t.Fatalf("QueryWithNonce: %v; want no-addresses error", err)
	}
}

// TestQueryGoogleVersionPath verifies versionsForServer's Google-Roughtime
// branch is exercised.
func TestQueryGoogleVersionPath(t *testing.T) {
	c := roughtime.Client{Timeout: 50 * time.Millisecond, MaxAttempts: 1}
	_, err := c.Query(context.Background(), roughtime.Server{
		Version:   "Google-Roughtime",
		PublicKey: make([]byte, ed25519.PublicKeySize),
		Addresses: []roughtime.Address{{Transport: "udp", Address: "127.0.0.1:1"}},
	})
	if err == nil {
		t.Fatal("Query against closed port returned nil err")
	}
}

// TestSendWithRetryContextCancel verifies sendWithRetry honors a pre-cancelled
// context.
func TestSendWithRetryContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel so the first ctx.Err() check trips
	c := roughtime.Client{Timeout: 50 * time.Millisecond, MaxAttempts: 5}
	_, err := c.Query(ctx, roughtime.Server{
		PublicKey: make([]byte, ed25519.PublicKeySize),
		Addresses: []roughtime.Address{{Transport: "udp", Address: "127.0.0.1:1"}},
	})
	if err == nil {
		t.Fatal("Query did not honor pre-cancelled context")
	}
}

// TestSendWithRetryBackoffCancel verifies sleepCtx returns false when the
// context is cancelled mid-backoff.
func TestSendWithRetryBackoffCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	c := roughtime.Client{Timeout: 10 * time.Millisecond, MaxAttempts: 5}
	// closed port; first attempt fails fast, then sleepCtx triggers
	_, err := c.Query(ctx, roughtime.Server{
		PublicKey: make([]byte, ed25519.PublicKeySize),
		Addresses: []roughtime.Address{{Transport: "udp", Address: "127.0.0.1:1"}},
	})
	if err == nil {
		t.Fatal("Query succeeded with cancelled context mid-backoff")
	}
}

// TestQueryAllPreCancelled verifies QueryAll surfaces a per-server error for
// every entry on a pre-cancelled context.
func TestQueryAllPreCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	bad := roughtime.Server{PublicKey: make([]byte, ed25519.PublicKeySize)} // no addresses
	servers := []roughtime.Server{bad, bad, bad}
	c := roughtime.Client{Concurrency: 1}
	results := c.QueryAll(ctx, servers)
	if len(results) != 3 {
		t.Fatalf("got %d results", len(results))
	}
	for i, r := range results {
		if r.Err == nil {
			t.Fatalf("result[%d]: expected error, got success", i)
		}
	}
}

// TestQueryChainPreCancelled verifies queryChain populates per-link errors when
// the context is pre-cancelled.
func TestQueryChainPreCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	servers := []roughtime.Server{{PublicKey: make([]byte, ed25519.PublicKeySize)}}
	var c roughtime.Client
	cr, err := c.QueryChain(ctx, servers)
	if err != nil {
		t.Fatalf("QueryChain: %v", err)
	}
	if len(cr.Results) != 1 || cr.Results[0].Err == nil {
		t.Fatalf("expected per-link error from cancelled context, got %+v", cr.Results)
	}
}

// TestQueryChainResolveServerError verifies queryChain surfaces a resolveServer
// error in the per-link Result.
func TestQueryChainResolveServerError(t *testing.T) {
	servers := []roughtime.Server{{PublicKey: make([]byte, ed25519.PublicKeySize)}}
	var c roughtime.Client
	cr, _ := c.QueryChain(context.Background(), servers)
	if cr.Results[0].Err == nil {
		t.Fatal("expected resolveServer error, got nil")
	}
}

// TestClientConcurrentQueryAll verifies overlapping QueryAll calls do not
// corrupt Results under -race.
func TestClientConcurrentQueryAll(t *testing.T) {
	f := newFakeServer(t)
	defer f.Close()
	servers := []roughtime.Server{f.server(), f.server(), f.server()}

	var c roughtime.Client
	var wg sync.WaitGroup
	const goroutines = 8
	for range goroutines {
		wg.Go(func() {
			results := c.QueryAll(context.Background(), servers)
			for i, r := range results {
				if r.Err != nil {
					t.Errorf("result[%d]: %v", i, r.Err)
				}
			}
		})
	}
	wg.Wait()
}
