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
)

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

// Close shuts down the UDP and TCP listeners and waits for their loops.
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
	defer func() { _ = conn.Close() }()
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

// TestClientQueryUDP covers a verified UDP query.
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
	if len(resp.Request) != 1024 {
		t.Fatalf("request length = %d, want 1024", len(resp.Request))
	}
	if _, _, err := roughtime.Verify(f.rootPK, resp.Request, resp.Reply); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// TestClientQueryTCP covers a verified TCP query.
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

// TestClientDefaultFallsBackToTCP covers zero-client endpoint fallback.
func TestClientDefaultFallsBackToTCP(t *testing.T) {
	f := newFakeServer(t)
	defer f.Close()

	closed, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Fatal(err)
	}
	closedAddr := closed.LocalAddr().String()
	_ = closed.Close()

	s := f.server()
	s.Addresses[0].Address = closedAddr
	resp, err := new(roughtime.Client).Query(context.Background(), s)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if resp.Address.Transport != "tcp" {
		t.Fatalf("transport = %q, want tcp", resp.Address.Transport)
	}
}

// TestClientRetryOnDrop covers retry after a dropped request.
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

// TestClientQueryChainWithNonceBindsSeed covers caller-supplied chain seeds.
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

// TestPickAddressMLDSARequiresTCP covers the PQ transport constraint.
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

// TestPickAddressGoogleRequiresUDP covers the Google transport constraint.
func TestPickAddressGoogleRequiresUDP(t *testing.T) {
	for _, version := range []string{"Google-Roughtime", "3000600613"} {
		s := roughtime.Server{
			Name:      "google-tcp-only",
			Version:   version,
			PublicKey: make([]byte, ed25519.PublicKeySize),
			Addresses: []roughtime.Address{{Transport: "tcp", Address: "example.com:2002"}},
		}
		var c roughtime.Client
		_, err := c.Query(context.Background(), s)
		if err == nil || !strings.Contains(err.Error(), "udp address") {
			t.Fatalf("Query with version %q: %v; want 'no udp address' error", version, err)
		}
	}
}

// TestQueryAllSemaphoreCap covers the concurrency limit.
func TestQueryAllSemaphoreCap(t *testing.T) {
	const total, limit = 4, 2
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

	c := roughtime.Client{Concurrency: limit}
	done := make(chan []roughtime.Result, 1)
	go func() {
		done <- c.QueryAll(context.Background(), servers)
	}()

	// fill the cap, assert peak, then release
	for range limit {
		<-gate
	}
	if got := peak.Load(); got > limit {
		t.Fatalf("peak concurrency = %d > cap %d", got, limit)
	}
	go func() {
		// drain remaining gates as later waves acquire the semaphore
		for range total - limit {
			<-gate
		}
	}()
	closeHold()
	results := <-done
	if len(results) != total {
		t.Fatalf("got %d results, want %d", len(results), total)
	}
	if peak.Load() > limit {
		t.Fatalf("final peak %d > cap %d", peak.Load(), limit)
	}
}

// TestQueryAllPreservesOrder covers slot-aligned results.
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

// TestClientRespectsContextCancel covers query cancellation.
func TestClientRespectsContextCancel(t *testing.T) {
	f := newFakeServer(t)
	defer f.Close()
	blackhole, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blackhole.Close() }()

	s := f.server()
	s.Addresses = []roughtime.Address{{Transport: "udp", Address: blackhole.LocalAddr().String()}}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	c := roughtime.Client{Timeout: 5 * time.Second}
	start := time.Now()
	_, err = c.Query(ctx, s)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Query error = %v, want context.Canceled", err)
	}
	if time.Since(start) > time.Second {
		t.Fatalf("Query took %s after cancel; should unblock promptly", time.Since(start))
	}

	nextCtx, nextCancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer nextCancel()
	if _, err := c.Query(nextCtx, f.server()); err != nil {
		t.Fatalf("query after cancellation: %v", err)
	}
}

// TestQueryWithNonceRejectsBadLength covers nonce-size validation.
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
