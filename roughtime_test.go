// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package roughtime_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
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

// fakeMLServer is a minimal TCP-only ML-DSA-44 responder.
type fakeMLServer struct {
	rootPK  []byte
	cert    *protocol.Certificate
	tcpAddr string
	tcpLis  net.Listener
	wg      sync.WaitGroup
}

// newFakeMLServer creates a fresh experimental ML-DSA-44 test server.
func newFakeMLServer(t *testing.T) *fakeMLServer {
	t.Helper()
	rootSK, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("ML-DSA root: %v", err)
	}
	onlineSK, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("ML-DSA online: %v", err)
	}
	now := time.Now()
	cert, err := protocol.NewCertificateMLDSA44(now.Add(-time.Hour), now.Add(time.Hour), onlineSK, rootSK)
	if err != nil {
		t.Fatalf("NewCertificateMLDSA44: %v", err)
	}
	lis, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Fatalf("ML-DSA TCP listen: %v", err)
	}
	f := &fakeMLServer{
		rootPK:  bytes.Clone(rootSK.PublicKey().Bytes()),
		cert:    cert,
		tcpAddr: lis.Addr().String(),
		tcpLis:  lis,
	}
	f.wg.Add(1)
	go f.serveTCP()
	return f
}

// Close shuts down the ML-DSA-44 listener and joins its bounded-I/O handlers.
func (f *fakeMLServer) Close() {
	_ = f.tcpLis.Close()
	f.wg.Wait()
}

// serveTCP accepts and handles ML-DSA-44 requests.
func (f *fakeMLServer) serveTCP() {
	defer f.wg.Done()
	for {
		conn, err := f.tcpLis.Accept()
		if err != nil {
			return
		}
		f.wg.Add(1)
		go f.serveTCPConn(conn)
	}
}

// serveTCPConn reads one framed request and writes its signed response.
func (f *fakeMLServer) serveTCPConn(conn net.Conn) {
	defer f.wg.Done()
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	var hdr [protocol.PacketHeaderSize]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return
	}
	bodyLen, err := protocol.ParsePacketHeader(hdr[:])
	if err != nil || bodyLen == 0 || bodyLen > 8192 {
		return
	}
	raw := make([]byte, protocol.PacketHeaderSize+int(bodyLen))
	copy(raw, hdr[:])
	if _, err := io.ReadFull(conn, raw[protocol.PacketHeaderSize:]); err != nil {
		return
	}
	req, err := protocol.ParseRequest(raw)
	if err != nil {
		return
	}
	ver, err := protocol.SelectVersion(req.Versions, len(req.Nonce), protocol.ServerPreferenceMLDSA44)
	if err != nil {
		return
	}
	replies, err := protocol.CreateReplies(ver, []protocol.Request{*req}, time.Now(), time.Second, f.cert)
	if err != nil {
		return
	}
	_, _ = conn.Write(replies[0])
}

// server returns the public description of the ML-DSA-44 test server.
func (f *fakeMLServer) server() roughtime.Server {
	return roughtime.Server{
		Name:      "fake-ml-dsa-44",
		PublicKey: bytes.Clone(f.rootPK),
		Addresses: []roughtime.Address{{Transport: "tcp", Address: f.tcpAddr}},
	}
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

// Close shuts down both listeners and joins their bounded-I/O handlers.
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
		f.wg.Add(1)
		go f.serveTCPConn(conn)
	}
}

// serveTCPConn reads one framed request from conn, generates a reply, and
// writes it back.
func (f *fakeServer) serveTCPConn(conn net.Conn) {
	defer f.wg.Done()
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	var hdr [protocol.PacketHeaderSize]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return
	}
	bodyLen, err := protocol.ParsePacketHeader(hdr[:])
	if err != nil || bodyLen == 0 || bodyLen > 8192 {
		return
	}
	pkt := make([]byte, protocol.PacketHeaderSize+int(bodyLen))
	copy(pkt[:protocol.PacketHeaderSize], hdr[:])
	if _, err := io.ReadFull(conn, pkt[protocol.PacketHeaderSize:]); err != nil {
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
		t.Fatalf("RTT = %s, want > 0", resp.RTT)
	}
	if resp.Radius <= 0 {
		t.Fatalf("Radius = %s, want > 0", resp.Radius)
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

// TestAddressString covers the exact public endpoint rendering contract.
func TestAddressString(t *testing.T) {
	for _, tc := range []struct {
		addr roughtime.Address
		want string
	}{
		{roughtime.Address{}, "://"},
		{roughtime.Address{Transport: "UDP", Address: "[::1]:2002"}, "UDP://[::1]:2002"},
	} {
		if got := tc.addr.String(); got != tc.want {
			t.Errorf("Address.String() = %q, want %q", got, tc.want)
		}
	}
}

// TestClientPacketSizing covers all three high-level request-construction paths
// in both legacy-default and standard-body modes.
func TestClientPacketSizing(t *testing.T) {
	f := newFakeServer(t)
	defer f.Close()
	s := f.server()
	nonce := bytes.Repeat([]byte{0x5a}, 32)

	for _, tc := range []struct {
		name string
		c    roughtime.Client
		want int
	}{
		{"legacy default", roughtime.Client{}, 1024},
		{"standard body", roughtime.Client{StandardPacketSize: true}, 1024 + protocol.PacketHeaderSize},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := tc.c.Query(context.Background(), s)
			if err != nil {
				t.Fatalf("Query: %v", err)
			}
			if got := len(resp.Request); got != tc.want {
				t.Fatalf("Query request length = %d, want %d", got, tc.want)
			}

			resp, err = tc.c.QueryWithNonce(context.Background(), s, nonce)
			if err != nil {
				t.Fatalf("QueryWithNonce: %v", err)
			}
			if got := len(resp.Request); got != tc.want {
				t.Fatalf("QueryWithNonce request length = %d, want %d", got, tc.want)
			}

			chain, err := tc.c.QueryChain(context.Background(), []roughtime.Server{s})
			if err != nil {
				t.Fatalf("QueryChain: %v", err)
			}
			if got := len(chain.Results[0].Response.Request); got != tc.want {
				t.Fatalf("QueryChain request length = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestPackageQueryWrappers covers the shared package-level client helpers.
func TestPackageQueryWrappers(t *testing.T) {
	f := newFakeServer(t)
	defer f.Close()
	s := f.server()
	resp, err := roughtime.Query(context.Background(), s)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(resp.Request) != 1024 {
		t.Fatalf("Query request length = %d, want legacy default 1024", len(resp.Request))
	}
	nonce := bytes.Repeat([]byte{0x6b}, 32)
	resp, err = roughtime.QueryWithNonce(context.Background(), s, nonce)
	if err != nil {
		t.Fatalf("QueryWithNonce: %v", err)
	}
	parsed, err := protocol.ParseRequest(resp.Request)
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}
	if !bytes.Equal(parsed.Nonce, nonce) {
		t.Fatal("package QueryWithNonce did not preserve caller nonce")
	}
}

// TestNormalizeServer covers client-side preflight, endpoint preference, and
// address-slice independence without network I/O.
func TestNormalizeServer(t *testing.T) {
	pk := make([]byte, ed25519.PublicKeySize)
	in := roughtime.Server{
		Name:      "mixed",
		PublicKey: pk,
		Addresses: []roughtime.Address{
			{Transport: "tcp", Address: "tcp.example:2003"},
			{Transport: "UDP", Address: "udp1.example:2002"},
			{Transport: "udp", Address: "udp2.example:2002"},
		},
	}
	got, err := roughtime.NormalizeServer(in)
	if err != nil {
		t.Fatalf("NormalizeServer: %v", err)
	}
	if len(got.Addresses) != 3 || got.Addresses[0].Address != "udp1.example:2002" ||
		got.Addresses[1].Address != "udp2.example:2002" || got.Addresses[2].Address != "tcp.example:2003" {
		t.Fatalf("normalized addresses = %+v", got.Addresses)
	}
	got.Addresses[0].Address = "mutated"
	if in.Addresses[1].Address != "udp1.example:2002" {
		t.Fatal("NormalizeServer result aliases input address slice")
	}

	pq := roughtime.Server{
		PublicKey: make([]byte, protocol.MLDSA44PublicKeySize),
		Addresses: []roughtime.Address{
			{Transport: "udp", Address: "ignored.example:2002"},
			{Transport: "tcp", Address: "pq.example:2003"},
		},
	}
	got, err = roughtime.NormalizeServer(pq)
	if err != nil || len(got.Addresses) != 1 || got.Addresses[0].Transport != "tcp" {
		t.Fatalf("NormalizeServer(ML) = %+v, %v", got, err)
	}

	google := in
	google.Version = "google-roughtime"
	got, err = roughtime.NormalizeServer(google)
	if err != nil || len(got.Addresses) != 2 || !strings.EqualFold(got.Addresses[0].Transport, "udp") {
		t.Fatalf("NormalizeServer(Google) = %+v, %v", got, err)
	}

	tooOld := in
	tooOld.Version = "1"
	if _, err := roughtime.NormalizeServer(tooOld); err == nil || !strings.Contains(err.Error(), "no supported") {
		t.Fatalf("NormalizeServer(old version) = %v, want compatibility error", err)
	}
}

// TestClientMLDSAAndMixedProof covers a successful high-level ML-DSA-44 query,
// a mixed-scheme causal chain, and its offline proof round trip.
func TestClientMLDSAAndMixedProof(t *testing.T) {
	ed := newFakeServer(t)
	defer ed.Close()
	pq := newFakeMLServer(t)
	defer pq.Close()

	c := roughtime.Client{StandardPacketSize: true}
	pqResponse, err := c.Query(context.Background(), pq.server())
	if err != nil {
		t.Fatalf("ML-DSA Query: %v", err)
	}
	if pqResponse.Version != protocol.VersionMLDSA44 {
		t.Fatalf("ML-DSA version = %v", pqResponse.Version)
	}
	if got, want := len(pqResponse.Request), 8192+protocol.PacketHeaderSize; got != want {
		t.Fatalf("ML-DSA request length = %d, want %d", got, want)
	}

	servers := []roughtime.Server{ed.server(), pq.server(), ed.server()}
	chain, err := c.QueryChain(context.Background(), servers)
	if err != nil {
		t.Fatalf("mixed QueryChain: %v", err)
	}
	for i, result := range chain.Results {
		if result.Err != nil || result.Response == nil {
			t.Fatalf("result[%d] = %+v", i, result)
		}
	}
	proof, err := chain.Proof()
	if err != nil {
		t.Fatalf("Proof: %v", err)
	}
	data, err := proof.MarshalGzip()
	if err != nil {
		t.Fatalf("MarshalGzip: %v", err)
	}
	parsed, err := roughtime.ParseProof(data)
	if err != nil {
		t.Fatalf("ParseProof: %v", err)
	}
	if err := parsed.Verify(); err != nil {
		t.Fatalf("parsed mixed proof Verify: %v", err)
	}
	if err := parsed.Trust(servers); err != nil {
		t.Fatalf("parsed mixed proof Trust: %v", err)
	}
	links, err := parsed.Links()
	if err != nil {
		t.Fatalf("Links: %v", err)
	}
	wantVersions := []protocol.Version{protocol.VersionDraft12, protocol.VersionMLDSA44, protocol.VersionDraft12}
	for i, want := range wantVersions {
		if links[i].Version != want {
			t.Errorf("link[%d] version = %v, want %v", i, links[i].Version, want)
		}
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
		t.Fatalf("Query: %v, want 'no tcp address'", err)
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
			t.Fatalf("Query with version %q: %v, want 'no udp address' error", version, err)
		}
	}
}

// TestQueryAllSemaphoreCap covers the concurrency limit.
func TestQueryAllSemaphoreCap(t *testing.T) {
	const total, limit = 4, 2
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	servers := make([]roughtime.Server, total)
	var inFlight, peak atomic.Int32
	gate := make(chan struct{}, total)
	hold := make(chan struct{})
	var holdOnce sync.Once
	closeHold := func() { holdOnce.Do(func() { close(hold) }) }
	for i := range total {
		f := newFakeServerWithHook(t, func() {
			n := inFlight.Add(1)
			defer inFlight.Add(-1)
			for {
				p := peak.Load()
				if n <= p || peak.CompareAndSwap(p, n) {
					break
				}
			}
			select {
			case gate <- struct{}{}:
			case <-ctx.Done():
				return
			}
			select {
			case <-hold:
			case <-ctx.Done():
			}
		})
		t.Cleanup(f.Close)
		servers[i] = f.server()
	}
	t.Cleanup(closeHold) // Runs before the earlier server cleanups.

	c := roughtime.Client{Concurrency: limit}
	done := make(chan []roughtime.Result, 1)
	go func() {
		done <- c.QueryAll(ctx, servers)
	}()
	joined := false
	defer func() {
		cancel()
		closeHold()
		if joined {
			return
		}
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("QueryAll did not stop during cleanup")
		}
	}()

	for range limit {
		select {
		case <-gate:
		case <-ctx.Done():
			t.Fatalf("waiting for initial queries: %v", ctx.Err())
		}
	}
	if got := peak.Load(); got > limit {
		t.Fatalf("peak concurrency = %d > cap %d", got, limit)
	}
	closeHold()
	for range total - limit {
		select {
		case <-gate:
		case <-ctx.Done():
			t.Fatalf("waiting for remaining queries: %v", ctx.Err())
		}
	}
	var results []roughtime.Result
	select {
	case results = <-done:
		joined = true
	case <-ctx.Done():
		t.Fatalf("waiting for QueryAll: %v", ctx.Err())
	}
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
			t.Fatalf("result[%d] has Name %q, out of order", i, r.Server.Name)
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
		t.Fatalf("Query took %s after cancel, should unblock promptly", time.Since(start))
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
		t.Fatalf("error %q, want 'nonce length' message", err)
	}
}

// TestChainPublicErrorBranches covers empty public inputs and nil receivers.
func TestChainPublicErrorBranches(t *testing.T) {
	var nilResult *roughtime.ChainResult
	if _, err := nilResult.Proof(); err == nil {
		t.Fatal("nil ChainResult.Proof succeeded")
	}
	chain, err := new(roughtime.Client).QueryChain(context.Background(), nil)
	if err != nil {
		t.Fatalf("empty QueryChain: %v", err)
	}
	if _, err := chain.Proof(); err == nil {
		t.Fatal("empty ChainResult.Proof succeeded")
	}
	if _, err := new(roughtime.Client).QueryChainWithNonce(context.Background(), nil, nil); err == nil {
		t.Fatal("QueryChainWithNonce accepted empty seed")
	}
}
