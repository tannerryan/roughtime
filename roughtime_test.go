// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package roughtime_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
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
	dropCount int    // >0 drops the next N requests
	hook      func() // optional pre-handle hook
}

func newFakeServer(t *testing.T) *fakeServer {
	return newFakeServerWithHook(t, nil)
}

func newFakeServerWithHook(t *testing.T, hook func()) *fakeServer {
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
	}
	f.wg.Add(2)
	go f.serveUDP()
	go f.serveTCP()
	return f
}

func (f *fakeServer) Close() {
	_ = f.udpConn.Close()
	_ = f.tcpLis.Close()
	f.wg.Wait()
}

func (f *fakeServer) dropNext(n int) {
	f.mu.Lock()
	f.dropCount = n
	f.mu.Unlock()
}

func (f *fakeServer) shouldDrop() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.dropCount > 0 {
		f.dropCount--
		return true
	}
	return false
}

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
	replies, err := protocol.CreateReplies(ver, []protocol.Request{*req}, time.Now(), time.Second, f.cert)
	if err != nil {
		return nil, err
	}
	return replies[0], nil
}

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

// TestClientQueryUDP verifies a UDP round-trip yields non-zero RTT and Radius.
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

// TestClientQueryTCP verifies a TCP round-trip when only TCP is advertised.
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

// TestClientRetryOnDrop verifies the retry path recovers from a single drop.
func TestClientRetryOnDrop(t *testing.T) {
	f := newFakeServer(t)
	defer f.Close()
	f.dropNext(1)

	c := roughtime.Client{Timeout: 200 * time.Millisecond, Retries: 3}
	_, err := c.Query(context.Background(), f.server())
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
}

// TestClientQueryAllConcurrent verifies parallel queries return per-slot results.
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

// TestClientQueryChainVerified verifies a three-link chain via [protocol.Chain].
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
	if err := cr.Chain.Verify(); err != nil {
		t.Fatalf("chain Verify: %v", err)
	}
}

// TestResponseDriftAndInSync verifies Drift and InSync on a hand-built response.
func TestResponseDriftAndInSync(t *testing.T) {
	now := time.Unix(1000, 0)
	r := roughtime.Response{
		Midpoint: now,
		Radius:   2 * time.Second,
		RTT:      10 * time.Millisecond,
		LocalNow: now.Add(1 * time.Second),
	}
	// RTT-corrected clock at now+995ms vs midpoint now → drift ≈ -995ms
	if d := r.Drift(); d > -990*time.Millisecond || d < -1000*time.Millisecond {
		t.Fatalf("Drift = %s; want ~-995ms", d)
	}
	if !r.InSync() {
		t.Fatal("InSync = false; expected true")
	}
	r.Radius = 100 * time.Millisecond
	if r.InSync() {
		t.Fatal("InSync = true with small Radius; expected false")
	}
}

// TestParseEcosystemRoundTrip verifies [ParseEcosystem] decodes a minimal doc.
func TestParseEcosystemRoundTrip(t *testing.T) {
	pk, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	doc := map[string]any{
		"servers": []map[string]any{{
			"name":          "example",
			"version":       "draft-ietf-ntp-roughtime-12",
			"publicKeyType": "ed25519",
			"publicKey":     base64.StdEncoding.EncodeToString(pk),
			"addresses":     []map[string]string{{"protocol": "udp", "address": "example.com:2002"}},
		}},
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	servers, err := roughtime.ParseEcosystem(data)
	if err != nil {
		t.Fatalf("ParseEcosystem: %v", err)
	}
	if len(servers) != 1 {
		t.Fatalf("got %d servers, want 1", len(servers))
	}
	got := servers[0]
	if got.Name != "example" {
		t.Fatalf("Name = %q", got.Name)
	}
	if len(got.PublicKey) != ed25519.PublicKeySize || !bytes.Equal(got.PublicKey, pk) {
		t.Fatalf("PublicKey mismatch")
	}
	if len(got.Addresses) != 1 || got.Addresses[0].Transport != "udp" {
		t.Fatalf("addresses = %+v", got.Addresses)
	}
}

// TestParseEcosystemRejectsJunk confirms malformed input is surfaced as an error.
func TestParseEcosystemRejectsJunk(t *testing.T) {
	cases := [][]byte{
		[]byte(""),
		[]byte("{"),
		[]byte(`{"servers":[]}`),
		[]byte(`{"servers":[{"publicKey":"not-base64-or-hex"}]}`),
	}
	for i, in := range cases {
		if _, err := roughtime.ParseEcosystem(in); err == nil {
			t.Fatalf("case %d: ParseEcosystem accepted junk", i)
		}
	}
}

// TestPickAddressMLDSARequiresTCP confirms a UDP-only ML-DSA-44 server is rejected.
func TestPickAddressMLDSARequiresTCP(t *testing.T) {
	// 1312-byte key selects ML-DSA-44
	pk := make([]byte, 1312)
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

// TestVersionsForScheme confirms scheme→version lists partition correctly.
func TestVersionsForScheme(t *testing.T) {
	ed := roughtime.VersionsForScheme(roughtime.SchemeEd25519)
	if len(ed) == 0 {
		t.Fatal("Ed25519 list empty")
	}
	for _, v := range ed {
		if v == protocol.VersionGoogle || v == protocol.VersionMLDSA44 {
			t.Fatalf("Ed25519 list contains %v; should exclude Google and PQ", v)
		}
	}

	pq := roughtime.VersionsForScheme(roughtime.SchemeMLDSA44)
	if len(pq) != 1 || pq[0] != protocol.VersionMLDSA44 {
		t.Fatalf("MLDSA44 list = %v; want [VersionMLDSA44]", pq)
	}
}

// TestSchemeOfKey confirms scheme selection by key length.
func TestSchemeOfKey(t *testing.T) {
	if sch, err := roughtime.SchemeOfKey(make([]byte, 32)); err != nil || sch != roughtime.SchemeEd25519 {
		t.Fatalf("32-byte: sch=%v err=%v", sch, err)
	}
	if sch, err := roughtime.SchemeOfKey(make([]byte, 1312)); err != nil || sch != roughtime.SchemeMLDSA44 {
		t.Fatalf("1312-byte: sch=%v err=%v", sch, err)
	}
	if _, err := roughtime.SchemeOfKey(make([]byte, 16)); err == nil {
		t.Fatal("16-byte key accepted")
	}
}

// TestDecodePublicKey confirms base64/hex inputs all round-trip.
func TestDecodePublicKey(t *testing.T) {
	want := make([]byte, 32)
	for i := range want {
		want[i] = byte(i)
	}
	inputs := []string{
		base64.StdEncoding.EncodeToString(want),
		base64.RawStdEncoding.EncodeToString(want),
		base64.URLEncoding.EncodeToString(want),
		fmt.Sprintf("%x", want),
	}
	for _, in := range inputs {
		got, err := roughtime.DecodePublicKey(in)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("DecodePublicKey(%q): got=%x err=%v", in, got, err)
		}
	}
	if _, err := roughtime.DecodePublicKey("definitely not a key"); err == nil {
		t.Fatal("accepted garbage")
	}
}

// FuzzParseEcosystem asserts the parser never panics and preserves invariants.
func FuzzParseEcosystem(f *testing.F) {
	pk, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	doc := map[string]any{"servers": []map[string]any{{
		"name":      "ex",
		"publicKey": base64.StdEncoding.EncodeToString(pk),
		"addresses": []map[string]string{{"protocol": "udp", "address": "x:1"}},
	}}}
	good, _ := json.Marshal(doc)
	f.Add(good)
	f.Add([]byte(""))
	f.Add([]byte("{"))
	f.Add([]byte(`{"servers":[]}`))
	f.Add([]byte(`{"servers":[{}]}`))

	f.Fuzz(func(t *testing.T, in []byte) {
		servers, err := roughtime.ParseEcosystem(in)
		if err != nil {
			return
		}
		if len(servers) == 0 {
			t.Fatal("ParseEcosystem returned empty list without error")
		}
		for _, s := range servers {
			if _, err := roughtime.SchemeOfKey(s.PublicKey); err != nil {
				t.Fatalf("ParseEcosystem returned server with invalid key length %d", len(s.PublicKey))
			}
		}
	})
}

// FuzzDecodePublicKey asserts the decoder never panics and returns only valid lengths.
func FuzzDecodePublicKey(f *testing.F) {
	pk := make([]byte, 32)
	f.Add(base64.StdEncoding.EncodeToString(pk))
	f.Add(fmt.Sprintf("%x", pk))
	f.Add("")
	f.Add("not a key")
	f.Fuzz(func(t *testing.T, s string) {
		b, err := roughtime.DecodePublicKey(s)
		if err != nil {
			return
		}
		if _, err := roughtime.SchemeOfKey(b); err != nil {
			t.Fatalf("DecodePublicKey returned length %d; SchemeOfKey rejects it", len(b))
		}
	})
}

// TestQueryRejectsEmptyAddresses confirms a Server with no addresses errors early.
func TestQueryRejectsEmptyAddresses(t *testing.T) {
	var c roughtime.Client
	_, err := c.Query(context.Background(), roughtime.Server{
		PublicKey: make([]byte, ed25519.PublicKeySize),
	})
	if err == nil || !strings.Contains(err.Error(), "no addresses") {
		t.Fatalf("Query: %v; want 'no addresses' error", err)
	}
}

// TestQueryRejectsBadKeyLength confirms an invalid PublicKey length is rejected.
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

// TestQueryRejectsUnsupportedTransport confirms unknown transports surface an error.
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

// TestPickAddressEd25519PrefersUDP confirms Ed25519 prefers UDP when both are advertised.
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

// TestParseEcosystemValidatesPublicKeyType rejects publicKeyType vs key-length mismatch.
func TestParseEcosystemValidatesPublicKeyType(t *testing.T) {
	pk, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	doc := map[string]any{
		"servers": []map[string]any{{
			"name":          "mismatch",
			"publicKeyType": "ml-dsa-44",
			"publicKey":     base64.StdEncoding.EncodeToString(pk),
			"addresses":     []map[string]string{{"protocol": "udp", "address": "example.com:2002"}},
		}},
	}
	data, _ := json.Marshal(doc)
	if _, err := roughtime.ParseEcosystem(data); err == nil || !strings.Contains(err.Error(), "publicKeyType") {
		t.Fatalf("ParseEcosystem: %v; want publicKeyType mismatch error", err)
	}
}

// TestParseEcosystemAllowsMissingPublicKeyType confirms publicKeyType is optional.
func TestParseEcosystemAllowsMissingPublicKeyType(t *testing.T) {
	pk, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	doc := map[string]any{
		"servers": []map[string]any{{
			"name":      "ok",
			"publicKey": base64.StdEncoding.EncodeToString(pk),
			"addresses": []map[string]string{{"protocol": "udp", "address": "example.com:2002"}},
		}},
	}
	data, _ := json.Marshal(doc)
	if _, err := roughtime.ParseEcosystem(data); err != nil {
		t.Fatalf("ParseEcosystem rejected entry without publicKeyType: %v", err)
	}
}

// TestParseEcosystemEnforcesMaxServers confirms the server-count cap is enforced.
func TestParseEcosystemEnforcesMaxServers(t *testing.T) {
	pk, _, _ := ed25519.GenerateKey(rand.Reader)
	entry := map[string]any{
		"name":      "x",
		"publicKey": base64.StdEncoding.EncodeToString(pk),
		"addresses": []map[string]string{{"protocol": "udp", "address": "x:1"}},
	}
	servers := make([]map[string]any, roughtime.MaxEcosystemServers+1)
	for i := range servers {
		servers[i] = entry
	}
	data, _ := json.Marshal(map[string]any{"servers": servers})
	if _, err := roughtime.ParseEcosystem(data); err == nil || !strings.Contains(err.Error(), "max") {
		t.Fatalf("ParseEcosystem: %v; want max-entries error", err)
	}
}

// TestParseEcosystemSanitizesStrings confirms control and bidi chars are stripped.
func TestParseEcosystemSanitizesStrings(t *testing.T) {
	pk, _, _ := ed25519.GenerateKey(rand.Reader)
	const rlo = "\u202E"
	const lro = "\u202D"
	doc := map[string]any{
		"servers": []map[string]any{{
			"name":      "evil" + rlo + ".com\x07",
			"publicKey": base64.StdEncoding.EncodeToString(pk),
			"addresses": []map[string]string{{"protocol": "udp", "address": "host" + lro + ":1"}},
		}},
	}
	data, _ := json.Marshal(doc)
	servers, err := roughtime.ParseEcosystem(data)
	if err != nil {
		t.Fatalf("ParseEcosystem: %v", err)
	}
	if strings.ContainsAny(servers[0].Name, lro+rlo+"\x07") {
		t.Fatalf("Name not sanitized: %q", servers[0].Name)
	}
	if strings.ContainsAny(servers[0].Addresses[0].Address, lro+rlo) {
		t.Fatalf("Address not sanitized: %q", servers[0].Addresses[0].Address)
	}
}

// TestDecodePublicKeyMLDSA44 confirms a 1312-byte key round-trips.
func TestDecodePublicKeyMLDSA44(t *testing.T) {
	want := bytes.Repeat([]byte{0x42}, 1312)
	got, err := roughtime.DecodePublicKey(base64.StdEncoding.EncodeToString(want))
	if err != nil {
		t.Fatalf("DecodePublicKey: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("ML-DSA-44 key round-trip mismatch")
	}
}

// TestDecodePublicKeyRejectsWrongLength confirms non-32/1312-byte inputs are rejected.
func TestDecodePublicKeyRejectsWrongLength(t *testing.T) {
	for _, n := range []int{0, 16, 33, 64, 1311, 1313, 2048} {
		raw := bytes.Repeat([]byte{0x99}, n)
		if _, err := roughtime.DecodePublicKey(base64.StdEncoding.EncodeToString(raw)); err == nil {
			t.Fatalf("DecodePublicKey accepted %d-byte key", n)
		}
	}
}

// TestDecodePublicKeyTruncatesError confirms error messages stay bounded for huge inputs.
func TestDecodePublicKeyTruncatesError(t *testing.T) {
	huge := strings.Repeat("X", 100_000)
	_, err := roughtime.DecodePublicKey(huge)
	if err == nil {
		t.Fatal("DecodePublicKey accepted 100k-byte garbage")
	}
	if len(err.Error()) > 200 {
		t.Fatalf("error message length %d exceeds bound; should truncate", len(err.Error()))
	}
}

// TestQueryAllSemaphoreCap verifies QueryAll bounds in-flight to MaxQueryAllConcurrency.
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
	close(hold)
	results := <-done
	if len(results) != total {
		t.Fatalf("got %d results, want %d", len(results), total)
	}
	if peak.Load() > roughtime.MaxQueryAllConcurrency {
		t.Fatalf("final peak %d > cap %d", peak.Load(), roughtime.MaxQueryAllConcurrency)
	}
}

// TestQueryAllPreservesOrder confirms results are aligned with the input slice.
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

// TestClientRetriesExhausted confirms retry exhaustion surfaces the underlying error.
func TestClientRetriesExhausted(t *testing.T) {
	f := newFakeServer(t)
	defer f.Close()
	f.dropNext(100)
	c := roughtime.Client{Timeout: 50 * time.Millisecond, Retries: 2}
	// large context budget so the surfaced error is the per-attempt timeout, not ctx cancel
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := c.Query(ctx, f.server())
	if err == nil {
		t.Fatal("Query succeeded despite drops")
	}
}

// FuzzVersionsForScheme asserts the helper never panics and excludes PQ for non-PQ schemes.
func FuzzVersionsForScheme(f *testing.F) {
	f.Add(int(roughtime.SchemeEd25519))
	f.Add(int(roughtime.SchemeMLDSA44))
	f.Add(99)
	f.Add(-1)
	f.Fuzz(func(t *testing.T, n int) {
		vs := roughtime.VersionsForScheme(roughtime.Scheme(n))
		seenPQ := false
		for _, v := range vs {
			if v == protocol.VersionMLDSA44 {
				seenPQ = true
			}
		}
		if roughtime.Scheme(n) != roughtime.SchemeMLDSA44 && seenPQ {
			t.Fatalf("non-PQ scheme %d returned VersionMLDSA44", n)
		}
	})
}

// TestClientRespectsContextCancel confirms cancellation unblocks an in-flight query.
func TestClientRespectsContextCancel(t *testing.T) {
	// closed port so Dial/Read hangs on an unreachable peer
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	host, port, _ := net.SplitHostPort(addr)
	_ = port

	s := roughtime.Server{
		PublicKey: make([]byte, 32),
		Addresses: []roughtime.Address{{Transport: "udp", Address: net.JoinHostPort(host, strconv.Itoa(19))}},
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

// TestQueryWithNonceUsesCallerNonce confirms the supplied nonce is bound into the request.
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

// TestQueryWithNonceRejectsBadLength confirms wrong-length nonces error early.
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

// TestResponseRawBytesPopulated confirms Query fills Request, Reply, and AmplificationOK.
func TestResponseRawBytesPopulated(t *testing.T) {
	f := newFakeServer(t)
	defer f.Close()

	var c roughtime.Client
	resp, err := c.Query(context.Background(), f.server())
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(resp.Request) == 0 || len(resp.Reply) == 0 {
		t.Fatalf("raw bytes empty: req=%d reply=%d", len(resp.Request), len(resp.Reply))
	}
	if !resp.AmplificationOK {
		t.Fatalf("AmplificationOK=false; reply (%d) > request (%d)", len(resp.Reply), len(resp.Request))
	}
}

// TestPackageLevelQuery confirms the convenience wrapper matches a zero-Client call.
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

// TestPackageLevelQueryWithNonce confirms the package-level nonce-binding wrapper.
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

// TestClientConcurrencyOverride confirms Client.Concurrency caps QueryAll fan-out.
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
	close(hold)
	<-done
}

// TestChainResultMalfeasanceReport confirms the convenience method mirrors chain.MalfeasanceReport.
func TestChainResultMalfeasanceReport(t *testing.T) {
	f1 := newFakeServer(t)
	defer f1.Close()
	f2 := newFakeServer(t)
	defer f2.Close()

	var c roughtime.Client
	cr, err := c.QueryChain(context.Background(), []roughtime.Server{f1.server(), f2.server()})
	if err != nil {
		t.Fatalf("QueryChain: %v", err)
	}
	report, err := cr.MalfeasanceReport()
	if err != nil {
		t.Fatalf("MalfeasanceReport: %v", err)
	}
	if !bytes.Contains(report, []byte(`"responses"`)) {
		t.Fatalf("report missing 'responses' field: %s", report)
	}
}

// TestChainResultMalfeasanceReportNil confirms nil receiver/chain errors instead of panicking.
func TestChainResultMalfeasanceReportNil(t *testing.T) {
	var cr *roughtime.ChainResult
	if _, err := cr.MalfeasanceReport(); err == nil {
		t.Fatal("nil receiver should error, not panic")
	}
	cr = &roughtime.ChainResult{}
	if _, err := cr.MalfeasanceReport(); err == nil {
		t.Fatal("nil Chain should error")
	}
}

// TestErrorSentinelsReExported confirms package errors match protocol origins via errors.Is.
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

// TestMarshalEcosystemRoundTrip confirms MarshalEcosystem output round-trips through ParseEcosystem.
func TestMarshalEcosystemRoundTrip(t *testing.T) {
	pk1, _, _ := ed25519.GenerateKey(rand.Reader)
	pq := bytes.Repeat([]byte{0x42}, 1312)
	in := []roughtime.Server{
		{
			Name:      "alpha",
			Version:   "draft-ietf-ntp-roughtime-12",
			PublicKey: pk1,
			Addresses: []roughtime.Address{{Transport: "udp", Address: "alpha.example:2002"}},
		},
		{
			Name:      "beta-pq",
			PublicKey: pq,
			Addresses: []roughtime.Address{{Transport: "tcp", Address: "beta.example:2003"}},
		},
	}
	data, err := roughtime.MarshalEcosystem(in)
	if err != nil {
		t.Fatalf("MarshalEcosystem: %v", err)
	}
	out, err := roughtime.ParseEcosystem(data)
	if err != nil {
		t.Fatalf("ParseEcosystem (round-trip): %v", err)
	}
	if len(out) != len(in) {
		t.Fatalf("round-trip length: got %d want %d", len(out), len(in))
	}
	for i := range in {
		if out[i].Name != in[i].Name {
			t.Errorf("server[%d] Name mismatch: %q vs %q", i, out[i].Name, in[i].Name)
		}
		if !bytes.Equal(out[i].PublicKey, in[i].PublicKey) {
			t.Errorf("server[%d] PublicKey mismatch", i)
		}
	}
}

// TestMarshalEcosystemRejectsTooMany confirms exceeding MaxEcosystemServers errors early.
func TestMarshalEcosystemRejectsTooMany(t *testing.T) {
	pk, _, _ := ed25519.GenerateKey(rand.Reader)
	servers := make([]roughtime.Server, roughtime.MaxEcosystemServers+1)
	for i := range servers {
		servers[i] = roughtime.Server{PublicKey: pk}
	}
	if _, err := roughtime.MarshalEcosystem(servers); err == nil {
		t.Fatal("expected too-many error")
	}
}
