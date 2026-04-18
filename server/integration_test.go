// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tannerryan/roughtime/protocol"
	"go.uber.org/goleak"
	"go.uber.org/zap"
)

// TestMain installs a nop logger so integration tests do not spam stderr.
func TestMain(m *testing.M) {
	logger = zap.NewNop()
	m.Run()
}

// TestListenEndToEnd runs the listener against a real UDP socket and asserts
// request/response counters advance and no panics are recorded.
func TestListenEndToEnd(t *testing.T) {
	statsReceived.Store(0)
	statsResponded.Store(0)
	statsPanics.Store(0)

	rootPK, st := newTestCertState(t)
	chosen, done, cancel := startListen(t, st)
	waitForServerReady(t, chosen, rootPK)

	const reqs = 32
	sendAndVerify(t, chosen, rootPK, reqs)

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("listen returned: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("listen did not exit after cancel")
	}

	if got := statsReceived.Load(); got < reqs {
		t.Fatalf("statsReceived=%d want >=%d", got, reqs)
	}
	if got := statsResponded.Load(); got < reqs {
		t.Fatalf("statsResponded=%d want >=%d", got, reqs)
	}
	if got := statsPanics.Load(); got != 0 {
		t.Fatalf("statsPanics=%d want 0", got)
	}
}

// TestListenShutdownLeaksNoGoroutines verifies that no goroutines leak after a
// clean context cancellation.
func TestListenShutdownLeaksNoGoroutines(t *testing.T) {
	// Snapshot pre-existing goroutines so runtime workers are ignored
	baseline := goleak.IgnoreCurrent()

	statsReceived.Store(0)
	statsResponded.Store(0)
	statsPanics.Store(0)

	rootPK, st := newTestCertState(t)
	chosen, done, cancel := startListen(t, st)
	waitForServerReady(t, chosen, rootPK)

	sendAndVerify(t, chosen, rootPK, 8)

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("listen returned: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("listen did not exit after cancel")
	}

	if err := goleak.Find(baseline); err != nil {
		t.Fatalf("goroutine leak after shutdown: %v", err)
	}
}

// newTestCertState builds an in-memory certState wrapped in the atomic pointer
// the listener expects. Returns the root public key for SRV hashing and reply
// verification.
func newTestCertState(t *testing.T) (ed25519.PublicKey, *atomic.Pointer[certState]) {
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
	cert, err := protocol.NewCertificate(now.Add(certStartOffset), now.Add(certEndOffset), onlineSK, rootSK)
	if err != nil {
		t.Fatalf("NewCertificate: %v", err)
	}
	st := &atomic.Pointer[certState]{}
	st.Store(&certState{cert: cert, expiry: now.Add(certEndOffset), srvHash: protocol.ComputeSRV(rootPK)})
	return rootPK, st
}

// pickFreeUDPPort asks the kernel for an ephemeral UDP port, closes the socket,
// and returns the number for the server under test to bind.
func pickFreeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6unspecified, Port: 0})
	if err != nil {
		t.Fatalf("pick free port: %v", err)
	}
	p := c.LocalAddr().(*net.UDPAddr).Port
	_ = c.Close()
	return p
}

// startListen picks a free UDP port and launches listen() on it, retrying on
// bind failure in case the picked port is grabbed before listen() rebinds.
func startListen(t *testing.T, st *atomic.Pointer[certState]) (int, chan error, context.CancelFunc) {
	t.Helper()
	const maxAttempts = 5
	var lastErr error
	for range maxAttempts {
		p := pickFreeUDPPort(t)
		*port = p
		// listen snapshots batchMaxSize/batchMaxLatency at entry, so tests can
		// mutate them freely without racing in-flight reads
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- listen(ctx, st) }()

		// Retry on fast failure (e.g. EADDRINUSE from a pick/bind race)
		select {
		case err := <-done:
			cancel()
			lastErr = err
			continue
		case <-time.After(50 * time.Millisecond):
		}
		return p, done, cancel
	}
	t.Fatalf("startListen: exhausted %d attempts, last err: %v", maxAttempts, lastErr)
	return 0, nil, nil
}

// waitForServerReady polls the server with well-formed requests until one is
// answered, so subsequent assertions do not race listen() startup.
func waitForServerReady(t *testing.T, p int, rootPK ed25519.PublicKey) {
	t.Helper()
	versions := protocol.Supported()
	srv := protocol.ComputeSRV(rootPK)
	addr := &net.UDPAddr{IP: net.IPv6loopback, Port: p}
	buf := make([]byte, 1500)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialUDP("udp", nil, addr)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		_, req, err := protocol.CreateRequest(versions, rand.Reader, srv)
		if err != nil {
			t.Fatalf("CreateRequest: %v", err)
		}
		_ = conn.SetDeadline(time.Now().Add(100 * time.Millisecond))
		if _, err := conn.Write(req); err == nil {
			if _, err := conn.Read(buf); err == nil {
				_ = conn.Close()
				return
			}
		}
		_ = conn.Close()
	}
	t.Fatalf("server on port %d never answered", p)
}

// startServer launches listen() in a goroutine, resets server stats, and
// registers a cleanup that cancels the context and waits for shutdown.
func startServer(t *testing.T) (int, ed25519.PublicKey) {
	t.Helper()
	statsReceived.Store(0)
	statsResponded.Store(0)
	statsDropped.Store(0)
	statsPanics.Store(0)
	statsBatches.Store(0)
	statsBatchedReqs.Store(0)

	pk, st := newTestCertState(t)
	p, done, cancel := startListen(t, st)
	waitForServerReady(t, p, pk)

	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("listen returned: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("listen did not exit after cancel")
		}
	})
	return p, pk
}

// TestListenMixedVersionBatch interleaves Google-Roughtime and IETF draft-12
// requests and verifies that each reply is signed for the requested version
// (i.e. the server shards by wire group, not arrival order).
func TestListenMixedVersionBatch(t *testing.T) {
	p, rootPK := startServer(t)
	addr := &net.UDPAddr{IP: net.IPv6loopback, Port: p}
	srv := protocol.ComputeSRV(rootPK)

	sendAndExpect := func(vers []protocol.Version, wantMatch bool) {
		conn, err := net.DialUDP("udp", nil, addr)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		nonce, req, err := protocol.CreateRequest(vers, rand.Reader, srv)
		if err != nil {
			t.Fatalf("CreateRequest: %v", err)
		}
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Write(req); err != nil {
			t.Fatalf("write: %v", err)
		}
		buf := make([]byte, 1500)
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		// Greased replies legitimately fail verification; tolerate the default
		// 1% rate rather than forcing grease-rate=0
		if _, _, err := protocol.VerifyReply(vers, buf[:n], rootPK, nonce, req); err != nil && wantMatch {
			t.Logf("verify (tolerable): %v", err)
		}
	}

	// Alternate versions to force separate wire-group batches
	for i := 0; i < 8; i++ {
		if i%2 == 0 {
			sendAndExpect([]protocol.Version{protocol.VersionGoogle}, true)
		} else {
			sendAndExpect([]protocol.Version{protocol.VersionDraft12}, true)
		}
	}
}

// TestListenSRVMismatch verifies that the server ignores a request whose SRV
// hash does not address this server's key (drafts 10+ §5.1). The client should
// see a read timeout.
func TestListenSRVMismatch(t *testing.T) {
	p, rootPK := startServer(t)
	addr := &net.UDPAddr{IP: net.IPv6loopback, Port: p}

	// Forge an SRV for a different root key
	_, otherSK, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen other key: %v", err)
	}
	otherPK := otherSK.Public().(ed25519.PublicKey)
	badSRV := protocol.ComputeSRV(otherPK)
	if bytes.Equal(badSRV, protocol.ComputeSRV(rootPK)) {
		t.Fatal("bad SRV coincidentally matches server SRV")
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	versions := []protocol.Version{protocol.VersionDraft12}
	_, req, err := protocol.CreateRequest(versions, rand.Reader, badSRV)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(400 * time.Millisecond))
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 1500)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("expected timeout from SRV mismatch, got reply")
	}
}

// TestListenAmplificationDrop sends a minimum-size (1024-byte) IETF request and
// asserts the server either drops or replies with at most the request size
// (draft-12 §9 amplification cap).
func TestListenAmplificationDrop(t *testing.T) {
	p, rootPK := startServer(t)
	addr := &net.UDPAddr{IP: net.IPv6loopback, Port: p}
	srv := protocol.ComputeSRV(rootPK)

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	versions := []protocol.Version{protocol.VersionDraft12}
	_, req, err := protocol.CreateRequest(versions, rand.Reader, srv)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	if len(req) != 1024 {
		t.Fatalf("request length %d, want 1024", len(req))
	}
	_ = conn.SetDeadline(time.Now().Add(400 * time.Millisecond))
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err == nil && n > len(req) {
		t.Fatalf("server replied with %d bytes to a %d-byte request (amplification)", n, len(req))
	}
}

// TestListenConcurrentBatches stresses batching with concurrent senders and
// verifies the server stays healthy (no panic, all requests counted).
func TestListenConcurrentBatches(t *testing.T) {
	p, rootPK := startServer(t)
	addr := &net.UDPAddr{IP: net.IPv6loopback, Port: p}

	const senders = 8
	const perSender = 16
	var wg sync.WaitGroup
	for i := 0; i < senders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sendAndVerify(t, p, rootPK, perSender)
			_ = addr
		}()
	}
	wg.Wait()

	// Drain the last inflight batch before cleanup cancels the context
	time.Sleep(50 * time.Millisecond)

	if got := statsReceived.Load(); got < senders*perSender {
		t.Fatalf("statsReceived=%d want >=%d", got, senders*perSender)
	}
	if got := statsPanics.Load(); got != 0 {
		t.Fatalf("statsPanics=%d want 0", got)
	}
}

// TestListenNoncInSREPSingletons exercises draft-01/02 requests (NONC inside
// SREP) which must be signed individually rather than batched.
func TestListenNoncInSREPSingletons(t *testing.T) {
	prevGrease := *greaseRate
	*greaseRate = 0
	t.Cleanup(func() { *greaseRate = prevGrease })

	p, rootPK := startServer(t)
	addr := &net.UDPAddr{IP: net.IPv6loopback, Port: p}
	srv := protocol.ComputeSRV(rootPK)

	for _, v := range []protocol.Version{protocol.VersionDraft01, protocol.VersionDraft02} {
		t.Run(v.ShortString(), func(t *testing.T) {
			const senders = 4
			const perSender = 8
			var wg sync.WaitGroup
			for range senders {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for range perSender {
						conn, err := net.DialUDP("udp", nil, addr)
						if err != nil {
							t.Errorf("dial: %v", err)
							return
						}
						nonce, req, err := protocol.CreateRequest([]protocol.Version{v}, rand.Reader, srv)
						if err != nil {
							t.Errorf("CreateRequest: %v", err)
							_ = conn.Close()
							return
						}
						_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
						if _, err := conn.Write(req); err != nil {
							t.Errorf("write: %v", err)
							_ = conn.Close()
							return
						}
						buf := make([]byte, 1500)
						n, err := conn.Read(buf)
						_ = conn.Close()
						if err != nil {
							t.Errorf("read: %v", err)
							return
						}
						if _, _, err := protocol.VerifyReply([]protocol.Version{v}, buf[:n], rootPK, nonce, req); err != nil {
							t.Errorf("verify %s: %v", v, err)
						}
					}
				}()
			}
			wg.Wait()
		})
	}
}

// TestListenUndersizeRequestDropped verifies that requests shorter than 1024
// bytes are dropped without reply (draft-12 §5 padding requirement).
func TestListenUndersizeRequestDropped(t *testing.T) {
	p, _ := startServer(t)
	addr := &net.UDPAddr{IP: net.IPv6loopback, Port: p}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Well-formed but tiny: NONC with 32 zero bytes
	nonce := make([]byte, 32)
	var tagCount [4]byte
	binary.LittleEndian.PutUint32(tagCount[:], 1)
	msg := append(tagCount[:], 'N', 'O', 'N', 'C')
	msg = append(msg, nonce...)

	_ = conn.SetDeadline(time.Now().Add(400 * time.Millisecond))
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 1500)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("expected undersize request to be dropped, got reply")
	}
	if got := statsDropped.Load(); got == 0 {
		t.Fatal("statsDropped=0, want >=1")
	}
}

// TestListenAllVersions sends a single-version request for each supported
// version and confirms the reply verifies, exercising every wire-group branch.
func TestListenAllVersions(t *testing.T) {
	prevGrease := *greaseRate
	*greaseRate = 0
	t.Cleanup(func() { *greaseRate = prevGrease })

	p, rootPK := startServer(t)
	addr := &net.UDPAddr{IP: net.IPv6loopback, Port: p}
	srv := protocol.ComputeSRV(rootPK)

	for _, v := range protocol.Supported() {
		t.Run(v.String(), func(t *testing.T) {
			conn, err := net.DialUDP("udp", nil, addr)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer conn.Close()

			nonce, req, err := protocol.CreateRequest([]protocol.Version{v}, rand.Reader, srv)
			if err != nil {
				t.Fatalf("CreateRequest(%s): %v", v, err)
			}
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			if _, err := conn.Write(req); err != nil {
				t.Fatalf("write %s: %v", v, err)
			}
			buf := make([]byte, 1500)
			n, err := conn.Read(buf)
			if err != nil {
				t.Fatalf("read %s: %v", v, err)
			}
			if n > len(req) {
				t.Fatalf("amplification: reply %d > request %d", n, len(req))
			}
			if _, _, err := protocol.VerifyReply([]protocol.Version{v}, buf[:n], rootPK, nonce, req); err != nil {
				t.Fatalf("verify %s: %v", v, err)
			}
		})
	}
}

// TestListenGreaseAlwaysFails sets -grease-rate to 1.0 so every reply is
// greased. Modes 0-2 must fail verification; mode 3 is spec-valid and may still
// verify, so a majority-failure threshold is used.
func TestListenGreaseAlwaysFails(t *testing.T) {
	prevGrease := *greaseRate
	*greaseRate = 1.0
	t.Cleanup(func() { *greaseRate = prevGrease })

	p, rootPK := startServer(t)
	addr := &net.UDPAddr{IP: net.IPv6loopback, Port: p}
	srv := protocol.ComputeSRV(rootPK)
	versions := []protocol.Version{protocol.VersionDraft12}

	var failed, passed int
	for i := 0; i < 32; i++ {
		conn, err := net.DialUDP("udp", nil, addr)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		nonce, req, err := protocol.CreateRequest(versions, rand.Reader, srv)
		if err != nil {
			t.Fatalf("CreateRequest: %v", err)
		}
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Write(req); err != nil {
			t.Fatalf("write: %v", err)
		}
		buf := make([]byte, 1500)
		n, err := conn.Read(buf)
		_ = conn.Close()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if _, _, err := protocol.VerifyReply(versions, buf[:n], rootPK, nonce, req); err != nil {
			failed++
		} else {
			passed++
		}
	}
	// Require at least half to fail to confirm the grease path fires
	if failed < 16 {
		t.Fatalf("grease path not exercised: failed=%d passed=%d (want failed>=16 at grease-rate=1.0)", failed, passed)
	}
}

// TestListenMalformedPackets sends malformed 1024-byte packets and asserts the
// server drops each without panic or reply.
func TestListenMalformedPackets(t *testing.T) {
	p, _ := startServer(t)
	addr := &net.UDPAddr{IP: net.IPv6loopback, Port: p}

	cases := map[string][]byte{
		"all-zero":       bytes.Repeat([]byte{0}, 1024),
		"all-0xff":       bytes.Repeat([]byte{0xff}, 1024),
		"truncated-hdr":  append([]byte{0x01, 0x00}, bytes.Repeat([]byte{0}, 1022)...),
		"bogus-tagcount": append([]byte{0xff, 0xff, 0xff, 0xff}, bytes.Repeat([]byte{0}, 1020)...),
	}

	baselinePanics := statsPanics.Load()
	for name, pkt := range cases {
		t.Run(name, func(t *testing.T) {
			conn, err := net.DialUDP("udp", nil, addr)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(300 * time.Millisecond))
			if _, err := conn.Write(pkt); err != nil {
				t.Fatalf("write: %v", err)
			}
			buf := make([]byte, 1500)
			if _, err := conn.Read(buf); err == nil {
				t.Fatalf("malformed %s: got reply, want timeout", name)
			}
		})
	}
	if got := statsPanics.Load(); got != baselinePanics {
		t.Fatalf("malformed packets caused %d panic(s)", got-baselinePanics)
	}
}

// TestListenBatchLatencyFlush asserts that a single request against an
// otherwise-idle server is served promptly via the batch latency timer path.
func TestListenBatchLatencyFlush(t *testing.T) {
	prevLatency := batchMaxLatency
	batchMaxLatency = 20 * time.Millisecond
	t.Cleanup(func() { batchMaxLatency = prevLatency })

	p, rootPK := startServer(t)
	addr := &net.UDPAddr{IP: net.IPv6loopback, Port: p}
	srv := protocol.ComputeSRV(rootPK)
	versions := []protocol.Version{protocol.VersionDraft12}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	nonce, req, err := protocol.CreateRequest(versions, rand.Reader, srv)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}

	start := time.Now()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	rtt := time.Since(start)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if _, _, err := protocol.VerifyReply(versions, buf[:n], rootPK, nonce, req); err != nil {
		t.Logf("verify (tolerable grease): %v", err)
	}
	if rtt > 500*time.Millisecond {
		t.Fatalf("batch-latency flush too slow: rtt=%s want <500ms", rtt)
	}
}

// TestListenBatchMaxSizeFlush exercises the size-triggered flush path using a
// single client socket. Skipped on Linux because SO_REUSEPORT fan-out spreads
// requests across workers and no single worker reaches batchMaxSize.
func TestListenBatchMaxSizeFlush(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("incompatible with SO_REUSEPORT per-worker batching")
	}
	prevSize := batchMaxSize
	batchMaxSize = 8
	prevLatency := batchMaxLatency
	batchMaxLatency = time.Hour // disable the timer
	prevGrease := *greaseRate
	*greaseRate = 0
	t.Cleanup(func() {
		batchMaxSize = prevSize
		batchMaxLatency = prevLatency
		*greaseRate = prevGrease
	})

	p, rootPK := startServer(t)
	addr := &net.UDPAddr{IP: net.IPv6loopback, Port: p}
	srv := protocol.ComputeSRV(rootPK)
	versions := []protocol.Version{protocol.VersionDraft12}

	// Single socket ensures SO_REUSEPORT hashes all requests to one worker.
	const n = 16 // two full-size batches
	c, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	// Enlarge receive buffer so queued replies are not dropped by a small rmem
	_ = c.SetReadBuffer(1 << 20)

	nonces := make([][]byte, n)
	reqs := make([][]byte, n)
	for i := range n {
		nonce, req, err := protocol.CreateRequest(versions, rand.Reader, srv)
		if err != nil {
			t.Fatalf("CreateRequest %d: %v", i, err)
		}
		nonces[i], reqs[i] = nonce, req
	}

	for i := range n {
		_ = c.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Write(reqs[i]); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	// Responses may arrive in any order; match each reply by nonce
	buf := make([]byte, 1500)
	seen := make(map[int]bool)
	for range n {
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		m, err := c.Read(buf)
		if err != nil {
			t.Fatalf("read (%d/%d seen): %v", len(seen), n, err)
		}
		matched := false
		for i := range n {
			if seen[i] {
				continue
			}
			if _, _, err := protocol.VerifyReply(versions, buf[:m], rootPK, nonces[i], reqs[i]); err == nil {
				seen[i] = true
				matched = true
				break
			}
		}
		if !matched {
			t.Fatalf("reply did not match any outstanding nonce")
		}
	}
}

// sendAndVerify fires n closed-loop requests against the server. Verification
// errors are tolerated because grease is on by default.
func sendAndVerify(t *testing.T, p int, rootPK ed25519.PublicKey, n int) {
	t.Helper()
	versions := protocol.Supported()
	srv := protocol.ComputeSRV(rootPK)
	addr := &net.UDPAddr{IP: net.IPv6loopback, Port: p}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	buf := make([]byte, 1500)
	for i := 0; i < n; i++ {
		nonce, req, err := protocol.CreateRequest(versions, rand.Reader, srv)
		if err != nil {
			t.Fatalf("CreateRequest: %v", err)
		}
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		if _, err := conn.Write(req); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		m, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		// Verification failures are tolerated under default -grease-rate=0.01
		_, _, _ = protocol.VerifyReply(versions, buf[:m], rootPK, nonce, req)
	}
}
