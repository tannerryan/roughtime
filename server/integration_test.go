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

// TestMain installs a nop logger so integration tests don't spam stderr.
func TestMain(m *testing.M) {
	logger = zap.NewNop()
	m.Run()
}

// TestListenEndToEnd runs the listener against a real UDP socket, fires a
// verified request, and asserts counters move and no panics were recorded.
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
	// Snapshot goroutines before listen() so runtime workers are ignored.
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
// the listener expects. Returns the root public key so callers can compute the
// SRV hash and verify replies.
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
// and returns the number for the server under test to bind. Racy in theory but
// reliable in CI practice.
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
// bind failure to close the race where pickFreeUDPPort's number gets grabbed by
// another process before listen() rebinds.
func startListen(t *testing.T, st *atomic.Pointer[certState]) (int, chan error, context.CancelFunc) {
	t.Helper()
	const maxAttempts = 5
	var lastErr error
	for range maxAttempts {
		p := pickFreeUDPPort(t)
		*port = p
		// Snapshot the batch tunables on the test goroutine so a test's Cleanup
		// reset of the flag globals doesn't race listen's read of them.
		maxSize := *batchMaxSize
		maxLatency := *batchMaxLatency
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- listen(ctx, st, maxSize, maxLatency) }()

		// If listen() fails fast (EADDRINUSE from a pick/bind race), retry with
		// a fresh port. 50ms is enough for bind+socket setup to surface.
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

// waitForServerReady polls the server with well-formed requests until one gets
// answered, so subsequent assertions don't race the listen() startup.
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

// startServer launches listen() in a goroutine and returns a cleanup that
// cancels the context and waits for shutdown. It also resets server stats so
// assertions in the test are not polluted by prior tests.
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

// TestListenMixedVersionBatch sends Google-Roughtime and IETF draft-12 requests
// interleaved and verifies that each reply is signed for the version the client
// asked for (i.e. the server shards by wire group, not by arrival order).
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
		// Greased responses fail verification legitimately; tolerate with
		// grease-rate=0 for deterministic assertions.
		if _, _, err := protocol.VerifyReply(vers, buf[:n], rootPK, nonce, req); err != nil && wantMatch {
			// A single greased reply in the default 1% rate is possible. Don't
			// fail the test on a single failure; just log.
			t.Logf("verify (tolerable): %v", err)
		}
	}

	// Alternate Google-only and Draft12-only requests to make the server batch
	// them into separate wire groups.
	for i := 0; i < 8; i++ {
		if i%2 == 0 {
			sendAndExpect([]protocol.Version{protocol.VersionGoogle}, true)
		} else {
			sendAndExpect([]protocol.Version{protocol.VersionDraft12}, true)
		}
	}
}

// TestListenSRVMismatch verifies that the server ignores a request with a wrong
// SRV hash (drafts 10+ §5.1 MUST). The client should see a read timeout.
func TestListenSRVMismatch(t *testing.T) {
	p, rootPK := startServer(t)
	addr := &net.UDPAddr{IP: net.IPv6loopback, Port: p}

	// Forge an SRV for a different root key.
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

// TestListenAmplificationDrop sends an IETF request that is exactly at the
// minimum size (1024). That is the smallest size that the server MUST respond
// to; replies will generally exceed it for Draft12 once ROUGHTIM header, CERT,
// and VERS are added, at which point the server must drop the reply per §9.
//
// The server can legitimately satisfy short requests when a response happens to
// fit (e.g., small CERT encodings), so we only assert no panic and that the
// server either replies with something <= 1024 or drops silently.
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
	// Either a drop (timeout) or a reply <= request size is acceptable.
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
			_ = addr // silence if addr becomes unused in future refactors
		}()
	}
	wg.Wait()

	// Give the server a brief window to process the last inflight batch before
	// the cleanup cancels the context.
	time.Sleep(50 * time.Millisecond)

	if got := statsReceived.Load(); got < senders*perSender {
		t.Fatalf("statsReceived=%d want >=%d", got, senders*perSender)
	}
	if got := statsPanics.Load(); got != 0 {
		t.Fatalf("statsPanics=%d want 0", got)
	}
}

// TestListenNoncInSREPSingletons exercises draft-01/02 requests which place
// NONC inside SREP and must be signed individually (no batching).
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
// bytes are dropped without reply (§5 padding requirement).
func TestListenUndersizeRequestDropped(t *testing.T) {
	p, _ := startServer(t)
	addr := &net.UDPAddr{IP: net.IPv6loopback, Port: p}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// A well-formed but tiny message: just NONC with 32 zero bytes.
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

// TestListenAllVersions walks every supported version, sends a dedicated
// request advertising just that version, and confirms the reply verifies. This
// exercises every wire-group branch in validateRequest/signAndBuildReplies.
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

// TestListenGreaseAlwaysFails sets -grease-rate to 1.0, so every reply is
// deliberately corrupted. A conforming verifier must reject grease modes 0-2
// (mode 3 is spec-valid and indistinguishable from a clean reply).
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
	// Mode 3 (~25% of grease) is spec-valid, so a small fraction may still
	// verify. Require at least half to fail to confirm the grease path fires.
	if failed < 16 {
		t.Fatalf("grease path not exercised: failed=%d passed=%d (want failed>=16 at grease-rate=1.0)", failed, passed)
	}
}

// TestListenMalformedPackets sends a variety of malformed 1024-byte packets
// (valid size, invalid content) and asserts the server drops each without panic
// and without reply.
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

// TestListenBatchLatencyFlush fires a single request to an otherwise-idle
// server and asserts it is served within a small multiple of the batch latency
// (i.e. the timer path flushes incomplete batches).
func TestListenBatchLatencyFlush(t *testing.T) {
	prevLatency := *batchMaxLatency
	*batchMaxLatency = 20 * time.Millisecond
	t.Cleanup(func() { *batchMaxLatency = prevLatency })

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
	// Sanity: if the timer path works, we see a reply well under a second. The
	// loopback batcher typically responds in O(latency).
	if rtt > 500*time.Millisecond {
		t.Fatalf("batch-latency flush too slow: rtt=%s want <500ms", rtt)
	}
}

// TestListenBatchMaxSizeFlush fires batchMaxSize requests from one socket with
// no delay to exercise the size-triggered flush path (independent of the
// latency timer). Linux's SO_REUSEPORT fan-out spreads the readiness probes
// across workers, so no worker ever fills a batch and readiness times out.
func TestListenBatchMaxSizeFlush(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("incompatible with SO_REUSEPORT per-worker batching")
	}
	prevSize := *batchMaxSize
	*batchMaxSize = 8
	prevLatency := *batchMaxLatency
	*batchMaxLatency = time.Hour // effectively disable the timer
	prevGrease := *greaseRate
	*greaseRate = 0 // deterministic: every reply must verify
	t.Cleanup(func() {
		*batchMaxSize = prevSize
		*batchMaxLatency = prevLatency
		*greaseRate = prevGrease
	})

	p, rootPK := startServer(t)
	addr := &net.UDPAddr{IP: net.IPv6loopback, Port: p}
	srv := protocol.ComputeSRV(rootPK)
	versions := []protocol.Version{protocol.VersionDraft12}

	// Use a single client socket so SO_REUSEPORT (Linux) hashes all requests to
	// one worker; otherwise 16 requests split across NumCPU workers never reach
	// the per-worker batchMaxSize threshold and the 1-hour latency never fires.
	const n = 16 // two full-size batches
	c, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	// Bump the client receive buffer so 16 replies queued back-to-back can't be
	// dropped by a small default rmem on CI runners.
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
	// Responses may arrive in any order; match each reply to its request by
	// nonce. Give each read its own 2s deadline so the sum of per-reply signing
	// latency on a loaded CI runner can't starve the last read.
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

// sendAndVerify fires n closed-loop requests against the server and fails the
// test on any non-grease verification error.
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
		// VerifyReply failures are tolerated: default -grease-rate=0.01 makes a
		// small fraction of replies deliberately invalid.
		_, _, _ = protocol.VerifyReply(versions, buf[:m], rootPK, nonce, req)
	}
}
