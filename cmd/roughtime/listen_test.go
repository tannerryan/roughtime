// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

//go:build unix

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
	"go.uber.org/zap"
)

// TestMain installs deterministic package-wide test settings.
func TestMain(m *testing.M) {
	logger = zap.NewNop()
	*greaseRate = 0
	m.Run()
}

// TestListenEndToEnd covers UDP serving and shutdown.
func TestListenEndToEnd(t *testing.T) {
	requestsReceived.reset()
	requestsResponded.reset()
	statsPanics.Store(0)

	rootPK, st := newCertState(t)
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

	if got := requestsReceived.total(); got < reqs {
		t.Fatalf("requestsReceived total=%d want >=%d", got, reqs)
	}
	if got := requestsResponded.total(); got < reqs {
		t.Fatalf("requestsResponded total=%d want >=%d", got, reqs)
	}
	if got := statsPanics.Load(); got != 0 {
		t.Fatalf("statsPanics=%d want 0", got)
	}
}

// TestListenBatchesConcurrentRequests covers shared signing batches.
func TestListenBatchesConcurrentRequests(t *testing.T) {
	previousProcs := runtime.GOMAXPROCS(1)
	t.Cleanup(func() {
		runtime.GOMAXPROCS(previousProcs)
	})

	p, rootPK := startServer(t)
	startBatches := statsBatches.Load()
	startRequests := statsBatchedReqs.Load()
	addr := &net.UDPAddr{IP: net.IPv6loopback, Port: p}
	srv := protocol.ComputeSRV(rootPK)

	const requests = 8
	ready := make(chan struct{}, requests)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range requests {
		wg.Go(func() {
			conn, err := net.DialUDP("udp", nil, addr)
			if err != nil {
				t.Errorf("dial: %v", err)
				ready <- struct{}{}
				return
			}
			defer func() { _ = conn.Close() }()
			nonce, req, err := protocol.CreateRequest([]protocol.Version{protocol.VersionDraft12}, rand.Reader, srv)
			if err != nil {
				t.Errorf("CreateRequest: %v", err)
				ready <- struct{}{}
				return
			}
			ready <- struct{}{}
			<-start
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			if _, err := conn.Write(req); err != nil {
				t.Errorf("write: %v", err)
				return
			}
			buf := make([]byte, 1500)
			n, err := conn.Read(buf)
			if err != nil {
				t.Errorf("read: %v", err)
				return
			}
			if _, _, err := protocol.VerifyReply([]protocol.Version{protocol.VersionDraft12}, buf[:n], rootPK, nonce, req); err != nil {
				t.Errorf("VerifyReply: %v", err)
			}
		})
	}
	for range requests {
		<-ready
	}
	close(start)
	wg.Wait()

	batchedRequests := statsBatchedReqs.Load() - startRequests
	batches := statsBatches.Load() - startBatches
	if batchedRequests < requests {
		t.Fatalf("batched requests = %d, want at least %d", batchedRequests, requests)
	}
	if batches >= batchedRequests {
		t.Fatalf("batches = %d for %d requests; requests were not batched", batches, batchedRequests)
	}
}

// startListen launches listen on a free port, retrying on bind races.
func startListen(t *testing.T, st *atomic.Pointer[certState]) (int, chan error, context.CancelFunc) {
	t.Helper()
	const maxAttempts = 5
	var lastErr error
	for range maxAttempts {
		p := pickFreeUDPPort(t)
		*port = p
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- listen(ctx, st) }()

		// retry on fast failure (e.g. EADDRINUSE)
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

// waitForServerReady polls until the server answers, avoiding startup races.
func waitForServerReady(t *testing.T, p int, rootPK ed25519.PublicKey) {
	t.Helper()
	versions := protocol.ServerPreferenceEd25519
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

// startServer resets stats, launches listen, and registers a shutdown cleanup.
func startServer(t *testing.T) (int, ed25519.PublicKey) {
	t.Helper()
	requestsReceived.reset()
	requestsResponded.reset()
	requestsDropped.reset()
	statsPanics.Store(0)
	statsBatches.Store(0)
	statsBatchedReqs.Store(0)

	pk, st := newCertState(t)
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

// TestListenMixedVersionBatch covers sequential requests across wire versions.
func TestListenMixedVersionBatch(t *testing.T) {
	p, rootPK := startServer(t)
	addr := &net.UDPAddr{IP: net.IPv6loopback, Port: p}
	srv := protocol.ComputeSRV(rootPK)

	sendAndExpect := func(vers []protocol.Version) {
		conn, err := net.DialUDP("udp", nil, addr)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer func() { _ = conn.Close() }()
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
		if _, _, err := protocol.VerifyReply(vers, buf[:n], rootPK, nonce, req); err != nil {
			t.Fatalf("verify: %v", err)
		}
	}

	// Alternate Google and draft-12 requests.
	for i := range 8 {
		if i%2 == 0 {
			sendAndExpect([]protocol.Version{protocol.VersionGoogle})
		} else {
			sendAndExpect([]protocol.Version{protocol.VersionDraft12})
		}
	}
}

// TestListenNoncInSREPSingletons covers non-batchable response forms.
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
				wg.Go(func() {
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
				})
			}
			wg.Wait()
		})
	}
}

// TestListenUndersizeRequestDropped covers the UDP size floor.
func TestListenUndersizeRequestDropped(t *testing.T) {
	p, _ := startServer(t)
	addr := &net.UDPAddr{IP: net.IPv6loopback, Port: p}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// well-formed but tiny: NONC with 32 zero bytes
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
	if got := requestsDropped.total(); got == 0 {
		t.Fatal("requestsDropped total=0, want >=1")
	}
}

// TestListenMalformedPackets covers malformed datagram handling.
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
			defer func() { _ = conn.Close() }()
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

// sendAndVerify fires n closed-loop requests and verifies every reply.
func sendAndVerify(t *testing.T, p int, rootPK ed25519.PublicKey, n int) {
	t.Helper()
	versions := protocol.ServerPreferenceEd25519
	srv := protocol.ComputeSRV(rootPK)
	addr := &net.UDPAddr{IP: net.IPv6loopback, Port: p}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	buf := make([]byte, 1500)
	for i := range n {
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
		if _, _, err := protocol.VerifyReply(versions, buf[:m], rootPK, nonce, req); err != nil {
			t.Fatalf("verify %d: %v", i, err)
		}
	}
}
