// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

//go:build unix

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tannerryan/roughtime/protocol"
	"go.uber.org/zap"
)

// startListenTCP binds listenTCP to a free port and retries on a pick/bind
// race.
func startListenTCP(t *testing.T, edState, pqState *atomic.Pointer[certState]) (int, chan error, context.CancelFunc) {
	t.Helper()
	const maxAttempts = 5
	for range maxAttempts {
		p := pickFreeTCPPort(t)
		*port = p
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			done <- listenTCP(ctx, edState, pqState)
			close(done)
		}()

		select {
		case err := <-done:
			cancel()
			if err != nil {
				continue
			}
		case <-time.After(50 * time.Millisecond):
		}
		// Drain listener before caller's global-restore cleanups (LIFO).
		t.Cleanup(func() {
			cancel()
			<-done
		})
		return p, done, cancel
	}
	t.Fatalf("startListenTCP: exhausted %d attempts", maxAttempts)
	return 0, nil, nil
}

// dialTCP opens a TCP connection to [::1]:p with a one-second timeout.
func dialTCP(t *testing.T, p int) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", net.JoinHostPort("::1", strconv.Itoa(p)), time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return c
}

// disableGrease zeroes the grease rate for the test's lifetime.
func disableGrease(t *testing.T) {
	t.Helper()
	prev := *greaseRate
	*greaseRate = 0
	t.Cleanup(func() { *greaseRate = prev })
}

// tcpRoundTrip writes a framed request and reads a framed reply with a 2s
// deadline.
func tcpRoundTrip(t *testing.T, conn net.Conn, req []byte) []byte {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write request: %v", err)
	}
	reply, err := readFramedReply(conn, maxTCPReplyBytes)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	return reply
}

// readFramedReply reads one ROUGHTIM frame from r, bounding the body by
// maxBodyLen.
func readFramedReply(r io.Reader, maxBodyLen int) ([]byte, error) {
	var hdr [protocol.PacketHeaderSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	bodyLen, err := protocol.ParsePacketHeader(hdr[:])
	if err != nil {
		return nil, err
	}
	if int(bodyLen) > maxBodyLen {
		return nil, fmt.Errorf("reply body %d exceeds cap %d", bodyLen, maxBodyLen)
	}
	out := make([]byte, protocol.PacketHeaderSize+int(bodyLen))
	copy(out[:protocol.PacketHeaderSize], hdr[:])
	if _, err := io.ReadFull(r, out[protocol.PacketHeaderSize:]); err != nil {
		return nil, err
	}
	return out, nil
}

// TestListenTCPEndToEndEd25519 verifies an Ed25519 round-trip through
// listenTCP.
func TestListenTCPEndToEndEd25519(t *testing.T) {
	disableGrease(t)
	rootPK, edState := newCertState(t)
	p, done, cancel := startListenTCP(t, edState, nil)

	srv := protocol.ComputeSRV(rootPK)
	nonce, req, err := protocol.CreateRequest([]protocol.Version{protocol.VersionDraft12}, rand.Reader, srv)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	conn := dialTCP(t, p)
	defer conn.Close()

	reply := tcpRoundTrip(t, conn, req)
	if _, _, err := protocol.VerifyReply([]protocol.Version{protocol.VersionDraft12}, reply, rootPK, nonce, req); err != nil {
		t.Fatalf("VerifyReply: %v", err)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(6 * time.Second):
		t.Fatal("listenTCP did not exit after cancel")
	}
}

// TestListenTCPEndToEndPQ verifies an ML-DSA-44 round-trip through listenTCP.
func TestListenTCPEndToEndPQ(t *testing.T) {
	disableGrease(t)
	rootPK, pqState := newPQCertState(t)
	p, done, cancel := startListenTCP(t, nil, pqState)

	srv := protocol.ComputeSRV(rootPK)
	nonce, req, err := protocol.CreateRequest([]protocol.Version{protocol.VersionMLDSA44}, rand.Reader, srv)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	conn := dialTCP(t, p)
	defer conn.Close()

	reply := tcpRoundTrip(t, conn, req)
	if _, _, err := protocol.VerifyReply([]protocol.Version{protocol.VersionMLDSA44}, reply, rootPK, nonce, req); err != nil {
		t.Fatalf("VerifyReply: %v", err)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(6 * time.Second):
		t.Fatal("listenTCP did not exit after cancel")
	}
}

// TestListenTCPBatchedPQRoundTrip verifies the PQ batcher coalesces n
// concurrent requests into fewer than n batches.
func TestListenTCPBatchedPQRoundTrip(t *testing.T) {
	disableGrease(t)
	const n = 4
	prevLat, prevSize := batchMaxLatency, batchMaxSize
	batchMaxLatency = 2 * time.Second
	batchMaxSize = n
	t.Cleanup(func() { batchMaxLatency = prevLat; batchMaxSize = prevSize })

	statsBatches.Store(0)
	statsBatchedReqs.Store(0)
	t.Cleanup(func() { statsBatches.Store(0); statsBatchedReqs.Store(0) })

	rootPK, pqState := newPQCertState(t)
	p, done, cancel := startListenTCP(t, nil, pqState)

	srv := protocol.ComputeSRV(rootPK)
	type result struct {
		nonce []byte
		req   []byte
		reply []byte
		err   error
	}
	results := make(chan result, n)
	for range n {
		go func() {
			nonce, req, err := protocol.CreateRequest([]protocol.Version{protocol.VersionMLDSA44}, rand.Reader, srv)
			if err != nil {
				results <- result{err: err}
				return
			}
			conn, err := net.DialTimeout("tcp", net.JoinHostPort("::1", strconv.Itoa(p)), time.Second)
			if err != nil {
				results <- result{err: err}
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := conn.Write(req); err != nil {
				results <- result{err: err}
				return
			}
			reply, err := readFramedReply(conn, maxTCPReplyBytes)
			results <- result{nonce: nonce, req: req, reply: reply, err: err}
		}()
	}

	for range n {
		r := <-results
		if r.err != nil {
			t.Fatalf("round-trip: %v", r.err)
		}
		if _, _, err := protocol.VerifyReply([]protocol.Version{protocol.VersionMLDSA44}, r.reply, rootPK, r.nonce, r.req); err != nil {
			t.Fatalf("VerifyReply: %v", err)
		}
	}

	batches := statsBatches.Load()
	reqs := statsBatchedReqs.Load()
	if reqs < n {
		t.Fatalf("statsBatchedReqs=%d want >= %d", reqs, n)
	}
	if batches >= uint64(n) {
		t.Fatalf("statsBatches=%d reqs=%d: every request got its own batch (no coalescing)", batches, reqs)
	}

	cancel()
	<-done
}

// TestListenTCPDualStackPQPreferred verifies dual-stack negotiation selects the
// PQ scheme when offered.
func TestListenTCPDualStackPQPreferred(t *testing.T) {
	disableGrease(t)
	edRootPK, edState := newCertState(t)
	pqRootPK, pqState := newPQCertState(t)
	p, done, cancel := startListenTCP(t, edState, pqState)

	// PQ is expected to win negotiation; SRV must address the PQ root
	srv := protocol.ComputeSRV(pqRootPK)
	offers := []protocol.Version{protocol.VersionDraft12, protocol.VersionMLDSA44}
	nonce, req, err := protocol.CreateRequest(offers, rand.Reader, srv)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	conn := dialTCP(t, p)
	defer conn.Close()

	reply := tcpRoundTrip(t, conn, req)
	if _, _, err := protocol.VerifyReply([]protocol.Version{protocol.VersionMLDSA44}, reply, pqRootPK, nonce, req); err != nil {
		t.Fatalf("PQ VerifyReply: %v", err)
	}
	if _, _, err := protocol.VerifyReply([]protocol.Version{protocol.VersionDraft12}, reply, edRootPK, nonce, req); err == nil {
		t.Fatal("reply unexpectedly verified under Ed25519 root (PQ preference not honoured)")
	}

	cancel()
	<-done
}

// TestListenTCPDualStackEd25519OnlyClient verifies an Ed25519-only client still
// negotiates against a dual-stack server.
func TestListenTCPDualStackEd25519OnlyClient(t *testing.T) {
	disableGrease(t)
	edRootPK, edState := newCertState(t)
	_, pqState := newPQCertState(t)
	p, done, cancel := startListenTCP(t, edState, pqState)

	srv := protocol.ComputeSRV(edRootPK)
	nonce, req, err := protocol.CreateRequest([]protocol.Version{protocol.VersionDraft12}, rand.Reader, srv)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	conn := dialTCP(t, p)
	defer conn.Close()

	reply := tcpRoundTrip(t, conn, req)
	if _, _, err := protocol.VerifyReply([]protocol.Version{protocol.VersionDraft12}, reply, edRootPK, nonce, req); err != nil {
		t.Fatalf("VerifyReply: %v", err)
	}

	cancel()
	<-done
}

// TestListenTCPSequentialRequests verifies multiple requests succeed on a
// single kept-alive connection.
func TestListenTCPSequentialRequests(t *testing.T) {
	disableGrease(t)
	rootPK, edState := newCertState(t)
	p, done, cancel := startListenTCP(t, edState, nil)

	srv := protocol.ComputeSRV(rootPK)
	conn := dialTCP(t, p)
	defer conn.Close()

	for i := range 4 {
		nonce, req, err := protocol.CreateRequest([]protocol.Version{protocol.VersionDraft12}, rand.Reader, srv)
		if err != nil {
			t.Fatalf("CreateRequest[%d]: %v", i, err)
		}
		reply := tcpRoundTrip(t, conn, req)
		if _, _, err := protocol.VerifyReply([]protocol.Version{protocol.VersionDraft12}, reply, rootPK, nonce, req); err != nil {
			t.Fatalf("VerifyReply[%d]: %v", i, err)
		}
	}

	cancel()
	<-done
}

// TestListenTCPRejectsGoogleRequest verifies listenTCP closes a connection that
// sends an unframed Google request.
func TestListenTCPRejectsGoogleRequest(t *testing.T) {
	_, edState := newCertState(t)
	p, done, cancel := startListenTCP(t, edState, nil)

	_, req, err := protocol.CreateRequest([]protocol.Version{protocol.VersionGoogle}, rand.Reader, nil)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}

	conn := dialTCP(t, p)
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write: %v", err)
	}
	var scratch [1]byte
	if _, err := conn.Read(scratch[:]); err == nil {
		t.Fatalf("expected EOF after Google request, got err=%v", err)
	}
	_ = conn.Close()

	cancel()
	<-done
}

// TestListenTCPRejectsBadMagic verifies listenTCP closes a connection whose
// header lacks the ROUGHTIM magic.
func TestListenTCPRejectsBadMagic(t *testing.T) {
	_, edState := newCertState(t)
	p, done, cancel := startListenTCP(t, edState, nil)

	conn := dialTCP(t, p)
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	junk := make([]byte, protocol.PacketHeaderSize)
	copy(junk[:8], []byte("NOTMAGIC"))
	if _, err := conn.Write(junk); err != nil {
		t.Fatalf("write: %v", err)
	}
	var scratch [1]byte
	if _, err := conn.Read(scratch[:]); err == nil {
		t.Fatalf("expected EOF after bad magic, got err=%v", err)
	}
	_ = conn.Close()

	cancel()
	<-done
}

// TestListenTCPRejectsOversizeLength verifies listenTCP rejects a header
// declaring more than maxTCPRequestSize bytes.
func TestListenTCPRejectsOversizeLength(t *testing.T) {
	_, edState := newCertState(t)
	p, done, cancel := startListenTCP(t, edState, nil)

	conn := dialTCP(t, p)
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	hdr := make([]byte, protocol.PacketHeaderSize)
	copy(hdr[:8], []byte("ROUGHTIM"))
	binary.LittleEndian.PutUint32(hdr[8:12], maxTCPRequestSize+1)
	if _, err := conn.Write(hdr); err != nil {
		t.Fatalf("write: %v", err)
	}
	var scratch [1]byte
	if _, err := conn.Read(scratch[:]); err == nil {
		t.Fatalf("expected EOF after oversize length, got err=%v", err)
	}
	_ = conn.Close()

	cancel()
	<-done
}

// TestListenTCPRejectsSRVMismatch verifies listenTCP drops a request whose SRV
// does not address the configured root.
func TestListenTCPRejectsSRVMismatch(t *testing.T) {
	_, edState := newCertState(t)
	p, done, cancel := startListenTCP(t, edState, nil)

	otherPK, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen other: %v", err)
	}
	_, req, err := protocol.CreateRequest([]protocol.Version{protocol.VersionDraft12}, rand.Reader, protocol.ComputeSRV(otherPK))
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}

	conn := dialTCP(t, p)
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write request: %v", err)
	}
	if _, err := readFramedReply(conn, maxTCPReplyBytes); err == nil {
		t.Fatal("readFramedReply succeeded; expected error after SRV mismatch")
	}
	_ = conn.Close()

	cancel()
	<-done
}

// TestListenTCPIdleTimeoutClosesConn verifies listenTCP closes an idle
// connection after tcpIdleTimeout.
func TestListenTCPIdleTimeoutClosesConn(t *testing.T) {
	prev := tcpIdleTimeout
	tcpIdleTimeout = 100 * time.Millisecond
	t.Cleanup(func() { tcpIdleTimeout = prev })

	_, edState := newCertState(t)
	p, done, cancel := startListenTCP(t, edState, nil)

	conn := dialTCP(t, p)
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	var scratch [1]byte
	if _, err := conn.Read(scratch[:]); err == nil {
		t.Fatalf("expected EOF after idle, got err=%v", err)
	}
	_ = conn.Close()

	cancel()
	<-done
}

// TestListenTCPReadTimeoutAfterHeader verifies listenTCP enforces
// tcpReadTimeout when the body stalls after a valid header.
func TestListenTCPReadTimeoutAfterHeader(t *testing.T) {
	prevIdle, prevRead := tcpIdleTimeout, tcpReadTimeout
	// idle generous so the header read succeeds, body deadline tight so the
	// stall trips the post-header timeout
	tcpIdleTimeout = 5 * time.Second
	tcpReadTimeout = 100 * time.Millisecond
	t.Cleanup(func() {
		tcpIdleTimeout = prevIdle
		tcpReadTimeout = prevRead
	})

	_, edState := newCertState(t)
	p, done, cancel := startListenTCP(t, edState, nil)

	conn := dialTCP(t, p)
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	// announce 1024-byte body, send no body bytes
	var hdr [protocol.PacketHeaderSize]byte
	copy(hdr[:8], []byte("ROUGHTIM"))
	binary.LittleEndian.PutUint32(hdr[8:], 1024)
	if _, err := conn.Write(hdr[:]); err != nil {
		t.Fatalf("write header: %v", err)
	}
	var scratch [1]byte
	if _, err := conn.Read(scratch[:]); err == nil {
		t.Fatalf("expected EOF after body read timeout, got err=%v", err)
	}
	_ = conn.Close()

	cancel()
	<-done
}

// TestListenTCPBatcherLatencyFlush verifies a single-item batch flushes once
// batchMaxLatency elapses.
func TestListenTCPBatcherLatencyFlush(t *testing.T) {
	disableGrease(t)
	prevLat, prevSize := batchMaxLatency, batchMaxSize
	batchMaxLatency = 50 * time.Millisecond
	batchMaxSize = 1000
	t.Cleanup(func() { batchMaxLatency = prevLat; batchMaxSize = prevSize })

	rootPK, edState := newCertState(t)
	p, done, cancel := startListenTCP(t, edState, nil)

	srv := protocol.ComputeSRV(rootPK)
	nonce, req, err := protocol.CreateRequest([]protocol.Version{protocol.VersionDraft12}, rand.Reader, srv)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}

	conn := dialTCP(t, p)

	start := time.Now()
	reply := tcpRoundTrip(t, conn, req)
	elapsed := time.Since(start)

	// Must wait a fraction of the timer; upper bound absorbs CI jitter
	if elapsed < batchMaxLatency/2 {
		t.Fatalf("reply returned in %s (< %s); size path likely triggered", elapsed, batchMaxLatency/2)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("reply took %s; batcher timer did not flush", elapsed)
	}
	if _, _, err := protocol.VerifyReply([]protocol.Version{protocol.VersionDraft12}, reply, rootPK, nonce, req); err != nil {
		t.Fatalf("VerifyReply: %v", err)
	}

	_ = conn.Close()
	cancel()
	<-done
}

// TestListenTCPShutdownForceClose verifies listenTCP force-closes idle conns
// after tcpShutdownGrace.
func TestListenTCPShutdownForceClose(t *testing.T) {
	prevGrace, prevIdle := tcpShutdownGrace, tcpIdleTimeout
	tcpShutdownGrace = 100 * time.Millisecond
	tcpIdleTimeout = 30 * time.Second
	t.Cleanup(func() { tcpShutdownGrace = prevGrace; tcpIdleTimeout = prevIdle })

	_, edState := newCertState(t)
	initialAccepted := statsTCPAccepted.Load()
	p, done, cancel := startListenTCP(t, edState, nil)

	conn := dialTCP(t, p)
	defer conn.Close()
	// poll until accept counter advances; brief grace below covers the gap
	// before live.add(c) lands
	deadline := time.Now().Add(time.Second)
	for statsTCPAccepted.Load() <= initialAccepted && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(5 * time.Millisecond)

	cancelStart := time.Now()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("listenTCP did not exit within 5s of cancel")
	}
	elapsed := time.Since(cancelStart)
	// Must exit well inside tcpIdleTimeout
	if elapsed > 2*time.Second {
		t.Fatalf("shutdown took %s; force-close path not taken (grace=%s, idle=%s)",
			elapsed, tcpShutdownGrace, tcpIdleTimeout)
	}
}

// TestListenTCPRejectsNoStateConfigured verifies listenTCP returns an error
// when no scheme state is configured.
func TestListenTCPRejectsNoStateConfigured(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := listenTCP(ctx, nil, nil); err == nil {
		t.Fatal("listenTCP with no state configured must error")
	}
}

// TestListenTCPRejectsAtMaxConnections verifies listenTCP closes excess accepts
// once maxTCPConnections is reached.
func TestListenTCPRejectsAtMaxConnections(t *testing.T) {
	prev := maxTCPConnections
	maxTCPConnections = 1
	t.Cleanup(func() { maxTCPConnections = prev })

	prevIdle := tcpIdleTimeout
	tcpIdleTimeout = 5 * time.Second
	t.Cleanup(func() { tcpIdleTimeout = prevIdle })

	_, edState := newCertState(t)
	startRejected := statsTCPRejected.Load()
	startAccepted := statsTCPAccepted.Load()
	p, done, cancel := startListenTCP(t, edState, nil)

	// First conn occupies the only slot; hold it idle so it stays counted
	hold := dialTCP(t, p)
	defer hold.Close()
	deadline := time.Now().Add(time.Second)
	for statsTCPAccepted.Load() <= startAccepted && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	// brief settle so live.add lands before the second dial
	time.Sleep(10 * time.Millisecond)

	// Second conn must be rejected; the listener accepts then closes
	rej, err := net.DialTimeout("tcp", net.JoinHostPort("::1", strconv.Itoa(p)), time.Second)
	if err != nil {
		t.Fatalf("dial second: %v", err)
	}
	defer rej.Close()
	_ = rej.SetDeadline(time.Now().Add(2 * time.Second))
	var scratch [1]byte
	if _, err := rej.Read(scratch[:]); err == nil {
		t.Fatalf("expected EOF on max-conns reject, got err=%v", err)
	}

	rejDeadline := time.Now().Add(time.Second)
	for statsTCPRejected.Load() <= startRejected && time.Now().Before(rejDeadline) {
		time.Sleep(time.Millisecond)
	}
	if got := statsTCPRejected.Load(); got <= startRejected {
		t.Fatalf("statsTCPRejected did not advance past %d (got %d)", startRejected, got)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("listenTCP did not exit after cancel")
	}
}

// TestGreasedPQReplyFitsMaxFrame verifies an ML-DSA-44 reply fits
// maxTCPReplyBytes through every grease mode.
func TestGreasedPQReplyFitsMaxFrame(t *testing.T) {
	rootPK, pqState := newPQCertState(t)
	st := pqState.Load()
	srv := protocol.ComputeSRV(rootPK)

	const batch = 64
	reqs := make([]protocol.Request, batch)
	for i := range batch {
		_, req, err := protocol.CreateRequest([]protocol.Version{protocol.VersionMLDSA44}, rand.Reader, srv)
		if err != nil {
			t.Fatalf("CreateRequest[%d]: %v", i, err)
		}
		parsed, err := protocol.ParseRequest(req)
		if err != nil {
			t.Fatalf("ParseRequest[%d]: %v", i, err)
		}
		reqs[i] = *parsed
	}
	replies, err := protocol.CreateReplies(protocol.VersionMLDSA44, reqs, time.Now(), time.Second, st.cert)
	if err != nil {
		t.Fatalf("CreateReplies: %v", err)
	}

	// 1024 iterations cover all four grease modes with overwhelming probability
	for i := 0; i < 1024; i++ {
		reply := append([]byte(nil), replies[i%len(replies)]...)
		if out := protocol.Grease(reply, protocol.VersionMLDSA44); out != nil {
			reply = out
		}
		if len(reply) > maxTCPReplyBytes {
			t.Fatalf("greased PQ reply %d bytes exceeds maxTCPReplyBytes %d", len(reply), maxTCPReplyBytes)
		}
	}
}

// TestWriteTCPReplyRejectsOversize verifies writeTCPReply rejects an oversize
// payload before any bytes are written.
func TestWriteTCPReplyRejectsOversize(t *testing.T) {
	var buf strings.Builder
	payload := make([]byte, maxTCPReplyBytes+1)
	if err := writeTCPReply(&buf, payload); err == nil {
		t.Fatal("writeTCPReply accepted oversize payload")
	}
	if buf.Len() != 0 {
		t.Fatalf("writeTCPReply wrote %d bytes on reject; expected 0", buf.Len())
	}
}

// TestFlushTCPBatchOversizeDeliversError verifies flushTCPBatch delivers an
// error to every handler when replies exceed the cap.
func TestFlushTCPBatchOversizeDeliversError(t *testing.T) {
	disableGrease(t)
	prev := maxTCPReplyBytes
	maxTCPReplyBytes = 8
	t.Cleanup(func() { maxTCPReplyBytes = prev })

	rootPK, edState := newCertState(t)
	st := edState.Load()
	srv := protocol.ComputeSRV(rootPK)

	const n = 3
	items := make([]tcpBatchItem, n)
	chans := make([]chan tcpBatchReply, n)
	for i := range n {
		_, req, err := protocol.CreateRequest([]protocol.Version{protocol.VersionDraft12}, rand.Reader, srv)
		if err != nil {
			t.Fatalf("CreateRequest[%d]: %v", i, err)
		}
		parsed, err := protocol.ParseRequest(req)
		if err != nil {
			t.Fatalf("ParseRequest[%d]: %v", i, err)
		}
		chans[i] = make(chan tcpBatchReply, 1)
		items[i] = tcpBatchItem{
			req:     *parsed,
			version: protocol.VersionDraft12,
			hasType: parsed.HasType,
			peer:    &net.TCPAddr{IP: net.IPv6loopback, Port: 10000 + i},
			reply:   chans[i],
		}
	}

	flushTCPBatch(zap.NewNop(), st, protocol.VersionDraft12, items)

	for i, ch := range chans {
		select {
		case br := <-ch:
			if br.err == nil {
				t.Fatalf("item %d: got bytes=%d, want err", i, len(br.bytes))
			}
			if br.bytes != nil {
				t.Fatalf("item %d: err set but bytes also delivered (%d)", i, len(br.bytes))
			}
		default:
			t.Fatalf("item %d: no reply delivered", i)
		}
	}
}

// TestTCPServerPrefsPQFirst verifies tcpServerPrefs places the PQ scheme first
// when both schemes are configured.
func TestTCPServerPrefsPQFirst(t *testing.T) {
	_, edState := newCertState(t)
	_, pqState := newPQCertState(t)

	prefs := tcpServerPrefs(edState, pqState)
	if len(prefs) == 0 || prefs[0] != protocol.VersionMLDSA44 {
		t.Fatalf("prefs[0]=%v want VersionMLDSA44; full=%v", prefs[0], prefs)
	}
}

// TestTCPServerPrefsEd25519Only verifies tcpServerPrefs omits the PQ scheme
// when only Ed25519 is configured.
func TestTCPServerPrefsEd25519Only(t *testing.T) {
	_, edState := newCertState(t)
	prefs := tcpServerPrefs(edState, nil)
	for _, v := range prefs {
		if v == protocol.VersionMLDSA44 {
			t.Fatalf("prefs contains PQ despite no PQ state: %v", prefs)
		}
	}
}

// TestTCPRouteForVersionRejectsMissingScheme verifies tcpRouteForVersion errors
// when the routed scheme is not configured.
func TestTCPRouteForVersionRejectsMissingScheme(t *testing.T) {
	_, edState := newCertState(t)
	edCh := make(chan tcpBatchItem, 1)
	if _, _, err := tcpRouteForVersion(protocol.VersionMLDSA44, edState, nil, edCh, nil); err == nil {
		t.Fatal("expected error for PQ version without PQ state")
	}
	_, pqState := newPQCertState(t)
	pqCh := make(chan tcpBatchItem, 1)
	if _, _, err := tcpRouteForVersion(protocol.VersionDraft12, nil, pqState, nil, pqCh); err == nil {
		t.Fatal("expected error for Ed25519 version without Ed25519 state")
	}
}

// FuzzReadTCPFrame verifies the TCP framing pipeline used by handleTCPConn
// rejects malformed input without panicking.
func FuzzReadTCPFrame(f *testing.F) {
	wellFormed := make([]byte, protocol.PacketHeaderSize+16)
	copy(wellFormed[:8], []byte("ROUGHTIM"))
	binary.LittleEndian.PutUint32(wellFormed[8:12], 16)
	f.Add(wellFormed)
	f.Add([]byte{})
	f.Add([]byte("ROUGHTIM"))
	f.Add(append([]byte("ROUGHTIM"), 0xff, 0xff, 0xff, 0xff))
	f.Add(append([]byte("BADMAGIC"), 0x10, 0x00, 0x00, 0x00))

	f.Fuzz(func(t *testing.T, data []byte) {
		r := newSliceReader(data)
		hdr := make([]byte, protocol.PacketHeaderSize)
		if _, err := io.ReadFull(r, hdr); err != nil {
			return
		}
		bodyLen, err := protocol.ParsePacketHeader(hdr)
		if err != nil {
			return
		}
		if bodyLen == 0 || bodyLen > maxTCPRequestSize {
			return
		}
		buf := make([]byte, protocol.PacketHeaderSize+int(bodyLen))
		copy(buf, hdr)
		if _, err := io.ReadFull(r, buf[protocol.PacketHeaderSize:]); err != nil {
			return
		}
		if uint32(len(buf)) != protocol.PacketHeaderSize+bodyLen {
			t.Fatalf("framed buffer length %d != header(%d)+body(%d)", len(buf), protocol.PacketHeaderSize, bodyLen)
		}
		if bodyLen > maxTCPRequestSize {
			t.Fatalf("framed bodyLen %d exceeds cap %d", bodyLen, maxTCPRequestSize)
		}
	})
}

// sliceReader adapts a byte slice as an io.Reader for the fuzzer.
type sliceReader struct {
	// b is the unread tail of the underlying slice.
	b []byte
}

// newSliceReader wraps b as an io.Reader.
func newSliceReader(b []byte) *sliceReader { return &sliceReader{b: b} }

// (sliceReader) Read drains the wrapped slice into p, returning io.EOF when
// empty.
func (r *sliceReader) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.b)
	r.b = r.b[n:]
	return n, nil
}
