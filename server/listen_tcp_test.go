// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/mldsa"
	"github.com/tannerryan/roughtime/protocol"
)

// newEdTCPState returns a fresh Ed25519 certState pointer and the root pubkey.
func newEdTCPState(t *testing.T) (ed25519.PublicKey, *atomic.Pointer[certState]) {
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

// newPQTCPState returns a fresh ML-DSA-44 certState pointer and the encoded
// root pubkey.
func newPQTCPState(t *testing.T) ([]byte, *atomic.Pointer[certState]) {
	t.Helper()
	rootSK, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("mldsa root: %v", err)
	}
	onlineSK, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("mldsa online: %v", err)
	}
	now := time.Now()
	cert, err := protocol.NewCertificateMLDSA44(now.Add(certStartOffset), now.Add(certEndOffset), onlineSK, rootSK)
	if err != nil {
		t.Fatalf("NewCertificateMLDSA44: %v", err)
	}
	rootPK := rootSK.PublicKey().Bytes()
	st := &atomic.Pointer[certState]{}
	st.Store(&certState{cert: cert, expiry: now.Add(certEndOffset), srvHash: protocol.ComputeSRV(rootPK)})
	return rootPK, st
}

// pickFreeTCPPort returns an ephemeral TCP port after closing the holder
// socket.
func pickFreeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "[::]:0")
	if err != nil {
		t.Fatalf("pick free TCP port: %v", err)
	}
	p := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return p
}

// startListenTCP binds listenTCP to a free port; retries on a pick/bind race.
func startListenTCP(t *testing.T, edState, pqState *atomic.Pointer[certState]) (int, chan error, context.CancelFunc) {
	t.Helper()
	const maxAttempts = 5
	for range maxAttempts {
		p := pickFreeTCPPort(t)
		*port = p
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- listenTCP(ctx, edState, pqState) }()

		select {
		case err := <-done:
			cancel()
			if err != nil {
				continue
			}
		case <-time.After(50 * time.Millisecond):
		}
		return p, done, cancel
	}
	t.Fatalf("startListenTCP: exhausted %d attempts", maxAttempts)
	return 0, nil, nil
}

func dialTCP(t *testing.T, p int) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", net.JoinHostPort("::1", strconv.Itoa(p)), time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return c
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

// TestListenTCPEndToEndEd25519 verifies an Ed25519 round-trip.
func TestListenTCPEndToEndEd25519(t *testing.T) {
	rootPK, edState := newEdTCPState(t)
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

// TestListenTCPEndToEndPQ verifies an ML-DSA-44 round-trip.
func TestListenTCPEndToEndPQ(t *testing.T) {
	rootPK, pqState := newPQTCPState(t)
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

// TestListenTCPBatchedPQRoundTrip verifies the PQ batcher coalesces concurrent
// requests.
func TestListenTCPBatchedPQRoundTrip(t *testing.T) {
	const n = 4
	prevLat, prevSize := batchMaxLatency, batchMaxSize
	batchMaxLatency = 2 * time.Second
	batchMaxSize = n
	t.Cleanup(func() { batchMaxLatency = prevLat; batchMaxSize = prevSize })

	statsBatches.Store(0)
	statsBatchedReqs.Store(0)
	t.Cleanup(func() { statsBatches.Store(0); statsBatchedReqs.Store(0) })

	rootPK, pqState := newPQTCPState(t)
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

// TestListenTCPDualStackPQPreferred verifies a dual-stack server picks
// ML-DSA-44 when both are offered.
func TestListenTCPDualStackPQPreferred(t *testing.T) {
	edRootPK, edState := newEdTCPState(t)
	pqRootPK, pqState := newPQTCPState(t)
	p, done, cancel := startListenTCP(t, edState, pqState)

	// PQ scheme is expected to win, so use its SRV
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

// TestListenTCPDualStackEd25519OnlyClient verifies a dual-stack server still
// serves an Ed25519-only client.
func TestListenTCPDualStackEd25519OnlyClient(t *testing.T) {
	edRootPK, edState := newEdTCPState(t)
	_, pqState := newPQTCPState(t)
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

// TestListenTCPSequentialRequests verifies one connection serves multiple
// sequential requests.
func TestListenTCPSequentialRequests(t *testing.T) {
	rootPK, edState := newEdTCPState(t)
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

// TestListenTCPRejectsGoogleRequest verifies an unframed Google-Roughtime
// request is rejected on TCP.
func TestListenTCPRejectsGoogleRequest(t *testing.T) {
	_, edState := newEdTCPState(t)
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
	if _, err := conn.Read(scratch[:]); !errors.Is(err, io.EOF) && err == nil {
		t.Fatalf("expected EOF after Google request, got err=%v", err)
	}
	_ = conn.Close()

	cancel()
	<-done
}

// TestListenTCPRejectsBadMagic verifies a non-ROUGHTIM magic closes the
// connection.
func TestListenTCPRejectsBadMagic(t *testing.T) {
	_, edState := newEdTCPState(t)
	p, done, cancel := startListenTCP(t, edState, nil)

	conn := dialTCP(t, p)
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	junk := make([]byte, protocol.PacketHeaderSize)
	copy(junk[:8], []byte("NOTMAGIC"))
	if _, err := conn.Write(junk); err != nil {
		t.Fatalf("write: %v", err)
	}
	var scratch [1]byte
	if _, err := conn.Read(scratch[:]); !errors.Is(err, io.EOF) && err == nil {
		t.Fatalf("expected EOF after bad magic, got err=%v", err)
	}
	_ = conn.Close()

	cancel()
	<-done
}

// TestListenTCPRejectsOversizeLength verifies a body length above
// maxTCPRequestSize closes the connection.
func TestListenTCPRejectsOversizeLength(t *testing.T) {
	_, edState := newEdTCPState(t)
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
	if _, err := conn.Read(scratch[:]); !errors.Is(err, io.EOF) && err == nil {
		t.Fatalf("expected EOF after oversize length, got err=%v", err)
	}
	_ = conn.Close()

	cancel()
	<-done
}

// TestListenTCPRejectsSRVMismatch verifies a request with a foreign SRV is
// rejected without a reply.
func TestListenTCPRejectsSRVMismatch(t *testing.T) {
	_, edState := newEdTCPState(t)
	p, done, cancel := startListenTCP(t, edState, nil)

	// SRV from an unrelated key
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

// TestListenTCPIdleTimeoutClosesConn verifies an idle connection is closed
// after tcpIdleTimeout.
func TestListenTCPIdleTimeoutClosesConn(t *testing.T) {
	prev := tcpIdleTimeout
	tcpIdleTimeout = 100 * time.Millisecond
	t.Cleanup(func() { tcpIdleTimeout = prev })

	_, edState := newEdTCPState(t)
	p, done, cancel := startListenTCP(t, edState, nil)

	conn := dialTCP(t, p)
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	var scratch [1]byte
	if _, err := conn.Read(scratch[:]); !errors.Is(err, io.EOF) && err == nil {
		t.Fatalf("expected EOF after idle, got err=%v", err)
	}
	_ = conn.Close()

	cancel()
	<-done
}

// TestListenTCPBatcherLatencyFlush verifies the batcher flushes via the latency
// timer, not size.
func TestListenTCPBatcherLatencyFlush(t *testing.T) {
	prevLat, prevSize := batchMaxLatency, batchMaxSize
	batchMaxLatency = 50 * time.Millisecond
	batchMaxSize = 1000
	t.Cleanup(func() { batchMaxLatency = prevLat; batchMaxSize = prevSize })

	rootPK, edState := newEdTCPState(t)
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

// TestListenTCPShutdownForceClose verifies idle handlers are force-closed after
// tcpShutdownGrace.
func TestListenTCPShutdownForceClose(t *testing.T) {
	prevGrace, prevIdle := tcpShutdownGrace, tcpIdleTimeout
	tcpShutdownGrace = 100 * time.Millisecond
	tcpIdleTimeout = 30 * time.Second
	t.Cleanup(func() { tcpShutdownGrace = prevGrace; tcpIdleTimeout = prevIdle })

	_, edState := newEdTCPState(t)
	p, done, cancel := startListenTCP(t, edState, nil)

	conn := dialTCP(t, p)
	defer conn.Close()
	// Let the accept goroutine register the conn in live
	time.Sleep(50 * time.Millisecond)

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

// TestListenTCPRejectsNoStateConfigured verifies listenTCP errors when no
// scheme is configured.
func TestListenTCPRejectsNoStateConfigured(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := listenTCP(ctx, nil, nil); err == nil {
		t.Fatal("listenTCP with no state configured must error")
	}
}

// TestGreasedPQReplyFitsMaxFrame verifies every grease mode keeps PQ replies
// under maxTCPReplyBytes.
func TestGreasedPQReplyFitsMaxFrame(t *testing.T) {
	rootPK, pqState := newPQTCPState(t)
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

// TestWriteTCPReplyRejectsOversize verifies writeTCPReply refuses payloads
// above maxTCPReplyBytes.
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

// TestTCPServerPrefsPQFirst verifies PQ sits ahead of Ed25519 when both are
// configured.
func TestTCPServerPrefsPQFirst(t *testing.T) {
	_, edState := newEdTCPState(t)
	_, pqState := newPQTCPState(t)

	prefs := tcpServerPrefs(edState, pqState)
	if len(prefs) == 0 || prefs[0] != protocol.VersionMLDSA44 {
		t.Fatalf("prefs[0]=%v want VersionMLDSA44; full=%v", prefs[0], prefs)
	}
}

// TestTCPServerPrefsEd25519Only verifies prefs omit PQ entries when PQ is not
// configured.
func TestTCPServerPrefsEd25519Only(t *testing.T) {
	_, edState := newEdTCPState(t)
	prefs := tcpServerPrefs(edState, nil)
	for _, v := range prefs {
		if v == protocol.VersionMLDSA44 {
			t.Fatalf("prefs contains PQ despite no PQ state: %v", prefs)
		}
	}
}

// TestTCPRouteForVersionRejectsMissingScheme verifies the helper rejects
// versions whose scheme is unconfigured.
func TestTCPRouteForVersionRejectsMissingScheme(t *testing.T) {
	_, edState := newEdTCPState(t)
	edCh := make(chan tcpBatchItem, 1)
	if _, _, err := tcpRouteForVersion(protocol.VersionMLDSA44, edState, nil, edCh, nil); err == nil {
		t.Fatal("expected error for PQ version without PQ state")
	}
	_, pqState := newPQTCPState(t)
	pqCh := make(chan tcpBatchItem, 1)
	if _, _, err := tcpRouteForVersion(protocol.VersionDraft12, nil, pqState, nil, pqCh); err == nil {
		t.Fatal("expected error for Ed25519 version without Ed25519 state")
	}
}

// FuzzReadTCPFrame fuzzes the TCP framing pipeline used by handleTCPConn.
func FuzzReadTCPFrame(f *testing.F) {
	// Seed with one well-formed frame and several malformed shapes
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
		// Framing succeeded; check buffer length matches the parsed header
		if uint32(len(buf)) != protocol.PacketHeaderSize+bodyLen {
			t.Fatalf("framed buffer length %d != header(%d)+body(%d)", len(buf), protocol.PacketHeaderSize, bodyLen)
		}
		if bodyLen > maxTCPRequestSize {
			t.Fatalf("framed bodyLen %d exceeds cap %d", bodyLen, maxTCPRequestSize)
		}
	})
}

// sliceReader adapts a byte slice as an io.Reader for the fuzzer.
type sliceReader struct{ b []byte }

func newSliceReader(b []byte) *sliceReader { return &sliceReader{b: b} }

func (r *sliceReader) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.b)
	r.b = r.b[n:]
	return n, nil
}
