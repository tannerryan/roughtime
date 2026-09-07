// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

//go:build unix

package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tannerryan/roughtime/protocol"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
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
			if err := awaitTest(t, done, 6*time.Second, "listenTCP cleanup"); err != nil {
				t.Errorf("listenTCP cleanup: %v", err)
			}
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

// TestListenTCPEndToEndEd25519 covers an Ed25519 TCP round trip.
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
	defer func() { _ = conn.Close() }()

	reply := tcpRoundTrip(t, conn, req)
	if _, _, err := protocol.VerifyReply([]protocol.Version{protocol.VersionDraft12}, reply, rootPK, nonce, req); err != nil {
		t.Fatalf("VerifyReply: %v", err)
	}

	cancel()
	if err := awaitTest(t, done, 6*time.Second, "listenTCP shutdown"); err != nil {
		t.Fatalf("listenTCP: %v", err)
	}
}

// TestListenTCPEndToEndPQ covers an ML-DSA-44 TCP round trip.
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
	defer func() { _ = conn.Close() }()

	reply := tcpRoundTrip(t, conn, req)
	if _, _, err := protocol.VerifyReply([]protocol.Version{protocol.VersionMLDSA44}, reply, rootPK, nonce, req); err != nil {
		t.Fatalf("VerifyReply: %v", err)
	}

	cancel()
	if err := awaitTest(t, done, 6*time.Second, "listenTCP shutdown"); err != nil {
		t.Fatalf("listenTCP: %v", err)
	}
}

// TestPrepareTCPItemRequiresSRVForDualRootModernRequests covers long-term-key
// selection before a request reaches either signing queue.
func TestPrepareTCPItemRequiresSRVForDualRootModernRequests(t *testing.T) {
	_, edState := newCertState(t)
	_, pqState := newPQCertState(t)
	edCh := make(chan tcpBatchItem)
	pqCh := make(chan tcpBatchItem)
	peer := &net.TCPAddr{IP: net.IPv6loopback, Port: 2002}
	prefs := tcpServerPrefs(edState, pqState)

	for _, version := range []protocol.Version{protocol.VersionDraft10, protocol.VersionDraft12, protocol.VersionMLDSA44} {
		t.Run(version.ShortString(), func(t *testing.T) {
			_, req, err := protocol.CreateRequest([]protocol.Version{version}, rand.Reader, nil)
			if err != nil {
				t.Fatalf("CreateRequest: %v", err)
			}
			_, ch, reason, err := prepareTCPItem(zap.NewNop(), peer, req, edState, pqState, edCh, pqCh, prefs)
			if err == nil || reason != dropSRV || ch != nil {
				t.Fatalf("prepareTCPItem: ch=%v reason=%q err=%v, want pre-route SRV rejection", ch, reason, err)
			}
		})
	}
}

// TestPrepareTCPItemAllowsMissingSRVWithOneRoot preserves the drafts' optional
// SRV behavior for an endpoint with one configured long-term key.
func TestPrepareTCPItemAllowsMissingSRVWithOneRoot(t *testing.T) {
	_, edState := newCertState(t)
	edCh := make(chan tcpBatchItem)
	peer := &net.TCPAddr{IP: net.IPv6loopback, Port: 2002}
	_, req, err := protocol.CreateRequest([]protocol.Version{protocol.VersionDraft12}, rand.Reader, nil)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	item, ch, reason, err := prepareTCPItem(zap.NewNop(), peer, req, edState, nil, edCh, nil, tcpServerPrefs(edState, nil))
	if err != nil || reason != dropNone || ch != edCh || item.version != protocol.VersionDraft12 {
		t.Fatalf("prepareTCPItem: version=%s ch=%v reason=%q err=%v", item.version, ch, reason, err)
	}
}

// TestPrepareTCPItemAllowsDualRootLegacyWithoutSRV preserves pre-draft-10
// negotiation, which predates long-term-key selection through SRV.
func TestPrepareTCPItemAllowsDualRootLegacyWithoutSRV(t *testing.T) {
	_, edState := newCertState(t)
	_, pqState := newPQCertState(t)
	edCh := make(chan tcpBatchItem)
	pqCh := make(chan tcpBatchItem)
	peer := &net.TCPAddr{IP: net.IPv6loopback, Port: 2002}
	prefs := []protocol.Version{protocol.VersionDraft09, protocol.VersionGoogle}

	for _, version := range prefs {
		t.Run(version.ShortString(), func(t *testing.T) {
			_, req, err := protocol.CreateRequest([]protocol.Version{version}, rand.Reader, nil)
			if err != nil {
				t.Fatalf("CreateRequest: %v", err)
			}
			item, ch, reason, err := prepareTCPItem(zap.NewNop(), peer, req, edState, pqState, edCh, pqCh, prefs)
			if err != nil || reason != dropNone || ch != edCh || item.version != version {
				t.Fatalf("prepareTCPItem: version=%s ch=%v reason=%q err=%v", item.version, ch, reason, err)
			}
		})
	}
}

// TestDeliverTCPBatchError covers queued delivery and verifies that abandoned
// full or nil reply channels cannot block the batcher.
func TestDeliverTCPBatchError(t *testing.T) {
	wantErr := errors.New("batch failed")
	queued := make(chan tcpBatchReply, 1)
	full := make(chan tcpBatchReply, 1)
	occupiedErr := errors.New("occupied")
	full <- tcpBatchReply{err: occupiedErr}
	items := []tcpBatchItem{
		{reply: queued},
		{reply: full},
		{reply: nil},
	}
	startBatchErrs := statsBatchErrs.Load()
	done := make(chan struct{})
	go func() {
		deliverTCPBatchError(items, wantErr)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("deliverTCPBatchError blocked on a full or nil reply channel")
	}
	if got := statsBatchErrs.Load(); got != startBatchErrs+1 {
		t.Fatalf("batch errors=%d want %d", got, startBatchErrs+1)
	}
	if got := awaitTest(t, queued, time.Second, "queued batch error"); got.err != wantErr {
		t.Fatalf("queued error=%v want %v", got.err, wantErr)
	}
	if got := awaitTest(t, full, time.Second, "existing batch error"); got.err != occupiedErr {
		t.Fatalf("full channel error=%v want original %v", got.err, occupiedErr)
	}
	select {
	case got := <-full:
		t.Fatalf("full channel received unexpected second result: %+v", got)
	default:
	}
}

// TestTCPBatcherPanicCountsBatchError checks error delivery and accounting
// after a logging hook panics while rejecting an invalid request.
func TestTCPBatcherPanicCountsBatchError(t *testing.T) {
	_, state := newCertState(t)
	core := zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()),
		zapcore.AddSync(io.Discard), zap.WarnLevel)
	log := zap.New(core, zap.Hooks(func(entry zapcore.Entry) error {
		if entry.Level == zap.WarnLevel {
			panic("test warning hook")
		}
		return nil
	}))
	reply := make(chan tcpBatchReply, 1)
	incoming := make(chan tcpBatchItem, 1)
	incoming <- tcpBatchItem{version: protocol.VersionDraft12, reply: reply}
	close(incoming)
	startPanics, startErrors := statsPanics.Load(), statsBatchErrs.Load()
	tcpBatcher(log, state, incoming, 1, time.Second)
	if got := statsPanics.Load(); got != startPanics+1 {
		t.Fatalf("panics=%d want %d", got, startPanics+1)
	}
	if got := statsBatchErrs.Load(); got != startErrors+1 {
		t.Fatalf("batch errors=%d want %d", got, startErrors+1)
	}
	if got := awaitTest(t, reply, time.Second, "panic batch error"); got.err == nil {
		t.Fatal("panic did not produce a batch error")
	}
}

// TestFlushTCPBatchCurrentWithoutCertificate covers fail-closed delivery when
// no signing state is published.
func TestFlushTCPBatchCurrentWithoutCertificate(t *testing.T) {
	reply := make(chan tcpBatchReply, 1)
	flushTCPBatchCurrent(zap.NewNop(), nil, protocol.VersionDraft12, []tcpBatchItem{{reply: reply}})
	select {
	case got := <-reply:
		if got.err == nil || got.err.Error() != "active certificate unavailable" {
			t.Fatalf("flush error=%v want active certificate unavailable", got.err)
		}
	case <-time.After(time.Second):
		t.Fatal("flush did not deliver missing-certificate error")
	}
}

// TestListenTCPSequentialRequests covers connection reuse.
func TestListenTCPSequentialRequests(t *testing.T) {
	disableGrease(t)
	rootPK, edState := newCertState(t)
	p, done, cancel := startListenTCP(t, edState, nil)

	srv := protocol.ComputeSRV(rootPK)
	conn := dialTCP(t, p)
	defer func() { _ = conn.Close() }()

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
	if err := awaitTest(t, done, 6*time.Second, "listenTCP shutdown"); err != nil {
		t.Fatalf("listenTCP: %v", err)
	}
}

// TestListenTCPRejectsBadMagic covers invalid frame magic.
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
	if err := awaitTest(t, done, 6*time.Second, "listenTCP shutdown"); err != nil {
		t.Fatalf("listenTCP: %v", err)
	}
}

// TestListenTCPRejectsOversizeLength covers oversized request bodies.
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
	if err := awaitTest(t, done, 6*time.Second, "listenTCP shutdown"); err != nil {
		t.Fatalf("listenTCP: %v", err)
	}
}

// TestListenTCPRejectsZeroBody covers the lower framing bound.
func TestListenTCPRejectsZeroBody(t *testing.T) {
	_, edState := newCertState(t)
	startDropped := droppedFor(transportTCP, dropFraming)
	p, done, cancel := startListenTCP(t, edState, nil)

	conn := dialTCP(t, p)
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	hdr := make([]byte, protocol.PacketHeaderSize)
	copy(hdr[:8], []byte("ROUGHTIM"))
	if _, err := conn.Write(hdr); err != nil {
		t.Fatalf("write: %v", err)
	}
	var scratch [1]byte
	if _, err := conn.Read(scratch[:]); err == nil {
		t.Fatal("expected EOF after zero body")
	}
	if got := droppedFor(transportTCP, dropFraming); got <= startDropped {
		t.Fatalf("framing drops=%d want greater than %d", got, startDropped)
	}
	_ = conn.Close()
	cancel()
	if err := awaitTest(t, done, 6*time.Second, "listenTCP shutdown"); err != nil {
		t.Fatalf("listenTCP: %v", err)
	}
}

// TestListenTCPRejectsShortBody covers the bounded body-read error path.
func TestListenTCPRejectsShortBody(t *testing.T) {
	prev := tcpReadTimeout
	tcpReadTimeout = 50 * time.Millisecond
	t.Cleanup(func() { tcpReadTimeout = prev })
	_, edState := newCertState(t)
	startDropped := droppedFor(transportTCP, dropRead)
	p, done, cancel := startListenTCP(t, edState, nil)

	conn := dialTCP(t, p)
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	hdr := make([]byte, protocol.PacketHeaderSize)
	copy(hdr[:8], []byte("ROUGHTIM"))
	binary.LittleEndian.PutUint32(hdr[8:12], 32)
	if _, err := conn.Write(append(hdr, 0)); err != nil {
		t.Fatalf("write: %v", err)
	}
	var scratch [1]byte
	if _, err := conn.Read(scratch[:]); err == nil {
		t.Fatal("expected EOF after short body timeout")
	}
	if got := droppedFor(transportTCP, dropRead); got <= startDropped {
		t.Fatalf("read drops=%d want greater than %d", got, startDropped)
	}
	_ = conn.Close()
	cancel()
	if err := awaitTest(t, done, 6*time.Second, "listenTCP shutdown"); err != nil {
		t.Fatalf("listenTCP: %v", err)
	}
}

// TestListenTCPIdleTimeoutClosesConn covers idle connection expiry.
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
	if err := awaitTest(t, done, 6*time.Second, "listenTCP shutdown"); err != nil {
		t.Fatalf("listenTCP: %v", err)
	}
}

// TestListenTCPShutdownForceClose covers shutdown after the grace period.
func TestListenTCPShutdownForceClose(t *testing.T) {
	prevGrace, prevIdle := tcpShutdownGrace, tcpIdleTimeout
	tcpShutdownGrace = 100 * time.Millisecond
	tcpIdleTimeout = 30 * time.Second
	t.Cleanup(func() { tcpShutdownGrace = prevGrace; tcpIdleTimeout = prevIdle })

	_, edState := newCertState(t)
	initialAccepted := statsTCPAccepted.Load()
	p, done, cancel := startListenTCP(t, edState, nil)

	conn := dialTCP(t, p)
	defer func() { _ = conn.Close() }()
	// poll until accept counter advances. The brief grace below covers the gap
	// before live.add(c) lands
	deadline := time.Now().Add(time.Second)
	for statsTCPAccepted.Load() <= initialAccepted && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(5 * time.Millisecond)

	cancelStart := time.Now()
	cancel()
	if err := awaitTest(t, done, 5*time.Second, "listenTCP forced shutdown"); err != nil {
		t.Fatalf("listenTCP: %v", err)
	}
	elapsed := time.Since(cancelStart)
	// Must exit well inside tcpIdleTimeout
	if elapsed > 2*time.Second {
		t.Fatalf("shutdown took %s, force-close path not taken (grace=%s, idle=%s)",
			elapsed, tcpShutdownGrace, tcpIdleTimeout)
	}
}

// TestListenTCPRejectsAtMaxConnections covers the connection cap.
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

	// First conn occupies the only slot, so hold it idle so it stays counted
	hold := dialTCP(t, p)
	defer func() { _ = hold.Close() }()
	deadline := time.Now().Add(time.Second)
	for statsTCPAccepted.Load() <= startAccepted && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	// brief settle so live.add lands before the second dial
	time.Sleep(10 * time.Millisecond)

	// Second conn must be rejected. The listener accepts then closes
	rej, err := net.DialTimeout("tcp", net.JoinHostPort("::1", strconv.Itoa(p)), time.Second)
	if err != nil {
		t.Fatalf("dial second: %v", err)
	}
	defer func() { _ = rej.Close() }()
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
	if err := awaitTest(t, done, 5*time.Second, "listenTCP shutdown"); err != nil {
		t.Fatalf("listenTCP: %v", err)
	}
}

// TestListenTCPPerFamily covers the OpenBSD layout that binds one listener per
// address family.
func TestListenTCPPerFamily(t *testing.T) {
	disableGrease(t)
	prev := listenNetworks
	listenNetworks = func(network, _ string) []string {
		return []string{network + "4", network + "6"}
	}
	t.Cleanup(func() { listenNetworks = prev })

	rootPK, edState := newCertState(t)
	p, done, cancel := startListenTCP(t, edState, nil)
	srv := protocol.ComputeSRV(rootPK)

	// both families must answer, not just the one a wildcard bind would pick
	for _, host := range []string{"127.0.0.1", "::1"} {
		nonce, req, err := protocol.CreateRequest([]protocol.Version{protocol.VersionDraft12}, rand.Reader, srv)
		if err != nil {
			t.Fatalf("CreateRequest: %v", err)
		}
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(p)), time.Second)
		if err != nil {
			t.Fatalf("dial %s: %v", host, err)
		}
		reply := tcpRoundTrip(t, conn, req)
		_ = conn.Close()
		if _, _, err := protocol.VerifyReply([]protocol.Version{protocol.VersionDraft12}, reply, rootPK, nonce, req); err != nil {
			t.Fatalf("VerifyReply %s: %v", host, err)
		}
	}

	cancel()
	if err := awaitTest(t, done, 6*time.Second, "listenTCP shutdown"); err != nil {
		t.Fatalf("listenTCP: %v", err)
	}
}
