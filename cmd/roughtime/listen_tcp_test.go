// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

//go:build unix

package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tannerryan/roughtime/protocol"
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
	select {
	case <-done:
	case <-time.After(6 * time.Second):
		t.Fatal("listenTCP did not exit after cancel")
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
	select {
	case <-done:
	case <-time.After(6 * time.Second):
		t.Fatal("listenTCP did not exit after cancel")
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
	<-done
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
	<-done
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
	<-done
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
	<-done
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
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("listenTCP did not exit after cancel")
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
	select {
	case <-done:
	case <-time.After(6 * time.Second):
		t.Fatal("listenTCP did not exit after cancel")
	}
}
