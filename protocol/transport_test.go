// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// udpEcho spins up a loopback UDP listener that echoes datagrams until ctx is
// cancelled.
func udpEcho(t *testing.T, ctx context.Context) string {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		t.Fatalf("udp listen: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buf := make([]byte, 65535)
		for ctx.Err() == nil {
			_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, peer, err := conn.ReadFromUDP(buf)
			if err != nil {
				continue
			}
			_, _ = conn.WriteToUDP(buf[:n], peer)
		}
	}()
	return conn.LocalAddr().String()
}

// tcpEchoFramed accepts one ROUGHTIM-framed request and echoes it back until
// ctx is cancelled.
func tcpEchoFramed(t *testing.T, ctx context.Context, handler func(req []byte) []byte) string {
	t.Helper()
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Fatalf("tcp listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				var hdr [PacketHeaderSize]byte
				if _, err := io.ReadFull(c, hdr[:]); err != nil {
					return
				}
				n, err := ParsePacketHeader(hdr[:])
				if err != nil {
					return
				}
				body := make([]byte, n)
				if _, err := io.ReadFull(c, body); err != nil {
					return
				}
				pkt := append(hdr[:0:PacketHeaderSize], hdr[:]...)
				pkt = append(pkt, body...)
				_, _ = c.Write(handler(pkt))
			}(conn)
		}
	}()
	return ln.Addr().String()
}

// TestRoundTripUDP verifies the happy-path exchange against a loopback echo
// server.
func TestRoundTripUDP(t *testing.T) {
	addr := udpEcho(t, t.Context())

	payload := []byte("hello roughtime over udp")
	reply, rtt, localNow, err := RoundTripUDP(context.Background(), addr, payload, time.Second)
	if err != nil {
		t.Fatalf("RoundTripUDP: %v", err)
	}
	if !bytes.Equal(reply, payload) {
		t.Fatalf("echo mismatch: got %q want %q", reply, payload)
	}
	if rtt <= 0 {
		t.Fatalf("rtt = %s; want > 0", rtt)
	}
	if localNow.IsZero() {
		t.Fatal("localNow unset")
	}
}

// TestRoundTripUDPTimeout confirms the timeout path surfaces an error.
func TestRoundTripUDPTimeout(t *testing.T) {
	// blackhole: valid address, closed socket
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	addr := conn.LocalAddr().String()
	_ = conn.Close()

	_, _, _, err = RoundTripUDP(context.Background(), addr, []byte("hi"), 50*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

// TestRoundTripTCP verifies a ROUGHTIM-framed exchange returns the reply
// intact.
func TestRoundTripTCP(t *testing.T) {
	addr := tcpEchoFramed(t, t.Context(), func(req []byte) []byte { return req })

	var req bytes.Buffer
	var hdr [PacketHeaderSize]byte
	copy(hdr[:8], []byte("ROUGHTIM"))
	body := []byte("roughtime over tcp")
	binary.LittleEndian.PutUint32(hdr[8:], uint32(len(body)))
	req.Write(hdr[:])
	req.Write(body)

	reply, rtt, localNow, err := RoundTripTCP(context.Background(), addr, req.Bytes(), time.Second)
	if err != nil {
		t.Fatalf("RoundTripTCP: %v", err)
	}
	if !bytes.Equal(reply, req.Bytes()) {
		t.Fatalf("reply != request: %q vs %q", reply, req.Bytes())
	}
	if rtt <= 0 || localNow.IsZero() {
		t.Fatalf("rtt=%s localNow=%v", rtt, localNow)
	}
}

// TestRoundTripTCPRejectsBadMagic confirms a non-ROUGHTIM reply surfaces an
// error.
func TestRoundTripTCPRejectsBadMagic(t *testing.T) {
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// consume request, return garbage header
		var scratch [64]byte
		_, _ = conn.Read(scratch[:])
		_, _ = conn.Write([]byte("NOTMAGIC\x00\x00\x00\x00"))
	}()

	_, _, _, err = RoundTripTCP(context.Background(), ln.Addr().String(), []byte("x"), time.Second)
	if err == nil || !strings.Contains(err.Error(), "header") {
		t.Fatalf("RoundTripTCP: err=%v; want header error", err)
	}
}

// TestRoundTripTCPPeerClosedNoReply confirms a peer closing without replying
// surfaces ErrPeerClosedNoReply (the signal for unsupported
// version/scheme/transport).
func TestRoundTripTCPPeerClosedNoReply(t *testing.T) {
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		// drain request, close without reply (mirrors unsupported version)
		var scratch [4096]byte
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		_, _ = conn.Read(scratch[:])
		_ = conn.Close()
	}()

	_, _, _, err = RoundTripTCP(context.Background(), ln.Addr().String(), []byte("x"), time.Second)
	if !errors.Is(err, ErrPeerClosedNoReply) {
		t.Fatalf("RoundTripTCP: err=%v; want ErrPeerClosedNoReply", err)
	}
}

// TestRoundTripTCPHonorsTotalTimeout confirms dial + r/w share one deadline so
// a non-responsive peer cannot extend the budget beyond timeout.
func TestRoundTripTCPHonorsTotalTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		// hold open without responding so read blocks
		<-t.Context().Done()
		_ = conn.Close()
	}()

	const budget = 200 * time.Millisecond
	start := time.Now()
	_, _, _, err = RoundTripTCP(context.Background(), ln.Addr().String(), []byte("x"), budget)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected timeout error from non-responsive peer")
	}
	// allow 1.5× for scheduling slack; reject old 2× behavior
	if elapsed > 3*budget/2 {
		t.Fatalf("RoundTripTCP took %s; want ≤ 1.5×%s (single shared deadline)", elapsed, budget)
	}
}

// TestRoundTripUDPContextCancel confirms cancelling ctx unblocks the read.
func TestRoundTripUDPContextCancel(t *testing.T) {
	// blackholed address; read would otherwise block for the full timeout
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	addr := conn.LocalAddr().String()
	_ = conn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	_, _, _, err = RoundTripUDP(ctx, addr, []byte("hi"), 5*time.Second)
	if err == nil {
		t.Fatal("expected cancel error")
	}
	if errors.Is(err, context.Canceled) || time.Since(start) < 5*time.Second {
		return
	}
	t.Fatalf("took %s; expected ctx cancel to unblock sooner", time.Since(start))
}
