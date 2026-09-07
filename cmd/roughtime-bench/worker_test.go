// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/tannerryan/roughtime"
	"github.com/tannerryan/roughtime/protocol"
)

// benchIdentity returns an Ed25519 root and active delegation for fixtures.
func benchIdentity(t *testing.T) ([]byte, *protocol.Certificate) {
	t.Helper()
	rootPK, rootSK, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("root key: %v", err)
	}
	_, onlineSK, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("online key: %v", err)
	}
	now := time.Now()
	cert, err := protocol.NewCertificate(now.Add(-time.Hour), now.Add(time.Hour), onlineSK, rootSK)
	if err != nil {
		t.Fatalf("certificate: %v", err)
	}
	return rootPK, cert
}

// benchConfigFor returns the common worker configuration for pk.
func benchConfigFor(transport, address string, pk []byte) benchConfig {
	cfg := benchConfig{
		addr:      address,
		transport: transport,
		rootPK:    bytes.Clone(pk),
		srv:       protocol.ComputeSRV(pk),
		versions:  roughtime.VersionsForScheme(roughtime.SchemeEd25519),
		timeout:   time.Hour,
		latencies: &latencyReservoir{},
	}
	return cfg
}

// readTCPRequest reads one framed benchmark request.
func readTCPRequest(conn net.Conn) ([]byte, error) {
	var hdr [protocol.PacketHeaderSize]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, err
	}
	bodyLen, err := protocol.ParsePacketHeader(hdr[:])
	if err != nil {
		return nil, err
	}
	pkt := make([]byte, protocol.PacketHeaderSize+int(bodyLen))
	copy(pkt, hdr[:])
	if _, err := io.ReadFull(conn, pkt[protocol.PacketHeaderSize:]); err != nil {
		return nil, err
	}
	return pkt, nil
}

// packetHeader returns a ROUGHTIM header declaring bodyLen bytes.
func packetHeader(bodyLen uint32) []byte {
	hdr := make([]byte, protocol.PacketHeaderSize)
	copy(hdr, "ROUGHTIM")
	binary.LittleEndian.PutUint32(hdr[8:], bodyLen)
	return hdr
}

// encodeReplyMessage is the small test-side canonical encoder needed to add an
// unsigned extension tag to an otherwise signed response.
func encodeReplyMessage(msg map[uint32][]byte) []byte {
	tags := make([]uint32, 0, len(msg))
	for tag := range msg {
		tags = append(tags, tag)
	}
	sort.Slice(tags, func(i, j int) bool { return tags[i] < tags[j] })
	n := len(tags)
	headerLen := 4 + 4*(n-1) + 4*n
	valueLen := 0
	for _, tag := range tags {
		valueLen += len(msg[tag])
	}
	body := make([]byte, headerLen+valueLen)
	binary.LittleEndian.PutUint32(body, uint32(n))
	offset := 0
	for i := 1; i < n; i++ {
		offset += len(msg[tags[i-1]])
		binary.LittleEndian.PutUint32(body[4+4*(i-1):], uint32(offset))
	}
	tagBase := 4 + 4*(n-1)
	pos := headerLen
	for i, tag := range tags {
		binary.LittleEndian.PutUint32(body[tagBase+4*i:], tag)
		copy(body[pos:], msg[tag])
		pos += len(msg[tag])
	}
	return append(packetHeader(uint32(len(body))), body...)
}

// paddedSignedReply returns a valid response larger than request by adding an
// ignored, unsigned extension tag at the top level.
func paddedSignedReply(request []byte, cert *protocol.Certificate) ([]byte, error) {
	req, err := protocol.ParseRequest(request)
	if err != nil {
		return nil, err
	}
	replies, err := protocol.CreateReplies(protocol.VersionDraft12, []protocol.Request{*req}, time.Now(), time.Second, cert)
	if err != nil {
		return nil, err
	}
	msg, err := protocol.Decode(replies[0][protocol.PacketHeaderSize:])
	if err != nil {
		return nil, err
	}
	msg[0xfefefefe] = make([]byte, len(request)+256)
	return encodeReplyMessage(msg), nil
}

// waitResult waits briefly for a worker or fake peer result.
func waitResult(t *testing.T, name string, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(2 * time.Second):
		t.Fatalf("%s did not stop promptly", name)
		return nil
	}
}

// TestWorkerTCPAcceptsLargerSignedReply covers the TCP/UDP policy split with
// verification both disabled and enabled.
func TestWorkerTCPAcceptsLargerSignedReply(t *testing.T) {
	for _, verify := range []bool{false, true} {
		t.Run(fmt.Sprintf("verify=%t", verify), func(t *testing.T) {
			pk, cert := benchIdentity(t)
			lis, err := net.Listen("tcp", "[::1]:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = lis.Close() }()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			serverErr := make(chan error, 1)
			go func() {
				conn, err := lis.Accept()
				if err != nil {
					serverErr <- err
					return
				}
				defer func() { _ = conn.Close() }()
				request, err := readTCPRequest(conn)
				if err != nil {
					serverErr <- err
					return
				}
				reply, err := paddedSignedReply(request, cert)
				if err != nil {
					serverErr <- err
					return
				}
				if len(reply) <= len(request) {
					serverErr <- fmt.Errorf("reply length %d <= request %d", len(reply), len(request))
					return
				}
				if _, err := conn.Write(reply); err != nil {
					serverErr <- err
					return
				}
				// Receiving the next request proves the first response was
				// fully processed before cancellation.
				if _, err := readTCPRequest(conn); err != nil {
					serverErr <- err
					return
				}
				cancel()
				serverErr <- nil
			}()

			cfg := benchConfigFor("tcp", lis.Addr().String(), pk)
			cfg.verify = verify
			var out workerResult
			if err := workerTCP(ctx, cfg, &out, time.Time{}); err != nil {
				t.Fatalf("workerTCP: %v", err)
			}
			if err := waitResult(t, "fake peer", serverErr); err != nil {
				t.Fatalf("server: %v", err)
			}
			if out.successes != 1 || out.received != 1 || out.errAmp != 0 {
				t.Fatalf("result = %+v, want one accepted larger TCP response", out)
			}
		})
	}
}

// TestWorkerUDPOversizeDetection covers request-sized acceptance, the single
// sentinel byte, and truncation of a much larger datagram.
func TestWorkerUDPOversizeDetection(t *testing.T) {
	pk, _ := benchIdentity(t)
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	serverErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 65535)
		for i := range 5 {
			n, peer, err := conn.ReadFromUDP(buf)
			if err != nil {
				serverErr <- err
				return
			}
			if i == 4 {
				cancel()
				serverErr <- nil
				return
			}
			sizes := []int{n - 1, n, n + 1, n + 4096}
			if _, err := conn.WriteToUDP(make([]byte, sizes[i]), peer); err != nil {
				serverErr <- err
				return
			}
		}
	}()
	cfg := benchConfigFor("udp", conn.LocalAddr().String(), pk)
	cfg.udpAddr = conn.LocalAddr().(*net.UDPAddr)
	var out workerResult
	if err := workerUDP(ctx, cfg, &out, time.Time{}); err != nil {
		t.Fatalf("workerUDP: %v", err)
	}
	if err := waitResult(t, "fake peer", serverErr); err != nil {
		t.Fatalf("server: %v", err)
	}
	if out.received != 4 || out.successes != 2 || out.errAmp != 2 {
		t.Fatalf("result = %+v, want received=4 successes=2 UDP-oversize=2", out)
	}
}

// TestWorkersCancelSilentIO ensures cancellation closes a live socket rather
// than waiting for the one-hour operation timeout.
func TestWorkersCancelSilentIO(t *testing.T) {
	t.Run("udp", func(t *testing.T) {
		pk, _ := benchIdentity(t)
		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		ready := make(chan error, 1)
		go func() {
			buf := make([]byte, 8192)
			_, _, err := conn.ReadFromUDP(buf)
			ready <- err
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cfg := benchConfigFor("udp", conn.LocalAddr().String(), pk)
		cfg.udpAddr = conn.LocalAddr().(*net.UDPAddr)
		done := make(chan error, 1)
		go func() { done <- workerUDP(ctx, cfg, new(workerResult), time.Time{}) }()
		select {
		case err := <-ready:
			if err != nil {
				t.Fatalf("fake UDP peer: %v", err)
			}
		case err := <-done:
			t.Fatalf("workerUDP stopped before receiving a request: %v", err)
		case <-ctx.Done():
			t.Fatalf("waiting for UDP request: %v", ctx.Err())
		}
		start := time.Now()
		cancel()
		if err := waitResult(t, "workerUDP", done); err != nil {
			t.Fatalf("workerUDP: %v", err)
		}
		if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
			t.Fatalf("UDP cancellation took %s", elapsed)
		}
	})

	t.Run("tcp", func(t *testing.T) {
		pk, _ := benchIdentity(t)
		lis, err := net.Listen("tcp", "[::1]:0")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = lis.Close() }()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		peerCtx, releasePeer := context.WithCancel(context.Background())
		defer releasePeer()
		ready := make(chan error, 1)
		peerDone := make(chan error, 1)
		go func() {
			conn, err := lis.Accept()
			if err != nil {
				ready <- err
				peerDone <- err
				return
			}
			defer func() { _ = conn.Close() }()
			_, err = readTCPRequest(conn)
			ready <- err
			if err != nil {
				peerDone <- err
				return
			}
			<-peerCtx.Done()
			peerDone <- nil
		}()
		cfg := benchConfigFor("tcp", lis.Addr().String(), pk)
		done := make(chan error, 1)
		go func() { done <- workerTCP(ctx, cfg, new(workerResult), time.Time{}) }()
		select {
		case err := <-ready:
			if err != nil {
				t.Fatalf("fake TCP peer: %v", err)
			}
		case err := <-done:
			t.Fatalf("workerTCP stopped before sending a request: %v", err)
		case <-ctx.Done():
			t.Fatalf("waiting for TCP request: %v", ctx.Err())
		}
		start := time.Now()
		cancel()
		if err := waitResult(t, "workerTCP", done); err != nil {
			t.Fatalf("workerTCP: %v", err)
		}
		releasePeer()
		if err := waitResult(t, "fake TCP peer", peerDone); err != nil {
			t.Fatalf("fake TCP peer: %v", err)
		}
		if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
			t.Fatalf("TCP cancellation took %s", elapsed)
		}
	})
}

// TestWorkerUDPReconnectCancellationHook proves that the cancellation callback
// moves to a replacement UDP socket after a timeout.
func TestWorkerUDPReconnectCancellationHook(t *testing.T) {
	pk, _ := benchIdentity(t)
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	second := make(chan error, 1)
	go func() {
		buf := make([]byte, 8192)
		for i := range 2 {
			_, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				second <- err
				return
			}
			if i == 1 {
				second <- nil
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cfg := benchConfigFor("udp", conn.LocalAddr().String(), pk)
	cfg.udpAddr = conn.LocalAddr().(*net.UDPAddr)
	cfg.timeout = 500 * time.Millisecond
	out := new(workerResult)
	done := make(chan error, 1)
	go func() { done <- workerUDP(ctx, cfg, out, time.Time{}) }()
	select {
	case err := <-second:
		if err != nil {
			t.Fatalf("fake UDP peer: %v", err)
		}
	case err := <-done:
		t.Fatalf("workerUDP stopped before reconnecting: %v", err)
	case <-ctx.Done():
		t.Fatalf("waiting for UDP reconnect: %v", ctx.Err())
	}
	start := time.Now()
	cancel()
	if err := waitResult(t, "workerUDP", done); err != nil {
		t.Fatalf("workerUDP: %v", err)
	}
	if out.timeouts != 1 {
		t.Fatalf("timeouts = %d, want 1 before reconnect", out.timeouts)
	}
	if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
		t.Fatalf("replacement UDP connection ignored cancellation for %s", elapsed)
	}
}

// TestWorkerTCPFrameBoundAndReconnectHook retains the 16 KiB body bound and
// proves cancellation follows the replacement TCP connection.
func TestWorkerTCPFrameBoundAndReconnectHook(t *testing.T) {
	pk, _ := benchIdentity(t)
	lis, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lis.Close() }()
	second := make(chan struct{})
	serverErr := make(chan error, 1)
	peerCtx, releasePeer := context.WithCancel(context.Background())
	defer releasePeer()
	go func() {
		first, err := lis.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer func() { _ = first.Close() }()
		if _, err := readTCPRequest(first); err != nil {
			serverErr <- err
			return
		}
		_, err = first.Write(packetHeader(protocol.MaxTCPReplyBody + 1))
		_ = first.Close()
		if err != nil {
			serverErr <- err
			return
		}
		replacement, err := lis.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer func() { _ = replacement.Close() }()
		if _, err := readTCPRequest(replacement); err != nil {
			serverErr <- err
			return
		}
		close(second)
		<-peerCtx.Done()
		serverErr <- nil
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cfg := benchConfigFor("tcp", lis.Addr().String(), pk)
	out := new(workerResult)
	done := make(chan error, 1)
	go func() { done <- workerTCP(ctx, cfg, out, time.Time{}) }()
	select {
	case <-second:
	case err := <-done:
		t.Fatalf("workerTCP stopped before reconnecting: %v", err)
	case <-ctx.Done():
		t.Fatalf("waiting for TCP reconnect: %v", ctx.Err())
	}
	start := time.Now()
	cancel()
	if err := waitResult(t, "workerTCP", done); err != nil {
		t.Fatalf("workerTCP: %v", err)
	}
	releasePeer()
	if err := waitResult(t, "fake peer", serverErr); err != nil {
		t.Fatalf("server: %v", err)
	}
	if out.errRead != 1 {
		t.Fatalf("read errors = %d, want oversized-frame error", out.errRead)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("replacement TCP connection ignored cancellation for %s", elapsed)
	}
}

// TestRunWorkersFailsFastWithCause makes one worker's reconnect fail while its
// sibling is blocked, requiring cancellation to wake the sibling immediately.
func TestRunWorkersFailsFastWithCause(t *testing.T) {
	pk, _ := benchIdentity(t)
	lis, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lis.Close() }()
	serverErr := make(chan error, 1)
	go func() {
		conns := make([]net.Conn, 0, 2)
		defer func() {
			for _, conn := range conns {
				_ = conn.Close()
			}
		}()
		for range 2 {
			conn, err := lis.Accept()
			if err != nil {
				serverErr <- err
				return
			}
			conns = append(conns, conn)
		}
		for _, conn := range conns {
			if _, err := readTCPRequest(conn); err != nil {
				serverErr <- err
				return
			}
		}
		_ = lis.Close()
		if _, err := conns[1].Write(packetHeader(protocol.MaxTCPReplyBody + 1)); err != nil {
			serverErr <- err
			return
		}
		serverErr <- nil
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cfg := benchConfigFor("tcp", lis.Addr().String(), pk)
	start := time.Now()
	results, _, err := runWorkers(ctx, cfg, 2, time.Time{})
	if err == nil || !strings.Contains(err.Error(), "redial TCP") {
		t.Fatalf("runWorkers error = %v, want concrete reconnect cause", err)
	}
	if results != nil {
		t.Fatal("fatal run returned partial results")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("fatal worker did not cancel sibling promptly: %s", elapsed)
	}
	if err := waitResult(t, "fake peer", serverErr); err != nil {
		t.Fatalf("server: %v", err)
	}
}
