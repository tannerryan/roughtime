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

// staticUDPResolver supplies deterministic address and service results.
type staticUDPResolver struct {
	ips        []net.IPAddr
	port       int
	lookupHost string
	lookupNet  string
	lookupPort string
}

func (r *staticUDPResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	r.lookupHost = host
	return append([]net.IPAddr(nil), r.ips...), nil
}

func (r *staticUDPResolver) LookupPort(_ context.Context, network, service string) (int, error) {
	r.lookupNet = network
	r.lookupPort = service
	return r.port, nil
}

// udpEcho starts a loopback UDP listener that echoes datagrams.
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

// tcpEchoFramed starts a TCP listener that runs handler on each ROUGHTIM-framed
// request.
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
				defer func() { _ = c.Close() }()
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

// TestRoundTripUDP covers a UDP exchange.
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
		t.Fatalf("rtt = %s, want > 0", rtt)
	}
	if localNow.IsZero() {
		t.Fatal("localNow unset")
	}
}

// TestRoundTripUDPTimeout covers UDP deadlines.
func TestRoundTripUDPTimeout(t *testing.T) {
	// blackhole: valid bound socket that deliberately does not read
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	addr := conn.LocalAddr().String()

	start := time.Now()
	_, _, _, err = RoundTripUDP(context.Background(), addr, []byte("hi"), 50*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if elapsed := time.Since(start); elapsed < 25*time.Millisecond || elapsed > time.Second {
		t.Fatalf("RoundTripUDP timeout took %s", elapsed)
	}
}

// TestRoundTripUDPDNSDeadlineAndCancellation covers the whole-operation
// deadline and caller cancellation while the hostname is being resolved.
func TestRoundTripUDPDNSDeadlineAndCancellation(t *testing.T) {
	originalResolver := net.DefaultResolver
	t.Cleanup(func() { net.DefaultResolver = originalResolver })

	for _, tc := range []struct {
		name    string
		timeout time.Duration
		cancel  bool
		wantErr error
	}{
		{"timeout", 40 * time.Millisecond, false, context.DeadlineExceeded},
		{"cancellation", 5 * time.Second, true, context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entered := make(chan struct{}, 1)
			net.DefaultResolver = &net.Resolver{
				PreferGo:     true,
				StrictErrors: true,
				Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
					select {
					case entered <- struct{}{}:
					default:
					}
					<-ctx.Done()
					return nil, ctx.Err()
				},
			}

			ctx, cancel := context.WithCancel(context.Background())
			if tc.cancel {
				time.AfterFunc(40*time.Millisecond, cancel)
			} else {
				defer cancel()
			}
			start := time.Now()
			_, _, _, err := RoundTripUDP(ctx, "resolver-test.invalid:2002", []byte("hi"), tc.timeout)
			elapsed := time.Since(start)
			cancel()

			select {
			case <-entered:
			default:
				t.Fatal("controlled resolver was not used")
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("RoundTripUDP error = %v, want %v", err, tc.wantErr)
			}
			if elapsed > 500*time.Millisecond {
				t.Fatalf("RoundTripUDP took %s during DNS %s", elapsed, tc.name)
			}
		})
	}
}

// TestResolveUDPAddrPrefersIPv4 deterministically preserves ResolveUDPAddr's
// IPv4 preference for a dual-stack hostname, regardless of DNS result order.
func TestResolveUDPAddrPrefersIPv4(t *testing.T) {
	resolver := &staticUDPResolver{
		ips: []net.IPAddr{
			{IP: net.ParseIP("2001:db8::1")},
			{IP: net.ParseIP("192.0.2.10")},
			{IP: net.ParseIP("192.0.2.11")},
		},
		port: 2002,
	}
	got, err := resolveUDPAddr(context.Background(), resolver, "dual.example:roughtime")
	if err != nil {
		t.Fatalf("resolveUDPAddr: %v", err)
	}
	if want := net.ParseIP("192.0.2.10"); !got.IP.Equal(want) {
		t.Fatalf("resolved IP = %v, want first IPv4 %v", got.IP, want)
	}
	if got.Port != 2002 || resolver.lookupHost != "dual.example" ||
		resolver.lookupNet != "udp" || resolver.lookupPort != "roughtime" {
		t.Fatalf("resolved=%v lookups=(%q,%q,%q)", got, resolver.lookupHost, resolver.lookupNet, resolver.lookupPort)
	}
}

// TestResolveUDPAddrIPv6Fallback covers an IPv6-only hostname and preserves its
// scope zone and numeric service.
func TestResolveUDPAddrIPv6Fallback(t *testing.T) {
	resolver := &staticUDPResolver{
		ips: []net.IPAddr{
			{IP: net.ParseIP("2001:db8::2"), Zone: "test-zone"},
			{IP: net.ParseIP("2001:db8::3")},
		},
		port: 2002,
	}
	got, err := resolveUDPAddr(context.Background(), resolver, "v6.example:2002")
	if err != nil {
		t.Fatalf("resolveUDPAddr: %v", err)
	}
	if want := net.ParseIP("2001:db8::2"); !got.IP.Equal(want) {
		t.Fatalf("resolved IP = %v, want first IPv6 %v", got.IP, want)
	}
	if got.Zone != "test-zone" || resolver.lookupPort != "2002" {
		t.Fatalf("resolved=%v service lookup=%q", got, resolver.lookupPort)
	}
}

// TestResolveUDPAddrIPv6LiteralPreservesZone covers the bracketed-literal path
// and its standard-library IPv6 preference.
func TestResolveUDPAddrIPv6LiteralPreservesZone(t *testing.T) {
	resolver := &staticUDPResolver{
		// A real resolver returns only the literal. Including IPv4 first proves
		// the bracketed-address family preference itself.
		ips: []net.IPAddr{
			{IP: net.ParseIP("192.0.2.10")},
			{IP: net.ParseIP("fe80::1"), Zone: "lo0"},
		},
		port: 2002,
	}
	got, err := resolveUDPAddr(context.Background(), resolver, "[fe80::1%lo0]:2002")
	if err != nil {
		t.Fatalf("resolveUDPAddr: %v", err)
	}
	if !got.IP.Equal(net.ParseIP("fe80::1")) || got.Zone != "lo0" {
		t.Fatalf("resolved literal = %v, want [fe80::1%%lo0]:2002", got)
	}
	if resolver.lookupHost != "fe80::1%lo0" {
		t.Fatalf("literal lookup host = %q", resolver.lookupHost)
	}
}

// TestRoundTripTCP covers a framed TCP exchange.
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

// TestRoundTripTCPRejectsBadMagic covers invalid reply framing.
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
		defer func() { _ = conn.Close() }()
		var scratch [64]byte
		_, _ = conn.Read(scratch[:])
		_, _ = conn.Write([]byte("NOTMAGIC\x00\x00\x00\x00"))
	}()

	_, _, _, err = RoundTripTCP(context.Background(), ln.Addr().String(), []byte("x"), time.Second)
	if err == nil || !strings.Contains(err.Error(), "header") {
		t.Fatalf("RoundTripTCP err = %v, want header error", err)
	}
}

// TestRoundTripTCPHonorsTotalTimeout covers the whole-operation deadline.
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
	// allow 1.5× for scheduling slack
	if elapsed > 3*budget/2 {
		t.Fatalf("RoundTripTCP took %s, want ≤ 1.5×%s (single shared deadline)", elapsed, budget)
	}
}

// TestRoundTripTCPRejectsOversizeBodyLen covers the reply-size limit.
func TestRoundTripTCPRejectsOversizeBodyLen(t *testing.T) {
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
		defer func() { _ = conn.Close() }()
		var scratch [64]byte
		_, _ = conn.Read(scratch[:])
		var hdr [PacketHeaderSize]byte
		copy(hdr[:8], []byte("ROUGHTIM"))
		binary.LittleEndian.PutUint32(hdr[8:], uint32(MaxTCPReplyBody+1))
		_, _ = conn.Write(hdr[:])
	}()

	_, _, _, err = RoundTripTCP(context.Background(), ln.Addr().String(), []byte("x"), time.Second)
	if err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Fatalf("RoundTripTCP err = %v, want length-range error", err)
	}
}

// TestRoundTripTCPPartialBody covers truncated reply bodies.
func TestRoundTripTCPPartialBody(t *testing.T) {
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
		defer func() { _ = conn.Close() }()
		var scratch [64]byte
		_, _ = conn.Read(scratch[:])
		var hdr [PacketHeaderSize]byte
		copy(hdr[:8], []byte("ROUGHTIM"))
		binary.LittleEndian.PutUint32(hdr[8:], 64)
		_, _ = conn.Write(hdr[:])
		_, _ = conn.Write(make([]byte, 8))
	}()

	_, _, _, err = RoundTripTCP(context.Background(), ln.Addr().String(), []byte("x"), time.Second)
	if err == nil || !strings.Contains(err.Error(), "reading body") {
		t.Fatalf("RoundTripTCP err = %v, want body-read error", err)
	}
}

// TestRoundTripContextCancel covers caller cancellation during UDP and TCP I/O.
func TestRoundTripContextCancel(t *testing.T) {
	for _, tc := range []struct {
		name      string
		network   string
		roundTrip func(context.Context, string, []byte, time.Duration) ([]byte, time.Duration, time.Time, error)
	}{
		{"UDP", "udp", RoundTripUDP},
		{"TCP", "tcp", RoundTripTCP},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := []byte("hi")
			requestSeen := make(chan struct{})
			serverDone := make(chan struct{})
			serverCtx, stopServer := context.WithCancel(context.Background())
			var address string
			var closeServer func()

			switch tc.network {
			case "udp":
				conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
				if err != nil {
					t.Fatal(err)
				}
				address = conn.LocalAddr().String()
				closeServer = func() { _ = conn.Close() }
				go func() {
					defer close(serverDone)
					buf := make([]byte, len(request))
					if _, _, err := conn.ReadFromUDP(buf); err == nil {
						close(requestSeen)
					}
				}()
			case "tcp":
				ln, err := net.Listen("tcp", "[::1]:0")
				if err != nil {
					t.Fatal(err)
				}
				address = ln.Addr().String()
				closeServer = func() { _ = ln.Close() }
				go func() {
					defer close(serverDone)
					conn, err := ln.Accept()
					if err != nil {
						return
					}
					defer func() { _ = conn.Close() }()
					stopClose := context.AfterFunc(serverCtx, func() { _ = conn.Close() })
					defer stopClose()
					buf := make([]byte, len(request))
					if _, err := io.ReadFull(conn, buf); err != nil {
						return
					}
					close(requestSeen)
					var scratch [1]byte
					_, _ = conn.Read(scratch[:])
				}()
			}

			t.Cleanup(func() {
				stopServer()
				closeServer()
				select {
				case <-serverDone:
				case <-time.After(2 * time.Second):
					t.Errorf("%s server did not stop", tc.name)
				}
			})

			ctx, cancel := context.WithCancel(context.Background())
			result := make(chan error, 1)
			go func() {
				defer close(result)
				_, _, _, err := tc.roundTrip(ctx, address, request, 5*time.Second)
				result <- err
			}()
			t.Cleanup(func() {
				cancel()
				select {
				case <-result:
				case <-time.After(2 * time.Second):
					t.Errorf("%s round trip did not stop", tc.name)
				}
			})

			select {
			case <-requestSeen:
			case <-time.After(2 * time.Second):
				t.Fatal("server did not receive request")
			}
			cancel()
			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("RoundTrip%s error = %v, want context.Canceled", tc.name, err)
				}
			case <-time.After(2 * time.Second):
				t.Fatalf("RoundTrip%s did not stop after cancellation", tc.name)
			}
		})
	}
}
