// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// MaxUDPReply is the maximum UDP datagram size accepted as a reply.
const MaxUDPReply = 65535

// MaxTCPReplyBody caps the declared body length of a TCP reply.
const MaxTCPReplyBody = 16 * 1024

// ErrPeerClosedNoReply is returned by [RoundTripTCP] when the peer closes
// before writing any reply.
var ErrPeerClosedNoReply = errors.New("peer closed connection with no reply (server may not support the requested version, scheme, or transport)")

// udpAddressResolver is the context-aware subset of net.Resolver needed to
// preserve ResolveUDPAddr's address selection while bounding DNS work.
type udpAddressResolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
	LookupPort(context.Context, string, string) (int, error)
}

// resolveUDPAddr is the context-aware equivalent of ResolveUDPAddr("udp",
// address). Like the standard library's addrList.forResolve, it prefers IPv4
// for hostnames and IPv6 for bracketed IPv6 literals, falling back to the first
// result when the preferred family is absent.
func resolveUDPAddr(ctx context.Context, resolver udpAddressResolver, address string) (*net.UDPAddr, error) {
	if address == "" {
		return &net.UDPAddr{}, nil
	}
	host, service, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := resolver.LookupPort(ctx, "udp", service)
	if err != nil {
		return nil, err
	}
	if host == "" {
		return &net.UDPAddr{Port: port}, nil
	}
	ips, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, &net.DNSError{Err: "no suitable address", Name: host}
	}

	selected := ips[0]
	wantIPv6 := strings.Contains(address, "[")
	for _, ip := range ips {
		isIPv4 := ip.IP.To4() != nil
		if isIPv4 != wantIPv6 {
			selected = ip
			break
		}
	}
	return &net.UDPAddr{IP: selected.IP, Port: port, Zone: selected.Zone}, nil
}

// RoundTripUDP sends one Roughtime request over UDP and returns the reply, RTT,
// and receipt time. timeout bounds name resolution, dialing, and I/O together.
func RoundTripUDP(ctx context.Context, address string, request []byte, timeout time.Duration) (reply []byte, rtt time.Duration, localNow time.Time, err error) {
	deadline := time.Now().Add(timeout)
	dialCtx, dialCancel := context.WithDeadline(ctx, deadline)
	defer dialCancel()
	raddr, err := resolveUDPAddr(dialCtx, net.DefaultResolver, address)
	if err != nil {
		return nil, 0, time.Time{}, fmt.Errorf("resolving %s: %w", address, err)
	}
	var dialer net.Dialer
	conn, err := dialer.DialContext(dialCtx, "udp", raddr.String())
	if err != nil {
		return nil, 0, time.Time{}, fmt.Errorf("dialing %s: %w", address, err)
	}
	defer func() { _ = conn.Close() }()

	stopCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCancel()

	if err := conn.SetDeadline(deadline); err != nil {
		return nil, 0, time.Time{}, fmt.Errorf("set deadline: %w", err)
	}
	start := time.Now()
	n, err := conn.Write(request)
	if err == nil && n != len(request) {
		err = io.ErrShortWrite
	}
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, 0, time.Time{}, ctxErr
		}
		return nil, 0, time.Time{}, fmt.Errorf("sending: %w", err)
	}

	buf := make([]byte, MaxUDPReply)
	n, err = conn.Read(buf)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, 0, time.Time{}, ctxErr
		}
		return nil, 0, time.Time{}, fmt.Errorf("reading: %w", err)
	}
	return buf[:n], time.Since(start), time.Now(), nil
}

// RoundTripTCP sends one ROUGHTIM-framed request over TCP and returns the
// reply, RTT, and receipt time. timeout bounds dialing and I/O together.
func RoundTripTCP(ctx context.Context, address string, request []byte, timeout time.Duration) (reply []byte, rtt time.Duration, localNow time.Time, err error) {
	deadline := time.Now().Add(timeout)
	dialCtx, dialCancel := context.WithDeadline(ctx, deadline)
	defer dialCancel()
	var dialer net.Dialer
	conn, err := dialer.DialContext(dialCtx, "tcp", address)
	if err != nil {
		return nil, 0, time.Time{}, fmt.Errorf("dialing %s: %w", address, err)
	}
	defer func() { _ = conn.Close() }()
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}

	stopCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCancel()

	if err := conn.SetDeadline(deadline); err != nil {
		return nil, 0, time.Time{}, fmt.Errorf("set deadline: %w", err)
	}

	start := time.Now()
	n, err := conn.Write(request)
	if err == nil && n != len(request) {
		err = io.ErrShortWrite
	}
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, 0, time.Time{}, ctxErr
		}
		return nil, 0, time.Time{}, fmt.Errorf("sending: %w", err)
	}

	var hdr [PacketHeaderSize]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, 0, time.Time{}, ctxErr
		}
		// io.EOF means zero bytes read, so the peer closed without replying
		if errors.Is(err, io.EOF) {
			return nil, 0, time.Time{}, ErrPeerClosedNoReply
		}
		return nil, 0, time.Time{}, fmt.Errorf("reading header: %w", err)
	}
	bodyLen, err := ParsePacketHeader(hdr[:])
	if err != nil {
		return nil, 0, time.Time{}, fmt.Errorf("reply header: %w", err)
	}
	if bodyLen == 0 || bodyLen > MaxTCPReplyBody {
		return nil, 0, time.Time{}, fmt.Errorf("reply length %d out of range", bodyLen)
	}
	out := make([]byte, PacketHeaderSize+int(bodyLen))
	copy(out[:PacketHeaderSize], hdr[:])
	if _, err := io.ReadFull(conn, out[PacketHeaderSize:]); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, 0, time.Time{}, ctxErr
		}
		return nil, 0, time.Time{}, fmt.Errorf("reading body: %w", err)
	}
	return out, time.Since(start), time.Now(), nil
}
