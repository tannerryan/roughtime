// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// MaxUDPReply is the maximum UDP datagram size accepted as a reply.
const MaxUDPReply = 65535

// MaxTCPReplyBody caps the declared body length of a TCP reply.
const MaxTCPReplyBody = 16 * 1024

// ErrPeerClosedNoReply is returned by [RoundTripTCP] when the peer closes
// before writing any reply.
var ErrPeerClosedNoReply = errors.New("peer closed connection with no reply (server may not support the requested version, scheme, or transport)")

// RoundTripUDP sends one Roughtime request over UDP and returns the reply, RTT,
// and receipt time.
func RoundTripUDP(ctx context.Context, address string, request []byte, timeout time.Duration) (reply []byte, rtt time.Duration, localNow time.Time, err error) {
	raddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, 0, time.Time{}, fmt.Errorf("resolving %s: %w", address, err)
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, 0, time.Time{}, fmt.Errorf("dialing %s: %w", address, err)
	}
	defer conn.Close()

	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, 0, time.Time{}, fmt.Errorf("set deadline: %w", err)
	}
	start := time.Now()
	if _, err := conn.Write(request); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, 0, time.Time{}, ctxErr
		}
		return nil, 0, time.Time{}, fmt.Errorf("sending: %w", err)
	}

	buf := make([]byte, MaxUDPReply)
	n, err := conn.Read(buf)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, 0, time.Time{}, ctxErr
		}
		return nil, 0, time.Time{}, fmt.Errorf("reading: %w", err)
	}
	return buf[:n], time.Since(start), time.Now(), nil
}

// RoundTripTCP sends one ROUGHTIM-framed request over TCP and returns the
// reply, RTT, and receipt time.
func RoundTripTCP(ctx context.Context, address string, request []byte, timeout time.Duration) (reply []byte, rtt time.Duration, localNow time.Time, err error) {
	deadline := time.Now().Add(timeout)
	dialCtx, dialCancel := context.WithDeadline(ctx, deadline)
	defer dialCancel()
	var dialer net.Dialer
	conn, err := dialer.DialContext(dialCtx, "tcp", address)
	if err != nil {
		return nil, 0, time.Time{}, fmt.Errorf("dialing %s: %w", address, err)
	}
	defer conn.Close()
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}

	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()

	if err := conn.SetDeadline(deadline); err != nil {
		return nil, 0, time.Time{}, fmt.Errorf("set deadline: %w", err)
	}

	start := time.Now()
	if _, err := conn.Write(request); err != nil {
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
		// io.EOF means zero bytes read; peer closed without replying
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
