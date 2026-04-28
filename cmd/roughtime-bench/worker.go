// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"
	"os"
	"sync"
	"time"

	"github.com/tannerryan/roughtime/protocol"
)

// recordLatency adds an RTT sample to out via Algorithm R reservoir sampling.
func recordLatency(out *workerResult, rtt time.Duration) {
	out.received++
	if len(out.latencies) < reservoirSize {
		out.latencies = append(out.latencies, rtt)
		return
	}
	j := mrand.Uint64N(out.received)
	if j < reservoirSize {
		out.latencies[j] = rtt
	}
}

// bumpAfter increments *c when start is at or past collectAfter.
func bumpAfter(start, collectAfter time.Time, c *uint64) {
	if !start.Before(collectAfter) {
		*c++
	}
}

// randomizeNonce fills n with non-cryptographic random bytes for distinctness.
func randomizeNonce(n []byte) {
	full := len(n) - len(n)%8
	for i := 0; i < full; i += 8 {
		binary.LittleEndian.PutUint64(n[i:], mrand.Uint64())
	}
	if tail := n[full:]; len(tail) > 0 {
		var t [8]byte
		binary.LittleEndian.PutUint64(t[:], mrand.Uint64())
		copy(tail, t[:])
	}
}

// noDelayWarn fires once across all workers if SetNoDelay fails.
var noDelayWarn sync.Once

// setTCPNoDelay disables Nagle on c if it is a *net.TCPConn.
func setTCPNoDelay(c net.Conn) {
	tcp, ok := c.(*net.TCPConn)
	if !ok {
		return
	}
	if err := tcp.SetNoDelay(true); err != nil {
		noDelayWarn.Do(func() {
			fmt.Fprintf(os.Stderr, "bench: SetNoDelay failed: %s (latency measurements may be inflated)\n", err)
		})
	}
}

// worker dispatches to the UDP or TCP driver.
func worker(ctx context.Context, cfg benchConfig, out *workerResult, collectAfter time.Time) bool {
	if cfg.transport == "tcp" {
		return workerTCP(ctx, cfg, out, collectAfter)
	}
	return workerUDP(ctx, cfg, out, collectAfter)
}

// workerUDP runs the send/recv loop on one UDP socket and returns false if dial
// fails.
func workerUDP(ctx context.Context, cfg benchConfig, out *workerResult, collectAfter time.Time) bool {
	raddr, err := net.ResolveUDPAddr("udp", cfg.addr)
	if err != nil {
		return false
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return false
	}
	defer conn.Close()

	nonce, req, err := protocol.CreateRequest(cfg.versions, rand.Reader, cfg.srv)
	if err != nil {
		return false
	}
	// bytes.Index would be unsafe: a random nonce can collide with header or
	// SRV bytes
	nonceOff, err := protocol.NonceOffsetInRequest(req)
	if err != nil {
		return false
	}

	timeout := cfg.timeout
	verify := cfg.verify
	buf := make([]byte, protocol.MaxUDPReply)
	for ctx.Err() == nil {
		randomizeNonce(nonce)
		copy(req[nonceOff:nonceOff+len(nonce)], nonce)

		_ = conn.SetWriteDeadline(time.Now().Add(timeout))
		start := time.Now()
		if _, err := conn.Write(req); err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				bumpAfter(start, collectAfter, &out.timeouts)
			} else {
				bumpAfter(start, collectAfter, &out.errWrite)
			}
			continue
		}

		_ = conn.SetReadDeadline(time.Now().Add(timeout))
		n, err := conn.Read(buf)
		rtt := time.Since(start)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				bumpAfter(start, collectAfter, &out.timeouts)
			} else {
				bumpAfter(start, collectAfter, &out.errRead)
			}
			continue
		}

		// record latency on RX completion so verify-failed replies (often fast
		// grease) do not bias percentiles upward
		if !start.Before(collectAfter) {
			recordLatency(out, rtt)
		}

		if verify {
			if _, _, err := protocol.VerifyReply(cfg.versions, buf[:n], cfg.rootPK, nonce, req); err != nil {
				// grease and genuine faults share this bucket
				bumpAfter(start, collectAfter, &out.errVerify)
				continue
			}
		}
	}
	return true
}

// workerTCP runs the send/recv loop on a TCP connection and redials on
// transport or framing errors.
func workerTCP(ctx context.Context, cfg benchConfig, out *workerResult, collectAfter time.Time) bool {
	timeout := cfg.timeout
	verify := cfg.verify
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", cfg.addr)
	if err != nil {
		return false
	}
	defer func() { conn.Close() }()
	setTCPNoDelay(conn)

	nonce, req, err := protocol.CreateRequest(cfg.versions, rand.Reader, cfg.srv)
	if err != nil {
		return false
	}
	nonceOff, err := protocol.NonceOffsetInRequest(req)
	if err != nil {
		return false
	}

	// reconnect closes conn and redials; returns false if the redial fails. No
	// exponential backoff: this bench is a load generator, not a conformant
	// client.
	reconnect := func() bool {
		conn.Close()
		c, err := dialer.DialContext(ctx, "tcp", cfg.addr)
		if err != nil {
			return false
		}
		conn = c
		setTCPNoDelay(conn)
		return true
	}

	replyBuf := make([]byte, protocol.PacketHeaderSize+protocol.MaxTCPReplyBody)
	for ctx.Err() == nil {
		randomizeNonce(nonce)
		copy(req[nonceOff:nonceOff+len(nonce)], nonce)

		_ = conn.SetWriteDeadline(time.Now().Add(timeout))
		start := time.Now()
		if _, err := conn.Write(req); err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				bumpAfter(start, collectAfter, &out.timeouts)
			} else {
				bumpAfter(start, collectAfter, &out.errWrite)
			}
			if !reconnect() {
				return true
			}
			continue
		}

		hdr := replyBuf[:protocol.PacketHeaderSize]
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
		if _, err := io.ReadFull(conn, hdr); err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				bumpAfter(start, collectAfter, &out.timeouts)
			} else {
				bumpAfter(start, collectAfter, &out.errRead)
			}
			if !reconnect() {
				return true
			}
			continue
		}
		bodyLen, err := protocol.ParsePacketHeader(hdr)
		if err != nil || bodyLen == 0 || bodyLen > protocol.MaxTCPReplyBody {
			bumpAfter(start, collectAfter, &out.errRead)
			if !reconnect() {
				return true
			}
			continue
		}
		pkt := replyBuf[:protocol.PacketHeaderSize+int(bodyLen)]
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
		if _, err := io.ReadFull(conn, pkt[protocol.PacketHeaderSize:]); err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				bumpAfter(start, collectAfter, &out.timeouts)
			} else {
				bumpAfter(start, collectAfter, &out.errRead)
			}
			if !reconnect() {
				return true
			}
			continue
		}
		rtt := time.Since(start)

		// record latency on RX completion so verify-failed replies (often fast
		// grease) do not bias percentiles upward
		if !start.Before(collectAfter) {
			recordLatency(out, rtt)
		}

		if verify {
			if _, _, err := protocol.VerifyReply(cfg.versions, pkt, cfg.rootPK, nonce, req); err != nil {
				bumpAfter(start, collectAfter, &out.errVerify)
				continue
			}
		}
	}
	return true
}
