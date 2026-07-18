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

// latencyReservoir holds a bounded random sample of RTTs.
type latencyReservoir struct {
	mu     sync.Mutex
	values []time.Duration
	seen   uint64
}

// record adds an RTT sample via Algorithm R reservoir sampling.
func (r *latencyReservoir) record(rtt time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen++
	if len(r.values) < reservoirSize {
		r.values = append(r.values, rtt)
		return
	}
	j := mrand.Uint64N(r.seen)
	if j < reservoirSize {
		r.values[j] = rtt
	}
}

// bumpAfter increments *c when start is at or past collectAfter.
func bumpAfter(start, collectAfter time.Time, c *uint64) {
	if !start.Before(collectAfter) {
		*c++
	}
}

// recordLatency updates full-run latency aggregates.
func recordLatency(out *workerResult, rtt time.Duration) {
	if out.successes == 0 || rtt < out.latencyMin {
		out.latencyMin = rtt
	}
	if rtt > out.latencyMax {
		out.latencyMax = rtt
	}
	out.latencyTotal += float64(rtt)
}

// operationDeadline returns the earlier timeout or context deadline.
func operationDeadline(ctx context.Context, timeout time.Duration) time.Time {
	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		return contextDeadline
	}
	return deadline
}

// contextStopped also recognizes a deadline before its cancellation propagates.
func contextStopped(ctx context.Context) bool {
	if ctx.Err() != nil {
		return true
	}
	deadline, ok := ctx.Deadline()
	return ok && !time.Now().Before(deadline)
}

// randomizeNonce fills n with non-cryptographic bytes for per-request variation.
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

// worker dispatches to a transport driver and reports whether it ran until
// cancellation.
func worker(ctx context.Context, cfg benchConfig, out *workerResult, collectAfter time.Time) bool {
	if cfg.transport == "tcp" {
		return workerTCP(ctx, cfg, out, collectAfter)
	}
	return workerUDP(ctx, cfg, out, collectAfter)
}

// workerUDP runs one UDP loop and returns false on initialization or reconnect
// failure.
func workerUDP(ctx context.Context, cfg benchConfig, out *workerResult, collectAfter time.Time) bool {
	conn, err := net.DialUDP("udp", nil, cfg.udpAddr)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()

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
	for !contextStopped(ctx) {
		randomizeNonce(nonce)
		copy(req[nonceOff:nonceOff+len(nonce)], nonce)

		// absolute deadline set before timing, so SetDeadline stays out of the
		// RTT
		deadline := operationDeadline(ctx, timeout)
		_ = conn.SetWriteDeadline(deadline)
		_ = conn.SetReadDeadline(deadline)
		start := time.Now()
		if _, err := conn.Write(req); err != nil {
			if contextStopped(ctx) {
				return true
			}
			if errors.Is(err, os.ErrDeadlineExceeded) {
				bumpAfter(start, collectAfter, &out.timeouts)
			} else {
				bumpAfter(start, collectAfter, &out.errWrite)
			}
			continue
		}
		bumpAfter(start, collectAfter, &out.sent)

		n, err := conn.Read(buf)
		rtt := time.Since(start)
		if err != nil {
			if contextStopped(ctx) {
				return true
			}
			if errors.Is(err, os.ErrDeadlineExceeded) {
				bumpAfter(start, collectAfter, &out.timeouts)
				_ = conn.Close()
				conn, err = net.DialUDP("udp", nil, cfg.udpAddr)
				if err != nil {
					return false
				}
			} else {
				bumpAfter(start, collectAfter, &out.errRead)
			}
			continue
		}

		collect := !start.Before(collectAfter)
		if collect {
			out.received++
		}
		if n > len(req) {
			if collect {
				out.errAmp++
			}
			continue
		}

		if verify {
			if _, _, err := protocol.VerifyReply(cfg.versions, buf[:n], cfg.rootPK, nonce, req); err != nil {
				// grease and genuine faults share this bucket
				if collect {
					out.errVerify++
				}
				continue
			}
		}
		if collect {
			recordLatency(out, rtt)
			out.successes++
			cfg.latencies.record(rtt)
		}
	}
	return true
}

// workerTCP runs the TCP loop and returns false on initialization or reconnect
// failure.
func workerTCP(ctx context.Context, cfg benchConfig, out *workerResult, collectAfter time.Time) bool {
	timeout := cfg.timeout
	verify := cfg.verify
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", cfg.addr)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	setTCPNoDelay(conn)

	nonce, req, err := protocol.CreateRequest(cfg.versions, rand.Reader, cfg.srv)
	if err != nil {
		return false
	}
	nonceOff, err := protocol.NonceOffsetInRequest(req)
	if err != nil {
		return false
	}

	// reconnect closes conn and redials, returning false if the redial fails.
	// No exponential backoff: this bench is a load generator, not a conformant
	// client.
	reconnect := func() bool {
		_ = conn.Close()
		c, err := dialer.DialContext(ctx, "tcp", cfg.addr)
		if err != nil {
			return false
		}
		conn = c
		setTCPNoDelay(conn)
		return true
	}

	replyBuf := make([]byte, protocol.PacketHeaderSize+protocol.MaxTCPReplyBody)
	for !contextStopped(ctx) {
		randomizeNonce(nonce)
		copy(req[nonceOff:nonceOff+len(nonce)], nonce)

		// one absolute deadline covers both reads and stays out of the measured
		// RTT
		deadline := operationDeadline(ctx, timeout)
		_ = conn.SetWriteDeadline(deadline)
		_ = conn.SetReadDeadline(deadline)
		start := time.Now()
		if _, err := conn.Write(req); err != nil {
			if contextStopped(ctx) {
				return true
			}
			if errors.Is(err, os.ErrDeadlineExceeded) {
				bumpAfter(start, collectAfter, &out.timeouts)
			} else {
				bumpAfter(start, collectAfter, &out.errWrite)
			}
			if !reconnect() {
				return false
			}
			continue
		}
		bumpAfter(start, collectAfter, &out.sent)

		hdr := replyBuf[:protocol.PacketHeaderSize]
		if _, err := io.ReadFull(conn, hdr); err != nil {
			if contextStopped(ctx) {
				return true
			}
			if errors.Is(err, os.ErrDeadlineExceeded) {
				bumpAfter(start, collectAfter, &out.timeouts)
			} else {
				bumpAfter(start, collectAfter, &out.errRead)
			}
			if !reconnect() {
				return false
			}
			continue
		}
		bodyLen, err := protocol.ParsePacketHeader(hdr)
		if err != nil || bodyLen == 0 || bodyLen > protocol.MaxTCPReplyBody {
			bumpAfter(start, collectAfter, &out.errRead)
			if !reconnect() {
				return false
			}
			continue
		}
		pkt := replyBuf[:protocol.PacketHeaderSize+int(bodyLen)]
		if _, err := io.ReadFull(conn, pkt[protocol.PacketHeaderSize:]); err != nil {
			if contextStopped(ctx) {
				return true
			}
			if errors.Is(err, os.ErrDeadlineExceeded) {
				bumpAfter(start, collectAfter, &out.timeouts)
			} else {
				bumpAfter(start, collectAfter, &out.errRead)
			}
			if !reconnect() {
				return false
			}
			continue
		}
		rtt := time.Since(start)

		collect := !start.Before(collectAfter)
		if collect {
			out.received++
		}
		if len(pkt) > len(req) {
			if collect {
				out.errAmp++
			}
			continue
		}

		if verify {
			if _, _, err := protocol.VerifyReply(cfg.versions, pkt, cfg.rootPK, nonce, req); err != nil {
				if collect {
					out.errVerify++
				}
				continue
			}
		}
		if collect {
			recordLatency(out, rtt)
			out.successes++
			cfg.latencies.record(rtt)
		}
	}
	return true
}
