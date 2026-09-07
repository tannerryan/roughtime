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

// randomizeNonce fills n with non-cryptographic bytes for per-request
// variation.
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

// closeOnCancel closes this specific connection when ctx stops. The returned
// function detaches the hook before a deliberate close or replacement.
func closeOnCancel(ctx context.Context, conn net.Conn) func() {
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	return func() { _ = stop() }
}

// worker dispatches to a transport driver. Cancellation is not an error.
func worker(ctx context.Context, cfg benchConfig, out *workerResult, collectAfter time.Time) error {
	if cfg.transport == "tcp" {
		return workerTCP(ctx, cfg, out, collectAfter)
	}
	return workerUDP(ctx, cfg, out, collectAfter)
}

// workerUDP runs one UDP loop until cancellation or a fatal initialization or
// reconnect failure.
func workerUDP(ctx context.Context, cfg benchConfig, out *workerResult, collectAfter time.Time) error {
	conn, err := net.DialUDP("udp", nil, cfg.udpAddr)
	if err != nil {
		if contextStopped(ctx) {
			return nil
		}
		return fmt.Errorf("dial UDP: %w", err)
	}
	stopClose := closeOnCancel(ctx, conn)
	defer func() {
		stopClose()
		_ = conn.Close()
	}()

	nonce, req, err := protocol.CreateRequest(cfg.versions, rand.Reader, cfg.srv)
	if err != nil {
		return fmt.Errorf("create UDP request: %w", err)
	}
	// bytes.Index would be unsafe: a random nonce can collide with header or
	// SRV bytes
	nonceOff, err := protocol.NonceOffsetInRequest(req)
	if err != nil {
		return fmt.Errorf("locate UDP request nonce: %w", err)
	}
	reconnect := func() error {
		stopClose()
		_ = conn.Close()
		c, err := net.DialUDP("udp", nil, cfg.udpAddr)
		if err != nil {
			if contextStopped(ctx) {
				return nil
			}
			return fmt.Errorf("redial UDP: %w", err)
		}
		conn = c
		stopClose = closeOnCancel(ctx, c)
		return nil
	}

	timeout := cfg.timeout
	verify := cfg.verify
	// One byte beyond the request distinguishes allowed replies from oversized
	// datagrams. Any remainder of a much larger datagram is intentionally
	// discarded by UDP semantics.
	buf := make([]byte, len(req)+1)
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
				return nil
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
				return nil
			}
			if errors.Is(err, os.ErrDeadlineExceeded) {
				bumpAfter(start, collectAfter, &out.timeouts)
				if err := reconnect(); err != nil || contextStopped(ctx) {
					return err
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
	return nil
}

// workerTCP runs the TCP loop until cancellation or a fatal initialization or
// reconnect failure.
func workerTCP(ctx context.Context, cfg benchConfig, out *workerResult, collectAfter time.Time) error {
	timeout := cfg.timeout
	verify := cfg.verify
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", cfg.addr)
	if err != nil {
		if contextStopped(ctx) {
			return nil
		}
		return fmt.Errorf("dial TCP: %w", err)
	}
	stopClose := closeOnCancel(ctx, conn)
	defer func() {
		stopClose()
		_ = conn.Close()
	}()
	setTCPNoDelay(conn)

	nonce, req, err := protocol.CreateRequest(cfg.versions, rand.Reader, cfg.srv)
	if err != nil {
		return fmt.Errorf("create TCP request: %w", err)
	}
	nonceOff, err := protocol.NonceOffsetInRequest(req)
	if err != nil {
		return fmt.Errorf("locate TCP request nonce: %w", err)
	}

	// reconnect detaches the old connection's cancellation callback before
	// closing it, then installs a callback that captures the replacement. No
	// exponential backoff: this bench is a load generator, not a conformant
	// client.
	reconnect := func() error {
		stopClose()
		_ = conn.Close()
		c, err := dialer.DialContext(ctx, "tcp", cfg.addr)
		if err != nil {
			if contextStopped(ctx) {
				return nil
			}
			return fmt.Errorf("redial TCP: %w", err)
		}
		conn = c
		stopClose = closeOnCancel(ctx, c)
		setTCPNoDelay(conn)
		return nil
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
				return nil
			}
			if errors.Is(err, os.ErrDeadlineExceeded) {
				bumpAfter(start, collectAfter, &out.timeouts)
			} else {
				bumpAfter(start, collectAfter, &out.errWrite)
			}
			if err := reconnect(); err != nil || contextStopped(ctx) {
				return err
			}
			continue
		}
		bumpAfter(start, collectAfter, &out.sent)

		hdr := replyBuf[:protocol.PacketHeaderSize]
		if _, err := io.ReadFull(conn, hdr); err != nil {
			if contextStopped(ctx) {
				return nil
			}
			if errors.Is(err, os.ErrDeadlineExceeded) {
				bumpAfter(start, collectAfter, &out.timeouts)
			} else {
				bumpAfter(start, collectAfter, &out.errRead)
			}
			if err := reconnect(); err != nil || contextStopped(ctx) {
				return err
			}
			continue
		}
		bodyLen, err := protocol.ParsePacketHeader(hdr)
		if err != nil || bodyLen == 0 || bodyLen > protocol.MaxTCPReplyBody {
			bumpAfter(start, collectAfter, &out.errRead)
			if err := reconnect(); err != nil || contextStopped(ctx) {
				return err
			}
			continue
		}
		pkt := replyBuf[:protocol.PacketHeaderSize+int(bodyLen)]
		if _, err := io.ReadFull(conn, pkt[protocol.PacketHeaderSize:]); err != nil {
			if contextStopped(ctx) {
				return nil
			}
			if errors.Is(err, os.ErrDeadlineExceeded) {
				bumpAfter(start, collectAfter, &out.timeouts)
			} else {
				bumpAfter(start, collectAfter, &out.errRead)
			}
			if err := reconnect(); err != nil || contextStopped(ctx) {
				return err
			}
			continue
		}
		rtt := time.Since(start)

		collect := !start.Before(collectAfter)
		if collect {
			out.received++
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
	return nil
}
