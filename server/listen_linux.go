// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/tannerryan/roughtime/protocol"
	"go.uber.org/zap"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

// idleReadTimeout bounds how long an idle worker blocks in ReadBatch before
// re-checking ctx. Long enough that idle CPU is negligible, short enough that
// shutdown is prompt.
const idleReadTimeout = 500 * time.Millisecond

// reqBufPool recycles per-packet copy buffers so payloads survive the next
// recvmmsg into the shared scratch buffers.
var reqBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, maxPacketSize)
		return &b
	},
}

// statsWorkerExits counts worker goroutines that returned before ctx was
// cancelled (one worker per SO_REUSEPORT socket). If this climbs during normal
// operation the pool is silently shrinking; surfaced in the shutdown log.
var statsWorkerExits atomic.Uint64

// listen starts one SO_REUSEPORT worker per CPU. Each worker owns its own
// kernel socket and drives recvmmsg/sendmmsg batches.
func listen(ctx context.Context, state *atomic.Pointer[certState], maxSize int, maxLatency time.Duration) error {
	listenLog := logger.Named("listener")
	numWorkers := runtime.NumCPU()
	addr := net.JoinHostPort("::", strconv.Itoa(*port))

	conns := make([]net.PacketConn, 0, numWorkers)
	for i := range numWorkers {
		c, err := listenReusePort("udp", addr)
		if err != nil {
			for _, prev := range conns {
				_ = prev.Close()
			}
			return fmt.Errorf("binding worker %d: %w", i, err)
		}
		if udp, ok := c.(*net.UDPConn); ok {
			if err := udp.SetReadBuffer(socketRecvBuffer); err != nil {
				listenLog.Warn("setting UDP receive buffer failed",
					zap.Int("requested", socketRecvBuffer),
					zap.Error(err),
				)
			}
		}
		conns = append(conns, c)
	}

	listenLog.Info("listening",
		zap.String("addr", addr),
		zap.Int("workers", numWorkers),
	)

	var wg sync.WaitGroup
	for i, c := range conns {
		wg.Add(1)
		go func(id int, c net.PacketConn) {
			defer wg.Done()
			wlog := listenLog.With(zap.Int("worker", id))
			// Supervise the worker so a panic doesn't silently shrink the
			// SO_REUSEPORT pool. The same socket is reused across restarts.
			for ctx.Err() == nil {
				func() {
					defer recoverGoroutine(wlog, "worker")
					worker(ctx, wlog, state, c, maxSize, maxLatency)
				}()
				if ctx.Err() != nil {
					return
				}
				wlog.Warn("worker exited before shutdown, restarting")
			}
		}(i, c)
	}
	wg.Wait()

	for _, c := range conns {
		_ = c.Close()
	}
	listenLog.Info("shutdown complete",
		zap.Uint64("received_total", statsReceived.Load()),
		zap.Uint64("responded_total", statsResponded.Load()),
		zap.Uint64("dropped_total", statsDropped.Load()),
		zap.Uint64("panics_total", statsPanics.Load()),
		zap.Uint64("batches_total", statsBatches.Load()),
		zap.Uint64("batched_reqs_total", statsBatchedReqs.Load()),
		zap.Uint64("batch_errs_total", statsBatchErrs.Load()),
		zap.Uint64("worker_exits_total", statsWorkerExits.Load()),
	)
	return nil
}

// worker reads, validates, signs, and responds in batches until ctx is done.
// Panic recovery and restart are handled by the caller's supervisor; the socket
// is closed by listen() after all workers drain.
func worker(ctx context.Context, log *zap.Logger, state *atomic.Pointer[certState], conn net.PacketConn, maxSize int, maxLatency time.Duration) {
	defer func() {
		if ctx.Err() == nil {
			// Non-shutdown exit is visible in stats so a silent capacity loss
			// in the SO_REUSEPORT pool can be diagnosed. The supervisor will
			// restart the worker on the same socket.
			statsWorkerExits.Add(1)
		}
	}()

	p := ipv6.NewPacketConn(conn)
	msgs := makeMessages(maxSize, maxPacketSize)

	for ctx.Err() == nil {
		batch := collectBatch(log, conn, p, msgs, maxSize, maxLatency, state)
		if len(batch) > 0 {
			respond(log, p, state.Load(), batch)
		}
	}
}

// collectBatch reads up to maxSize datagrams. The first read uses a bounded
// idle deadline so ctx cancellation is seen promptly; subsequent reads share a
// single maxLatency window.
func collectBatch(log *zap.Logger, conn net.PacketConn, p *ipv6.PacketConn, msgs []ipv6.Message, maxSize int, maxLatency time.Duration, state *atomic.Pointer[certState]) []validatedRequest {
	_ = conn.SetReadDeadline(time.Now().Add(idleReadTimeout))
	n, err := p.ReadBatch(msgs, 0)
	if err != nil {
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			log.Warn("ReadBatch failed", zap.Error(err))
		}
		return nil
	}

	batch := make([]validatedRequest, 0, maxSize)
	harvest(log, msgs[:n], state.Load(), &batch)
	if len(batch) >= maxSize {
		return batch
	}

	deadline := time.Now().Add(maxLatency)
	for len(batch) < maxSize {
		_ = conn.SetReadDeadline(deadline)
		rem := min(maxSize-len(batch), len(msgs))
		n, err := p.ReadBatch(msgs[:rem], 0)
		if err != nil {
			break
		}
		harvest(log, msgs[:n], state.Load(), &batch)
	}
	return batch
}

// harvest validates each datagram, copying payloads into pooled buffers so they
// survive the next ReadBatch. respond() returns the pooled buffers after
// signing.
func harvest(log *zap.Logger, msgs []ipv6.Message, st *certState, batch *[]validatedRequest) {
	for i := range msgs {
		n := msgs[i].N
		statsReceived.Add(1)
		if n < minRequestSize {
			statsDropped.Add(1)
			if ce := log.Check(zap.DebugLevel, "dropped undersize request"); ce != nil {
				ce.Write(zap.Any("peer", msgs[i].Addr), zap.Int("size", n))
			}
			continue
		}
		peer, ok := msgs[i].Addr.(*net.UDPAddr)
		if !ok {
			statsDropped.Add(1)
			continue
		}
		bufPtr := reqBufPool.Get().(*[]byte)
		copy(*bufPtr, msgs[i].Buffers[0][:n])

		vr, ok := validateRequest(log, (*bufPtr)[:n], peer, n, bufPtr, st)
		if !ok {
			reqBufPool.Put(bufPtr)
			continue
		}
		*batch = append(*batch, vr)
	}
}

// respond groups items by (version, hasType), signs each group, and writes
// replies via sendmmsg. Drafts 01–02 (NoncInSREP) are forced into singleton
// groups because they place NONC inside SREP, preventing aggregation.
func respond(log *zap.Logger, p *ipv6.PacketConn, st *certState, items []validatedRequest) {
	// Recover inside respond so a panicking batch does not take down the
	// worker.
	defer recoverGoroutine(log, "respond")
	// Return pooled request buffers after signing is complete.
	defer func() {
		for i := range items {
			if items[i].bufPtr != nil {
				reqBufPool.Put(items[i].bufPtr)
				items[i].bufPtr = nil
			}
		}
	}()

	type group struct {
		ver   protocol.Version
		items []validatedRequest
	}
	var groups []*group
	idx := make(map[batchKey]int, 2)

	for _, v := range items {
		// NoncInSREP: one item per group, never aggregated.
		if protocol.NoncInSREP(v.version, v.req.HasType) {
			groups = append(groups, &group{ver: v.version, items: []validatedRequest{v}})
			continue
		}
		key := batchKey{version: v.version, hasType: v.req.HasType}
		if i, ok := idx[key]; ok {
			groups[i].items = append(groups[i].items, v)
			continue
		}
		idx[key] = len(groups)
		groups = append(groups, &group{ver: v.version, items: []validatedRequest{v}})
	}

	out := make([]ipv6.Message, 0, len(items))
	for _, g := range groups {
		for _, r := range signAndBuildReplies(log, st, g.ver, g.items) {
			out = append(out, ipv6.Message{
				Addr:    r.peer,
				Buffers: [][]byte{r.bytes},
			})
		}
	}

	// sendmmsg may return a short count; loop until the slice drains.
	for len(out) > 0 {
		n, err := p.WriteBatch(out, 0)
		if err != nil {
			log.Warn("WriteBatch failed", zap.Error(err), zap.Int("dropped", len(out)))
			statsDropped.Add(uint64(len(out)))
			return
		}
		if n <= 0 {
			// Defensive: guard against an infinite loop on degenerate returns.
			log.Warn("WriteBatch wrote 0", zap.Int("dropped", len(out)))
			statsDropped.Add(uint64(len(out)))
			return
		}
		statsResponded.Add(uint64(n))
		out = out[n:]
	}
}

// listenReusePort binds a dual-stack UDP socket with SO_REUSEPORT so each
// worker gets its own kernel queue.
func listenReusePort(network, address string) (net.PacketConn, error) {
	lc := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			var opErr error
			err := c.Control(func(fd uintptr) {
				opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			})
			if err != nil {
				return err
			}
			return opErr
		},
	}
	return lc.ListenPacket(context.Background(), network, address)
}

// makeMessages pre-allocates a batch of ipv6.Messages with per-slot read
// buffers sized to hold one UDP datagram.
func makeMessages(count, size int) []ipv6.Message {
	msgs := make([]ipv6.Message, count)
	for i := range msgs {
		msgs[i] = ipv6.Message{Buffers: [][]byte{make([]byte, size)}}
	}
	return msgs
}
