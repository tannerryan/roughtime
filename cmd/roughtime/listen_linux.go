// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

//go:build linux

// Linux UDP listener: one SO_REUSEPORT socket per CPU with recvmmsg/sendmmsg
// batching.
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

// idleReadTimeout bounds ReadBatch blocking so ctx cancellation is observed
// promptly.
const idleReadTimeout = 500 * time.Millisecond

// readErrorBackoff throttles the worker loop after a non-deadline ReadBatch
// error.
const readErrorBackoff = 100 * time.Millisecond

// reqBufPool recycles per-packet copy buffers so payloads survive the next
// recvmmsg.
var reqBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, maxPacketSize)
		return &b
	},
}

// statsWorkerExits counts worker returns before ctx cancellation.
var statsWorkerExits atomic.Uint64

// listen starts one SO_REUSEPORT worker per CPU, each driving its own
// recvmmsg/sendmmsg loop.
func listen(ctx context.Context, state *atomic.Pointer[certState]) error {
	listenLog := logger.Named("listener")
	numWorkers := runtime.NumCPU()
	addr := net.JoinHostPort("::", strconv.Itoa(*port))
	maxSize := batchMaxSize
	maxLatency := batchMaxLatency

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
			applyReadBuffer(listenLog.With(zap.Int("worker", i)), udp)
		}
		conns = append(conns, c)
	}

	listenLog.Info("listening",
		zap.String("addr", addr),
		zap.Int("workers", numWorkers),
	)

	var wg sync.WaitGroup
	for i, c := range conns {
		wg.Go(func() {
			wlog := listenLog.With(zap.Int("worker", i))
			// restart on panic so the SO_REUSEPORT pool doesn't shrink
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
		})
	}
	wg.Wait()

	for _, c := range conns {
		_ = c.Close()
	}
	listenLog.Info("shutdown complete",
		zap.Uint64("received_total", statsReceived.Load()),
		zap.Uint64("responded_total", statsResponded.Load()),
		zap.Uint64("dropped_total", statsDropped.Load()),
		zap.Uint64("amp_suppressed_total", statsAmpDropped.Load()),
		zap.Uint64("panics_total", statsPanics.Load()),
		zap.Uint64("batches_total", statsBatches.Load()),
		zap.Uint64("batched_reqs_total", statsBatchedReqs.Load()),
		zap.Uint64("batch_errs_total", statsBatchErrs.Load()),
		zap.Uint64("worker_exits_total", statsWorkerExits.Load()),
	)
	return nil
}

// worker reads, validates, signs, and responds in batches until ctx is done.
func worker(ctx context.Context, log *zap.Logger, state *atomic.Pointer[certState], conn net.PacketConn, maxSize int, maxLatency time.Duration) {
	defer func() {
		if ctx.Err() == nil {
			statsWorkerExits.Add(1)
		}
	}()

	p := ipv6.NewPacketConn(conn)
	msgs := makeMessages(maxSize, maxPacketSize)

	for ctx.Err() == nil {
		batch, hardErr := collectBatch(log, conn, p, msgs, maxSize, maxLatency, state)
		if len(batch) > 0 {
			respond(log, p, state.Load(), batch)
		}
		// throttle the loop on persistent non-deadline read errors so a wedged
		// socket can't burn a core; ctx.Done preempts the sleep
		if hardErr {
			select {
			case <-ctx.Done():
				return
			case <-time.After(readErrorBackoff):
			}
		}
	}
}

// collectBatch reads up to maxSize datagrams; hardErr signals a non-deadline
// error on the first read.
func collectBatch(log *zap.Logger, conn net.PacketConn, p *ipv6.PacketConn, msgs []ipv6.Message, maxSize int, maxLatency time.Duration, state *atomic.Pointer[certState]) (batch []validatedRequest, hardErr bool) {
	_ = conn.SetReadDeadline(time.Now().Add(idleReadTimeout))
	n, err := p.ReadBatch(msgs, 0)
	if err != nil {
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			log.Warn("ReadBatch failed", zap.Error(err))
			return nil, true
		}
		return nil, false
	}

	batch = make([]validatedRequest, 0, maxSize)
	harvest(log, msgs[:n], state.Load(), &batch)
	if len(batch) >= maxSize {
		return batch, false
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
	return batch, false
}

// harvest validates each datagram into pooled buffers, which respond returns to
// the pool.
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

// respond groups items by (version, hasType), signs, and writes via sendmmsg.
func respond(log *zap.Logger, p *ipv6.PacketConn, st *certState, items []validatedRequest) {
	defer recoverGoroutine(log, "respond")
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
		// NoncInSREP versions cannot aggregate
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

	// sendmmsg may return a short count; loop until the slice drains
	for len(out) > 0 {
		n, err := p.WriteBatch(out, 0)
		if err != nil {
			log.Warn("WriteBatch failed", zap.Error(err), zap.Int("dropped", len(out)))
			statsDropped.Add(uint64(len(out)))
			return
		}
		if n <= 0 {
			// guard against infinite loop on degenerate returns
			log.Warn("WriteBatch wrote 0", zap.Int("dropped", len(out)))
			statsDropped.Add(uint64(len(out)))
			return
		}
		statsResponded.Add(uint64(n))
		out = out[n:]
	}
}

// listenReusePort binds a dual-stack UDP socket with SO_REUSEPORT and
// IPV6_V6ONLY=0.
func listenReusePort(network, address string) (net.PacketConn, error) {
	lc := net.ListenConfig{
		Control: func(ctrlNetwork, _ string, c syscall.RawConn) error {
			var opErr error
			err := c.Control(func(fd uintptr) {
				if opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); opErr != nil {
					return
				}
				if ctrlNetwork == "udp6" {
					opErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 0)
				}
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
// buffers.
func makeMessages(count, size int) []ipv6.Message {
	msgs := make([]ipv6.Message, count)
	for i := range msgs {
		msgs[i] = ipv6.Message{Buffers: [][]byte{make([]byte, size)}}
	}
	return msgs
}
