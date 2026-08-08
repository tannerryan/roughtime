// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

//go:build unix && !linux

package main

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tannerryan/roughtime/protocol"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// batchQueueSize bounds the batcher channel. Overflow is dropped for
// backpressure.
const batchQueueSize = 4096

// udpHasQueue is true: the channel-fed batcher here can saturate and produce
// dropQueue.
const udpHasQueue = true

// readErrorBackoff throttles the read loop after a UDP read error.
const readErrorBackoff = 100 * time.Millisecond

// bufPool recycles read buffers to cut GC pressure under load.
var bufPool = sync.Pool{
	New: func() any {
		// The extra byte detects oversize datagrams even on kernels that do not
		// surface MSG_TRUNC through ReadMsgUDP.
		b := make([]byte, maxPacketSize+1)
		return &b
	},
}

// listenPortable runs a single-socket UDP server with inline validation and a
// channel-fed batcher.
func listenPortable(ctx context.Context, state *atomic.Pointer[certState]) error {
	listenLog := logger.Named("listener")
	maxSize := batchMaxSize
	maxLatency := batchMaxLatency

	addr, err := net.ResolveUDPAddr("udp", serverListenAddr())
	if err != nil {
		return fmt.Errorf("resolving UDP listen address: %w", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("starting UDP server: %w", err)
	}
	applyReadBuffer(listenLog, conn)

	batchCh := make(chan validatedRequest, batchQueueSize)

	var batcherWg sync.WaitGroup
	batcherLog := logger.Named("batcher")
	// per-iteration recovery lives inside batcher so batches persist and
	// close(batchCh) on shutdown isn't raced by a restart
	batcherWg.Go(func() {
		batcher(ctx, batcherLog, udpConnReplyWriter{conn: conn}, state, batchCh, maxSize, maxLatency)
	})

	listenLog.Info("listening",
		zap.String("addr", conn.LocalAddr().String()),
		zap.Int("port", *port),
		zap.Int("queue_size", batchQueueSize),
	)

	// past deadline unblocks the read loop without closing the socket while
	// in-flight work still holds it
	go func() {
		<-ctx.Done()
		listenLog.Info("shutdown initiated, unblocking reads")
		_ = conn.SetDeadline(time.Unix(1, 0))
	}()

	// readOne does one read-dispatch iteration and returns true on shutdown.
	// Recovered panics leak the in-flight buffer rather than returning it
	readOne := func() bool {
		defer recoverGoroutine(listenLog, "listen")

		bufPtr := bufPool.Get().(*[]byte)
		reqLen, _, flags, peer, err := conn.ReadMsgUDP(*bufPtr, nil)
		if err != nil {
			bufPool.Put(bufPtr)
			if ctx.Err() != nil {
				return true
			}
			listenLog.Warn("UDP read error", zap.Error(err))
			// throttle so a wedged socket can't spin a core, ctx.Done preempts
			select {
			case <-ctx.Done():
				return true
			case <-time.After(readErrorBackoff):
			}
			return false
		}
		if flags&unix.MSG_TRUNC != 0 || reqLen > maxPacketSize {
			bufPool.Put(bufPtr)
			incDropped(transportUDP, dropOversize)
			if ce := listenLog.Check(zap.DebugLevel, "dropped truncated UDP request"); ce != nil {
				ce.Write(zap.Stringer("peer", peer), zap.Int("reported_size", reqLen), zap.Int("buffer_size", len(*bufPtr)))
			}
			return false
		}
		// undersize packets are always droppable per the drafts
		if reqLen < minRequestSize {
			bufPool.Put(bufPtr)
			incDropped(transportUDP, dropUndersize)
			if ce := listenLog.Check(zap.DebugLevel, "dropped undersize request"); ce != nil {
				ce.Write(zap.Stringer("peer", peer), zap.Int("size", reqLen))
			}
			return false
		}
		vr, reason, ok := validateRequest(listenLog, (*bufPtr)[:reqLen], peer, reqLen, bufPtr, state.Load())
		if !ok {
			bufPool.Put(bufPtr)
			incDropped(transportUDP, reason)
			return false
		}
		udpReceivedEd.Add(1)
		select {
		case batchCh <- vr:
		default:
			bufPool.Put(bufPtr)
			incDropped(transportUDP, dropQueue)
			// hot path under overload, so gate the per-drop log. The dropQueue
			// metric is the source of truth
			if ce := listenLog.Check(zap.DebugLevel, "dropped request: batcher queue full"); ce != nil {
				ce.Write(zap.Stringer("peer", peer), zap.Int("size", reqLen), zap.Int("queue_size", batchQueueSize))
			}
		}
		return false
	}
	for !readOne() {
	}

	drainStart := time.Now()
	close(batchCh)
	batcherWg.Wait()
	_ = conn.Close()
	listenLog.Info("shutdown complete",
		zap.Uint64("received_total", requestsReceived.total()),
		zap.Uint64("responded_total", requestsResponded.total()),
		zap.Uint64("dropped_total", requestsDropped.total()),
		zap.Uint64("amp_suppressed_total", statsAmpDropped.Load()),
		zap.Uint64("panics_total", statsPanics.Load()),
		zap.Uint64("batches_total", statsBatches.Load()),
		zap.Uint64("batched_reqs_total", statsBatchedReqs.Load()),
		zap.Uint64("batch_errs_total", statsBatchErrs.Load()),
		zap.Duration("drain_duration", time.Since(drainStart)),
	)
	return nil
}

// batcher groups validated requests by (version, hasType) and flushes on size
// or latency triggers.
func batcher(ctx context.Context, log *zap.Logger, writer udpReplyWriter, state *atomic.Pointer[certState], incoming <-chan validatedRequest, maxSize int, maxLatency time.Duration) {
	// pending holds one keyed batch and its first-arrival time.
	type pending struct {
		items []validatedRequest
		start time.Time
	}
	batches := make(map[batchKey]*pending)

	timer := time.NewTimer(0)
	if !timer.Stop() {
		<-timer.C
	}
	timerRunning := false

	resetTimer := func() {
		var earliest time.Time
		for _, b := range batches {
			deadline := b.start.Add(maxLatency)
			if earliest.IsZero() || deadline.Before(earliest) {
				earliest = deadline
			}
		}
		if earliest.IsZero() {
			if timerRunning {
				timer.Stop()
				timerRunning = false
			}
			return
		}
		timer.Reset(max(time.Until(earliest), 0))
		timerRunning = true
	}

	flush := func(key batchKey) {
		b := batches[key]
		if b == nil || len(b.items) == 0 {
			return
		}
		delete(batches, key)
		flushBatch(ctx, log, writer, state, key.version, b.items)
	}

	// step runs one select iteration and returns true after incoming closes and
	// residual batches flush. Per-iteration recovery keeps the batcher serving
	// after a recovered panic.
	step := func() (done bool) {
		defer recoverGoroutine(log, "batcher")
		select {
		case vr, ok := <-incoming:
			if !ok {
				for key := range batches {
					flush(key)
				}
				return true
			}
			key := batchKey{version: vr.version, hasType: vr.req.HasType}
			b, exists := batches[key]
			if !exists {
				b = &pending{items: make([]validatedRequest, 0, maxSize), start: time.Now()}
				batches[key] = b
			}
			b.items = append(b.items, vr)

			// NoncInSREP versions cannot batch, so flush immediately
			if protocol.NoncInSREP(vr.version, vr.req.HasType) || len(b.items) >= maxSize {
				flush(key)
			}
			resetTimer()
		case <-timer.C:
			timerRunning = false
			now := time.Now()
			for key, b := range batches {
				if now.Sub(b.start) >= maxLatency {
					flush(key)
				}
			}
			resetTimer()
		}
		return false
	}

	for !step() {
	}
}

// flushBatch signs a batch, writes responses, and returns pooled read buffers
// regardless of outcome.
func flushBatch(ctx context.Context, log *zap.Logger, writer udpReplyWriter, state *atomic.Pointer[certState], ver protocol.Version, items []validatedRequest) {
	defer func() {
		for i := range items {
			if items[i].bufPtr != nil {
				bufPool.Put(items[i].bufPtr)
				items[i].bufPtr = nil
			}
		}
	}()
	replies := signAndBuildRepliesCurrent(log, state, ver, items)
	writer.writeReplies(ctx, log, ver, replies)
}

// udpReplyWriter sends a group of already-built UDP replies.
type udpReplyWriter interface {
	writeReplies(context.Context, *zap.Logger, protocol.Version, []readyReply)
}

// udpConnReplyWriter is the portable one-datagram-at-a-time writer.
type udpConnReplyWriter struct {
	conn *net.UDPConn
}

func (w udpConnReplyWriter) writeReplies(ctx context.Context, log *zap.Logger, ver protocol.Version, replies []readyReply) {
	for i, r := range replies {
		if ctx.Err() != nil {
			for range replies[i:] {
				incDropped(transportUDP, dropWrite)
			}
			return
		}
		_ = w.conn.SetWriteDeadline(time.Now().Add(udpWriteTimeout))
		if _, err := w.conn.WriteToUDP(r.bytes, r.peer); err != nil {
			log.Warn("UDP write failed", zap.Stringer("peer", r.peer), zap.Error(err))
			incDropped(transportUDP, dropWrite)
			continue
		}
		udpRespondedEd.Add(1)
		if ce := log.Check(zap.DebugLevel, "sent response"); ce != nil {
			ce.Write(
				zap.Stringer("peer", r.peer),
				zap.Int("size", len(r.bytes)),
				zap.Stringer("version", ver),
			)
		}
	}
}
