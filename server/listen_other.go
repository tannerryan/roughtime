// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

//go:build !linux

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
)

// bufPool recycles read buffers to reduce GC pressure under high packet rates.
var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, maxPacketSize)
		return &b
	},
}

// listen runs a single-socket UDP server with inline validation and a
// channel-fed batcher. Linux builds use listen_linux.go instead.
func listen(ctx context.Context, state *atomic.Pointer[certState], maxSize int, maxLatency time.Duration) error {
	listenLog := logger.Named("listener")

	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: *port})
	if err != nil {
		return fmt.Errorf("starting UDP server: %w", err)
	}
	if err := conn.SetReadBuffer(socketRecvBuffer); err != nil {
		listenLog.Warn("setting UDP receive buffer failed",
			zap.Int("requested", socketRecvBuffer),
			zap.Error(err),
		)
	}

	batchCh := make(chan validatedRequest, batchQueueSize)

	var batcherWg sync.WaitGroup
	batcherLog := logger.Named("batcher")
	batcherWg.Add(1)
	// Panic recovery lives inside batcher() on a per-iteration basis: a
	// supervisor-style restart would lose the in-memory batches map and, worse,
	// race the shutdown's close(batchCh) into a dead re-entry.
	go func() {
		defer batcherWg.Done()
		batcher(batcherLog, conn, state, batchCh, maxSize, maxLatency)
	}()

	listenLog.Info("listening",
		zap.String("addr", conn.LocalAddr().String()),
		zap.Int("port", *port),
		zap.Int("queue_size", batchQueueSize),
	)

	// On shutdown, set a past read deadline so the read loop unblocks cleanly
	// without closing the socket from underneath in-flight work.
	go func() {
		<-ctx.Done()
		listenLog.Info("shutdown initiated, unblocking reads")
		_ = conn.SetReadDeadline(time.Unix(1, 0))
	}()

	// readOne handles one read-dispatch iteration. A panic (e.g. in
	// validateRequest) is absorbed so a single malformed request can't crash
	// the server; the offending buffer is leaked rather than returned to the
	// pool, which the pool tolerates. Returns true when shutdown is requested.
	readOne := func() bool {
		defer recoverGoroutine(listenLog, "listen")

		bufPtr := bufPool.Get().(*[]byte)
		reqLen, peer, err := conn.ReadFromUDP(*bufPtr)
		if err != nil {
			bufPool.Put(bufPtr)
			if ctx.Err() != nil {
				return true
			}
			listenLog.Warn("UDP read error", zap.Error(err))
			return false
		}
		statsReceived.Add(1)
		// Drop undersize packets without dispatching: responding to requests
		// shorter than 1024 bytes is OPTIONAL per all drafts (§5/§6).
		if reqLen < minRequestSize {
			bufPool.Put(bufPtr)
			statsDropped.Add(1)
			if ce := listenLog.Check(zap.DebugLevel, "dropped undersize request"); ce != nil {
				ce.Write(zap.Stringer("peer", peer), zap.Int("size", reqLen))
			}
			return false
		}
		vr, ok := validateRequest(listenLog, (*bufPtr)[:reqLen], peer, reqLen, bufPtr, state.Load())
		if !ok {
			bufPool.Put(bufPtr)
			return false
		}
		select {
		case batchCh <- vr:
		default:
			bufPool.Put(bufPtr)
			statsDropped.Add(1)
			listenLog.Warn("dropped request: batcher queue full",
				zap.Stringer("peer", peer),
				zap.Int("size", reqLen),
				zap.Int("queue_size", batchQueueSize),
			)
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
		zap.Uint64("received_total", statsReceived.Load()),
		zap.Uint64("responded_total", statsResponded.Load()),
		zap.Uint64("dropped_total", statsDropped.Load()),
		zap.Uint64("panics_total", statsPanics.Load()),
		zap.Uint64("batches_total", statsBatches.Load()),
		zap.Uint64("batched_reqs_total", statsBatchedReqs.Load()),
		zap.Uint64("batch_errs_total", statsBatchErrs.Load()),
		zap.Duration("drain_duration", time.Since(drainStart)),
	)
	return nil
}

// batcher accumulates validated requests grouped by (version, hasType) and
// flushes them in bulk signing batches. It fires when a batch reaches maxSize
// or when maxLatency has elapsed since the first request in a batch arrived.
func batcher(log *zap.Logger, conn *net.UDPConn, state *atomic.Pointer[certState], incoming <-chan validatedRequest, maxSize int, maxLatency time.Duration) {
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
		flushBatch(log, conn, state, key.version, b.items)
		delete(batches, key)
	}

	// One select-iteration. Returns true when the incoming channel has been
	// closed and any residual batches have been flushed. Panic recovery is
	// per-iteration so batches persists across a recovered panic.
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

			// Drafts 01-02 place NONC inside SREP, preventing multi-request
			// batches. Flush immediately to avoid the noncInSREP rejection.
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

// flushBatch signs a batch and writes responses via WriteToUDP, returning
// pooled read buffers regardless of outcome.
func flushBatch(log *zap.Logger, conn *net.UDPConn, state *atomic.Pointer[certState], ver protocol.Version, items []validatedRequest) {
	defer func() {
		for i := range items {
			if items[i].bufPtr != nil {
				bufPool.Put(items[i].bufPtr)
				items[i].bufPtr = nil
			}
		}
	}()
	defer recoverGoroutine(log, "flushBatch")

	replies := signAndBuildReplies(log, state.Load(), ver, items)
	for _, r := range replies {
		if _, err := conn.WriteToUDP(r.bytes, r.peer); err != nil {
			log.Warn("UDP write failed", zap.Stringer("peer", r.peer), zap.Error(err))
			continue
		}
		statsResponded.Add(1)
		if ce := log.Check(zap.DebugLevel, "sent response"); ce != nil {
			ce.Write(
				zap.Stringer("peer", r.peer),
				zap.Int("size", len(r.bytes)),
				zap.Stringer("version", ver),
			)
		}
	}
}
