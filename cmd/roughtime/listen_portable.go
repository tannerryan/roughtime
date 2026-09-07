// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

//go:build unix && !linux && !openbsd

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

// socketRecvBuffer is the requested receive-buffer size for each UDP socket.
const socketRecvBuffer = 8 * 1024 * 1024

// listen runs a single-socket UDP server with inline validation and a
// channel-fed batcher.
func listen(ctx context.Context, state *atomic.Pointer[certState]) error {
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

	// readOne does one read-dispatch iteration and returns true on shutdown. A
	// recovered panic discards the in-flight pooled buffer. The garbage
	// collector can reclaim it.
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

// udpConnReplyWriter is the portable one-datagram-at-a-time writer.
type udpConnReplyWriter struct {
	conn *net.UDPConn
}

// writeReplies sends replies one datagram at a time through the portable path.
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
