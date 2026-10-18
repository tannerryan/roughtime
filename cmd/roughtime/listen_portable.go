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

// socketRecvBuffer is the requested receive-buffer size for each UDP socket.
const socketRecvBuffer = 8 * 1024 * 1024

// listen serves UDP sockets through the portable path and drains them on
// cancellation.
func listen(ctx context.Context, state *atomic.Pointer[certState], listenPort int) error {
	log := logger.Named("listener")
	addr := serverListenAddr(listenPort)
	networks := listenNetworks("udp", addr)
	conns := make([]*net.UDPConn, 0, len(networks))
	// closeAll also releases sockets bound before a startup failure.
	closeAll := func() {
		for _, conn := range conns {
			_ = conn.Close()
		}
	}
	for _, network := range networks {
		udpAddr, err := net.ResolveUDPAddr(network, addr)
		if err != nil {
			closeAll()
			return fmt.Errorf("resolving %s listen address: %w", network, err)
		}
		conn, err := net.ListenUDP(network, udpAddr)
		if err != nil {
			closeAll()
			return fmt.Errorf("starting %s server: %w", network, err)
		}
		applyReadBuffer(log, conn)
		conns = append(conns, conn)
	}
	log.Info("listening",
		zap.String("addr", addr),
		zap.Strings("networks", networks),
		zap.Int("port", listenPort),
		zap.Int("queue_size", batchQueueSize),
	)

	// Deadlines unblock reads while queued replies retain socket ownership.
	go func() {
		<-ctx.Done()
		for _, conn := range conns {
			_ = conn.SetDeadline(time.Unix(1, 0))
		}
	}()
	var wg sync.WaitGroup
	for _, conn := range conns {
		wg.Go(func() {
			serveUDP(ctx, log.With(zap.Stringer("addr", conn.LocalAddr())), state, conn, isFlexPort(listenPort))
		})
	}
	<-ctx.Done()
	drainStart := time.Now()
	wg.Wait()
	closeAll()
	log.Info("shutdown complete",
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

// serveUDP validates one socket's datagrams and drains its batcher on shutdown.
func serveUDP(ctx context.Context, log *zap.Logger, state *atomic.Pointer[certState], conn *net.UDPConn, allowDrafts bool) {
	batchCh := make(chan validatedRequest, batchQueueSize)
	var batcherWg sync.WaitGroup
	batcherWg.Go(func() {
		batcher(ctx, log.Named("batcher"), udpConnReplyWriter{conn: conn}, state, batchCh, batchMaxSize, batchMaxLatency)
	})
	// readOne does one read-dispatch iteration and returns true on shutdown. A
	// recovered panic discards the in-flight pooled buffer. The garbage
	// collector can reclaim it.
	readOne := func() bool {
		defer recoverGoroutine(log, "listen")

		bufPtr := bufPool.Get().(*[]byte)
		reqLen, _, flags, peer, err := conn.ReadMsgUDP(*bufPtr, nil)
		if err != nil {
			bufPool.Put(bufPtr)
			if ctx.Err() != nil {
				return true
			}
			log.Warn("UDP read error", zap.Error(err))
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
			if ce := log.Check(zap.DebugLevel, "dropped truncated UDP request"); ce != nil {
				ce.Write(zap.Stringer("peer", peer), zap.Int("reported_size", reqLen), zap.Int("buffer_size", len(*bufPtr)))
			}
			return false
		}
		// Responses to undersized requests are optional.
		if reqLen < minRequestSize {
			bufPool.Put(bufPtr)
			incDropped(transportUDP, dropUndersize)
			if ce := log.Check(zap.DebugLevel, "dropped undersize request"); ce != nil {
				ce.Write(zap.Stringer("peer", peer), zap.Int("size", reqLen))
			}
			return false
		}
		vr, reason, ok := validateRequest(log, (*bufPtr)[:reqLen], peer, reqLen, bufPtr, state.Load(), allowDrafts)
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
			if ce := log.Check(zap.DebugLevel, "dropped request: batcher queue full"); ce != nil {
				ce.Write(zap.Stringer("peer", peer), zap.Int("size", reqLen), zap.Int("queue_size", batchQueueSize))
			}
		}
		return false
	}
	for !readOne() {
	}

	close(batchCh)
	batcherWg.Wait()
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
