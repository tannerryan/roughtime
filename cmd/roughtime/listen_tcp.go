// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

//go:build unix

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tannerryan/roughtime/protocol"
	"go.uber.org/zap"
)

// maxTCPRequestSize bounds the declared body length on a TCP request.
const maxTCPRequestSize uint32 = 8192

// TCP tunables; var so tests can shrink them.
var (
	// maxTCPConnections caps concurrent accepted connections.
	maxTCPConnections int32 = 16384
	// tcpIdleTimeout is the idle wait between requests on a kept-alive
	// connection.
	tcpIdleTimeout = 10 * time.Second
	// tcpReadTimeout bounds the body read after a length prefix.
	tcpReadTimeout = 5 * time.Second
	// tcpWriteTimeout bounds the reply send.
	tcpWriteTimeout = 5 * time.Second
	// tcpShutdownGrace is the drain window for in-flight conns before
	// force-close.
	tcpShutdownGrace = 5 * time.Second
	// acceptErrorBackoff throttles the Accept loop after a transient error.
	acceptErrorBackoff = 50 * time.Millisecond
	// tcpBatchQueueSize caps in-flight submissions to each per-scheme batcher.
	tcpBatchQueueSize = 4096
	// tcpBatchSubmitWait bounds the wait to enqueue when the batcher queue is
	// full.
	tcpBatchSubmitWait = 100 * time.Millisecond
	// maxTCPReplyBytes is the sanity cap for a framed reply.
	maxTCPReplyBytes = 8 * 1024
)

// TCP-specific counters; the statsTCPDrop* counters split statsDropped by
// reason.
var (
	// statsTCPAccepted counts conns accepted by the listener.
	statsTCPAccepted atomic.Uint64
	// statsTCPRejected counts conns closed at accept due to the connection cap.
	statsTCPRejected atomic.Uint64
	// statsTCPCompleted counts request/reply round-trips that finished cleanly.
	statsTCPCompleted atomic.Uint64
	// statsTCPDropFraming counts drops due to bad magic, bad length, or header
	// parse.
	statsTCPDropFraming atomic.Uint64
	// statsTCPDropRead counts drops due to body short-read or read timeout.
	statsTCPDropRead atomic.Uint64
	// statsTCPDropPrepare counts drops due to parse, version, or SRV mismatch.
	statsTCPDropPrepare atomic.Uint64
	// statsTCPDropQueue counts drops due to batcher queue saturation past
	// submit wait.
	statsTCPDropQueue atomic.Uint64
	// statsTCPDropBatchErr counts drops due to batch-level signing or oversize
	// reply.
	statsTCPDropBatchErr atomic.Uint64
	// statsTCPDropWrite counts drops due to a failed socket write.
	statsTCPDropWrite atomic.Uint64
)

// tcpBatchItem is a request submitted to the batcher by a handler.
type tcpBatchItem struct {
	// req is the parsed Roughtime request body.
	req protocol.Request
	// version is the negotiated wire version for this request.
	version protocol.Version
	// hasType records whether the request carries the explicit TYPE tag.
	hasType bool
	// peer is the remote address used for log fields.
	peer net.Addr
	// reply receives the signed response or batch error exactly once.
	reply chan<- tcpBatchReply
}

// tcpBatchReply carries the signed response back to the handler.
type tcpBatchReply struct {
	// bytes is the framed reply on success.
	bytes []byte
	// err is set when the batch failed to sign or produced an oversize reply.
	err error
}

// activeConnSet tracks live conns so shutdown can force-close them after
// tcpShutdownGrace.
type activeConnSet struct {
	// mu guards m.
	mu sync.Mutex
	// m is the live connection set.
	m map[net.Conn]struct{}
}

// (activeConnSet) add registers c so closeAll can reach it during shutdown.
func (s *activeConnSet) add(c net.Conn) {
	s.mu.Lock()
	if s.m == nil {
		s.m = make(map[net.Conn]struct{})
	}
	s.m[c] = struct{}{}
	s.mu.Unlock()
}

// (activeConnSet) remove drops c from the live set.
func (s *activeConnSet) remove(c net.Conn) {
	s.mu.Lock()
	delete(s.m, c)
	s.mu.Unlock()
}

// (activeConnSet) closeAll force-closes every live conn.
func (s *activeConnSet) closeAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for c := range s.m {
		_ = c.Close()
	}
}

// listenTCP serves Roughtime over a dual-stack TCP listener on *port; edState
// and pqState are each nilable.
func listenTCP(ctx context.Context, edState, pqState *atomic.Pointer[certState]) error {
	if edState == nil && pqState == nil {
		return errors.New("listenTCP: no certificate state configured")
	}

	prefs := tcpServerPrefs(edState, pqState)

	tcpLog := logger.Named("tcp")
	addr := net.JoinHostPort("::", strconv.Itoa(*port))
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("binding TCP: %w", err)
	}

	var (
		edBatchCh, pqBatchCh chan tcpBatchItem
		batcherWg            sync.WaitGroup
	)
	if edState != nil {
		edBatchCh = make(chan tcpBatchItem, tcpBatchQueueSize)
		batcherLog := tcpLog.Named("batcher").With(zap.String("scheme", "Ed25519"))
		batcherWg.Go(func() {
			superviseLoop(ctx, batcherLog, "tcpBatcher-ed25519", func() {
				tcpBatcher(batcherLog, edState, edBatchCh, batchMaxSize, batchMaxLatency)
			})
		})
	}
	if pqState != nil {
		pqBatchCh = make(chan tcpBatchItem, tcpBatchQueueSize)
		batcherLog := tcpLog.Named("batcher").With(zap.String("scheme", "ML-DSA-44"))
		batcherWg.Go(func() {
			superviseLoop(ctx, batcherLog, "tcpBatcher-ml-dsa-44", func() {
				tcpBatcher(batcherLog, pqState, pqBatchCh, batchMaxSize, batchMaxLatency)
			})
		})
	}

	tcpLog.Info("listening TCP",
		zap.String("addr", addr),
		zap.Int32("max_conns", maxTCPConnections),
		zap.Uint32("max_request_bytes", maxTCPRequestSize),
		zap.Duration("idle_timeout", tcpIdleTimeout),
		zap.Duration("read_timeout", tcpReadTimeout),
		zap.Duration("write_timeout", tcpWriteTimeout),
		zap.Int("batch_max_size", batchMaxSize),
		zap.Duration("batch_max_latency", batchMaxLatency),
		zap.Int("batch_queue_size", tcpBatchQueueSize),
		zap.Strings("offered_versions", versionNames(prefs)),
	)

	// close listener on shutdown to unblock Accept
	go func() {
		defer recoverGoroutine(tcpLog, "shutdown closer")
		<-ctx.Done()
		_ = ln.Close()
	}()

	var live activeConnSet
	var active atomic.Int32
	var wg sync.WaitGroup

	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			tcpLog.Warn("Accept failed", zap.Error(err))
			// backoff to avoid hot spin; observe ctx.Done so shutdown isn't
			// held
			select {
			case <-time.After(acceptErrorBackoff):
			case <-ctx.Done():
			}
			continue
		}
		statsTCPAccepted.Add(1)
		if active.Load() >= maxTCPConnections {
			_ = c.Close()
			statsTCPRejected.Add(1)
			if ce := tcpLog.Check(zap.DebugLevel, "rejected: max_conns reached"); ce != nil {
				ce.Write(zap.Stringer("peer", c.RemoteAddr()))
			}
			continue
		}
		if tcp, ok := c.(*net.TCPConn); ok {
			_ = tcp.SetNoDelay(true)
		}
		active.Add(1)
		live.add(c)
		wg.Go(func() {
			defer func() {
				live.remove(c)
				active.Add(-1)
				_ = c.Close()
			}()
			defer recoverGoroutine(tcpLog, "tcp conn")
			handleTCPConn(ctx, tcpLog, c, edState, pqState, edBatchCh, pqBatchCh, prefs)
		})
	}

	// graceful drain: wait up to tcpShutdownGrace, then force-close
	drainStart := time.Now()
	done := make(chan struct{})
	go func() {
		defer recoverGoroutine(tcpLog, "shutdown drainer")
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(tcpShutdownGrace):
		live.closeAll()
		<-done
	}

	// handlers exited; close batch channels so batchers flush and return
	if edBatchCh != nil {
		close(edBatchCh)
	}
	if pqBatchCh != nil {
		close(pqBatchCh)
	}
	batcherWg.Wait()

	tcpLog.Info("TCP shutdown complete",
		zap.Duration("drain_duration", time.Since(drainStart)),
		zap.Uint64("accepted_total", statsTCPAccepted.Load()),
		zap.Uint64("rejected_total", statsTCPRejected.Load()),
		zap.Uint64("completed_total", statsTCPCompleted.Load()),
		zap.Uint64("received_total", statsReceived.Load()),
		zap.Uint64("responded_total", statsResponded.Load()),
		zap.Uint64("dropped_total", statsDropped.Load()),
		zap.Uint64("drop_framing_total", statsTCPDropFraming.Load()),
		zap.Uint64("drop_read_total", statsTCPDropRead.Load()),
		zap.Uint64("drop_prepare_total", statsTCPDropPrepare.Load()),
		zap.Uint64("drop_queue_total", statsTCPDropQueue.Load()),
		zap.Uint64("drop_batch_err_total", statsTCPDropBatchErr.Load()),
		zap.Uint64("drop_write_total", statsTCPDropWrite.Load()),
		zap.Uint64("batches_total", statsBatches.Load()),
		zap.Uint64("batched_reqs_total", statsBatchedReqs.Load()),
		zap.Uint64("batch_errs_total", statsBatchErrs.Load()),
		zap.Uint64("panics_total", statsPanics.Load()),
	)
	return nil
}

// tcpReqBufPool pools read buffers sized to hold the ROUGHTIM header plus the
// max allowed body.
var tcpReqBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, protocol.PacketHeaderSize+int(maxTCPRequestSize))
		return &b
	},
}

// handleTCPConn reads framed Roughtime packets until idle timeout or peer
// close, batching each via the per-scheme batcher.
func handleTCPConn(ctx context.Context, log *zap.Logger, conn net.Conn, edState, pqState *atomic.Pointer[certState], edBatchCh, pqBatchCh chan<- tcpBatchItem, prefs []protocol.Version) {
	reqBufPtr := tcpReqBufPool.Get().(*[]byte)
	defer tcpReqBufPool.Put(reqBufPtr)
	reqBuf := *reqBufPtr
	// reused across requests; handler is sequential (read → submit → wait →
	// write → next read) so the channel is always drained before next submit
	replyCh := make(chan tcpBatchReply, 1)

	for {
		// idle timeout covers both initial wait and between-request wait
		_ = conn.SetReadDeadline(time.Now().Add(tcpIdleTimeout))
		hdr := reqBuf[:protocol.PacketHeaderSize]
		if _, err := io.ReadFull(conn, hdr); err != nil {
			// EOF / idle timeout / peer close — all terminal
			return
		}
		bodyLen, err := protocol.ParsePacketHeader(hdr)
		if err != nil {
			statsDropped.Add(1)
			statsTCPDropFraming.Add(1)
			if ce := log.Check(zap.DebugLevel, "TCP bad header"); ce != nil {
				ce.Write(zap.Stringer("peer", conn.RemoteAddr()), zap.Error(err))
			}
			return
		}
		if bodyLen == 0 || bodyLen > maxTCPRequestSize {
			statsDropped.Add(1)
			statsTCPDropFraming.Add(1)
			if ce := log.Check(zap.DebugLevel, "TCP bad length"); ce != nil {
				ce.Write(zap.Stringer("peer", conn.RemoteAddr()), zap.Uint32("len", bodyLen))
			}
			return
		}

		// bound body read so a slow sender can't hold the slot; read in place
		// so prepareTCPItem gets the full framed packet
		_ = conn.SetReadDeadline(time.Now().Add(tcpReadTimeout))
		pkt := reqBuf[:protocol.PacketHeaderSize+int(bodyLen)]
		if _, err := io.ReadFull(conn, pkt[protocol.PacketHeaderSize:]); err != nil {
			statsDropped.Add(1)
			statsTCPDropRead.Add(1)
			if ce := log.Check(zap.DebugLevel, "TCP short read"); ce != nil {
				ce.Write(zap.Stringer("peer", conn.RemoteAddr()), zap.Error(err))
			}
			return
		}
		statsReceived.Add(1)

		item, ch, err := prepareTCPItem(log, conn.RemoteAddr(), pkt, edState, pqState, edBatchCh, pqBatchCh, prefs)
		if err != nil {
			statsDropped.Add(1)
			statsTCPDropPrepare.Add(1)
			return
		}

		// fast path non-blocking; on a queue spike, fall back to a short
		// bounded wait so a transient burst doesn't tear down every conn
		item.reply = replyCh
		select {
		case ch <- item:
		default:
			submitTimer := time.NewTimer(tcpBatchSubmitWait)
			select {
			case ch <- item:
				submitTimer.Stop()
			case <-ctx.Done():
				submitTimer.Stop()
				return
			case <-submitTimer.C:
				statsDropped.Add(1)
				statsTCPDropQueue.Add(1)
				if ce := log.Check(zap.WarnLevel, "TCP batcher queue full"); ce != nil {
					ce.Write(zap.Stringer("peer", conn.RemoteAddr()))
				}
				return
			}
		}

		// wait for batcher to sign; ctx.Done() unblocks on shutdown. Peek
		// replyCh first so a reply already produced by the batcher isn't
		// discarded by a racing ctx cancellation
		var br tcpBatchReply
		select {
		case br = <-replyCh:
		default:
			select {
			case br = <-replyCh:
			case <-ctx.Done():
				return
			}
		}
		if br.err != nil {
			// batch-level failure already logged by flushTCPBatch
			statsDropped.Add(1)
			statsTCPDropBatchErr.Add(1)
			return
		}

		_ = conn.SetWriteDeadline(time.Now().Add(tcpWriteTimeout))
		if err := writeTCPReply(conn, br.bytes); err != nil {
			statsDropped.Add(1)
			statsTCPDropWrite.Add(1)
			if ce := log.Check(zap.DebugLevel, "TCP write failed"); ce != nil {
				ce.Write(zap.Stringer("peer", conn.RemoteAddr()), zap.Error(err))
			}
			return
		}
		statsResponded.Add(1)
		statsTCPCompleted.Add(1)
	}
}

// prepareTCPItem parses, negotiates, and SRV-checks reqBytes, returning the
// tcpBatchItem and destination batch channel.
func prepareTCPItem(log *zap.Logger, peer net.Addr, reqBytes []byte, edState, pqState *atomic.Pointer[certState], edBatchCh, pqBatchCh chan<- tcpBatchItem, prefs []protocol.Version) (tcpBatchItem, chan<- tcpBatchItem, error) {
	req, err := protocol.ParseRequest(reqBytes)
	if err != nil {
		if ce := log.Check(zap.DebugLevel, "request parse failed"); ce != nil {
			ce.Write(zap.Stringer("peer", peer), zap.Int("size", len(reqBytes)), zap.Error(err))
		}
		return tcpBatchItem{}, nil, err
	}
	ver, err := protocol.SelectVersion(req.Versions, len(req.Nonce), prefs)
	if err != nil {
		if ce := log.Check(zap.DebugLevel, "version negotiation failed"); ce != nil {
			ce.Write(zap.Stringer("peer", peer), zap.Error(err))
		}
		return tcpBatchItem{}, nil, err
	}
	st, ch, err := tcpRouteForVersion(ver, edState, pqState, edBatchCh, pqBatchCh)
	if err != nil {
		if ce := log.Check(zap.DebugLevel, "TCP route unavailable"); ce != nil {
			ce.Write(zap.Stringer("peer", peer), zap.Error(err))
		}
		return tcpBatchItem{}, nil, err
	}
	// drafts 10+: reject SRV not addressing a key we control
	if req.SRV != nil && !bytes.Equal(req.SRV, st.srvHash) {
		if ce := log.Check(zap.DebugLevel, "SRV mismatch"); ce != nil {
			ce.Write(zap.Stringer("peer", peer))
		}
		return tcpBatchItem{}, nil, errors.New("SRV mismatch")
	}
	return tcpBatchItem{req: *req, version: ver, hasType: req.HasType, peer: peer}, ch, nil
}

// tcpRouteForVersion picks the certState snapshot and batcher channel for ver's
// scheme.
func tcpRouteForVersion(ver protocol.Version, edState, pqState *atomic.Pointer[certState], edBatchCh, pqBatchCh chan<- tcpBatchItem) (*certState, chan<- tcpBatchItem, error) {
	if ver == protocol.VersionMLDSA44 {
		if pqState == nil || pqBatchCh == nil {
			return nil, nil, errors.New("PQ version selected but no PQ state configured")
		}
		return pqState.Load(), pqBatchCh, nil
	}
	if edState == nil || edBatchCh == nil {
		return nil, nil, errors.New("Ed25519 version selected but no Ed25519 state configured")
	}
	return edState.Load(), edBatchCh, nil
}

// tcpBatcher accumulates requests by (version, hasType) and flushes on size or
// latency triggers.
func tcpBatcher(log *zap.Logger, state *atomic.Pointer[certState], incoming <-chan tcpBatchItem, maxSize int, maxLatency time.Duration) {
	type pending struct {
		items []tcpBatchItem
		start time.Time
	}
	batches := make(map[batchKey]*pending)

	defer func() {
		r := recover()
		if r == nil {
			return
		}
		statsPanics.Add(1)
		log.Error("tcp batcher panic recovered",
			zap.Any("panic", r),
			zap.Stack("stack"),
		)
		err := fmt.Errorf("tcp batcher panic: %v", r)
		for _, b := range batches {
			for _, it := range b.items {
				select {
				case it.reply <- tcpBatchReply{err: err}:
				default:
				}
			}
		}
	}()

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
		flushTCPBatch(log, state.Load(), key.version, b.items)
		delete(batches, key)
	}

	for {
		select {
		case it, ok := <-incoming:
			if !ok {
				for key := range batches {
					flush(key)
				}
				return
			}
			key := batchKey{version: it.version, hasType: it.hasType}
			b, exists := batches[key]
			if !exists {
				b = &pending{items: make([]tcpBatchItem, 0, maxSize), start: time.Now()}
				batches[key] = b
			}
			b.items = append(b.items, it)
			// NoncInSREP versions cannot batch; flush immediately
			if protocol.NoncInSREP(it.version, it.hasType) || len(b.items) >= maxSize {
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
	}
}

// flushTCPBatch signs a homogeneous batch and dispatches each reply back to its
// handler.
func flushTCPBatch(log *zap.Logger, st *certState, ver protocol.Version, items []tcpBatchItem) {
	delivered := make([]bool, len(items))
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		statsPanics.Add(1)
		log.Error("flushTCPBatch panic recovered",
			zap.Stringer("version", ver),
			zap.Int("batch_size", len(items)),
			zap.Any("panic", r),
			zap.Stack("stack"),
		)
		err := fmt.Errorf("flushTCPBatch panic: %v", r)
		for i := range items {
			if delivered[i] {
				continue
			}
			select {
			case items[i].reply <- tcpBatchReply{err: err}:
			default:
			}
		}
	}()

	reqs := make([]protocol.Request, len(items))
	for i := range items {
		reqs[i] = items[i].req
	}
	// zero midpoint defers timestamping to CreateReplies
	replies, err := protocol.CreateReplies(ver, reqs, time.Time{}, radius, st.cert)
	if err != nil {
		statsBatchErrs.Add(1)
		log.Warn("batch CreateReplies failed",
			zap.Stringer("version", ver),
			zap.Int("batch_size", len(items)),
			zap.Error(err),
		)
		for i := range items {
			select {
			case items[i].reply <- tcpBatchReply{err: err}:
			default:
			}
			delivered[i] = true
		}
		return
	}
	statsBatches.Add(1)
	statsBatchedReqs.Add(uint64(len(items)))
	for i, reply := range replies {
		if *greaseRate > 0 && mrand.Float64() < *greaseRate {
			if greased := protocol.Grease(reply, ver); greased != nil {
				reply = greased
				if ce := log.Check(zap.DebugLevel, "greased response"); ce != nil {
					ce.Write(zap.Stringer("peer", items[i].peer))
				}
			}
		}
		// signing-bug guard: oversized replies indicate a CreateReplies/Grease
		// bug; fail the handler with an error rather than write garbage on the
		// wire
		var br tcpBatchReply
		if len(reply) > maxTCPReplyBytes {
			log.Warn("oversize TCP reply rejected",
				zap.Stringer("peer", items[i].peer),
				zap.Stringer("version", ver),
				zap.Int("reply_size", len(reply)),
				zap.Int("max", maxTCPReplyBytes),
			)
			br = tcpBatchReply{err: fmt.Errorf("reply size %d exceeds sanity bound %d", len(reply), maxTCPReplyBytes)}
		} else {
			br = tcpBatchReply{bytes: reply}
		}
		// non-blocking: a full buffer means the handler already returned
		select {
		case items[i].reply <- br:
		default:
		}
		delivered[i] = true
	}
}

// tcpServerPrefs builds the offered preference list with PQ first when
// configured and VersionGoogle filtered out.
func tcpServerPrefs(edState, pqState *atomic.Pointer[certState]) []protocol.Version {
	var prefs []protocol.Version
	if pqState != nil {
		prefs = append(prefs, protocol.ServerPreferenceMLDSA44...)
	}
	if edState != nil {
		for _, v := range protocol.ServerPreferenceEd25519 {
			if v == protocol.VersionGoogle {
				continue
			}
			prefs = append(prefs, v)
		}
	}
	return prefs
}

// writeTCPReply writes an already-framed reply to w, rejecting payloads over
// maxTCPReplyBytes before any bytes are sent.
func writeTCPReply(w io.Writer, reply []byte) error {
	if len(reply) > maxTCPReplyBytes {
		return fmt.Errorf("reply size %d exceeds sanity bound %d", len(reply), maxTCPReplyBytes)
	}
	_, err := w.Write(reply)
	return err
}

// versionNames renders a preference list as readable names for structured logs.
func versionNames(vs []protocol.Version) []string {
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = v.String()
	}
	return out
}
