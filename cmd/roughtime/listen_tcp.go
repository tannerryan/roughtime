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
	"sync"
	"sync/atomic"
	"time"

	"github.com/tannerryan/roughtime/protocol"
	"go.uber.org/zap"
)

// maxTCPRequestSize bounds the declared body length on a TCP request.
const maxTCPRequestSize uint32 = 8192

// tcpReqBufPool pools read buffers sized to hold the ROUGHTIM header plus the
// max allowed body.
var tcpReqBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, protocol.PacketHeaderSize+int(maxTCPRequestSize))
		return &b
	},
}

// TCP tunables are variables so tests can override them.
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

var (
	// statsTCPAccepted counts connections returned by Accept.
	statsTCPAccepted atomic.Uint64
	// statsTCPRejected counts connections closed at the connection cap.
	statsTCPRejected atomic.Uint64
	// statsTCPCompleted counts successful request/reply round trips.
	statsTCPCompleted atomic.Uint64
)

// tcpBatchItem carries a validated request to a scheme batcher.
type tcpBatchItem struct {
	req     protocol.Request
	version protocol.Version
	hasType bool
	peer    net.Addr
	reply   chan<- tcpBatchReply
}

// tcpBatchReply carries a framed reply or batch error.
type tcpBatchReply struct {
	bytes []byte
	err   error
}

// activeConnSet tracks live connections for forced shutdown.
type activeConnSet struct {
	mu sync.Mutex
	m  map[net.Conn]struct{}
}

// add records c as active.
func (s *activeConnSet) add(c net.Conn) {
	s.mu.Lock()
	if s.m == nil {
		s.m = make(map[net.Conn]struct{})
	}
	s.m[c] = struct{}{}
	s.mu.Unlock()
}

// remove stops tracking c.
func (s *activeConnSet) remove(c net.Conn) {
	s.mu.Lock()
	delete(s.m, c)
	s.mu.Unlock()
}

// closeAll closes every tracked connection.
func (s *activeConnSet) closeAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for c := range s.m {
		_ = c.Close()
	}
}

// listenTCP serves Roughtime over a dual-stack TCP listener on *port. edState
// and pqState are each nilable.
func listenTCP(ctx context.Context, edState, pqState *atomic.Pointer[certState]) error {
	if edState == nil && pqState == nil {
		return errors.New("listenTCP: no certificate state configured")
	}

	prefs := tcpServerPrefs(edState, pqState)

	tcpLog := logger.Named("tcp")
	addr := serverListenAddr()
	networks := listenNetworks("tcp", addr)

	var lc net.ListenConfig
	lns := make([]net.Listener, 0, len(networks))
	for _, network := range networks {
		ln, err := lc.Listen(ctx, network, addr)
		if err != nil {
			for _, prev := range lns {
				_ = prev.Close()
			}
			return fmt.Errorf("binding %s: %w", network, err)
		}
		lns = append(lns, ln)
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
		zap.Strings("networks", networks),
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

	// close listeners on shutdown to unblock Accept
	go func() {
		<-ctx.Done()
		for _, ln := range lns {
			_ = ln.Close()
		}
	}()

	var live activeConnSet
	var active atomic.Int32
	var wg sync.WaitGroup

	// accept serves one listener until ctx is done or it stops accepting.
	accept := func(ln net.Listener) {
		for {
			c, err := ln.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				tcpLog.Warn("Accept failed", zap.Error(err))
				// backoff to avoid hot spin, and observe ctx.Done so shutdown
				// isn't held
				select {
				case <-time.After(acceptErrorBackoff):
				case <-ctx.Done():
				}
				continue
			}
			statsTCPAccepted.Add(1)
			// reserve the slot before checking so concurrent accept loops can't
			// both admit the last connection
			if active.Add(1) > maxTCPConnections {
				active.Add(-1)
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
	}

	var acceptWg sync.WaitGroup
	for _, ln := range lns {
		acceptWg.Go(func() {
			accept(ln)
		})
	}
	acceptWg.Wait()

	// graceful drain: wait up to tcpShutdownGrace, then force-close
	drainStart := time.Now()
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(tcpShutdownGrace):
		live.closeAll()
		<-done
	}

	// handlers exited, so close batch channels to make batchers flush and
	// return
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
		zap.Uint64("received_total", requestsReceived.total()),
		zap.Uint64("responded_total", requestsResponded.total()),
		zap.Uint64("dropped_total", requestsDropped.total()),
		zap.Uint64("drop_framing_total", droppedFor(transportTCP, dropFraming)),
		zap.Uint64("drop_oversize_total", droppedFor(transportTCP, dropOversize)),
		zap.Uint64("drop_read_total", droppedFor(transportTCP, dropRead)),
		zap.Uint64("drop_parse_total", droppedFor(transportTCP, dropParse)),
		zap.Uint64("drop_version_total", droppedFor(transportTCP, dropVersion)),
		zap.Uint64("drop_config_total", droppedFor(transportTCP, dropConfig)),
		zap.Uint64("drop_srv_total", droppedFor(transportTCP, dropSRV)),
		zap.Uint64("drop_queue_total", droppedFor(transportTCP, dropQueue)),
		zap.Uint64("drop_batch_err_total", droppedFor(transportTCP, dropBatchErr)),
		zap.Uint64("drop_write_total", droppedFor(transportTCP, dropWrite)),
		zap.Uint64("batches_total", statsBatches.Load()),
		zap.Uint64("batched_reqs_total", statsBatchedReqs.Load()),
		zap.Uint64("batch_errs_total", statsBatchErrs.Load()),
		zap.Uint64("panics_total", statsPanics.Load()),
	)
	return nil
}

// handleTCPConn processes framed Roughtime packets sequentially until idle
// timeout, cancellation, or peer close.
func handleTCPConn(ctx context.Context, log *zap.Logger, conn net.Conn, edState, pqState *atomic.Pointer[certState], edBatchCh, pqBatchCh chan<- tcpBatchItem, prefs []protocol.Version) {
	reqBufPtr := tcpReqBufPool.Get().(*[]byte)
	// a submitted-but-unanswered item still aliases reqBuf inside the batcher,
	// so skip recycling the buffer if we return before the reply arrives
	outstanding := false
	defer func() {
		if !outstanding {
			tcpReqBufPool.Put(reqBufPtr)
		}
	}()
	reqBuf := *reqBufPtr
	// reused across requests. The handler is sequential (read, submit, wait,
	// write, then next read) so the channel is always drained before next
	// submit
	replyCh := make(chan tcpBatchReply, 1)

	for {
		// idle timeout covers both initial wait and between-request wait
		_ = conn.SetReadDeadline(time.Now().Add(tcpIdleTimeout))
		hdr := reqBuf[:protocol.PacketHeaderSize]
		if _, err := io.ReadFull(conn, hdr); err != nil {
			// EOF, idle timeout, or peer close, all terminal
			return
		}
		bodyLen, err := protocol.ParsePacketHeader(hdr)
		if err != nil {
			incDropped(transportTCP, dropFraming)
			if ce := log.Check(zap.DebugLevel, "TCP bad header"); ce != nil {
				ce.Write(zap.Stringer("peer", conn.RemoteAddr()), zap.Error(err))
			}
			return
		}
		if bodyLen == 0 {
			incDropped(transportTCP, dropFraming)
			if ce := log.Check(zap.DebugLevel, "TCP zero body length"); ce != nil {
				ce.Write(zap.Stringer("peer", conn.RemoteAddr()))
			}
			return
		}
		if bodyLen > maxTCPRequestSize {
			incDropped(transportTCP, dropOversize)
			if ce := log.Check(zap.DebugLevel, "TCP oversize body"); ce != nil {
				ce.Write(zap.Stringer("peer", conn.RemoteAddr()), zap.Uint32("len", bodyLen))
			}
			return
		}

		// bound body read so a slow sender can't hold the slot, read in place
		// so prepareTCPItem gets the full framed packet
		_ = conn.SetReadDeadline(time.Now().Add(tcpReadTimeout))
		pkt := reqBuf[:protocol.PacketHeaderSize+int(bodyLen)]
		if _, err := io.ReadFull(conn, pkt[protocol.PacketHeaderSize:]); err != nil {
			incDropped(transportTCP, dropRead)
			if ce := log.Check(zap.DebugLevel, "TCP short read"); ce != nil {
				ce.Write(zap.Stringer("peer", conn.RemoteAddr()), zap.Error(err))
			}
			return
		}

		item, ch, reason, err := prepareTCPItem(log, conn.RemoteAddr(), pkt, edState, pqState, edBatchCh, pqBatchCh, prefs)
		if err != nil {
			incDropped(transportTCP, reason)
			return
		}
		scheme := schemeForVersion(item.version)
		incReceived(transportTCP, scheme)

		// fast path is non-blocking. On a queue spike, fall back to a short
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
				incDropped(transportTCP, dropQueue)
				if ce := log.Check(zap.DebugLevel, "TCP batcher queue full"); ce != nil {
					ce.Write(zap.Stringer("peer", conn.RemoteAddr()))
				}
				return
			}
		}
		outstanding = true

		// wait for batcher to sign. ctx.Done() unblocks on shutdown. Peek
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
		outstanding = false
		if br.err != nil {
			// The drop metric records certificate-state and signing failures.
			incDropped(transportTCP, dropBatchErr)
			return
		}

		_ = conn.SetWriteDeadline(time.Now().Add(tcpWriteTimeout))
		if err := writeTCPReply(conn, br.bytes); err != nil {
			incDropped(transportTCP, dropWrite)
			if ce := log.Check(zap.DebugLevel, "TCP write failed"); ce != nil {
				ce.Write(zap.Stringer("peer", conn.RemoteAddr()), zap.Error(err))
			}
			return
		}
		incResponded(transportTCP, scheme, 1)
		statsTCPCompleted.Add(1)
	}
}

// prepareTCPItem parses, negotiates, and SRV-checks reqBytes, returning the
// tcpBatchItem and destination batch channel. On failure the dropReason
// classifies the rejection; success returns dropNone.
func prepareTCPItem(log *zap.Logger, peer net.Addr, reqBytes []byte, edState, pqState *atomic.Pointer[certState], edBatchCh, pqBatchCh chan<- tcpBatchItem, prefs []protocol.Version) (tcpBatchItem, chan<- tcpBatchItem, dropReason, error) {
	req, err := protocol.ParseRequest(reqBytes)
	if err != nil {
		if ce := log.Check(zap.DebugLevel, "request parse failed"); ce != nil {
			ce.Write(zap.Stringer("peer", peer), zap.Int("size", len(reqBytes)), zap.Error(err))
		}
		return tcpBatchItem{}, nil, dropParse, err
	}
	routePrefs := prefs
	if req.SRV != nil {
		routePrefs = filterTCPPrefsBySRV(prefs, req.SRV, edState, pqState)
		if len(routePrefs) == 0 {
			if ce := log.Check(zap.DebugLevel, "SRV mismatch"); ce != nil {
				ce.Write(zap.Stringer("peer", peer))
			}
			return tcpBatchItem{}, nil, dropSRV, errors.New("SRV mismatch")
		}
	}
	ver, err := protocol.SelectVersion(req.Versions, len(req.Nonce), routePrefs)
	if err != nil {
		if ce := log.Check(zap.DebugLevel, "version negotiation failed"); ce != nil {
			ce.Write(zap.Stringer("peer", peer), zap.Error(err))
		}
		return tcpBatchItem{}, nil, dropVersion, err
	}
	st, ch, err := tcpRouteForVersion(ver, edState, pqState, edBatchCh, pqBatchCh)
	if err != nil {
		if ce := log.Check(zap.DebugLevel, "TCP route unavailable"); ce != nil {
			ce.Write(zap.Stringer("peer", peer), zap.Error(err))
		}
		return tcpBatchItem{}, nil, dropConfig, err
	}
	if req.SRV != nil && (st == nil || !bytes.Equal(req.SRV, st.srvHash)) {
		if ce := log.Check(zap.DebugLevel, "SRV mismatch"); ce != nil {
			ce.Write(zap.Stringer("peer", peer))
		}
		return tcpBatchItem{}, nil, dropSRV, errors.New("SRV mismatch")
	}
	return tcpBatchItem{req: *req, version: ver, hasType: req.HasType, peer: peer}, ch, dropNone, nil
}

// filterTCPPrefsBySRV keeps only versions whose configured key matches srv.
func filterTCPPrefsBySRV(prefs []protocol.Version, srv []byte, edState, pqState *atomic.Pointer[certState]) []protocol.Version {
	out := make([]protocol.Version, 0, len(prefs))
	for _, v := range prefs {
		var st *certState
		if v == protocol.VersionMLDSA44 {
			if pqState != nil {
				st = pqState.Load()
			}
		} else if edState != nil {
			st = edState.Load()
		}
		if st != nil && bytes.Equal(srv, st.srvHash) {
			out = append(out, v)
		}
	}
	return out
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
	// pending holds one keyed batch and its first-arrival time.
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
		flushTCPBatchCurrent(log, state, key.version, b.items)
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
			// NoncInSREP versions cannot batch, so flush immediately
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

// flushTCPBatchCurrent signs with the currently published certificate, retrying
// a concurrent rotation before beginning the operation.
func flushTCPBatchCurrent(log *zap.Logger, state *atomic.Pointer[certState], ver protocol.Version, items []tcpBatchItem) {
	st := acquireCurrent(state)
	if st == nil {
		deliverTCPBatchError(items, errors.New("active certificate unavailable"))
		return
	}
	defer st.release()
	now := wallClockNow()
	if now.Before(st.notBefore) || !now.Before(st.expiry) {
		err := errors.New("active certificate expired")
		if now.Before(st.notBefore) {
			err = errors.New("active certificate is not yet valid")
		}
		deliverTCPBatchError(items, err)
		return
	}

	reqs := make([]protocol.Request, len(items))
	for i := range items {
		reqs[i] = items[i].req
	}
	// zero midpoint defers timestamping to CreateReplies
	replies, err := protocol.CreateReplies(ver, reqs, time.Time{}, radius, st.cert)
	if err != nil {
		log.Warn("batch CreateReplies failed",
			zap.Stringer("version", ver),
			zap.Int("batch_size", len(items)),
			zap.Error(err),
		)
		deliverTCPBatchError(items, err)
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
		// non-blocking: a full buffer means the handler already returned
		select {
		case items[i].reply <- tcpBatchReply{bytes: reply}:
		default:
		}
	}
}

// deliverTCPBatchError reports a batch failure to each waiting request.
func deliverTCPBatchError(items []tcpBatchItem, err error) {
	statsBatchErrs.Add(1)
	for i := range items {
		select {
		case items[i].reply <- tcpBatchReply{err: err}:
		default:
		}
	}
}

// tcpServerPrefs builds the server's internal preference list with PQ first
// when configured and VersionGoogle omitted.
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

// writeTCPReply writes one bounded reply and rejects short writes.
func writeTCPReply(conn net.Conn, reply []byte) error {
	if len(reply) > maxTCPReplyBytes {
		return fmt.Errorf("reply size %d exceeds sanity bound %d", len(reply), maxTCPReplyBytes)
	}
	n, err := conn.Write(reply)
	if err == nil && n != len(reply) {
		return io.ErrShortWrite
	}
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
