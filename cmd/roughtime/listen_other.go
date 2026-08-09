// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

//go:build unix && !linux

package main

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tannerryan/roughtime/protocol"
	"go.uber.org/zap"
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
