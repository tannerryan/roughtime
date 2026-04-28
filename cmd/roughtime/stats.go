// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

//go:build unix

package main

import (
	"context"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// statsInterval is the cadence of the periodic stats log.
var statsInterval = 60 * time.Second

// Server-wide counters read by stats loop and shutdown log.
var (
	// statsReceived counts requests that arrived on the listener.
	statsReceived atomic.Uint64
	// statsResponded counts responses written to the wire.
	statsResponded atomic.Uint64
	// statsDropped counts requests that failed to ship for any listener-side
	// reason.
	statsDropped atomic.Uint64
	// statsPanics counts goroutine panics absorbed by recoverGoroutine.
	statsPanics atomic.Uint64
	// statsBatches counts signing batches flushed by either listener.
	statsBatches atomic.Uint64
	// statsBatchedReqs counts requests included in a flushed batch.
	statsBatchedReqs atomic.Uint64
	// statsBatchErrs counts batches that failed to sign.
	statsBatchErrs atomic.Uint64
	// statsAmpDropped counts UDP replies suppressed by the amplification guard.
	statsAmpDropped atomic.Uint64
)

// statsLoop emits a periodic summary of server activity until ctx is cancelled.
func statsLoop(ctx context.Context, log *zap.Logger, edState, pqState *atomic.Pointer[certState]) {
	ticker := time.NewTicker(statsInterval)
	defer ticker.Stop()
	log.Info("stats loop started", zap.Duration("interval", statsInterval))

	var lastReceived, lastResponded, lastDropped, lastPanics, lastBatchCount, lastBatchTotal, lastBatchErrs uint64
	var lastTCPAccepted, lastTCPRejected, lastTCPCompleted, lastAmp uint64
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		r := statsReceived.Load()
		s := statsResponded.Load()
		d := statsDropped.Load()
		p := statsPanics.Load()
		bc := statsBatches.Load()
		bt := statsBatchedReqs.Load()
		be := statsBatchErrs.Load()
		ta := statsTCPAccepted.Load()
		tr := statsTCPRejected.Load()
		tc := statsTCPCompleted.Load()
		amp := statsAmpDropped.Load()
		intervalBatches := bc - lastBatchCount
		var avgBatch float64
		if intervalBatches > 0 {
			avgBatch = float64(bt-lastBatchTotal) / float64(intervalBatches)
		}
		fields := []zap.Field{
			zap.Uint64("received", r-lastReceived),
			zap.Uint64("responded", s-lastResponded),
			zap.Uint64("dropped", d-lastDropped),
			zap.Uint64("panics", p-lastPanics),
			zap.Uint64("batches", intervalBatches),
			zap.Uint64("batch_errs", be-lastBatchErrs),
			zap.Float64("avg_batch_size", avgBatch),
			zap.Uint64("tcp_accepted", ta-lastTCPAccepted),
			zap.Uint64("tcp_rejected", tr-lastTCPRejected),
			zap.Uint64("tcp_completed", tc-lastTCPCompleted),
			zap.Uint64("amp_suppressed", amp-lastAmp),
		}
		if edState != nil {
			fields = append(fields, zap.Duration("cert_remaining", time.Until(edState.Load().expiry)))
		}
		if pqState != nil {
			fields = append(fields, zap.Duration("pq_cert_remaining", time.Until(pqState.Load().expiry)))
		}
		log.Info("stats", fields...)
		lastReceived, lastResponded, lastDropped, lastPanics = r, s, d, p
		lastBatchCount, lastBatchTotal, lastBatchErrs = bc, bt, be
		lastTCPAccepted, lastTCPRejected, lastTCPCompleted = ta, tr, tc
		lastAmp = amp
	}
}
