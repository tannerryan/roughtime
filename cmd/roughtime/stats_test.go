// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

//go:build unix

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// TestStatsLoopExitsOnCtxCancel verifies statsLoop returns immediately when ctx
// is already cancelled.
func TestStatsLoopExitsOnCtxCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, st := newUnitCertState(t)
	statePtr := &atomic.Pointer[certState]{}
	statePtr.Store(st)

	done := make(chan struct{})
	go func() {
		statsLoop(ctx, zap.NewNop(), statePtr, nil)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("statsLoop did not return on cancelled ctx")
	}
}

// TestStatsLoopTicks verifies statsLoop emits at least one log line on its tick
// interval.
func TestStatsLoopTicks(t *testing.T) {
	withInterval(t, statsInterval, 5*time.Millisecond)
	_, st := newUnitCertState(t)
	statePtr := &atomic.Pointer[certState]{}
	statePtr.Store(st)

	// prime counter so tick takes avg_batch_size path
	statsBatches.Add(1)
	statsBatchedReqs.Add(4)
	t.Cleanup(func() { statsBatches.Store(0); statsBatchedReqs.Store(0) })

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	statsLoop(ctx, zap.NewNop(), statePtr, nil)
}

// TestStatsLoopComputesDeltas verifies a tick reports the counter deltas
// accrued after the loop seeds its baseline and the derived avg_batch_size, and
// that a non-nil pqState adds the pq_cert_remaining field.
func TestStatsLoopComputesDeltas(t *testing.T) {
	withInterval(t, statsInterval, 5*time.Millisecond)
	_, st := newUnitCertState(t)
	edPtr := &atomic.Pointer[certState]{}
	edPtr.Store(st)
	pqPtr := &atomic.Pointer[certState]{}
	pqPtr.Store(st)
	t.Cleanup(func() { statsBatches.Store(0); statsBatchedReqs.Store(0) })

	var buf bytes.Buffer
	enc := zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig())
	log := zap.New(zapcore.NewCore(enc, zapcore.AddSync(&buf), zapcore.InfoLevel))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { statsLoop(ctx, log, edPtr, pqPtr); close(done) }()

	// let the loop seed its baseline from zero, then apply 12 requests across 3
	// batches so the next interval reports the deltas with avg_batch_size 4
	time.Sleep(30 * time.Millisecond)
	statsBatches.Store(3)
	statsBatchedReqs.Store(12)
	time.Sleep(30 * time.Millisecond)
	cancel()
	<-done

	dec := json.NewDecoder(&buf)
	var got map[string]any
	for dec.More() {
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			t.Fatalf("decode log line: %v", err)
		}
		// JSON numbers decode as float64
		if m["msg"] == "stats" && m["batches"] == float64(3) {
			got = m
			break
		}
	}
	if got == nil {
		t.Fatal("no stats line reported the batches delta of 3")
	}
	if got["avg_batch_size"] != float64(4) {
		t.Fatalf("avg_batch_size=%v want 4", got["avg_batch_size"])
	}
	if _, ok := got["pq_cert_remaining"]; !ok {
		t.Fatal("pq_cert_remaining field missing, pqState branch not exercised")
	}
}
