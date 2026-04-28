// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

//go:build unix

package main

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
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
	withInterval(t, &statsInterval, 5*time.Millisecond)
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
