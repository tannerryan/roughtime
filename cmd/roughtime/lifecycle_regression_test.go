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

// TestSuperviseLoopRestartsAfterPanic checks both restart and cleanup of state
// owned by the failed invocation.
func TestSuperviseLoopRestartsAfterPanic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	owned := make(chan struct{}, 1)
	owned <- struct{}{}
	var calls atomic.Int32
	startPanics := statsPanics.Load()
	done := make(chan struct{})

	go func() {
		superviseLoop(ctx, zap.NewNop(), "test", func() {
			<-owned
			defer func() { owned <- struct{}{} }()
			if calls.Add(1) == 1 {
				panic("test panic")
			}
			cancel()
		})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("supervisor did not restart after panic")
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("calls=%d want 2", got)
	}
	if got := statsPanics.Load(); got != startPanics+1 {
		t.Fatalf("panic count=%d want %d", got, startPanics+1)
	}
	select {
	case <-owned:
	default:
		t.Fatal("panicking invocation did not release owned state")
	}
}
