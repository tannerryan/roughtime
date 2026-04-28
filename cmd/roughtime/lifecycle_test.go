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

// TestRecoverGoroutineAbsorbsPanic verifies recoverGoroutine swallows a panic
// and bumps statsPanics.
func TestRecoverGoroutineAbsorbsPanic(t *testing.T) {
	before := statsPanics.Load()
	func() {
		defer recoverGoroutine(zap.NewNop(), "unit")
		panic("boom")
	}()
	if got := statsPanics.Load(); got != before+1 {
		t.Fatalf("statsPanics delta=%d, want 1", got-before)
	}
}

// TestRecoverGoroutineNoPanicNoOp verifies recoverGoroutine leaves statsPanics
// untouched when no panic occurred.
func TestRecoverGoroutineNoPanicNoOp(t *testing.T) {
	before := statsPanics.Load()
	func() {
		defer recoverGoroutine(zap.NewNop(), "unit")
	}()
	if got := statsPanics.Load(); got != before {
		t.Fatalf("statsPanics changed without panic: %d", got-before)
	}
}

// TestSuperviseLoopRestartsOnPanic verifies superviseLoop restarts fn after a
// panic until ctx is cancelled.
func TestSuperviseLoopRestartsOnPanic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var runs atomic.Int32
	done := make(chan struct{})
	go func() {
		superviseLoop(ctx, zap.NewNop(), "unit", func() {
			n := runs.Add(1)
			if n < 3 {
				panic("induced")
			}
			// third iteration exits cleanly to exercise restart path
		})
		close(done)
	}()

	deadline := time.Now().Add(5 * time.Second)
	for runs.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if runs.Load() < 3 {
		t.Fatalf("superviseLoop did not reach 3 runs (got %d)", runs.Load())
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("superviseLoop did not exit after cancel")
	}
}

// TestSuperviseLoopExitsOnCtxCancel verifies superviseLoop returns immediately
// when ctx is already cancelled.
func TestSuperviseLoopExitsOnCtxCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan struct{})
	var ran atomic.Bool
	go func() {
		superviseLoop(ctx, zap.NewNop(), "unit", func() {
			ran.Store(true)
		})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("superviseLoop did not return on pre-cancelled ctx")
	}
	if ran.Load() {
		t.Fatal("fn ran when ctx was already cancelled")
	}
}
