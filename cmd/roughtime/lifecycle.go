// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

//go:build unix

package main

import (
	"context"
	"time"

	"go.uber.org/zap"
)

// recoverGoroutine logs and absorbs a panic, returning true if one was
// recovered.
func recoverGoroutine(log *zap.Logger, where string) bool {
	if r := recover(); r != nil {
		statsPanics.Add(1)
		log.Error("goroutine panic recovered",
			zap.String("where", where),
			zap.Any("panic", r),
			zap.Stack("stack"),
		)
		return true
	}
	return false
}

// superviseLoop runs fn, restarting it after panic or clean return with a short
// backoff, until ctx is cancelled.
func superviseLoop(ctx context.Context, log *zap.Logger, where string, fn func()) {
	const restartBackoff = time.Second
	for ctx.Err() == nil {
		func() {
			defer recoverGoroutine(log, where)
			fn()
		}()
		if ctx.Err() != nil {
			return
		}
		log.Warn("goroutine exited before shutdown, restarting", zap.String("where", where))
		select {
		case <-ctx.Done():
			return
		case <-time.After(restartBackoff):
		}
	}
}
