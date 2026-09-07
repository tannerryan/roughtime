// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package main

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestValidateFlagsCombinedDuration covers the largest non-overflowing sum and
// a pair of individually valid durations whose sum would wrap negative.
func TestValidateFlagsCombinedDuration(t *testing.T) {
	savedWorkers, savedDuration, savedWarmup := *workers, *duration, *warmup
	savedTimeout, savedPubkey := *timeout, *pubkey
	t.Cleanup(func() {
		*workers, *duration, *warmup = savedWorkers, savedDuration, savedWarmup
		*timeout, *pubkey = savedTimeout, savedPubkey
	})
	*workers = 1
	*timeout = time.Second
	*pubkey = "test"
	maxDuration := time.Duration(1<<63 - 1)
	*duration = maxDuration - 1
	*warmup = 1
	if err := validateFlags(); err != nil {
		t.Fatalf("largest duration sum rejected: %v", err)
	}
	*duration = maxDuration
	*warmup = 1
	if err := validateFlags(); err == nil || !strings.Contains(err.Error(), "exceeds maximum") {
		t.Fatalf("overflowing duration sum error = %v", err)
	}
}

// TestCaptureContextStop checks cancellation timing before worker cleanup.
func TestCaptureContextStop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stoppedAt := captureContextStop(ctx)
	beforeCancel := time.Now()
	cancel()
	select {
	case got := <-stoppedAt:
		if got.Before(beforeCancel) || got.After(time.Now()) {
			t.Fatalf("stop instant %v is outside the cancellation interval", got)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation time was not reported")
	}
}
