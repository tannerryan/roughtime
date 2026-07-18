// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package roughtime_test

import (
	"errors"
	"testing"
	"time"

	"github.com/tannerryan/roughtime"
)

// TestConsensus covers drift summary calculation.
func TestConsensus(t *testing.T) {
	mk := func(d time.Duration, ok bool) roughtime.Result {
		if !ok {
			return roughtime.Result{Err: errors.New("x")}
		}
		now := time.Now()
		return roughtime.Result{Response: &roughtime.Response{Midpoint: now.Add(d), LocalNow: now}}
	}
	results := []roughtime.Result{
		mk(50*time.Millisecond, true),
		mk(0, false), // failure: ignored
		mk(100*time.Millisecond, true),
		mk(150*time.Millisecond, true),
	}
	c := roughtime.Consensus(results)
	if c.Samples != 3 {
		t.Fatalf("Samples = %d, want 3", c.Samples)
	}
	if c.Median != 100*time.Millisecond {
		t.Fatalf("Median = %s, want 100ms", c.Median)
	}
	if c.Min != 50*time.Millisecond || c.Max != 150*time.Millisecond {
		t.Fatalf("Min/Max = %s/%s, want 50ms/150ms", c.Min, c.Max)
	}

	if got := roughtime.Consensus(nil); got.Samples != 0 {
		t.Fatalf("empty: Samples = %d, want 0", got.Samples)
	}
}

// TestConsensusEvenN covers the upper-middle choice for even samples.
func TestConsensusEvenN(t *testing.T) {
	mk := func(d time.Duration) roughtime.Result {
		now := time.Now()
		return roughtime.Result{Response: &roughtime.Response{Midpoint: now.Add(d), LocalNow: now}}
	}
	results := []roughtime.Result{
		mk(10 * time.Millisecond),
		mk(20 * time.Millisecond),
		mk(30 * time.Millisecond),
		mk(40 * time.Millisecond),
	}
	c := roughtime.Consensus(results)
	if c.Samples != 4 {
		t.Fatalf("Samples = %d, want 4", c.Samples)
	}
	if c.Median != 30*time.Millisecond {
		t.Fatalf("Median = %s, want 30ms (upper of two middles, not 25ms mean)", c.Median)
	}
}

// TestConsensusAllFailed covers a result set with no verified samples.
func TestConsensusAllFailed(t *testing.T) {
	results := []roughtime.Result{
		{Err: errors.New("a")},
		{Err: errors.New("b")},
	}
	got := roughtime.Consensus(results)
	if got.Samples != 0 {
		t.Fatalf("Samples = %d, want 0", got.Samples)
	}
}
