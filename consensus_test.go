// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package roughtime_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/tannerryan/roughtime"
)

// TestConsensus verifies Consensus ignores failed entries and reports correct
// median, min, and max drifts.
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

// TestConsensusEvenN verifies the even-N median rule selects the upper middle
// rather than the mean.
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

// TestConsensusAllFailed verifies Consensus reports zero Samples when every
// entry has an error.
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

// FuzzConsensus fuzzes Consensus with synthetic Results to ensure it never
// panics on arbitrary inputs.
func FuzzConsensus(f *testing.F) {
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0x01}, 9))
	f.Add(append(bytes.Repeat([]byte{0xff}, 8), 0x00)) // failure entry

	f.Fuzz(func(t *testing.T, data []byte) {
		const recordLen = 9
		results := make([]roughtime.Result, 0, len(data)/recordLen)
		wantOK := 0
		now := time.Now()
		for i := 0; i+recordLen <= len(data); i += recordLen {
			drift := time.Duration(binary.LittleEndian.Uint64(data[i:]))
			ok := data[i+8]&1 == 1
			if ok {
				wantOK++
				results = append(results, roughtime.Result{Response: &roughtime.Response{
					Midpoint: now.Add(drift),
					LocalNow: now,
				}})
			} else {
				results = append(results, roughtime.Result{Err: errors.New("synthetic")})
			}
		}
		got := roughtime.Consensus(results)
		if got.Samples != wantOK {
			t.Fatalf("Samples = %d, want %d", got.Samples, wantOK)
		}
		if wantOK == 0 && (got.Median != 0 || got.Min != 0 || got.Max != 0) {
			t.Fatalf("zero-samples report has nonzero stats: %+v", got)
		}
	})
}
