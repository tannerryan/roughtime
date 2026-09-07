// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"math"
	"slices"
	"time"
)

// runMeta represents the per-run flags that report needs for headers and
// gating.
type runMeta struct {
	workers int
	verify  bool
}

// report aggregates per-worker results and prints a summary.
func report(meta runMeta, results []workerResult, latencies []time.Duration, elapsed time.Duration) {
	var sent, received, successes, errVerify, errAmp, errWrite, errRead, timeouts uint64
	var latencyMin, latencyMax time.Duration
	var latencyTotal float64
	for i := range results {
		sent += results[i].sent
		received += results[i].received
		successes += results[i].successes
		errVerify += results[i].errVerify
		errAmp += results[i].errAmp
		errWrite += results[i].errWrite
		errRead += results[i].errRead
		timeouts += results[i].timeouts
		if results[i].successes > 0 {
			if latencyMin == 0 || results[i].latencyMin < latencyMin {
				latencyMin = results[i].latencyMin
			}
			latencyMax = max(latencyMax, results[i].latencyMax)
			latencyTotal += results[i].latencyTotal
		}
	}

	// Verification and UDP amplification failures are sub-buckets of received.
	errs := errWrite + errRead

	var successRate, throughput float64
	if sent > 0 {
		successRate = 100 * float64(successes) / float64(sent)
	}
	if elapsed > 0 {
		throughput = float64(successes) / elapsed.Seconds()
	}

	fmt.Println()
	fmt.Println("=== results ===")
	fmt.Printf("Duration:     %s\n", elapsed.Round(time.Millisecond))
	fmt.Printf("Workers:      %d\n", meta.workers)
	fmt.Printf("Sent:         %d\n", sent)
	fmt.Printf("Received:     %d\n", received)
	if meta.verify {
		fmt.Printf("Verify fail:  %d (grease or fault)\n", errVerify)
	}
	if errAmp > 0 {
		fmt.Printf("UDP oversize: %d\n", errAmp)
	}
	fmt.Printf("Errors:       %d\n", errs)
	fmt.Printf("Timeouts:     %d\n", timeouts)
	fmt.Printf("Success rate: %.2f%%\n", successRate)
	fmt.Printf("Throughput:   %.0f req/s\n", throughput)

	if len(latencies) > 0 {
		slices.Sort(latencies)
		fmt.Println()
		fmt.Println("latency:")
		fmt.Printf("  min:   %s\n", latencyMin.Round(time.Microsecond))
		fmt.Printf("  p50:   %s\n", percentile(latencies, 0.50).Round(time.Microsecond))
		fmt.Printf("  p90:   %s\n", percentile(latencies, 0.90).Round(time.Microsecond))
		fmt.Printf("  p99:   %s\n", percentile(latencies, 0.99).Round(time.Microsecond))
		fmt.Printf("  p99.9: %s\n", percentile(latencies, 0.999).Round(time.Microsecond))
		fmt.Printf("  max:   %s\n", latencyMax.Round(time.Microsecond))
		fmt.Printf("  mean:  %s\n", time.Duration(latencyTotal/float64(successes)).Round(time.Microsecond))
	}
}

// percentile returns the nearest-rank p-th percentile of a sorted slice with p
// in [0,1].
func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := min(max(int(math.Ceil(p*float64(len(sorted))))-1, 0), len(sorted)-1)
	return sorted[idx]
}
