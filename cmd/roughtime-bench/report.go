// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package main

import (
	"fmt"
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
func report(meta runMeta, results []workerResult, elapsed time.Duration) {
	total := 0
	for i := range results {
		total += len(results[i].latencies)
	}
	all := make([]time.Duration, 0, total)
	var received, errVerify, errWrite, errRead, timeouts uint64
	for i := range results {
		all = append(all, results[i].latencies...)
		received += results[i].received
		errVerify += results[i].errVerify
		errWrite += results[i].errWrite
		errRead += results[i].errRead
		timeouts += results[i].timeouts
	}

	// errVerify is a sub-bucket of received (latency is recorded on RX before
	// the verify block) so it is not summed into errs or sent
	errs := errWrite + errRead
	sent := received + errs + timeouts
	verified := received - errVerify

	var successRate, throughput float64
	if sent > 0 {
		successRate = 100 * float64(verified) / float64(sent)
	}
	if elapsed > 0 {
		throughput = float64(verified) / elapsed.Seconds()
	}

	fmt.Println()
	fmt.Println("=== results ===")
	fmt.Printf("Duration:     %s\n", elapsed.Round(time.Millisecond))
	fmt.Printf("Workers:      %d\n", meta.workers)
	fmt.Printf("Sent:         %d\n", sent)
	fmt.Printf("Received:     %d\n", received)
	if meta.verify {
		fmt.Printf("Verify fail:  %d (grease + genuine faults — indistinguishable on the wire; counted in Received)\n", errVerify)
	}
	fmt.Printf("Errors:       %d\n", errs)
	fmt.Printf("Timeouts:     %d\n", timeouts)
	fmt.Printf("Success rate: %.2f%%\n", successRate)
	fmt.Printf("Throughput:   %.0f req/s\n", throughput)

	if len(all) > 0 {
		slices.Sort(all)
		fmt.Println()
		fmt.Println("latency:")
		fmt.Printf("  min:   %s\n", all[0].Round(time.Microsecond))
		fmt.Printf("  p50:   %s\n", percentile(all, 0.50).Round(time.Microsecond))
		fmt.Printf("  p90:   %s\n", percentile(all, 0.90).Round(time.Microsecond))
		fmt.Printf("  p99:   %s\n", percentile(all, 0.99).Round(time.Microsecond))
		fmt.Printf("  p99.9: %s\n", percentile(all, 0.999).Round(time.Microsecond))
		fmt.Printf("  max:   %s\n", all[len(all)-1].Round(time.Microsecond))
		fmt.Printf("  mean:  %s\n", mean(all).Round(time.Microsecond))
	}
}

// percentile returns the nearest-rank p-th percentile of a sorted slice with p
// in [0,1].
func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := min(max(int(p*float64(len(sorted)-1)), 0), len(sorted)-1)
	return sorted[idx]
}

// mean returns the arithmetic mean of xs.
func mean(xs []time.Duration) time.Duration {
	var sum time.Duration
	for _, x := range xs {
		sum += x
	}
	return sum / time.Duration(len(xs))
}
