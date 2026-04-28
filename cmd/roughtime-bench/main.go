// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

// Command roughtime-bench is a closed-loop load generator for the Roughtime
// server. Each worker owns one socket, fires a request, waits for the reply,
// records the RTT, and repeats. It reports throughput, latency percentiles, and
// an error breakdown.
//
// Latencies feed a per-worker Algorithm R reservoir capped at 100k samples, so
// p99.9 is approximate once a worker exceeds that count. Warmup samples are
// dropped but sockets stay open across the boundary so the measurement window
// inherits warm kernel state. Per-iteration SetReadDeadline sits inside the
// timing window, inflating measured RTT on sub-millisecond servers.
//
// The bench is a closed-loop load generator: it deliberately omits exponential
// backoff on TCP redial and has no rate limit, so it is not a conformant client
// and must only target servers you own.
//
// With -verify, replies are signature-checked. RTT is recorded on RX before the
// verify block so verification cost stays out of the percentile. The "verify
// fail" bucket lumps grease and genuine faults together since the wire cannot
// distinguish them.
//
// Key length selects the suite: 32 bytes Ed25519, 1312 bytes ML-DSA-44
// (experimental, always TCP). -tcp forces TCP for Ed25519.
//
// File layout:
//   - main.go    — flags, dispatch, worker fan-out
//   - worker.go  — per-worker UDP/TCP send-recv loops + nonce/sample helpers
//   - report.go  — aggregation and latency-percentile output
//
// Example:
//
//	go run ./cmd/roughtime-bench -addr server:2002 -pubkey <base64-or-hex> -workers 256 -duration 30s -warmup 2s
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/tannerryan/roughtime"
	"github.com/tannerryan/roughtime/internal/version"
	"github.com/tannerryan/roughtime/protocol"
)

// addr is the server host:port flag.
var addr = flag.String("addr", "127.0.0.1:2002", "server host:port")

// pubkey is the root public key flag (base64 or hex; length selects suite).
var pubkey = flag.String("pubkey", "", "root public key (base64 or hex); 32 bytes selects Ed25519, 1312 bytes selects ML-DSA-44")

// useTCP forces TCP transport for Ed25519; ML-DSA-44 always uses TCP.
var useTCP = flag.Bool("tcp", false, "use TCP transport; ML-DSA-44 keys always use TCP")

// workers is the concurrent client socket count flag.
var workers = flag.Int("workers", 64, "concurrent client sockets")

// duration is the measurement window flag.
var duration = flag.Duration("duration", 10*time.Second, "measurement duration")

// warmup is the pre-measurement warmup period flag.
var warmup = flag.Duration("warmup", 2*time.Second, "warmup period before measurement (not counted)")

// timeout is the per-request read/write timeout flag.
var timeout = flag.Duration("timeout", 500*time.Millisecond, "per-request read/write timeout")

// verify enables per-reply signature and Merkle-proof verification.
var verify = flag.Bool("verify", false, "verify every reply's signature and Merkle proof (slower, client-bound)")

// showVersion prints the version string and exits.
var showVersion = flag.Bool("version", false, "print version and exit")

// reservoirSize is the per-worker Algorithm R latency-sample cap.
const reservoirSize = 100_000

// workerResult represents the per-goroutine stats accumulator.
type workerResult struct {
	latencies []time.Duration
	received  uint64
	errVerify uint64
	errWrite  uint64
	errRead   uint64
	timeouts  uint64
}

// benchConfig represents the per-run configuration shared by all workers.
type benchConfig struct {
	addr      string
	transport string
	rootPK    []byte
	srv       []byte
	versions  []protocol.Version
	timeout   time.Duration
	verify    bool
}

// main parses flags, validates inputs, and runs the bench.
func main() {
	flag.Parse()
	if *showVersion {
		fmt.Printf("roughtime-bench %s (github.com/tannerryan/roughtime)\n\n%s\n", version.Full(), version.Copyright)
		return
	}
	if err := validateFlags(); err != nil {
		fmt.Fprintf(os.Stderr, "bench: %s\n", err)
		os.Exit(1)
	}

	fmt.Fprintln(os.Stderr, "WARNING: closed-loop load generator; do not target servers you do not own")

	// under -verify the bench is CPU-bound; cap default workers
	if *verify && !flagSet("workers") {
		if maxW := runtime.NumCPU() * 2; *workers > maxW {
			fmt.Fprintf(os.Stderr, "bench: -verify is CPU-bound; capping workers %d -> %d (override with -workers)\n", *workers, maxW)
			*workers = maxW
		}
	}

	rootPK, err := roughtime.DecodePublicKey(*pubkey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bench: %s\n", err)
		os.Exit(1)
	}
	sch, err := roughtime.SchemeOfKey(rootPK)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bench: %s\n", err)
		os.Exit(1)
	}
	srv := protocol.ComputeSRV(rootPK)

	versions := roughtime.VersionsForScheme(sch)
	transport := "udp"
	if sch == roughtime.SchemeMLDSA44 || *useTCP {
		transport = "tcp"
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	fmt.Printf("roughtime-bench -> %s (%s)\n", *addr, transport)
	fmt.Printf("  workers=%d duration=%s warmup=%s timeout=%s verify=%t\n",
		*workers, *duration, *warmup, *timeout, *verify)

	cfg := benchConfig{
		addr:      *addr,
		transport: transport,
		rootPK:    rootPK,
		srv:       srv,
		versions:  versions,
		timeout:   *timeout,
		verify:    *verify,
	}

	// run warmup and measurement in one pass so sockets stay open across the
	// boundary
	totalCtx, totalCancel := context.WithTimeout(ctx, *warmup+*duration)
	defer totalCancel()
	start := time.Now()
	collectAfter := start.Add(*warmup)
	results := runWorkers(totalCtx, cfg, *workers, collectAfter)
	// clamp at zero in case a SIGINT cancels before collectAfter elapses
	elapsed := max(time.Since(collectAfter), 0)

	report(runMeta{workers: *workers, verify: *verify}, results, elapsed)
}

// flagSet reports whether name was set on the command line.
func flagSet(name string) bool {
	set := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}

// validateFlags checks CLI flag values and returns the first violation.
func validateFlags() error {
	if *workers < 1 {
		return fmt.Errorf("-workers %d must be >= 1", *workers)
	}
	if *duration <= 0 {
		return fmt.Errorf("-duration %s must be > 0", *duration)
	}
	if *warmup < 0 {
		return fmt.Errorf("-warmup %s must be >= 0", *warmup)
	}
	if *timeout <= 0 {
		return fmt.Errorf("-timeout %s must be > 0", *timeout)
	}
	if *pubkey == "" {
		return fmt.Errorf("provide -pubkey")
	}
	return nil
}

// runWorkers spins up n workers and returns their results when ctx ends.
func runWorkers(ctx context.Context, cfg benchConfig, n int, collectAfter time.Time) []workerResult {
	results := make([]workerResult, n)
	var wg sync.WaitGroup
	var dialed atomic.Int32
	for i := range n {
		wg.Go(func() {
			if worker(ctx, cfg, &results[i], collectAfter) {
				dialed.Add(1)
			}
		})
	}
	wg.Wait()
	if dialed.Load() == 0 {
		fmt.Fprintln(os.Stderr, "bench: all workers failed to start")
	}
	return results
}
