// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

// Command roughtime-bench is a closed-loop Roughtime load generator. It has no
// rate limit or reconnect backoff and must only target servers you control.
// Latency percentiles use a run-wide bounded reservoir; -verify excludes
// unauthenticated replies from it. ML-DSA-44 always uses TCP.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
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

var (
	// addr is the target endpoint flag.
	addr = flag.String("addr", "127.0.0.1:2002", "server host:port")
	// pubkey is the root public-key flag.
	pubkey = flag.String("pubkey", "", "root public key (base64 or hex). 32 bytes selects Ed25519, 1312 bytes selects ML-DSA-44")
	// useTCP selects TCP for Ed25519.
	useTCP = flag.Bool("tcp", false, "use TCP transport. ML-DSA-44 keys always use TCP")
	// workers sets concurrent client sockets.
	workers = flag.Int("workers", 64, "concurrent client sockets")
	// duration sets the measurement period.
	duration = flag.Duration("duration", 10*time.Second, "measurement duration")
	// warmup sets the unmeasured warmup period.
	warmup = flag.Duration("warmup", 2*time.Second, "warmup period before measurement (not counted)")
	// timeout bounds each request.
	timeout = flag.Duration("timeout", 500*time.Millisecond, "per-request read/write timeout")
	// verify enables response authentication.
	verify = flag.Bool("verify", false, "verify every reply's signature and Merkle proof (slower, client-bound)")
	// showVersion requests version output and exit.
	showVersion = flag.Bool("version", false, "print version and exit")
)

// reservoirSize is the run-wide Algorithm R latency-sample cap.
const reservoirSize = 100_000

// maxWorkers bounds accidental local fd and memory use.
const maxWorkers = 65_536

// workerResult holds one worker's measurement counters.
type workerResult struct {
	sent         uint64
	received     uint64
	successes    uint64
	errVerify    uint64
	errAmp       uint64
	errWrite     uint64
	errRead      uint64
	timeouts     uint64
	latencyMin   time.Duration
	latencyMax   time.Duration
	latencyTotal float64
}

// benchConfig is immutable configuration shared by workers.
type benchConfig struct {
	addr      string
	transport string
	rootPK    []byte
	srv       []byte
	versions  []protocol.Version
	timeout   time.Duration
	verify    bool
	udpAddr   *net.UDPAddr
	latencies *latencyReservoir
}

// main parses flags and runs the benchmark.
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

	// Verification can be CPU-bound, so cap default workers.
	if *verify && !flagSet("workers") {
		if maxW := runtime.NumCPU() * 2; *workers > maxW {
			fmt.Fprintf(os.Stderr, "bench: -verify can be CPU-bound; capping workers %d -> %d (override with -workers)\n", *workers, maxW)
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
	var udpAddr *net.UDPAddr
	if transport == "udp" {
		dialer := net.Dialer{Timeout: *timeout}
		conn, err := dialer.DialContext(ctx, "udp", *addr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "bench: resolving target: %s\n", err)
			os.Exit(1)
		}
		resolved, ok := conn.RemoteAddr().(*net.UDPAddr)
		_ = conn.Close()
		if !ok {
			fmt.Fprintln(os.Stderr, "bench: resolved target is not UDP")
			os.Exit(1)
		}
		udpAddr = &net.UDPAddr{IP: append(net.IP(nil), resolved.IP...), Port: resolved.Port, Zone: resolved.Zone}
	}

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
		udpAddr:   udpAddr,
	}

	// run warmup and measurement in one pass so sockets stay open across the
	// boundary
	totalCtx, totalCancel := context.WithTimeout(ctx, *warmup+*duration)
	defer totalCancel()
	start := time.Now()
	collectAfter := start.Add(*warmup)
	results, latencies, err := runWorkers(totalCtx, cfg, *workers, collectAfter)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bench: %s\n", err)
		os.Exit(1)
	}
	// clamp at zero in case a SIGINT cancels before collectAfter elapses
	elapsed := min(max(time.Since(collectAfter), 0), *duration)

	report(runMeta{workers: *workers, verify: *verify}, results, latencies, elapsed)
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
	if flag.NArg() > 0 {
		return fmt.Errorf("unexpected positional args: %v", flag.Args())
	}
	if *workers > maxWorkers {
		return fmt.Errorf("-workers %d exceeds max %d", *workers, maxWorkers)
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

// runWorkers starts n workers and waits for them to finish.
func runWorkers(ctx context.Context, cfg benchConfig, n int, collectAfter time.Time) ([]workerResult, []time.Duration, error) {
	results := make([]workerResult, n)
	reservoir := &latencyReservoir{values: make([]time.Duration, 0, reservoirSize)}
	cfg.latencies = reservoir
	var wg sync.WaitGroup
	var completed atomic.Int32
	for i := range n {
		wg.Go(func() {
			if worker(ctx, cfg, &results[i], collectAfter) {
				completed.Add(1)
			}
		})
	}
	wg.Wait()
	if got := int(completed.Load()); got != n {
		return nil, nil, fmt.Errorf("%d of %d workers failed to start or terminated early", n-got, n)
	}
	return results, reservoir.values, nil
}
