// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

// Command roughtime-bench is an end-to-end closed-loop UDP load generator for
// the Roughtime server. Each worker owns one UDP socket, fires a well-formed
// request, waits for the reply, records the RTT, and repeats for the configured
// duration. It reports throughput, latency percentiles, and an error breakdown.
//
// With -verify, every reply is signature-checked against the root public key.
// Verification failures under an honest server are attributed to grease (RFC
// §7) and counted separately from hard errors. Verification adds ~100µs/reply
// of client CPU, which caps throughput before the server does — leave it off
// for pure throughput numbers.
//
// Note: grease mode 3 (unknown-tag injection) is, by spec, ignored by
// conforming verifiers, so observed grease rate settles around 75% of the
// server's configured rate.
//
// Example:
//
//	roughtime-bench -addr server:2002 -pubkey <base64-or-hex> -workers 256 -duration 30s -warmup 2s
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/tannerryan/roughtime/internal/version"
	"github.com/tannerryan/roughtime/protocol"
)

var (
	addr        = flag.String("addr", "127.0.0.1:2002", "server host:port")
	pubkey      = flag.String("pubkey", "", "Ed25519 root public key (base64 or hex)")
	workers     = flag.Int("workers", 64, "concurrent client sockets")
	duration    = flag.Duration("duration", 10*time.Second, "measurement duration")
	warmup      = flag.Duration("warmup", 2*time.Second, "warmup period before measurement (not counted)")
	timeout     = flag.Duration("timeout", 500*time.Millisecond, "per-request UDP read/write timeout")
	verify      = flag.Bool("verify", false, "verify every reply and report grease rate (slower, client-bound)")
	showVersion = flag.Bool("version", false, "print version and exit")
)

// ietfVersions is the set advertised in each request. We skip Google-Roughtime
// so the server exercises its batch-signing path.
var ietfVersions = func() []protocol.Version {
	s := protocol.Supported()
	return s[:len(s)-1]
}()

// workerResult is the private, per-goroutine accumulation. Merging at the end
// avoids lock contention on the hot path.
//
// Under -verify, a reply that fails verification is counted as greased rather
// than errored because the server's only expected source of invalid replies is
// deliberate grease.
type workerResult struct {
	latencies []time.Duration
	greased   uint64
	errWrite  uint64
	errRead   uint64
	timeouts  uint64
}

func main() {
	flag.Parse()
	if *showVersion {
		fmt.Printf("roughtime-bench %s (github.com/tannerryan/roughtime)\n\n%s\n", version.Version, version.Copyright)
		return
	}
	if err := validateFlags(); err != nil {
		fmt.Fprintf(os.Stderr, "bench: %s\n", err)
		os.Exit(1)
	}

	// -verify turns the bench CPU-bound on the client (one Ed25519 verify per
	// reply). If the user left -workers at its default, cap it to 2× NumCPU so
	// oversubscription does not starve the verifier and skew latency numbers.
	// Explicit -workers values are always respected.
	if *verify && !flagSet("workers") {
		if maxW := runtime.NumCPU() * 2; *workers > maxW {
			*workers = maxW
		}
	}

	rootPK, err := loadPubKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "bench: %s\n", err)
		os.Exit(1)
	}
	srv := protocol.ComputeSRV(rootPK)

	raddr, err := net.ResolveUDPAddr("udp", *addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bench: resolving %s: %s\n", *addr, err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	fmt.Printf("roughtime-bench -> %s\n", raddr)
	fmt.Printf("  workers=%d duration=%s warmup=%s timeout=%s verify=%t\n",
		*workers, *duration, *warmup, *timeout, *verify)

	// Warmup: drive load without collecting, so JIT-like warmups (cert refresh
	// loop, kernel queue fill, Go scheduler) stabilize before measuring.
	if *warmup > 0 {
		warmCtx, warmCancel := context.WithTimeout(ctx, *warmup)
		runWorkers(warmCtx, raddr, rootPK, srv, *workers, false)
		warmCancel()
	}

	measureCtx, measureCancel := context.WithTimeout(ctx, *duration)
	defer measureCancel()
	start := time.Now()
	results := runWorkers(measureCtx, raddr, rootPK, srv, *workers, true)
	elapsed := time.Since(start)

	report(results, elapsed)
}

// flagSet reports whether the named flag was explicitly provided on the command
// line, letting callers distinguish "user left it at default" from "user picked
// a value that happens to equal the default".
func flagSet(name string) bool {
	set := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}

// validateFlags checks CLI flags are within permitted ranges.
func validateFlags() error {
	if *workers < 1 {
		return fmt.Errorf("-workers %d must be >= 1", *workers)
	}
	if *duration <= 0 {
		return fmt.Errorf("-duration %s must be > 0", *duration)
	}
	if *timeout <= 0 {
		return fmt.Errorf("-timeout %s must be > 0", *timeout)
	}
	if *pubkey == "" {
		return fmt.Errorf("provide -pubkey")
	}
	return nil
}

// loadPubKey decodes the root public key from the -pubkey flag.
func loadPubKey() (ed25519.PublicKey, error) {
	b, err := decodePubKey(*pubkey)
	if err != nil {
		return nil, err
	}
	return ed25519.PublicKey(b), nil
}

// decodePubKey accepts a base64 or hex ed25519 public key.
func decodePubKey(s string) ([]byte, error) {
	for _, dec := range []func(string) ([]byte, error){
		base64.StdEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		base64.RawURLEncoding.DecodeString,
		hex.DecodeString,
	} {
		if b, err := dec(s); err == nil && len(b) == ed25519.PublicKeySize {
			return b, nil
		}
	}
	return nil, fmt.Errorf("public key %q is not 32 bytes of base64 or hex", s)
}

// runWorkers spins up n goroutines, waits for ctx, and returns merged results.
// When collect is false, samples are discarded (used for the warmup phase).
func runWorkers(ctx context.Context, raddr *net.UDPAddr, rootPK ed25519.PublicKey, srv []byte, n int, collect bool) []workerResult {
	results := make([]workerResult, n)
	var wg sync.WaitGroup
	wg.Add(n)
	// started counts workers that successfully dialled; the reporter divides by
	// this if all workers fail outright.
	var started atomic.Int32
	for i := range n {
		go func(idx int) {
			defer wg.Done()
			if worker(ctx, raddr, rootPK, srv, &results[idx], collect) {
				started.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if started.Load() == 0 {
		fmt.Fprintln(os.Stderr, "bench: all workers failed to start")
	}
	return results
}

// worker runs the closed-loop send/recv cycle on a single UDP socket until ctx
// is cancelled. Returns false if it could not dial.
func worker(ctx context.Context, raddr *net.UDPAddr, rootPK ed25519.PublicKey, srv []byte, out *workerResult, collect bool) bool {
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return false
	}
	defer conn.Close()

	buf := make([]byte, 1500)
	for ctx.Err() == nil {
		nonce, req, err := protocol.CreateRequest(ietfVersions, rand.Reader, srv)
		if err != nil {
			// CreateRequest only fails on entropy source failure; bucket with
			// writes so it surfaces as a hard error.
			out.errWrite++
			continue
		}

		_ = conn.SetWriteDeadline(time.Now().Add(*timeout))
		start := time.Now()
		if _, err := conn.Write(req); err != nil {
			out.errWrite++
			continue
		}

		_ = conn.SetReadDeadline(time.Now().Add(*timeout))
		n, err := conn.Read(buf)
		rtt := time.Since(start)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				out.timeouts++
			} else {
				out.errRead++
			}
			continue
		}

		if *verify {
			if _, _, err := protocol.VerifyReply(ietfVersions, buf[:n], rootPK, nonce, req); err != nil {
				out.greased++
				continue
			}
		}

		if collect {
			out.latencies = append(out.latencies, rtt)
		}
	}
	return true
}

// report aggregates per-worker results and prints a single summary block. The
// Greased / Grease rate lines are emitted only when -verify is set, because
// grease can only be distinguished from a valid reply by signature check.
func report(results []workerResult, elapsed time.Duration) {
	var all []time.Duration
	var greased, errWrite, errRead, timeouts uint64
	for i := range results {
		all = append(all, results[i].latencies...)
		greased += results[i].greased
		errWrite += results[i].errWrite
		errRead += results[i].errRead
		timeouts += results[i].timeouts
	}

	received := uint64(len(all))
	errs := errWrite + errRead
	sent := received + greased + errs + timeouts

	var successRate, greaseRate, throughput float64
	if sent > 0 {
		successRate = 100 * float64(received+greased) / float64(sent)
	}
	if received+greased > 0 {
		greaseRate = 100 * float64(greased) / float64(received+greased)
	}
	if elapsed > 0 {
		throughput = float64(received) / elapsed.Seconds()
	}

	fmt.Println()
	fmt.Println("=== results ===")
	fmt.Printf("Duration:     %s\n", elapsed.Round(time.Millisecond))
	fmt.Printf("Workers:      %d\n", *workers)
	fmt.Printf("Sent:         %d\n", sent)
	fmt.Printf("Received:     %d\n", received)
	if *verify {
		fmt.Printf("Greased:      %d\n", greased)
	}
	fmt.Printf("Errors:       %d\n", errs)
	fmt.Printf("Timeouts:     %d\n", timeouts)
	fmt.Printf("Success rate: %.2f%%\n", successRate)
	if *verify {
		fmt.Printf("Grease rate:  %.2f%% (caps at ~75%% of server rate; mode-3 grease is spec-valid)\n", greaseRate)
	}
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

// percentile returns the p-th percentile from a pre-sorted ascending slice
// using nearest-rank. p is in [0, 1].
func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := min(max(int(p*float64(len(sorted)-1)), 0), len(sorted)-1)
	return sorted[idx]
}

// mean returns the arithmetic mean of a non-empty duration slice.
func mean(xs []time.Duration) time.Duration {
	var sum time.Duration
	for _, x := range xs {
		sum += x
	}
	return sum / time.Duration(len(xs))
}
