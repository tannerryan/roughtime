// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

// Command bench is an end-to-end closed-loop UDP load generator for the
// Roughtime server. Each worker owns one UDP socket, fires a well-formed
// request, waits for the reply, records the RTT, and repeats for the configured
// duration. It reports throughput, latency percentiles, and an error breakdown.
//
// With -verify, every reply is signature-checked against the root public key.
// Verification failures are reported as "verify fail" — this bucket includes
// both grease (RFC §7 deliberately malformed replies from an honest server) and
// genuine faults, since the wire carries no signal to tell them apart.
// Verification adds ~100µs/reply of client CPU, which caps throughput before
// the server does — leave it off for pure throughput numbers.
//
// Example:
//
//	go run bench/main.go -addr server:2002 -pubkey <base64-or-hex> -workers 256 -duration 30s -warmup 2s
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	mrand "math/rand/v2"
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
	verify      = flag.Bool("verify", false, "verify every reply's signature and Merkle proof (slower, client-bound)")
	showVersion = flag.Bool("version", false, "print version and exit")
)

// ietfVersions is advertised in each request. Google-Roughtime is excluded so
// the server exercises its batch-signing path.
var ietfVersions = func() []protocol.Version {
	s := protocol.Supported()
	out := make([]protocol.Version, 0, len(s))
	for _, v := range s {
		if v != protocol.VersionGoogle {
			out = append(out, v)
		}
	}
	return out
}()

// reservoirSize caps per-worker latency samples (Algorithm R).
const reservoirSize = 100_000

// workerResult accumulates per-goroutine stats and is merged after the run.
// errVerify aggregates grease and genuine verification failures.
type workerResult struct {
	latencies []time.Duration
	received  uint64
	errVerify uint64
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

	// Under -verify the bench is CPU-bound; cap default worker count to avoid
	// oversubscription. Explicit -workers is always respected
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

	// Warmup drives load without collecting samples so runtime effects settle
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
// line.
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

// runWorkers spins up n goroutines and returns per-worker results once ctx is
// cancelled. When collect is false, samples are discarded.
func runWorkers(ctx context.Context, raddr *net.UDPAddr, rootPK ed25519.PublicKey, srv []byte, n int, collect bool) []workerResult {
	results := make([]workerResult, n)
	var wg sync.WaitGroup
	wg.Add(n)
	var dialed atomic.Int32
	for i := range n {
		go func(idx int) {
			defer wg.Done()
			if worker(ctx, raddr, rootPK, srv, &results[idx], collect) {
				dialed.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if dialed.Load() == 0 {
		fmt.Fprintln(os.Stderr, "bench: all workers failed to start")
	}
	return results
}

// recordLatency adds an RTT sample via Algorithm R reservoir sampling.
func recordLatency(out *workerResult, rtt time.Duration) {
	out.received++
	if len(out.latencies) < reservoirSize {
		out.latencies = append(out.latencies, rtt)
		return
	}
	// Replace index j with probability reservoirSize/received
	j := mrand.Uint64N(out.received)
	if j < reservoirSize {
		out.latencies[j] = rtt
	}
}

// worker runs the closed-loop send/recv cycle on a single UDP socket until ctx
// is cancelled. The request is built once and each iteration rewrites only the
// NONC bytes. Returns false if it could not dial.
func worker(ctx context.Context, raddr *net.UDPAddr, rootPK ed25519.PublicKey, srv []byte, out *workerResult, collect bool) bool {
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return false
	}
	defer conn.Close()

	nonce, req, err := protocol.CreateRequest(ietfVersions, rand.Reader, srv)
	if err != nil {
		return false
	}
	// bytes.Index would be unsafe: a random nonce can collide with an earlier
	// byte window in the header or SRV tag
	nonceOff, err := protocol.NonceOffsetInRequest(req)
	if err != nil {
		return false
	}

	buf := make([]byte, 1500)
	for ctx.Err() == nil {
		// math/rand suffices; the server does not check nonce entropy
		for i := 0; i < len(nonce); i += 8 {
			binary.LittleEndian.PutUint64(nonce[i:], mrand.Uint64())
		}
		copy(req[nonceOff:nonceOff+len(nonce)], nonce)

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
				// Grease (RFC §7) and genuine faults share this bucket
				out.errVerify++
				continue
			}
		}

		if collect {
			recordLatency(out, rtt)
		}
	}
	return true
}

// report aggregates per-worker results and prints a single summary block.
func report(results []workerResult, elapsed time.Duration) {
	var all []time.Duration
	var received, errVerify, errWrite, errRead, timeouts uint64
	for i := range results {
		all = append(all, results[i].latencies...)
		received += results[i].received
		errVerify += results[i].errVerify
		errWrite += results[i].errWrite
		errRead += results[i].errRead
		timeouts += results[i].timeouts
	}

	errs := errVerify + errWrite + errRead
	sent := received + errs + timeouts

	var successRate, throughput float64
	if sent > 0 {
		successRate = 100 * float64(received) / float64(sent)
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
		fmt.Printf("Verify fail:  %d (grease + genuine faults — indistinguishable on the wire)\n", errVerify)
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
