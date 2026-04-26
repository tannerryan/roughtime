// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

// Command bench is a closed-loop load generator for the Roughtime server. Each
// worker owns one socket, fires a request, waits for the reply, records the
// RTT, and repeats. It reports throughput, latency percentiles, and an error
// breakdown.
//
// With -verify, replies are signature-checked. The "verify fail" bucket lumps
// grease and genuine faults together since the wire cannot distinguish them.
//
// Key length selects the suite: 32 bytes Ed25519, 1312 bytes ML-DSA-44
// (experimental, always TCP). -tcp forces TCP for Ed25519.
//
// Example:
//
//	go run bench/main.go -addr server:2002 -pubkey <base64-or-hex> -workers 256 -duration 30s -warmup 2s
package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
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

	"github.com/tannerryan/roughtime"
	"github.com/tannerryan/roughtime/internal/version"
	"github.com/tannerryan/roughtime/protocol"
)

var (
	addr        = flag.String("addr", "127.0.0.1:2002", "server host:port")
	pubkey      = flag.String("pubkey", "", "root public key (base64 or hex); 32 bytes selects Ed25519, 1312 bytes selects ML-DSA-44")
	useTCP      = flag.Bool("tcp", false, "use TCP transport; ML-DSA-44 keys always use TCP")
	workers     = flag.Int("workers", 64, "concurrent client sockets")
	duration    = flag.Duration("duration", 10*time.Second, "measurement duration")
	warmup      = flag.Duration("warmup", 2*time.Second, "warmup period before measurement (not counted)")
	timeout     = flag.Duration("timeout", 500*time.Millisecond, "per-request read/write timeout")
	verify      = flag.Bool("verify", false, "verify every reply's signature and Merkle proof (slower, client-bound)")
	showVersion = flag.Bool("version", false, "print version and exit")
)

// maxTCPReply caps the TCP reply payload.
const maxTCPReply = protocol.MaxTCPReplyBody

// maxUDPReply bounds the UDP read buffer.
const maxUDPReply = protocol.MaxUDPReply

// reservoirSize caps per-worker latency samples (Algorithm R).
const reservoirSize = 100_000

// workerResult accumulates per-goroutine stats.
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

	// under -verify the bench is CPU-bound; cap default workers
	if *verify && !flagSet("workers") {
		if maxW := runtime.NumCPU() * 2; *workers > maxW {
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
	elapsed := max(time.Since(collectAfter), 0)

	report(results, elapsed)
}

type benchConfig struct {
	addr      string
	transport string
	rootPK    []byte
	srv       []byte
	versions  []protocol.Version
	timeout   time.Duration
	verify    bool
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
// Samples before collectAfter are dropped to fold warmup into the same sockets.
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

// recordLatency adds an RTT sample via Algorithm R reservoir sampling.
func recordLatency(out *workerResult, rtt time.Duration) {
	out.received++
	if len(out.latencies) < reservoirSize {
		out.latencies = append(out.latencies, rtt)
		return
	}
	// replace index j with probability reservoirSize/received
	j := mrand.Uint64N(out.received)
	if j < reservoirSize {
		out.latencies[j] = rtt
	}
}

// bumpAfter increments *c when start is at or past collectAfter; warmup samples
// are dropped to keep error and success counts on the same window.
func bumpAfter(start, collectAfter time.Time, c *uint64) {
	if !start.Before(collectAfter) {
		*c++
	}
}

// randomizeNonce fills n with non-cryptographic random bytes; nonces are opaque
// to the server and only need distinctness to avoid dedupe collapse.
func randomizeNonce(n []byte) {
	full := len(n) - len(n)%8
	for i := 0; i < full; i += 8 {
		binary.LittleEndian.PutUint64(n[i:], mrand.Uint64())
	}
	if tail := n[full:]; len(tail) > 0 {
		var t [8]byte
		binary.LittleEndian.PutUint64(t[:], mrand.Uint64())
		copy(tail, t[:])
	}
}

// worker dispatches to the UDP or TCP driver.
func worker(ctx context.Context, cfg benchConfig, out *workerResult, collectAfter time.Time) bool {
	if cfg.transport == "tcp" {
		return workerTCP(ctx, cfg, out, collectAfter)
	}
	return workerUDP(ctx, cfg, out, collectAfter)
}

// workerUDP runs the send/recv loop on one UDP socket. Returns false if dial
// fails.
func workerUDP(ctx context.Context, cfg benchConfig, out *workerResult, collectAfter time.Time) bool {
	raddr, err := net.ResolveUDPAddr("udp", cfg.addr)
	if err != nil {
		return false
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return false
	}
	defer conn.Close()

	nonce, req, err := protocol.CreateRequest(cfg.versions, rand.Reader, cfg.srv)
	if err != nil {
		return false
	}
	// bytes.Index would be unsafe: a random nonce can collide with header or
	// SRV bytes
	nonceOff, err := protocol.NonceOffsetInRequest(req)
	if err != nil {
		return false
	}

	timeout := cfg.timeout
	verify := cfg.verify
	buf := make([]byte, maxUDPReply)
	for ctx.Err() == nil {
		randomizeNonce(nonce)
		copy(req[nonceOff:nonceOff+len(nonce)], nonce)

		_ = conn.SetWriteDeadline(time.Now().Add(timeout))
		start := time.Now()
		if _, err := conn.Write(req); err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				bumpAfter(start, collectAfter, &out.timeouts)
			} else {
				bumpAfter(start, collectAfter, &out.errWrite)
			}
			continue
		}

		_ = conn.SetReadDeadline(time.Now().Add(timeout))
		n, err := conn.Read(buf)
		rtt := time.Since(start)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				bumpAfter(start, collectAfter, &out.timeouts)
			} else {
				bumpAfter(start, collectAfter, &out.errRead)
			}
			continue
		}

		if verify {
			if _, _, err := protocol.VerifyReply(cfg.versions, buf[:n], cfg.rootPK, nonce, req); err != nil {
				// grease and genuine faults share this bucket
				bumpAfter(start, collectAfter, &out.errVerify)
				continue
			}
		}

		if !start.Before(collectAfter) {
			recordLatency(out, rtt)
		}
	}
	return true
}

// workerTCP runs the send/recv loop on a TCP connection. Transport or framing
// errors close the connection and redial; a redial failure exits the worker.
func workerTCP(ctx context.Context, cfg benchConfig, out *workerResult, collectAfter time.Time) bool {
	timeout := cfg.timeout
	verify := cfg.verify
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", cfg.addr)
	if err != nil {
		return false
	}
	defer func() { conn.Close() }()
	setTCPNoDelay(conn)

	nonce, req, err := protocol.CreateRequest(cfg.versions, rand.Reader, cfg.srv)
	if err != nil {
		return false
	}
	nonceOff, err := protocol.NonceOffsetInRequest(req)
	if err != nil {
		return false
	}

	// reconnect closes conn and redials; returns false if the redial fails.
	reconnect := func() bool {
		conn.Close()
		c, err := dialer.DialContext(ctx, "tcp", cfg.addr)
		if err != nil {
			return false
		}
		conn = c
		setTCPNoDelay(conn)
		return true
	}

	replyBuf := make([]byte, protocol.PacketHeaderSize+maxTCPReply)
	for ctx.Err() == nil {
		randomizeNonce(nonce)
		copy(req[nonceOff:nonceOff+len(nonce)], nonce)

		_ = conn.SetWriteDeadline(time.Now().Add(timeout))
		start := time.Now()
		if _, err := conn.Write(req); err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				bumpAfter(start, collectAfter, &out.timeouts)
			} else {
				bumpAfter(start, collectAfter, &out.errWrite)
			}
			if !reconnect() {
				return true
			}
			continue
		}

		hdr := replyBuf[:protocol.PacketHeaderSize]
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
		if _, err := io.ReadFull(conn, hdr); err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				bumpAfter(start, collectAfter, &out.timeouts)
			} else {
				bumpAfter(start, collectAfter, &out.errRead)
			}
			if !reconnect() {
				return true
			}
			continue
		}
		bodyLen, err := protocol.ParsePacketHeader(hdr)
		if err != nil || bodyLen == 0 || bodyLen > maxTCPReply {
			bumpAfter(start, collectAfter, &out.errRead)
			if !reconnect() {
				return true
			}
			continue
		}
		pkt := replyBuf[:protocol.PacketHeaderSize+int(bodyLen)]
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
		if _, err := io.ReadFull(conn, pkt[protocol.PacketHeaderSize:]); err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				bumpAfter(start, collectAfter, &out.timeouts)
			} else {
				bumpAfter(start, collectAfter, &out.errRead)
			}
			if !reconnect() {
				return true
			}
			continue
		}
		rtt := time.Since(start)

		if verify {
			if _, _, err := protocol.VerifyReply(cfg.versions, pkt, cfg.rootPK, nonce, req); err != nil {
				bumpAfter(start, collectAfter, &out.errVerify)
				continue
			}
		}

		if !start.Before(collectAfter) {
			recordLatency(out, rtt)
		}
	}
	return true
}

// setTCPNoDelay disables Nagle on c if it is a *net.TCPConn.
func setTCPNoDelay(c net.Conn) {
	if tcp, ok := c.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}
}

// report aggregates per-worker results and prints a summary.
func report(results []workerResult, elapsed time.Duration) {
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

// percentile returns the nearest-rank p-th percentile of a sorted slice; p in
// [0,1].
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
