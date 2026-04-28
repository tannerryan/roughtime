// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

//go:build unix

// Command roughtime is a Roughtime server. It serves Ed25519 over UDP/TCP and
// the experimental ML-DSA-44 extension over TCP. Run with -h for flags.
//
// File layout:
//   - main.go        — flags, dispatch, serve orchestration
//   - bootstrap.go   — key files, cert provisioning, refresh loops
//   - respond.go     — per-request validation and reply signing
//   - stats.go       — server-wide counters and periodic stats log
//   - lifecycle.go   — recoverGoroutine and superviseLoop
//   - listen_unix.go  — UDP RCVBUF helper shared by Linux and non-Linux
//   - listen_linux.go — UDP listener (Linux fast path: SO_REUSEPORT, recvmmsg/sendmmsg)
//   - listen_other.go — UDP listener (non-Linux unix fallback, single socket)
//   - listen_tcp.go   — TCP listener and per-scheme batcher
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/tannerryan/roughtime/internal/version"
	"github.com/tannerryan/roughtime/protocol"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// logger is the package-wide structured logger; configured in serve.
var logger *zap.Logger

// Command-line flag bindings.
var (
	// port is the listen port for both UDP and TCP.
	port = flag.Int("port", 2002, "port to listen on")
	// rootKeySeedHexFile is the path to the Ed25519 root seed file.
	rootKeySeedHexFile = flag.String("root-key-file", "", "path to file containing hex-encoded Ed25519 root private key seed")
	// pqRootKeySeedHexFile is the path to the ML-DSA-44 root seed file.
	pqRootKeySeedHexFile = flag.String("pq-root-key-file", "", "path to file containing hex-encoded ML-DSA-44 root private key seed")
	// logLevel selects the zap log level.
	logLevel = flag.String("log-level", "info", "log level (debug, info, warn, error)")
	// showVersion prints version and exits when set.
	showVersion = flag.Bool("version", false, "print version and exit")
	// keygen requests Ed25519 root keypair generation at the given path.
	keygen = flag.String("keygen", "", "generate an Ed25519 root key pair and write the seed to the given path")
	// pubkey requests Ed25519 public-key derivation from the given seed file.
	pubkey = flag.String("pubkey", "", "derive and print the Ed25519 public key from an existing root key file")
	// pqKeygen requests ML-DSA-44 root keypair generation at the given path.
	pqKeygen = flag.String("pq-keygen", "", "generate an ML-DSA-44 root key pair and write the seed to the given path")
	// pqPubkey requests ML-DSA-44 public-key derivation from the given seed
	// file.
	pqPubkey = flag.String("pq-pubkey", "", "derive and print the ML-DSA-44 public key from an existing PQ root key file")
	// greaseRate is the fraction of responses to grease.
	greaseRate = flag.Float64("grease-rate", 0.01, "fraction of responses to grease (0 to disable)")
)

// Server-wide tunable constants.
const (
	// radius is the uncertainty radius advertised on every reply.
	radius = 3 * time.Second
	// minRequestSize is the minimum accepted on-the-wire request size.
	minRequestSize = 1024
	// maxPacketSize is the IPv4 Ethernet MTU payload (1500 - 20 IP - 8 UDP).
	maxPacketSize = 1472
	// socketRecvBuffer is the kernel UDP receive buffer per worker socket.
	socketRecvBuffer = 8 * 1024 * 1024
)

// Not exposed as flags; misconfiguration craters throughput or latency. var so
// tests can adjust.
var (
	// batchMaxSize bounds the requests-per-batch flush trigger.
	batchMaxSize = 256
	// batchMaxLatency bounds the time-since-first-request flush trigger.
	batchMaxLatency = 1 * time.Millisecond
)

// validateFlags checks the CLI flag globals and returns the first violation.
func validateFlags() error {
	if *rootKeySeedHexFile == "" && *pqRootKeySeedHexFile == "" {
		return fmt.Errorf("usage: roughtime -root-key-file <path> [-pq-root-key-file <path>] [-port <port>] [-log-level <level>]")
	}
	if *port < 1 || *port > 65535 {
		return fmt.Errorf("-port %d out of range (must be 1-65535)", *port)
	}
	if *greaseRate < 0 || *greaseRate > 1 {
		return fmt.Errorf("-grease-rate %v out of range (must be in [0, 1])", *greaseRate)
	}
	return nil
}

// main parses flags and dispatches to the appropriate subcommand or to serve.
func main() {
	flag.Parse()
	if err := dispatch(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}

// dispatch routes the parsed flag globals to a subcommand or to serve.
func dispatch() error {
	if *showVersion {
		fmt.Printf("roughtime %s (github.com/tannerryan/roughtime)\n\n%s\n", version.Full(), version.Copyright)
		return nil
	}
	if *keygen != "" {
		if err := generateKeypair(*keygen); err != nil {
			return fmt.Errorf("keygen: %w", err)
		}
		return nil
	}
	if *pqKeygen != "" {
		if err := generateMLDSA44Keypair(*pqKeygen); err != nil {
			return fmt.Errorf("pq-keygen: %w", err)
		}
		return nil
	}
	if *pubkey != "" {
		if err := derivePublicKey(*pubkey); err != nil {
			return fmt.Errorf("pubkey: %w", err)
		}
		return nil
	}
	if *pqPubkey != "" {
		if err := deriveMLDSA44PublicKey(*pqPubkey); err != nil {
			return fmt.Errorf("pq-pubkey: %w", err)
		}
		return nil
	}
	if err := validateFlags(); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return serve(ctx)
}

// serve runs the Roughtime server until ctx is cancelled or a listener fails.
func serve(ctx context.Context) error {
	lvl, err := zapcore.ParseLevel(*logLevel)
	if err != nil {
		return fmt.Errorf("invalid -log-level %q: %w", *logLevel, err)
	}
	zcfg := zap.NewProductionConfig()
	zcfg.Level = zap.NewAtomicLevelAt(lvl)
	base, err := zcfg.Build()
	if err != nil {
		return fmt.Errorf("creating logger: %w", err)
	}
	// zap.Sync returns ENOTTY on terminal stderr; ignore
	defer func() { _ = base.Sync() }()
	logger = base.Named("roughtime")

	logger.Info("starting roughtime server",
		zap.String("version", version.Version),
		zap.Int("pid", os.Getpid()),
		zap.Int("port", *port),
		zap.String("root_key", *rootKeySeedHexFile),
		zap.String("pq_root_key", *pqRootKeySeedHexFile),
		zap.Stringer("log_level", lvl),
		zap.Float64("grease_rate", *greaseRate),
		zap.Object("tunables", zapcore.ObjectMarshalerFunc(func(enc zapcore.ObjectEncoder) error {
			enc.AddInt("recv_buffer", socketRecvBuffer)
			enc.AddInt("max_packet_size", maxPacketSize)
			enc.AddInt("min_request_size", minRequestSize)
			enc.AddInt("batch_max_size", batchMaxSize)
			enc.AddDuration("batch_max_latency", batchMaxLatency)
			enc.AddDuration("radius", radius)
			enc.AddDuration("cert_start_offset", certStartOffset)
			enc.AddDuration("cert_end_offset", certEndOffset)
			enc.AddDuration("cert_refresh_threshold", certRefreshThreshold)
			enc.AddDuration("cert_check_interval", certCheckInterval)
			enc.AddDuration("stats_interval", statsInterval)
			return nil
		})),
	)

	certLog := logger.Named("cert")

	var edState *atomic.Pointer[certState]
	if *rootKeySeedHexFile != "" {
		cert, onlinePK, rootPK, expiry, err := provisionCertificateKey()
		if err != nil {
			return fmt.Errorf("provisioning initial Ed25519 certificate: %w", err)
		}
		certLog.Info("provisioned initial Ed25519 certificate",
			zap.String("online_pubkey", hex.EncodeToString(onlinePK)),
			zap.String("root_pubkey", hex.EncodeToString(rootPK)),
			zap.Time("expiry", expiry),
			zap.Duration("validity", time.Until(expiry)),
		)
		edState = &atomic.Pointer[certState]{}
		edState.Store(&certState{cert: cert, expiry: expiry, srvHash: protocol.ComputeSRV(rootPK)})

		// captured so refreshLoop detects silent on-disk root-key changes
		initialRootPK := append(ed25519.PublicKey(nil), rootPK...)
		go superviseLoop(ctx, certLog, "refreshLoop", func() { refreshLoop(ctx, certLog, edState, initialRootPK) })
	}

	var pqState *atomic.Pointer[certState]
	if *pqRootKeySeedHexFile != "" {
		cert, onlinePK, rootPK, expiry, err := provisionMLDSA44CertificateKey()
		if err != nil {
			return fmt.Errorf("provisioning initial ML-DSA-44 certificate: %w", err)
		}
		certLog.Info("provisioned initial ML-DSA-44 certificate",
			zap.String("online_pubkey", hex.EncodeToString(onlinePK)),
			zap.String("root_pubkey", hex.EncodeToString(rootPK)),
			zap.Time("expiry", expiry),
			zap.Duration("validity", time.Until(expiry)),
		)
		pqState = &atomic.Pointer[certState]{}
		pqState.Store(&certState{cert: cert, expiry: expiry, srvHash: protocol.ComputeSRV(rootPK)})

		initialRootPK := append([]byte(nil), rootPK...)
		go superviseLoop(ctx, certLog, "refreshLoopMLDSA44", func() { refreshLoopMLDSA44(ctx, certLog, pqState, initialRootPK) })
	}

	statsLog := logger.Named("stats")
	go superviseLoop(ctx, statsLog, "statsLoop", func() { statsLoop(ctx, statsLog, edState, pqState) })

	// UDP carries only Ed25519 (ML-DSA breaks the amplification budget); TCP
	// carries both. A listener error cancels the shared context so the peer
	// drains, and serve returns the first error.
	listenerCtx, cancelListeners := context.WithCancel(ctx)
	defer cancelListeners()
	var listenerErr atomic.Pointer[error]
	recordListenerErr := func(role string, err error) {
		logger.Error(role+" listener exited with error", zap.Error(err))
		wrapped := fmt.Errorf("%s listener: %w", role, err)
		listenerErr.CompareAndSwap(nil, &wrapped)
		cancelListeners()
	}
	var wg sync.WaitGroup
	if edState != nil {
		wg.Go(func() {
			if err := listen(listenerCtx, edState); err != nil {
				recordListenerErr("UDP", err)
			}
		})
	}
	wg.Go(func() {
		if err := listenTCP(listenerCtx, edState, pqState); err != nil {
			recordListenerErr("TCP", err)
		}
	})
	wg.Wait()
	if err := listenerErr.Load(); err != nil {
		return *err
	}
	return nil
}
