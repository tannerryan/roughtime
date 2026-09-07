// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

//go:build unix

// Command roughtime is a Roughtime server. It serves Ed25519 over UDP/TCP and
// the experimental ML-DSA-44 extension over TCP. Run with -h for flags.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"math"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/tannerryan/roughtime/internal/version"
	"github.com/tannerryan/roughtime/protocol"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// logger is the package-wide structured logger, configured in serve.
var logger *zap.Logger

var (
	// port is the shared UDP/TCP listen-port flag.
	port = flag.Int("port", 2002, "port to listen on")
	// listenAddress is the shared UDP/TCP bind-address flag.
	listenAddress = flag.String("listen-address", "", "local address for UDP/TCP listeners (empty binds all interfaces)")
	// rootKeySeedHexFile is the Ed25519 root-seed path flag.
	rootKeySeedHexFile = flag.String("root-key-file", "", "path to file containing hex-encoded Ed25519 root private key seed")
	// pqRootKeySeedHexFile is the ML-DSA-44 root-seed path flag.
	pqRootKeySeedHexFile = flag.String("pq-root-key-file", "", "path to file containing hex-encoded ML-DSA-44 root private key seed")
	// logLevel is the structured-log threshold flag.
	logLevel = flag.String("log-level", "info", "log level (debug, info, warn, error)")
	// showVersion requests version output and exit.
	showVersion = flag.Bool("version", false, "print version and exit")
	// keygen is the Ed25519 key-generation output-path flag.
	keygen = flag.String("keygen", "", "generate an Ed25519 root key pair and write the seed to the given path")
	// pubkey is the Ed25519 public-key derivation input-path flag.
	pubkey = flag.String("pubkey", "", "derive and print the Ed25519 public key from an existing root key file")
	// pqKeygen is the ML-DSA-44 key-generation output-path flag.
	pqKeygen = flag.String("pq-keygen", "", "generate an ML-DSA-44 root key pair and write the seed to the given path")
	// pqPubkey is the ML-DSA-44 public-key derivation input-path flag.
	pqPubkey = flag.String("pq-pubkey", "", "derive and print the ML-DSA-44 public key from an existing PQ root key file")
	// greaseRate is the probability of greasing each response.
	greaseRate = flag.Float64("grease-rate", 0.01, "fraction of responses to grease (0 to disable)")
	// metricsAddr is the optional metrics-listener address flag.
	metricsAddr = flag.String("metrics-addr", "", "unauthenticated /metrics and /healthz address (host:port, empty disables). Use 127.0.0.1:PORT for loopback")
	// statsInterval is the periodic statistics-log cadence flag.
	statsInterval = flag.Duration("stats-interval", 60*time.Second, "cadence of the periodic stats log (e.g. 10s, 5m). Minimum 1s")
	// offlineDelegation selects read-once root-key operation.
	offlineDelegation = flag.Bool("offline-delegation", false, "read root keys only at startup and disable delegation refresh. Restart before certificate expiry")
)

// Server-wide tunable constants.
const (
	// radius is the uncertainty radius advertised on every reply.
	radius = 3 * time.Second
	// minRequestSize is the minimum accepted UDP datagram size.
	minRequestSize = 1024
	// maxPacketSize is the UDP payload limit for a 1500-byte IPv4 MTU. Receive
	// buffers reserve one extra byte to detect larger datagrams.
	maxPacketSize = 1472
)

// Fixed batching parameters keep signing throughput predictable.
const (
	// batchMaxSize bounds the requests-per-batch flush trigger.
	batchMaxSize = 256
	// batchMaxLatency bounds the time-since-first-request flush trigger.
	batchMaxLatency = 1 * time.Millisecond
)

// validateFlags checks the CLI flag globals and returns the first violation.
func validateFlags() error {
	if *rootKeySeedHexFile == "" && *pqRootKeySeedHexFile == "" {
		return fmt.Errorf("usage: roughtime (-root-key-file <path> | -pq-root-key-file <path>) [-port <port>] [-log-level <level>]")
	}
	if *port < 1 || *port > 65535 {
		return fmt.Errorf("-port %d out of range (must be 1-65535)", *port)
	}
	if math.IsNaN(*greaseRate) || math.IsInf(*greaseRate, 0) || *greaseRate < 0 || *greaseRate > 1 {
		return fmt.Errorf("-grease-rate %v out of range (must be in [0, 1])", *greaseRate)
	}
	if *metricsAddr != "" {
		if _, _, err := net.SplitHostPort(*metricsAddr); err != nil {
			return fmt.Errorf("-metrics-addr %q invalid (want host:port): %w", *metricsAddr, err)
		}
	}
	if *statsInterval < time.Second {
		return fmt.Errorf("-stats-interval %v must be at least 1s", *statsInterval)
	}
	return nil
}

// serverListenAddr returns the shared UDP/TCP bind endpoint.
func serverListenAddr() string {
	return net.JoinHostPort(*listenAddress, strconv.Itoa(*port))
}

// main parses flags and dispatches to the appropriate subcommand or to serve.
func main() {
	flag.Parse()
	if err := dispatch(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// validateActionFlags rejects ambiguous one-shot command invocations before any
// action can modify a key file or print output.
func validateActionFlags() error {
	actions := make([]string, 0, 5)
	if *showVersion {
		actions = append(actions, "-version")
	}
	if *keygen != "" {
		actions = append(actions, "-keygen")
	}
	if *pqKeygen != "" {
		actions = append(actions, "-pq-keygen")
	}
	if *pubkey != "" {
		actions = append(actions, "-pubkey")
	}
	if *pqPubkey != "" {
		actions = append(actions, "-pq-pubkey")
	}
	if len(actions) > 1 {
		return fmt.Errorf("action flags are mutually exclusive: %s", strings.Join(actions, ", "))
	}
	return nil
}

// dispatch routes the parsed flag globals to a subcommand or to serve.
func dispatch() error {
	if err := validateActionFlags(); err != nil {
		return err
	}
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

// serve runs the Roughtime server until ctx is cancelled or a serving or
// certificate-management component fails.
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
	// zap.Sync returns ENOTTY on terminal stderr, so ignore it
	defer func() { _ = base.Sync() }()
	logger = base.Named("roughtime")

	logger.Info("starting roughtime server",
		zap.String("version", version.Version),
		zap.Int("pid", os.Getpid()),
		zap.Int("port", *port),
		zap.String("listen_address", *listenAddress),
		zap.String("root_key", *rootKeySeedHexFile),
		zap.String("pq_root_key", *pqRootKeySeedHexFile),
		zap.Stringer("log_level", lvl),
		zap.Float64("grease_rate", *greaseRate),
		zap.String("metrics_addr", *metricsAddr),
		zap.Bool("offline_delegation", *offlineDelegation),
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
			enc.AddDuration("cert_validity_check_interval", certValidityCheckInterval)
			enc.AddDuration("stats_interval", *statsInterval)
			return nil
		})),
	)

	certLog := logger.Named("cert")
	statsLog := logger.Named("stats")

	// listenerCtx fans cancellation across all spawned goroutines. The deferred
	// wg.Wait ensures serve does not return while any of them is still alive.
	listenerCtx, cancelListeners := context.WithCancel(ctx)
	var listenerErr atomic.Pointer[error]
	recordListenerErr := func(role string, err error) {
		logger.Error(role+" listener exited with error", zap.Error(err))
		wrapped := fmt.Errorf("%s listener: %w", role, err)
		listenerErr.CompareAndSwap(nil, &wrapped)
		cancelListeners()
	}
	recordRunningListenerErr := func(role string, err error) {
		if listenerCtx.Err() == nil && !errors.Is(err, context.Canceled) {
			recordListenerErr(role, err)
		}
	}
	var wg sync.WaitGroup
	var edState, pqState *atomic.Pointer[certState]
	defer func() {
		cancelListeners()
		wg.Wait()
		retireCurrent(edState)
		retireCurrent(pqState)
	}()

	if *rootKeySeedHexFile != "" {
		cert, onlinePK, rootPK, expiry, err := provisionCertificateKey()
		if err != nil {
			return fmt.Errorf("provisioning initial Ed25519 certificate: %w", err)
		}
		certLog.Info("provisioned initial Ed25519 certificate",
			zap.String("online_pubkey", hex.EncodeToString(onlinePK)),
			zap.String("root_pubkey", hex.EncodeToString(rootPK)),
			zap.Time("expiry", expiry),
			zap.Duration("validity", certRemaining(expiry)),
		)
		edState = &atomic.Pointer[certState]{}
		edState.Store(&certState{cert: cert, notBefore: certNotBefore(expiry), expiry: expiry, srvHash: protocol.ComputeSRV(rootPK)})
		noteCertProvisioned(schemeEd25519, onlinePK, rootPK, expiry, wallClockNow())

		// captured so refreshLoop detects silent on-disk root-key changes
		initialRootPK := append(ed25519.PublicKey(nil), rootPK...)
		if *offlineDelegation {
			certLog.Warn("offline delegation mode: Ed25519 root key will not be read again. Restart before expiry",
				zap.Time("expiry", expiry),
			)
			wg.Go(func() {
				if err := monitorOfflineDelegation(listenerCtx, "Ed25519", edState); err != nil {
					recordListenerErr("Ed25519 offline delegation", err)
				}
			})
		} else {
			wg.Go(func() {
				if err := refreshLoop(listenerCtx, certLog, edState, initialRootPK); err != nil {
					recordListenerErr("Ed25519 certificate refresh", err)
				}
			})
		}
	}

	if *pqRootKeySeedHexFile != "" {
		cert, onlinePK, rootPK, expiry, err := provisionMLDSA44CertificateKey()
		if err != nil {
			return fmt.Errorf("provisioning initial ML-DSA-44 certificate: %w", err)
		}
		certLog.Info("provisioned initial ML-DSA-44 certificate",
			zap.String("online_pubkey", hex.EncodeToString(onlinePK)),
			zap.String("root_pubkey", hex.EncodeToString(rootPK)),
			zap.Time("expiry", expiry),
			zap.Duration("validity", certRemaining(expiry)),
		)
		pqState = &atomic.Pointer[certState]{}
		pqState.Store(&certState{cert: cert, notBefore: certNotBefore(expiry), expiry: expiry, srvHash: protocol.ComputeSRV(rootPK)})
		noteCertProvisioned(schemeMLDSA44, onlinePK, rootPK, expiry, wallClockNow())

		initialRootPK := append([]byte(nil), rootPK...)
		if *offlineDelegation {
			certLog.Warn("offline delegation mode: ML-DSA-44 root key will not be read again. Restart before expiry",
				zap.Time("expiry", expiry),
			)
			wg.Go(func() {
				if err := monitorOfflineDelegation(listenerCtx, "ML-DSA-44", pqState); err != nil {
					recordListenerErr("ML-DSA-44 offline delegation", err)
				}
			})
		} else {
			wg.Go(func() {
				if err := refreshLoopMLDSA44(listenerCtx, certLog, pqState, initialRootPK); err != nil {
					recordListenerErr("ML-DSA-44 certificate refresh", err)
				}
			})
		}
	}

	wg.Go(func() { statsLoop(listenerCtx, statsLog, edState, pqState) })

	// UDP carries only Ed25519 (ML-DSA breaks the amplification budget). TCP
	// carries both. A listener error cancels listenerCtx and serve returns the
	// first error.
	if edState != nil {
		wg.Go(func() {
			if err := listen(listenerCtx, edState); err != nil {
				recordRunningListenerErr("UDP", err)
			}
		})
	}
	wg.Go(func() {
		if err := listenTCP(listenerCtx, edState, pqState); err != nil {
			recordRunningListenerErr("TCP", err)
		}
	})
	if *metricsAddr != "" {
		wg.Go(func() {
			if err := listenMetrics(listenerCtx, *metricsAddr); err != nil {
				recordRunningListenerErr("metrics", err)
			}
		})
	}
	wg.Wait()
	if err := listenerErr.Load(); err != nil {
		return *err
	}
	return nil
}
