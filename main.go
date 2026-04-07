// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

// Command roughtime is a UDP Roughtime server that listens for requests and
// responds with signed timestamps. The server automatically refreshes its
// online signing certificate before expiry. See the protocol package for
// supported versions.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
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

	"github.com/tannerryan/roughtime/protocol"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// logger is the package-wide structured logger, initialized in main.
var logger *zap.Logger

var (
	port               = flag.Int("port", 2002, "port to listen on")
	rootKeySeedHexFile = flag.String("root-key", "", "hex-encoded private key seed")
	logLevel           = flag.String("log-level", "info", "log level (debug, info, warn, error)")
)

const (
	// radius is the Roughtime uncertainty radius included in responses.
	radius = time.Second

	// certStartOffset is how far before now the certificate validity begins.
	certStartOffset = -7 * 24 * time.Hour

	// certEndOffset is how far after now the certificate validity ends.
	certEndOffset = 42 * 24 * time.Hour

	// certRefreshThreshold is the remaining validity at which a new certificate
	// is provisioned.
	certRefreshThreshold = 14 * 24 * time.Hour

	// certCheckInterval is how often the refresh loop checks certificate
	// expiry.
	certCheckInterval = time.Hour

	// refreshRetryCooldown is the minimum delay between failed refresh
	// attempts.
	refreshRetryCooldown = 5 * time.Minute

	// maxPacketSize is the maximum Roughtime UDP packet size.
	maxPacketSize = 1280

	// socketRecvBuffer is the kernel UDP receive buffer size. A larger buffer
	// reduces packet drops under burst traffic.
	socketRecvBuffer = 4 * 1024 * 1024

	// workerQueueSize is the capacity of the dispatch channel. Requests beyond
	// this are dropped to provide backpressure under extreme load.
	workerQueueSize = 4096

	// statsInterval is how often the periodic stats log line is emitted.
	statsInterval = 60 * time.Second
)

// Server-wide counters read by the stats loop and the shutdown log. The
// per-request atomic adds are negligible next to ed25519 signing.
var (
	statsReceived  atomic.Uint64
	statsResponded atomic.Uint64
	statsDropped   atomic.Uint64
)

// certState holds the current online certificate and its expiry. It is swapped
// atomically so the request path is lock-free.
type certState struct {
	cert   *protocol.Certificate
	expiry time.Time
}

// request is a unit of work dispatched from the read loop to a worker.
type request struct {
	bufPtr *[]byte
	len    int
	peer   *net.UDPAddr
}

// bufPool recycles read buffers to reduce GC pressure under high packet rates.
var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, maxPacketSize)
		return &b
	},
}

// main provisions the initial certificate and starts the UDP server.
func main() {
	flag.Parse()
	if *rootKeySeedHexFile == "" {
		fmt.Fprintf(os.Stderr, "usage: roughtime -root-key <path> [-port <port>] [-log-level <level>]\n")
		os.Exit(1)
	}

	lvl, err := zapcore.ParseLevel(*logLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid -log-level %q: %s\n", *logLevel, err)
		os.Exit(1)
	}
	cfg := zap.NewProductionConfig()
	cfg.Level = zap.NewAtomicLevelAt(lvl)
	base, err := cfg.Build()
	if err != nil {
		fmt.Fprintf(os.Stderr, "creating logger: %s\n", err)
		os.Exit(1)
	}
	// Sync is wrapped because zap returns an error when stderr/stdout is a
	// terminal on Unix ("inappropriate ioctl for device", ENOTTY); see
	// uber-go/zap#328 and uber-go/zap#991. Ignoring the error here is the
	// least-noisy idiomatic form.
	defer func() { _ = base.Sync() }()
	logger = base.Named("roughtime")

	logger.Info("starting roughtime server",
		zap.Int("pid", os.Getpid()),
		zap.Int("port", *port),
		zap.Int("workers", runtime.NumCPU()),
		zap.Int("queue_size", workerQueueSize),
		zap.Int("recv_buffer", socketRecvBuffer),
		zap.Duration("radius", radius),
		zap.Stringer("log_level", lvl),
	)

	certLog := logger.Named("cert")
	cert, onlinePK, expiry, err := provisionCertificateKey()
	if err != nil {
		certLog.Fatal("provisioning initial certificate", zap.Error(err))
	}
	certLog.Info("provisioned initial certificate",
		zap.String("online_pubkey", hex.EncodeToString(onlinePK)),
		zap.Time("expiry", expiry),
		zap.Duration("validity", time.Until(expiry)),
	)

	state := &atomic.Pointer[certState]{}
	state.Store(&certState{cert: cert, expiry: expiry})
	go refreshLoop(certLog, state)
	go statsLoop(logger.Named("stats"), state)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := listen(ctx, state); err != nil {
		logger.Fatal("running UDP server", zap.Error(err))
	}
}

// provisionCertificateKey reads the root key seed from disk and signs a fresh
// online delegation valid from certStartOffset to certEndOffset relative to
// now. It returns the certificate, the online public key (for audit logging),
// and the expiry.
func provisionCertificateKey() (*protocol.Certificate, ed25519.PublicKey, time.Time, error) {
	rootKeySeedHex, err := os.ReadFile(*rootKeySeedHexFile)
	if err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("opening root signing key file: %w", err)
	}
	rootKeySeed, err := hex.DecodeString(string(bytes.TrimSpace(rootKeySeedHex)))
	if err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("decoding root signing key seed: %w", err)
	}
	rootSK := ed25519.NewKeyFromSeed(rootKeySeed)

	onlinePK, onlineSK, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("generating online signing key: %w", err)
	}

	now := time.Now()
	startTime := now.Add(certStartOffset)
	endTime := now.Add(certEndOffset)

	cert, err := protocol.NewCertificate(startTime, endTime, onlineSK, rootSK)
	if err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("generating online certificate: %w", err)
	}
	return cert, onlinePK, endTime, nil
}

// statsLoop emits a periodic Info-level summary of server activity. It runs for
// the lifetime of the process; the final cumulative totals are emitted by the
// listener's shutdown log.
func statsLoop(log *zap.Logger, state *atomic.Pointer[certState]) {
	ticker := time.NewTicker(statsInterval)
	defer ticker.Stop()
	log.Info("stats loop started", zap.Duration("interval", statsInterval))

	var lastReceived, lastResponded, lastDropped uint64
	for range ticker.C {
		r := statsReceived.Load()
		s := statsResponded.Load()
		d := statsDropped.Load()
		log.Info("stats",
			zap.Uint64("received", r-lastReceived),
			zap.Uint64("responded", s-lastResponded),
			zap.Uint64("dropped", d-lastDropped),
			zap.Duration("cert_remaining", time.Until(state.Load().expiry)),
		)
		lastReceived, lastResponded, lastDropped = r, s, d
	}
}

// refreshLoop periodically checks whether the certificate is within
// certRefreshThreshold of expiring and provisions a replacement. On failure it
// retries no more frequently than refreshRetryCooldown. The supplied logger is
// expected to be the named "cert" child logger.
func refreshLoop(log *zap.Logger, state *atomic.Pointer[certState]) {
	ticker := time.NewTicker(certCheckInterval)
	defer ticker.Stop()
	var lastAttempt time.Time

	log.Info("certificate refresh loop started",
		zap.Duration("check_interval", certCheckInterval),
		zap.Duration("refresh_threshold", certRefreshThreshold),
		zap.Duration("retry_cooldown", refreshRetryCooldown),
	)

	for range ticker.C {
		cur := state.Load()
		if time.Until(cur.expiry) > certRefreshThreshold {
			continue
		}
		now := time.Now()
		if now.Sub(lastAttempt) < refreshRetryCooldown {
			continue
		}
		lastAttempt = now

		log.Info("attempting certificate refresh",
			zap.Time("current_expiry", cur.expiry),
			zap.Duration("remaining", time.Until(cur.expiry)),
		)
		newCert, newOnlinePK, newExpiry, err := provisionCertificateKey()
		if err != nil {
			log.Error("certificate refresh failed",
				zap.Error(err),
				zap.Time("current_expiry", cur.expiry),
				zap.Duration("retry_cooldown", refreshRetryCooldown),
			)
			continue
		}
		state.Store(&certState{cert: newCert, expiry: newExpiry})
		log.Info("certificate refreshed",
			zap.String("online_pubkey", hex.EncodeToString(newOnlinePK)),
			zap.Time("previous_expiry", cur.expiry),
			zap.Time("expiry", newExpiry),
			zap.Duration("validity", time.Until(newExpiry)),
		)
	}
}

// listen starts the UDP server, spawns a fixed worker pool sized to the number
// of CPUs, and dispatches incoming requests. If workers cannot keep up, excess
// requests are dropped to maintain throughput. It shuts down gracefully when
// ctx is cancelled, draining in-flight requests before returning.
func listen(ctx context.Context, state *atomic.Pointer[certState]) error {
	listenLog := logger.Named("listener")

	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: *port})
	if err != nil {
		return fmt.Errorf("starting UDP server: %w", err)
	}
	if err := conn.SetReadBuffer(socketRecvBuffer); err != nil {
		listenLog.Warn("setting UDP receive buffer failed",
			zap.Int("requested", socketRecvBuffer),
			zap.Error(err),
		)
	}

	work := make(chan request, workerQueueSize)
	var wg sync.WaitGroup
	workerLog := logger.Named("worker")
	for range runtime.NumCPU() {
		wg.Go(func() { worker(workerLog, conn, state, work) })
	}

	listenLog.Info("listening",
		zap.String("addr", conn.LocalAddr().String()),
		zap.Int("port", *port),
	)

	go func() {
		<-ctx.Done()
		listenLog.Info("shutdown initiated, closing socket")
		conn.Close()
	}()

	for {
		bufPtr := bufPool.Get().(*[]byte)
		reqLen, peer, err := conn.ReadFromUDP(*bufPtr)
		if err != nil {
			bufPool.Put(bufPtr)
			if ctx.Err() != nil {
				break
			}
			listenLog.Warn("UDP read error", zap.Error(err))
			continue
		}
		statsReceived.Add(1)
		select {
		case work <- request{bufPtr: bufPtr, len: reqLen, peer: peer}:
		default:
			bufPool.Put(bufPtr)
			statsDropped.Add(1)
			listenLog.Warn("dropped request: worker queue full",
				zap.Stringer("peer", peer),
				zap.Int("size", reqLen),
				zap.Int("queue_size", workerQueueSize),
			)
		}
	}

	drainStart := time.Now()
	close(work)
	wg.Wait()
	listenLog.Info("shutdown complete",
		zap.Uint64("received_total", statsReceived.Load()),
		zap.Uint64("responded_total", statsResponded.Load()),
		zap.Uint64("dropped_total", statsDropped.Load()),
		zap.Duration("drain_duration", time.Since(drainStart)),
	)
	return nil
}

// worker drains the work channel and processes each request for the lifetime of
// the server. It returns the read buffer to the pool after each request.
func worker(log *zap.Logger, conn *net.UDPConn, state *atomic.Pointer[certState], work <-chan request) {
	for req := range work {
		handleRequest(log, conn, req.peer, (*req.bufPtr)[:req.len], state.Load().cert)
		bufPool.Put(req.bufPtr)
	}
}

// handleRequest parses a Roughtime request, negotiates the protocol version,
// generates a signed response, and sends it back to the peer. Invalid or
// unsupported requests are silently discarded, and responses larger than the
// request are dropped to prevent amplification attacks. Per-request events are
// emitted at Debug level so they are filtered out in production.
func handleRequest(log *zap.Logger, conn *net.UDPConn, peer *net.UDPAddr, requestBytes []byte, cert *protocol.Certificate) {
	req, err := protocol.ParseRequest(requestBytes)
	if err != nil {
		if ce := log.Check(zap.DebugLevel, "request parse failed"); ce != nil {
			ce.Write(
				zap.Stringer("peer", peer),
				zap.Int("size", len(requestBytes)),
				zap.Error(err),
			)
		}
		return
	}
	responseVer, err := protocol.SelectVersion(req.Versions, len(req.Nonce))
	if err != nil {
		if ce := log.Check(zap.DebugLevel, "version negotiation failed"); ce != nil {
			ce.Write(zap.Stringer("peer", peer), zap.Error(err))
		}
		return
	}
	replies, err := protocol.CreateReplies(responseVer, []protocol.Request{*req}, time.Now(), radius, cert)
	if err != nil {
		if ce := log.Check(zap.DebugLevel, "creating reply failed"); ce != nil {
			ce.Write(zap.Stringer("peer", peer), zap.Error(err))
		}
		return
	}
	if len(replies) != 1 {
		if ce := log.Check(zap.DebugLevel, "unexpected reply count"); ce != nil {
			ce.Write(
				zap.Stringer("peer", peer),
				zap.Int("replies", len(replies)),
				zap.Stringer("version", responseVer),
			)
		}
		return
	}
	// Amplification protection: response must not exceed request size (draft-08
	// §13, draft-15 §9.7)
	if len(replies[0]) > len(requestBytes) {
		if ce := log.Check(zap.WarnLevel, "amplification-blocked response"); ce != nil {
			ce.Write(
				zap.Stringer("peer", peer),
				zap.Int("request_size", len(requestBytes)),
				zap.Int("reply_size", len(replies[0])),
				zap.Stringer("version", responseVer),
			)
		}
		return
	}
	if _, err := conn.WriteToUDP(replies[0], peer); err != nil {
		log.Warn("UDP write failed",
			zap.Stringer("peer", peer),
			zap.Error(err),
		)
		return
	}
	statsResponded.Add(1)
	if ce := log.Check(zap.DebugLevel, "sent response"); ce != nil {
		ce.Write(
			zap.Stringer("peer", peer),
			zap.Int("size", len(replies[0])),
			zap.Stringer("version", responseVer),
		)
	}
}
