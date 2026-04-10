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
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/tannerryan/roughtime/internal/version"
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
	showVersion        = flag.Bool("version", false, "print version and exit")
)

const (
	// radius is the Roughtime uncertainty radius. Drafts 10+ require RADI ≥ 3s
	// in the absence of leap-second info.
	radius = 3 * time.Second

	// minRequestSize is the minimum on-the-wire request size; all drafts pad
	// requests to 1024 bytes.
	minRequestSize = 1024

	// certStartOffset is how far before now the certificate validity begins.
	certStartOffset = -6 * time.Hour

	// certEndOffset is how far after now the certificate validity ends. Total
	// DELE window is 24h (certStartOffset + certEndOffset).
	certEndOffset = 18 * time.Hour

	// certRefreshThreshold is the remaining validity at which a new certificate
	// is provisioned.
	certRefreshThreshold = 3 * time.Hour

	// certCheckInterval is how often the refresh loop checks certificate
	// expiry.
	certCheckInterval = 15 * time.Minute

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
	statsPanics    atomic.Uint64
)

// certState holds the current online certificate, its expiry, and the
// pre-computed SRV hash of the long-term root key. Swapped atomically so the
// request path is lock-free.
type certState struct {
	cert    *protocol.Certificate
	expiry  time.Time
	srvHash []byte
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
	if *showVersion {
		fmt.Printf("roughtime %s (github.com/tannerryan/roughtime)\n", version.Version)
		return
	}
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
	// zap.Sync returns ENOTTY on a terminal stderr (uber-go/zap#328); ignore.
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
	cert, onlinePK, rootPK, expiry, err := provisionCertificateKey()
	if err != nil {
		certLog.Fatal("provisioning initial certificate", zap.Error(err))
	}
	certLog.Info("provisioned initial certificate",
		zap.String("online_pubkey", hex.EncodeToString(onlinePK)),
		zap.String("root_pubkey", hex.EncodeToString(rootPK)),
		zap.Time("expiry", expiry),
		zap.Duration("validity", time.Until(expiry)),
	)

	state := &atomic.Pointer[certState]{}
	state.Store(&certState{cert: cert, expiry: expiry, srvHash: protocol.ComputeSRV(rootPK)})

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go refreshLoop(ctx, certLog, state)
	go statsLoop(ctx, logger.Named("stats"), state)

	if err := listen(ctx, state); err != nil {
		logger.Fatal("running UDP server", zap.Error(err))
	}
}

// provisionCertificateKey reads the root key seed from disk, validates it, and
// signs a fresh online delegation valid from certStartOffset to certEndOffset.
// The seed buffer and derived private key are cleared before return.
func provisionCertificateKey() (*protocol.Certificate, ed25519.PublicKey, ed25519.PublicKey, time.Time, error) {
	path := filepath.Clean(*rootKeySeedHexFile)

	info, err := os.Stat(path)
	if err != nil {
		return nil, nil, nil, time.Time{}, fmt.Errorf("stat root key file: %w", err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return nil, nil, nil, time.Time{}, fmt.Errorf("root key file %s has insecure mode %#o (must be 0600 or stricter)", path, mode)
	}

	rootKeySeedHex, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, nil, time.Time{}, fmt.Errorf("opening root signing key file: %w", err)
	}
	defer clear(rootKeySeedHex)

	rootKeySeed, err := hex.DecodeString(string(bytes.TrimSpace(rootKeySeedHex)))
	if err != nil {
		return nil, nil, nil, time.Time{}, fmt.Errorf("decoding root signing key seed: %w", err)
	}
	defer clear(rootKeySeed)
	if len(rootKeySeed) != ed25519.SeedSize {
		return nil, nil, nil, time.Time{}, fmt.Errorf("root key seed has %d bytes, want %d", len(rootKeySeed), ed25519.SeedSize)
	}
	rootSK := ed25519.NewKeyFromSeed(rootKeySeed)
	defer clear(rootSK)
	rootPK := rootSK.Public().(ed25519.PublicKey)

	onlinePK, onlineSK, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, time.Time{}, fmt.Errorf("generating online signing key: %w", err)
	}

	now := time.Now()
	cert, err := protocol.NewCertificate(now.Add(certStartOffset), now.Add(certEndOffset), onlineSK, rootSK)
	if err != nil {
		return nil, nil, nil, time.Time{}, fmt.Errorf("generating online certificate: %w", err)
	}
	return cert, onlinePK, rootPK, now.Add(certEndOffset), nil
}

// statsLoop emits a periodic Info-level summary of server activity until ctx is
// cancelled.
func statsLoop(ctx context.Context, log *zap.Logger, state *atomic.Pointer[certState]) {
	defer recoverGoroutine(log, "stats")
	ticker := time.NewTicker(statsInterval)
	defer ticker.Stop()
	log.Info("stats loop started", zap.Duration("interval", statsInterval))

	var lastReceived, lastResponded, lastDropped, lastPanics uint64
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		r := statsReceived.Load()
		s := statsResponded.Load()
		d := statsDropped.Load()
		p := statsPanics.Load()
		log.Info("stats",
			zap.Uint64("received", r-lastReceived),
			zap.Uint64("responded", s-lastResponded),
			zap.Uint64("dropped", d-lastDropped),
			zap.Uint64("panics", p-lastPanics),
			zap.Duration("cert_remaining", time.Until(state.Load().expiry)),
		)
		lastReceived, lastResponded, lastDropped, lastPanics = r, s, d, p
	}
}

// recoverGoroutine logs and absorbs a panic so a single bad request or refresh
// failure cannot crash the server.
func recoverGoroutine(log *zap.Logger, where string) {
	if r := recover(); r != nil {
		statsPanics.Add(1)
		log.Error("goroutine panic recovered",
			zap.String("where", where),
			zap.Any("panic", r),
			zap.Stack("stack"),
		)
	}
}

// refreshLoop replaces the certificate as it approaches expiry, with a cooldown
// between failed attempts. Exits when ctx is cancelled.
func refreshLoop(ctx context.Context, log *zap.Logger, state *atomic.Pointer[certState]) {
	defer recoverGoroutine(log, "refreshLoop")
	ticker := time.NewTicker(certCheckInterval)
	defer ticker.Stop()
	var lastAttempt time.Time

	log.Info("certificate refresh loop started",
		zap.Duration("check_interval", certCheckInterval),
		zap.Duration("refresh_threshold", certRefreshThreshold),
		zap.Duration("retry_cooldown", refreshRetryCooldown),
	)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

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
		newCert, newOnlinePK, newRootPK, newExpiry, err := provisionCertificateKey()
		if err != nil {
			log.Error("certificate refresh failed",
				zap.Error(err),
				zap.Time("current_expiry", cur.expiry),
				zap.Duration("retry_cooldown", refreshRetryCooldown),
			)
			continue
		}
		state.Store(&certState{cert: newCert, expiry: newExpiry, srvHash: protocol.ComputeSRV(newRootPK)})
		log.Info("certificate refreshed",
			zap.String("online_pubkey", hex.EncodeToString(newOnlinePK)),
			zap.Time("previous_expiry", cur.expiry),
			zap.Time("expiry", newExpiry),
			zap.Duration("validity", time.Until(newExpiry)),
		)
	}
}

// listen runs the UDP server: a CPU-sized worker pool consumes a bounded queue,
// excess requests are dropped, and the loop drains in-flight work on ctx
// cancellation.
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

	// On shutdown, set a past read deadline so the read loop unblocks cleanly
	// without closing the socket from underneath in-flight workers.
	go func() {
		<-ctx.Done()
		listenLog.Info("shutdown initiated, unblocking reads")
		_ = conn.SetReadDeadline(time.Unix(1, 0))
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
		// Drop undersize packets without dispatching: every Roughtime draft
		// requires client requests to be at least 1024 bytes (§5.1).
		if reqLen < minRequestSize {
			bufPool.Put(bufPtr)
			statsDropped.Add(1)
			if ce := listenLog.Check(zap.DebugLevel, "dropped undersize request"); ce != nil {
				ce.Write(zap.Stringer("peer", peer), zap.Int("size", reqLen))
			}
			continue
		}
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
	_ = conn.Close()
	listenLog.Info("shutdown complete",
		zap.Uint64("received_total", statsReceived.Load()),
		zap.Uint64("responded_total", statsResponded.Load()),
		zap.Uint64("dropped_total", statsDropped.Load()),
		zap.Uint64("panics_total", statsPanics.Load()),
		zap.Duration("drain_duration", time.Since(drainStart)),
	)
	return nil
}

// worker drains the work channel. A per-request recover absorbs panics so a
// single bad input cannot kill the worker. handleRequest must not retain
// req.bufPtr past return — it is returned to the pool here.
func worker(log *zap.Logger, conn *net.UDPConn, state *atomic.Pointer[certState], work <-chan request) {
	for req := range work {
		func() {
			defer recoverGoroutine(log, "worker")
			defer bufPool.Put(req.bufPtr)
			handleRequest(log, conn, req.peer, (*req.bufPtr)[:req.len], state.Load())
		}()
	}
}

// handleRequest parses a request, validates SRV, negotiates a version, signs a
// reply, and sends it. Invalid, unsupported, or amplifying requests are
// silently discarded.
func handleRequest(log *zap.Logger, conn *net.UDPConn, peer *net.UDPAddr, requestBytes []byte, st *certState) {
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
	// Drafts 13+ §5.1: if SRV is present, the server MUST ignore the request
	// when the value does not address one of its long-term keys.
	if req.SRV != nil && !bytes.Equal(req.SRV, st.srvHash) {
		if ce := log.Check(zap.DebugLevel, "SRV mismatch"); ce != nil {
			ce.Write(zap.Stringer("peer", peer))
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
	replies, err := protocol.CreateReplies(responseVer, []protocol.Request{*req}, time.Now(), radius, st.cert)
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
