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
	mrand "math/rand/v2"
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
	batchMaxSize       = flag.Int("batch-max-size", 64, "max requests per signing batch (1 to disable)")
	batchMaxLatency    = flag.Duration("batch-max-latency", 5*time.Millisecond, "max wait before signing an incomplete batch")
	greaseRate         = flag.Float64("grease-rate", 0.01, "fraction of responses to grease (0 to disable)")
)

const (
	// radius is the Roughtime uncertainty radius. Drafts 10+ require RADI ≥ 3s
	// in the absence of leap-second info.
	radius = 3 * time.Second

	// minRequestSize is the minimum on-the-wire request size; all drafts SHOULD
	// pad requests to 1024 bytes. Responding to shorter requests is OPTIONAL.
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

	// maxPacketSize is the read buffer size for incoming UDP packets. Sized to
	// the standard IPv4 Ethernet MTU payload (1500 - 20 IP - 8 UDP = 1472) so
	// that clients sending larger-than-1280 requests (e.g. draft-14+ clients
	// padding to the MTU) are not truncated.
	maxPacketSize = 1472

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
	statsReceived    atomic.Uint64
	statsResponded   atomic.Uint64
	statsDropped     atomic.Uint64
	statsPanics      atomic.Uint64
	statsBatches     atomic.Uint64
	statsBatchedReqs atomic.Uint64
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

// validatedRequest is a parsed, validated request ready for batch signing.
// Ownership of bufPtr transfers from the worker to the batcher.
type validatedRequest struct {
	req         protocol.Request
	peer        *net.UDPAddr
	requestSize int // original wire size, for amplification check
	bufPtr      *[]byte
	version     protocol.Version
}

// batchKey groups requests that can share a single signing operation.
type batchKey struct {
	version protocol.Version
	hasType bool
}

// bufPool recycles read buffers to reduce GC pressure under high packet rates.
var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, maxPacketSize)
		return &b
	},
}

// validateFlags checks CLI flags are within permitted ranges.
func validateFlags() error {
	if *rootKeySeedHexFile == "" {
		return fmt.Errorf("usage: roughtime -root-key <path> [-port <port>] [-log-level <level>]")
	}
	if *port < 1 || *port > 65535 {
		return fmt.Errorf("-port %d out of range (must be 1-65535)", *port)
	}
	if *batchMaxSize < 1 {
		return fmt.Errorf("-batch-max-size %d must be >= 1", *batchMaxSize)
	}
	if *batchMaxLatency <= 0 {
		return fmt.Errorf("-batch-max-latency %s must be > 0", *batchMaxLatency)
	}
	if *greaseRate < 0 || *greaseRate > 1 {
		return fmt.Errorf("-grease-rate %v out of range (must be in [0, 1])", *greaseRate)
	}
	return nil
}

// main provisions the initial certificate and starts the UDP server.
func main() {
	flag.Parse()
	if *showVersion {
		fmt.Printf("roughtime %s (github.com/tannerryan/roughtime)\n\n%s\n", version.Version, version.Copyright)
		return
	}
	if err := validateFlags(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
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
		zap.Int("batch_max_size", *batchMaxSize),
		zap.Duration("batch_max_latency", *batchMaxLatency),
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

	var lastReceived, lastResponded, lastDropped, lastPanics, lastBatchCount, lastBatchTotal uint64
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
		bc := statsBatches.Load()
		bt := statsBatchedReqs.Load()
		intervalBatches := bc - lastBatchCount
		var avgBatch float64
		if intervalBatches > 0 {
			avgBatch = float64(bt-lastBatchTotal) / float64(intervalBatches)
		}
		log.Info("stats",
			zap.Uint64("received", r-lastReceived),
			zap.Uint64("responded", s-lastResponded),
			zap.Uint64("dropped", d-lastDropped),
			zap.Uint64("panics", p-lastPanics),
			zap.Uint64("batches", intervalBatches),
			zap.Float64("avg_batch_size", avgBatch),
			zap.Duration("cert_remaining", time.Until(state.Load().expiry)),
		)
		lastReceived, lastResponded, lastDropped, lastPanics = r, s, d, p
		lastBatchCount, lastBatchTotal = bc, bt
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
	batchCh := make(chan validatedRequest, workerQueueSize)

	var wg sync.WaitGroup
	workerLog := logger.Named("worker")
	for range runtime.NumCPU() {
		wg.Go(func() { worker(workerLog, state, work, batchCh) })
	}

	var batcherWg sync.WaitGroup
	batcherLog := logger.Named("batcher")
	batcherWg.Go(func() {
		batcher(batcherLog, conn, state, batchCh, *batchMaxSize, *batchMaxLatency)
	})

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
		// Drop undersize packets without dispatching: responding to requests
		// shorter than 1024 bytes is OPTIONAL per all drafts (§5/§6).
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
	close(batchCh)
	batcherWg.Wait()
	_ = conn.Close()
	listenLog.Info("shutdown complete",
		zap.Uint64("received_total", statsReceived.Load()),
		zap.Uint64("responded_total", statsResponded.Load()),
		zap.Uint64("dropped_total", statsDropped.Load()),
		zap.Uint64("panics_total", statsPanics.Load()),
		zap.Uint64("batches_total", statsBatches.Load()),
		zap.Duration("drain_duration", time.Since(drainStart)),
	)
	return nil
}

// worker drains the work channel, validates requests, and forwards them to the
// batcher for bulk signing. On validation failure the buffer is returned to the
// pool; on success ownership transfers to the batcher.
func worker(log *zap.Logger, state *atomic.Pointer[certState], work <-chan request, batchCh chan<- validatedRequest) {
	for req := range work {
		func() {
			sent := false
			defer func() {
				if !sent {
					bufPool.Put(req.bufPtr)
				}
			}()
			defer recoverGoroutine(log, "worker")
			vr, ok := validateRequest(log, (*req.bufPtr)[:req.len], req.peer, req.len, req.bufPtr, state.Load())
			if !ok {
				return
			}
			batchCh <- vr
			sent = true
		}()
	}
}

// validateRequest parses a request, validates SRV, and negotiates a version. On
// success the returned validatedRequest owns bufPtr. On failure the caller must
// return bufPtr to the pool.
func validateRequest(log *zap.Logger, requestBytes []byte, peer *net.UDPAddr, reqSize int, bufPtr *[]byte, st *certState) (validatedRequest, bool) {
	req, err := protocol.ParseRequest(requestBytes)
	if err != nil {
		if ce := log.Check(zap.DebugLevel, "request parse failed"); ce != nil {
			ce.Write(
				zap.Stringer("peer", peer),
				zap.Int("size", len(requestBytes)),
				zap.Error(err),
			)
		}
		return validatedRequest{}, false
	}
	// Drafts 10+ §5.1: if SRV is present, the server MUST ignore the request
	// when the value does not address one of its long-term keys.
	if req.SRV != nil && !bytes.Equal(req.SRV, st.srvHash) {
		if ce := log.Check(zap.DebugLevel, "SRV mismatch"); ce != nil {
			ce.Write(zap.Stringer("peer", peer))
		}
		return validatedRequest{}, false
	}
	responseVer, err := protocol.SelectVersion(req.Versions, len(req.Nonce))
	if err != nil {
		if ce := log.Check(zap.DebugLevel, "version negotiation failed"); ce != nil {
			ce.Write(zap.Stringer("peer", peer), zap.Error(err))
		}
		return validatedRequest{}, false
	}
	return validatedRequest{
		req:         *req,
		peer:        peer,
		requestSize: reqSize,
		bufPtr:      bufPtr,
		version:     responseVer,
	}, true
}

// batcher accumulates validated requests grouped by (version, hasType) and
// flushes them in bulk signing batches. It fires when a batch reaches maxSize
// or when maxLatency has elapsed since the first request in a batch arrived.
func batcher(log *zap.Logger, conn *net.UDPConn, state *atomic.Pointer[certState], incoming <-chan validatedRequest, maxSize int, maxLatency time.Duration) {
	defer recoverGoroutine(log, "batcher")

	type pending struct {
		items []validatedRequest
		start time.Time
	}
	batches := make(map[batchKey]*pending)

	timer := time.NewTimer(0)
	if !timer.Stop() {
		<-timer.C
	}
	timerRunning := false

	resetTimer := func() {
		var earliest time.Time
		for _, b := range batches {
			deadline := b.start.Add(maxLatency)
			if earliest.IsZero() || deadline.Before(earliest) {
				earliest = deadline
			}
		}
		if earliest.IsZero() {
			if timerRunning {
				timer.Stop()
				timerRunning = false
			}
			return
		}
		timer.Reset(max(time.Until(earliest), 0))
		timerRunning = true
	}

	flush := func(key batchKey) {
		b := batches[key]
		if b == nil || len(b.items) == 0 {
			return
		}
		flushBatch(log, conn, state, key.version, b.items)
		delete(batches, key)
	}

	for {
		select {
		case vr, ok := <-incoming:
			if !ok {
				// Channel closed — flush all remaining batches.
				for key := range batches {
					flush(key)
				}
				return
			}
			key := batchKey{version: vr.version, hasType: vr.req.HasType}
			b, exists := batches[key]
			if !exists {
				b = &pending{items: make([]validatedRequest, 0, maxSize), start: time.Now()}
				batches[key] = b
			}
			b.items = append(b.items, vr)

			// Drafts 01-02 place NONC inside SREP, preventing multi-request
			// batches. Flush immediately to avoid the noncInSREP rejection.
			if protocol.NoncInSREP(vr.version, vr.req.HasType) || len(b.items) >= maxSize {
				flush(key)
			}
			resetTimer()

		case <-timer.C:
			timerRunning = false
			now := time.Now()
			for key, b := range batches {
				if now.Sub(b.start) >= maxLatency {
					flush(key)
				}
			}
			resetTimer()
		}
	}
}

// flushBatch signs a batch of requests and sends individual replies. Buffers
// are returned to the pool after sending regardless of outcome.
func flushBatch(log *zap.Logger, conn *net.UDPConn, state *atomic.Pointer[certState], ver protocol.Version, items []validatedRequest) {
	defer func() {
		for i := range items {
			if items[i].bufPtr != nil {
				bufPool.Put(items[i].bufPtr)
				items[i].bufPtr = nil
			}
		}
	}()
	defer recoverGoroutine(log, "flushBatch")

	st := state.Load()
	reqs := make([]protocol.Request, len(items))
	for i := range items {
		reqs[i] = items[i].req
	}

	replies, err := protocol.CreateReplies(ver, reqs, time.Now(), radius, st.cert)
	if err != nil {
		log.Warn("batch CreateReplies failed",
			zap.Stringer("version", ver),
			zap.Int("batch_size", len(items)),
			zap.Error(err),
		)
		return
	}

	statsBatches.Add(1)
	statsBatchedReqs.Add(uint64(len(items)))

	for i, reply := range replies {
		// Grease (Section 7): apply a random grease transformation so clients
		// learn to reject invalid responses and ignore undefined tags.
		if *greaseRate > 0 && mrand.Float64() < *greaseRate {
			reply = protocol.Grease(reply, ver)
			if ce := log.Check(zap.DebugLevel, "greased response"); ce != nil {
				ce.Write(zap.Stringer("peer", items[i].peer))
			}
		}

		// Amplification protection: response must not exceed request size
		// (drafts 08+ §9/§13; all drafts require this).
		if len(reply) > items[i].requestSize {
			if ce := log.Check(zap.WarnLevel, "amplification-blocked response"); ce != nil {
				ce.Write(
					zap.Stringer("peer", items[i].peer),
					zap.Int("request_size", items[i].requestSize),
					zap.Int("reply_size", len(reply)),
					zap.Stringer("version", ver),
				)
			}
			continue
		}
		if _, err := conn.WriteToUDP(reply, items[i].peer); err != nil {
			log.Warn("UDP write failed",
				zap.Stringer("peer", items[i].peer),
				zap.Error(err),
			)
			continue
		}
		statsResponded.Add(1)
		if ce := log.Check(zap.DebugLevel, "sent response"); ce != nil {
			ce.Write(
				zap.Stringer("peer", items[i].peer),
				zap.Int("size", len(reply)),
				zap.Stringer("version", ver),
			)
		}
	}
}
