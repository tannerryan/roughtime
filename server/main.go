// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

// Command roughtime is a UDP Roughtime server that responds with signed
// timestamps and refreshes its online signing certificate before expiry.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/tannerryan/roughtime/internal/version"
	"github.com/tannerryan/roughtime/protocol"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var logger *zap.Logger

var (
	port               = flag.Int("port", 2002, "port to listen on")
	rootKeySeedHexFile = flag.String("root-key-file", "", "path to file containing hex-encoded root private key seed")
	logLevel           = flag.String("log-level", "info", "log level (debug, info, warn, error)")
	showVersion        = flag.Bool("version", false, "print version and exit")
	keygen             = flag.String("keygen", "", "generate a root key pair and write the seed to the given path")
	pubkey             = flag.String("pubkey", "", "derive and print the public key from an existing root key file")
	batchMaxSize       = flag.Int("batch-max-size", 64, "max requests per signing batch (1 to disable)")
	batchMaxLatency    = flag.Duration("batch-max-latency", 5*time.Millisecond, "max wait before signing an incomplete batch")
	greaseRate         = flag.Float64("grease-rate", 0.01, "fraction of responses to grease (0 to disable)")
)

const (
	// radius is the Roughtime uncertainty radius (drafts 10+ §5).
	radius = 3 * time.Second

	// minRequestSize is the minimum accepted on-the-wire request size.
	minRequestSize = 1024

	// certStartOffset is how far before now the certificate validity begins.
	certStartOffset = -6 * time.Hour

	// certEndOffset is how far after now the certificate validity ends.
	certEndOffset = 18 * time.Hour

	// maxPacketSize sizes the UDP read buffer to the IPv4 Ethernet MTU payload
	// (1500 - 20 IP - 8 UDP).
	maxPacketSize = 1472

	// socketRecvBuffer is the kernel UDP receive buffer size per worker socket.
	socketRecvBuffer = 8 * 1024 * 1024

	// batchQueueSize is the capacity of the batcher channel; excess requests
	// are dropped for backpressure.
	batchQueueSize = 4096
)

// Timer intervals declared as var so tests can shrink them.
var (
	// certRefreshThreshold is the remaining validity at which a new certificate
	// is provisioned.
	certRefreshThreshold = 3 * time.Hour

	// certCheckInterval is how often the refresh loop checks certificate
	// expiry.
	certCheckInterval = 15 * time.Minute

	// refreshRetryCooldown is the minimum delay between failed refresh
	// attempts.
	refreshRetryCooldown = 5 * time.Minute

	// statsInterval is how often the periodic stats log line is emitted.
	statsInterval = 60 * time.Second

	// certWipeGrace is the delay before zeroing a rotated-out certificate's
	// online signing key, covering any in-flight signing operations that loaded
	// the previous certState before the swap.
	certWipeGrace = 5 * time.Second
)

// Server-wide counters read by the stats loop and the shutdown log.
var (
	statsReceived    atomic.Uint64
	statsResponded   atomic.Uint64
	statsDropped     atomic.Uint64
	statsPanics      atomic.Uint64
	statsBatches     atomic.Uint64
	statsBatchedReqs atomic.Uint64
	statsBatchErrs   atomic.Uint64
)

// certState holds the current online certificate, its expiry, and the
// precomputed SRV hash of the long-term root key. Swapped atomically.
type certState struct {
	cert    *protocol.Certificate
	expiry  time.Time
	srvHash []byte
}

// validatedRequest is a parsed request ready for batch signing. bufPtr, when
// non-nil, must be returned to the pool after signing.
type validatedRequest struct {
	req         protocol.Request
	peer        *net.UDPAddr
	requestSize int
	bufPtr      *[]byte
	version     protocol.Version
}

// batchKey groups requests that can share a single signing operation.
type batchKey struct {
	version protocol.Version
	hasType bool
}

// readyReply is a response awaiting send.
type readyReply struct {
	peer  *net.UDPAddr
	bytes []byte
}

// generateKeypair generates a root Ed25519 key pair, writes the hex-encoded
// seed to path with mode 0600, and prints the public key to stdout. The seed
// file is created with O_EXCL|O_NOFOLLOW to avoid overwriting an existing file
// or following a symlink planted between an existence check and the write.
func generateKeypair(path string) error {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return fmt.Errorf("reading entropy: %w", err)
	}
	defer clear(seed)

	sk := ed25519.NewKeyFromSeed(seed)
	defer clear(sk)
	pk := sk.Public().(ed25519.PublicKey)

	encoded := []byte(hex.EncodeToString(seed) + "\n")
	defer clear(encoded)

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s already exists (refusing to overwrite)", path)
		}
		return fmt.Errorf("creating seed file %s: %w", path, err)
	}
	if _, err := f.Write(encoded); err != nil {
		_ = f.Close()
		return fmt.Errorf("writing seed to %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("closing seed file %s: %w", path, err)
	}

	fmt.Printf("Seed written to: %s\n", path)
	fmt.Printf("Public key (hex):    %s\n", hex.EncodeToString(pk))
	fmt.Printf("Public key (base64): %s\n", base64.StdEncoding.EncodeToString(pk))
	return nil
}

// derivePublicKey reads an existing root key seed and prints the public key.
func derivePublicKey(path string) error {
	seedHex, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	defer clear(seedHex)

	seed, err := hex.DecodeString(string(bytes.TrimSpace(seedHex)))
	if err != nil {
		return fmt.Errorf("decoding seed: %w", err)
	}
	defer clear(seed)
	if len(seed) != ed25519.SeedSize {
		return fmt.Errorf("seed has %d bytes, want %d", len(seed), ed25519.SeedSize)
	}

	sk := ed25519.NewKeyFromSeed(seed)
	defer clear(sk)
	pk := sk.Public().(ed25519.PublicKey)

	fmt.Printf("Public key (hex):    %s\n", hex.EncodeToString(pk))
	fmt.Printf("Public key (base64): %s\n", base64.StdEncoding.EncodeToString(pk))
	return nil
}

// validateFlags checks CLI flags are within permitted ranges.
func validateFlags() error {
	if *rootKeySeedHexFile == "" {
		return fmt.Errorf("usage: roughtime -root-key-file <path> [-port <port>] [-log-level <level>]")
	}
	if *port < 1 || *port > 65535 {
		return fmt.Errorf("-port %d out of range (must be 1-65535)", *port)
	}
	if *batchMaxSize < 1 {
		return fmt.Errorf("-batch-max-size %d must be >= 1", *batchMaxSize)
	}
	if *batchMaxSize > batchQueueSize {
		return fmt.Errorf("-batch-max-size %d must be <= %d", *batchMaxSize, batchQueueSize)
	}
	if *batchMaxLatency <= 0 {
		return fmt.Errorf("-batch-max-latency %s must be > 0", *batchMaxLatency)
	}
	if *greaseRate < 0 || *greaseRate > 1 {
		return fmt.Errorf("-grease-rate %v out of range (must be in [0, 1])", *greaseRate)
	}
	return nil
}

func main() {
	flag.Parse()
	if *showVersion {
		fmt.Printf("roughtime %s (github.com/tannerryan/roughtime)\n\n%s\n", version.Version, version.Copyright)
		return
	}
	if *keygen != "" {
		if err := generateKeypair(*keygen); err != nil {
			fmt.Fprintf(os.Stderr, "keygen: %s\n", err)
			os.Exit(1)
		}
		return
	}
	if *pubkey != "" {
		if err := derivePublicKey(*pubkey); err != nil {
			fmt.Fprintf(os.Stderr, "pubkey: %s\n", err)
			os.Exit(1)
		}
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
	// zap.Sync returns ENOTTY on a terminal stderr (uber-go/zap#328)
	defer func() { _ = base.Sync() }()
	logger = base.Named("roughtime")

	logger.Info("starting roughtime server",
		zap.String("version", version.Version),
		zap.Int("pid", os.Getpid()),
		zap.Int("port", *port),
		zap.String("root_key", *rootKeySeedHexFile),
		zap.Stringer("log_level", lvl),
		zap.Int("batch_max_size", *batchMaxSize),
		zap.Duration("batch_max_latency", *batchMaxLatency),
		zap.Float64("grease_rate", *greaseRate),
		zap.Object("tunables", zapcore.ObjectMarshalerFunc(func(enc zapcore.ObjectEncoder) error {
			enc.AddInt("recv_buffer", socketRecvBuffer)
			enc.AddInt("max_packet_size", maxPacketSize)
			enc.AddInt("min_request_size", minRequestSize)
			enc.AddInt("batch_queue_size", batchQueueSize)
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

	// Captured so refreshLoop can detect a silent root-key change on disk
	initialRootPK := append(ed25519.PublicKey(nil), rootPK...)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go superviseLoop(ctx, certLog, "refreshLoop", func() { refreshLoop(ctx, certLog, state, initialRootPK) })
	go superviseLoop(ctx, logger.Named("stats"), "statsLoop", func() { statsLoop(ctx, logger.Named("stats"), state) })

	if err := listen(ctx, state, *batchMaxSize, *batchMaxLatency); err != nil {
		logger.Fatal("running UDP server", zap.Error(err))
	}
}

// provisionCertificateKey reads the root key seed from disk and signs a fresh
// online delegation valid from certStartOffset to certEndOffset. The seed and
// derived private key are cleared before return.
func provisionCertificateKey() (*protocol.Certificate, ed25519.PublicKey, ed25519.PublicKey, time.Time, error) {
	path := filepath.Clean(*rootKeySeedHexFile)

	// Lstat rejects a symlinked key file
	info, err := os.Lstat(path)
	if err != nil {
		return nil, nil, nil, time.Time{}, fmt.Errorf("stat root key file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, nil, nil, time.Time{}, fmt.Errorf("root key file %s is a symlink (refusing to follow)", path)
	}
	if !info.Mode().IsRegular() {
		return nil, nil, nil, time.Time{}, fmt.Errorf("root key file %s is not a regular file", path)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return nil, nil, nil, time.Time{}, fmt.Errorf("root key file %s has insecure mode %#o (must be 0600 or stricter)", path, mode)
	}

	// O_NOFOLLOW closes the Lstat/open TOCTOU window
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, nil, time.Time{}, fmt.Errorf("opening root signing key file: %w", err)
	}
	rootKeySeedHex, err := io.ReadAll(f)
	_ = f.Close()
	if err != nil {
		return nil, nil, nil, time.Time{}, fmt.Errorf("reading root signing key file: %w", err)
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

// statsLoop emits a periodic summary of server activity until ctx is cancelled.
func statsLoop(ctx context.Context, log *zap.Logger, state *atomic.Pointer[certState]) {
	ticker := time.NewTicker(statsInterval)
	defer ticker.Stop()
	log.Info("stats loop started", zap.Duration("interval", statsInterval))

	var lastReceived, lastResponded, lastDropped, lastPanics, lastBatchCount, lastBatchTotal, lastBatchErrs uint64
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
		be := statsBatchErrs.Load()
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
			zap.Uint64("batch_errs", be-lastBatchErrs),
			zap.Float64("avg_batch_size", avgBatch),
			zap.Duration("cert_remaining", time.Until(state.Load().expiry)),
		)
		lastReceived, lastResponded, lastDropped, lastPanics = r, s, d, p
		lastBatchCount, lastBatchTotal, lastBatchErrs = bc, bt, be
	}
}

// recoverGoroutine logs and absorbs a panic, returning true if one was
// recovered.
func recoverGoroutine(log *zap.Logger, where string) bool {
	if r := recover(); r != nil {
		statsPanics.Add(1)
		log.Error("goroutine panic recovered",
			zap.String("where", where),
			zap.Any("panic", r),
			zap.Stack("stack"),
		)
		return true
	}
	return false
}

// superviseLoop runs fn, restarting on panic with a short backoff, until ctx is
// cancelled.
func superviseLoop(ctx context.Context, log *zap.Logger, where string, fn func()) {
	const restartBackoff = time.Second
	for ctx.Err() == nil {
		func() {
			defer recoverGoroutine(log, where)
			fn()
		}()
		if ctx.Err() != nil {
			return
		}
		log.Warn("goroutine exited before shutdown, restarting", zap.String("where", where))
		select {
		case <-ctx.Done():
			return
		case <-time.After(restartBackoff):
		}
	}
}

// refreshLoop replaces the certificate as it approaches expiry, with a cooldown
// between failed attempts. Refresh is rejected if the root public key on disk
// no longer matches initialRootPK. Exits when ctx is cancelled.
func refreshLoop(ctx context.Context, log *zap.Logger, state *atomic.Pointer[certState], initialRootPK ed25519.PublicKey) {
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
		newState, newOnlinePK, err := tryRefreshCert(initialRootPK)
		if err != nil {
			remaining := time.Until(cur.expiry)
			// Once remaining drops below 2 × cooldown, the next attempt may not
			// land before expiry; fail the process so the supervisor can
			// restart rather than serving an about-to-expire certificate
			if remaining < 2*refreshRetryCooldown {
				log.Fatal("certificate refresh failed near expiry; restart required",
					zap.Error(err),
					zap.Time("current_expiry", cur.expiry),
					zap.Duration("remaining", remaining),
					zap.Duration("retry_cooldown", refreshRetryCooldown),
				)
			}
			if ce := log.Check(zap.ErrorLevel, "certificate refresh failed"); ce != nil {
				ce.Write(
					zap.Error(err),
					zap.Time("current_expiry", cur.expiry),
					zap.Duration("remaining", remaining),
					zap.Duration("retry_cooldown", refreshRetryCooldown),
				)
			}
			continue
		}
		state.Store(newState)
		oldCert := cur.cert
		time.AfterFunc(certWipeGrace, oldCert.Wipe)
		log.Info("certificate refreshed",
			zap.String("online_pubkey", hex.EncodeToString(newOnlinePK)),
			zap.Time("previous_expiry", cur.expiry),
			zap.Time("expiry", newState.expiry),
			zap.Duration("validity", time.Until(newState.expiry)),
		)
	}
}

// tryRefreshCert reads the root key from disk, rejects any root public key
// change, and returns a fresh certState plus the new online public key.
func tryRefreshCert(initialRootPK ed25519.PublicKey) (*certState, ed25519.PublicKey, error) {
	newCert, newOnlinePK, newRootPK, newExpiry, err := provisionCertificateKey()
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(newRootPK, initialRootPK) {
		return nil, nil, fmt.Errorf("root public key on disk has changed since startup (want %s, got %s); restart required",
			hex.EncodeToString(initialRootPK), hex.EncodeToString(newRootPK))
	}
	return &certState{cert: newCert, expiry: newExpiry, srvHash: protocol.ComputeSRV(newRootPK)}, newOnlinePK, nil
}

// validateRequest parses a request, validates SRV, and negotiates a version.
// bufPtr, when non-nil, is stored on the returned struct for pool return.
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
	// Drafts 10+ §5.1: reject when SRV does not address a long-term key
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

// signAndBuildReplies signs a homogeneous batch and returns grease-applied,
// amplification-filtered replies. Callers record statsResponded after writing;
// this helper updates only batch-level counters.
func signAndBuildReplies(log *zap.Logger, st *certState, ver protocol.Version, items []validatedRequest) []readyReply {
	reqs := make([]protocol.Request, len(items))
	for i := range items {
		reqs[i] = items[i].req
	}

	// Zero midpoint defers timestamping to CreateReplies
	replies, err := protocol.CreateReplies(ver, reqs, time.Time{}, radius, st.cert)
	if err != nil {
		statsBatchErrs.Add(1)
		log.Warn("batch CreateReplies failed",
			zap.Stringer("version", ver),
			zap.Int("batch_size", len(items)),
			zap.Error(err),
		)
		return nil
	}

	statsBatches.Add(1)
	statsBatchedReqs.Add(uint64(len(items)))

	out := make([]readyReply, 0, len(replies))
	for i, reply := range replies {
		// Grease (§7); fall back to the ungreased reply if grease would push
		// the packet past the amplification budget
		if *greaseRate > 0 && mrand.Float64() < *greaseRate {
			if greased := protocol.Grease(reply, ver); len(greased) <= items[i].requestSize {
				reply = greased
				if ce := log.Check(zap.DebugLevel, "greased response"); ce != nil {
					ce.Write(zap.Stringer("peer", items[i].peer))
				}
			}
		}

		// Amplification protection (drafts 08+ §9/§13)
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
		out = append(out, readyReply{peer: items[i].peer, bytes: reply})
	}
	return out
}
