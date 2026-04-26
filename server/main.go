// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

//go:build unix

// Command roughtime is a Roughtime server. It serves Ed25519 over UDP/TCP and
// the experimental ML-DSA-44 extension over TCP. Run with -h for flags.
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
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"filippo.io/mldsa"
	"github.com/tannerryan/roughtime/internal/version"
	"github.com/tannerryan/roughtime/protocol"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var logger *zap.Logger

var (
	port                 = flag.Int("port", 2002, "port to listen on")
	rootKeySeedHexFile   = flag.String("root-key-file", "", "path to file containing hex-encoded Ed25519 root private key seed")
	pqRootKeySeedHexFile = flag.String("pq-root-key-file", "", "path to file containing hex-encoded ML-DSA-44 root private key seed")
	logLevel             = flag.String("log-level", "info", "log level (debug, info, warn, error)")
	showVersion          = flag.Bool("version", false, "print version and exit")
	keygen               = flag.String("keygen", "", "generate an Ed25519 root key pair and write the seed to the given path")
	pubkey               = flag.String("pubkey", "", "derive and print the Ed25519 public key from an existing root key file")
	pqKeygen             = flag.String("pq-keygen", "", "generate an ML-DSA-44 root key pair and write the seed to the given path")
	pqPubkey             = flag.String("pq-pubkey", "", "derive and print the ML-DSA-44 public key from an existing PQ root key file")
	greaseRate           = flag.Float64("grease-rate", 0.01, "fraction of responses to grease (0 to disable)")
)

// Seed-file headers bind a seed to its scheme. Ed25519 files still accept
// legacy bare hex; PQ files must carry the header.
const (
	ed25519SeedHeader = "roughtime-ed25519-seed-v1"
	mldsa44SeedHeader = "roughtime-mldsa44-seed-v1"
)

const (
	// Roughtime uncertainty radius (drafts 10+)
	radius = 3 * time.Second

	// minimum accepted on-the-wire request size
	minRequestSize = 1024

	// certificate validity window relative to now
	certStartOffset = -6 * time.Hour
	certEndOffset   = 18 * time.Hour

	// IPv4 Ethernet MTU payload (1500 - 20 IP - 8 UDP)
	maxPacketSize = 1472

	// kernel UDP receive buffer per worker socket; capped silently by the
	// kernel sysctl maximum, applyReadBuffer warns on truncation
	socketRecvBuffer = 8 * 1024 * 1024
)

// Not exposed as flags; misconfiguration craters throughput or latency. var so
// tests can adjust.
var (
	batchMaxSize    = 256
	batchMaxLatency = 1 * time.Millisecond
)

// Timer intervals; var so tests can shrink them.
var (
	certRefreshThreshold = 3 * time.Hour
	certCheckInterval    = 15 * time.Minute
	refreshRetryCooldown = 5 * time.Minute
	statsInterval        = 60 * time.Second

	// delay before zeroing a rotated-out certificate's online signing key, to
	// cover signing operations that loaded the previous certState before swap
	certWipeGrace = 5 * time.Second
)

// Server-wide counters read by stats loop and shutdown log
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
// precomputed SRV hash of the long-term root key; swapped atomically.
type certState struct {
	cert    *protocol.Certificate
	expiry  time.Time
	srvHash []byte
}

// validatedRequest is a parsed request ready for batch signing; bufPtr, when
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

// writeSeedFile writes header + hex(seed) to path mode 0600 with
// O_EXCL|O_NOFOLLOW to refuse existing files and symlink races.
func writeSeedFile(path, header string, seed []byte) error {
	encoded := []byte(header + "\n" + hex.EncodeToString(seed) + "\n")
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
	return nil
}

// generateKeypair generates an Ed25519 root key pair, writes the headered seed
// to path, and prints the public key.
func generateKeypair(path string) error {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return fmt.Errorf("reading entropy: %w", err)
	}
	defer clear(seed)

	sk := ed25519.NewKeyFromSeed(seed)
	defer clear(sk)
	pk := sk.Public().(ed25519.PublicKey)

	if err := writeSeedFile(path, ed25519SeedHeader, seed); err != nil {
		return err
	}

	fmt.Printf("Seed written to: %s\n", path)
	fmt.Printf("Public key (hex):    %s\n", hex.EncodeToString(pk))
	fmt.Printf("Public key (base64): %s\n", base64.StdEncoding.EncodeToString(pk))
	return nil
}

// generateMLDSA44Keypair generates an ML-DSA-44 root key pair, writes the
// headered seed to path, and prints the public key.
func generateMLDSA44Keypair(path string) error {
	sk, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		return fmt.Errorf("generating ML-DSA-44 key: %w", err)
	}
	seed := sk.Bytes()
	defer clear(seed)
	pk := sk.PublicKey().Bytes()

	if err := writeSeedFile(path, mldsa44SeedHeader, seed); err != nil {
		return err
	}

	fmt.Printf("Seed written to: %s\n", path)
	fmt.Printf("Public key (hex):    %s\n", hex.EncodeToString(pk))
	fmt.Printf("Public key (base64): %s\n", base64.StdEncoding.EncodeToString(pk))
	return nil
}

// derivePublicKey reads an Ed25519 root seed and prints the public key; accepts
// headered or legacy bare-hex format.
func derivePublicKey(path string) error {
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	defer clear(raw)

	seed, err := parseSeed(raw, path, ed25519SeedHeader, "", ed25519.SeedSize, true)
	if err != nil {
		return err
	}
	defer clear(seed)

	sk := ed25519.NewKeyFromSeed(seed)
	defer clear(sk)
	pk := sk.Public().(ed25519.PublicKey)

	fmt.Printf("Public key (hex):    %s\n", hex.EncodeToString(pk))
	fmt.Printf("Public key (base64): %s\n", base64.StdEncoding.EncodeToString(pk))
	return nil
}

// deriveMLDSA44PublicKey reads an ML-DSA-44 root seed and prints the public
// key; the header is required (no legacy bare-hex format).
func deriveMLDSA44PublicKey(path string) error {
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	defer clear(raw)

	seed, err := parseSeed(raw, path, mldsa44SeedHeader, "PQ", mldsa.PrivateKeySize, false)
	if err != nil {
		return err
	}
	defer clear(seed)

	sk, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), seed)
	if err != nil {
		return fmt.Errorf("loading ML-DSA-44 key: %w", err)
	}
	pk := sk.PublicKey().Bytes()

	fmt.Printf("Public key (hex):    %s\n", hex.EncodeToString(pk))
	fmt.Printf("Public key (base64): %s\n", base64.StdEncoding.EncodeToString(pk))
	return nil
}

// readPrivateKeyFile Lstats, opens with O_NOFOLLOW, and reads a
// 0600-or-stricter seed file; role labels error messages (e.g. "root", "PQ
// root").
func readPrivateKeyFile(path, role string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %s key file: %w", role, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s key file %s is a symlink (refusing to follow)", role, path)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s key file %s is not a regular file", role, path)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return nil, fmt.Errorf("%s key file %s has insecure mode %#o (must be 0600 or stricter)", role, path, mode)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("opening %s signing key file: %w", role, err)
	}
	raw, err := io.ReadAll(f)
	_ = f.Close()
	if err != nil {
		return nil, fmt.Errorf("reading %s signing key file: %w", role, err)
	}
	return raw, nil
}

// parseSeed extracts a hex-encoded seed from raw; with acceptBareHex, missing
// header is treated as legacy bare hex. label (may be empty) prefixes errors;
// path is echoed in every error.
func parseSeed(raw []byte, path, header, label string, wantLen int, acceptBareHex bool) ([]byte, error) {
	noun := "seed"
	if label != "" {
		noun = label + " seed"
	}
	trimmed := bytes.TrimSpace(raw)
	// require whitespace/EOF after header so v10 doesn't accept v1
	hasHeader := false
	var afterHeader []byte
	if bytes.HasPrefix(trimmed, []byte(header)) {
		rest := trimmed[len(header):]
		if len(rest) == 0 || rest[0] == ' ' || rest[0] == '\t' || rest[0] == '\n' || rest[0] == '\r' {
			hasHeader = true
			afterHeader = rest
		}
	}
	var hexPart []byte
	switch {
	case hasHeader:
		hexPart = bytes.TrimSpace(afterHeader)
	case acceptBareHex:
		hexPart = trimmed
	default:
		return nil, fmt.Errorf("%s file %s missing %q header", noun, path, header)
	}
	seed, err := hex.DecodeString(string(hexPart))
	if err != nil {
		return nil, fmt.Errorf("decoding %s in %s: %w", noun, path, err)
	}
	if len(seed) != wantLen {
		clear(seed)
		return nil, fmt.Errorf("%s in %s has %d bytes, want %d", noun, path, len(seed), wantLen)
	}
	return seed, nil
}

// validateFlags checks CLI flags; at least one of -root-key-file or
// -pq-root-key-file must be set, and both enables dual-stack.
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

func main() {
	flag.Parse()
	if err := dispatch(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}

// dispatch routes flag.Parsed input to a subcommand or to [serve], returning
// any error to main for unified os.Exit handling. Tests invoke serve directly.
func dispatch() error {
	if *showVersion {
		fmt.Printf("roughtime %s (github.com/tannerryan/roughtime)\n\n%s\n", version.Version, version.Copyright)
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
// Reads the standard flag globals; configure them before calling.
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

// provisionCertificateKey reads the Ed25519 root seed and signs a fresh online
// delegation; seed and derived private key are cleared before return.
func provisionCertificateKey() (*protocol.Certificate, ed25519.PublicKey, ed25519.PublicKey, time.Time, error) {
	path := filepath.Clean(*rootKeySeedHexFile)

	raw, err := readPrivateKeyFile(path, "root")
	if err != nil {
		return nil, nil, nil, time.Time{}, err
	}
	defer clear(raw)

	rootKeySeed, err := parseSeed(raw, path, ed25519SeedHeader, "root signing key", ed25519.SeedSize, true)
	if err != nil {
		return nil, nil, nil, time.Time{}, err
	}
	defer clear(rootKeySeed)

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

// provisionMLDSA44CertificateKey reads the ML-DSA-44 root seed and signs a
// fresh online delegation; returns the encoded online and root public keys.
func provisionMLDSA44CertificateKey() (*protocol.Certificate, []byte, []byte, time.Time, error) {
	path := filepath.Clean(*pqRootKeySeedHexFile)

	raw, err := readPrivateKeyFile(path, "PQ root")
	if err != nil {
		return nil, nil, nil, time.Time{}, err
	}
	defer clear(raw)

	rootKeySeed, err := parseSeed(raw, path, mldsa44SeedHeader, "PQ root signing key", mldsa.PrivateKeySize, false)
	if err != nil {
		return nil, nil, nil, time.Time{}, err
	}
	defer clear(rootKeySeed)

	rootSK, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), rootKeySeed)
	if err != nil {
		return nil, nil, nil, time.Time{}, fmt.Errorf("loading PQ root signing key: %w", err)
	}
	rootPK := rootSK.PublicKey().Bytes()

	onlineSK, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		return nil, nil, nil, time.Time{}, fmt.Errorf("generating PQ online signing key: %w", err)
	}
	onlinePK := onlineSK.PublicKey().Bytes()

	now := time.Now()
	cert, err := protocol.NewCertificateMLDSA44(now.Add(certStartOffset), now.Add(certEndOffset), onlineSK, rootSK)
	if err != nil {
		return nil, nil, nil, time.Time{}, fmt.Errorf("generating PQ online certificate: %w", err)
	}
	return cert, onlinePK, rootPK, now.Add(certEndOffset), nil
}

// statsLoop emits a periodic summary of server activity until ctx is cancelled.
func statsLoop(ctx context.Context, log *zap.Logger, edState, pqState *atomic.Pointer[certState]) {
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
		fields := []zap.Field{
			zap.Uint64("received", r-lastReceived),
			zap.Uint64("responded", s-lastResponded),
			zap.Uint64("dropped", d-lastDropped),
			zap.Uint64("panics", p-lastPanics),
			zap.Uint64("batches", intervalBatches),
			zap.Uint64("batch_errs", be-lastBatchErrs),
			zap.Float64("avg_batch_size", avgBatch),
		}
		if edState != nil {
			fields = append(fields, zap.Duration("cert_remaining", time.Until(edState.Load().expiry)))
		}
		if pqState != nil {
			fields = append(fields, zap.Duration("pq_cert_remaining", time.Until(pqState.Load().expiry)))
		}
		log.Info("stats", fields...)
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

// refreshLoop replaces the Ed25519 certificate near expiry; refresh is rejected
// if the root key on disk no longer matches initialRootPK.
func refreshLoop(ctx context.Context, log *zap.Logger, state *atomic.Pointer[certState], initialRootPK ed25519.PublicKey) {
	runRefreshLoop(ctx, log, "Ed25519", state, func() (*certState, []byte, error) {
		return tryRefreshCert(initialRootPK)
	})
}

// refreshLoopMLDSA44 is the ML-DSA-44 counterpart of refreshLoop; initialRootPK
// is the encoded root public key captured at startup.
func refreshLoopMLDSA44(ctx context.Context, log *zap.Logger, state *atomic.Pointer[certState], initialRootPK []byte) {
	runRefreshLoop(ctx, log, "ML-DSA-44", state, func() (*certState, []byte, error) {
		return tryRefreshCertMLDSA44(initialRootPK)
	})
}

// runRefreshLoop is the scheme-agnostic refresh driver; refresh returns a new
// certState and the new online public key (logged only).
func runRefreshLoop(ctx context.Context, log *zap.Logger, scheme string, state *atomic.Pointer[certState], refresh func() (*certState, []byte, error)) {
	ticker := time.NewTicker(certCheckInterval)
	defer ticker.Stop()
	var lastAttempt time.Time

	log.Info("certificate refresh loop started",
		zap.String("scheme", scheme),
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
			zap.String("scheme", scheme),
			zap.Time("current_expiry", cur.expiry),
			zap.Duration("remaining", time.Until(cur.expiry)),
		)
		newState, newOnlinePK, err := refresh()
		if err != nil {
			remaining := time.Until(cur.expiry)
			// below 2x cooldown the next attempt may miss expiry; fail so the
			// supervisor restarts rather than serving an expiring cert
			if remaining < 2*refreshRetryCooldown {
				log.Fatal("certificate refresh failed near expiry; restart required",
					zap.String("scheme", scheme),
					zap.Error(err),
					zap.Time("current_expiry", cur.expiry),
					zap.Duration("remaining", remaining),
					zap.Duration("retry_cooldown", refreshRetryCooldown),
				)
			}
			if ce := log.Check(zap.ErrorLevel, "certificate refresh failed"); ce != nil {
				ce.Write(
					zap.String("scheme", scheme),
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
			zap.String("scheme", scheme),
			zap.String("online_pubkey", hex.EncodeToString(newOnlinePK)),
			zap.Time("previous_expiry", cur.expiry),
			zap.Time("expiry", newState.expiry),
			zap.Duration("validity", time.Until(newState.expiry)),
		)
	}
}

// tryRefreshCert reads the Ed25519 root key, rejects any root-key change, and
// returns a fresh certState plus the new online public key.
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

// tryRefreshCertMLDSA44 reads the ML-DSA-44 root key, rejects any root-key
// change, and returns a fresh certState plus the encoded new online public key.
func tryRefreshCertMLDSA44(initialRootPK []byte) (*certState, []byte, error) {
	newCert, newOnlinePK, newRootPK, newExpiry, err := provisionMLDSA44CertificateKey()
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(newRootPK, initialRootPK) {
		return nil, nil, fmt.Errorf("PQ root public key on disk has changed since startup (want %s, got %s); restart required",
			hex.EncodeToString(initialRootPK), hex.EncodeToString(newRootPK))
	}
	return &certState{cert: newCert, expiry: newExpiry, srvHash: protocol.ComputeSRV(newRootPK)}, newOnlinePK, nil
}

// validateRequest parses a request, validates SRV, and negotiates a version;
// bufPtr (when non-nil) is stored on the returned struct for pool return.
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
	// drafts 10+: reject when SRV does not address a long-term key
	if req.SRV != nil && !bytes.Equal(req.SRV, st.srvHash) {
		if ce := log.Check(zap.DebugLevel, "SRV mismatch"); ce != nil {
			ce.Write(zap.Stringer("peer", peer))
		}
		return validatedRequest{}, false
	}
	responseVer, err := protocol.SelectVersion(req.Versions, len(req.Nonce), protocol.ServerPreferenceEd25519)
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
// amplification-filtered replies; updates only batch-level counters.
func signAndBuildReplies(log *zap.Logger, st *certState, ver protocol.Version, items []validatedRequest) []readyReply {
	reqs := make([]protocol.Request, len(items))
	for i := range items {
		reqs[i] = items[i].req
	}

	// zero midpoint defers timestamping to CreateReplies
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
		// fall back to ungreased if grease would exceed the amplification
		// budget
		if *greaseRate > 0 && mrand.Float64() < *greaseRate {
			if greased := protocol.Grease(reply, ver); len(greased) <= items[i].requestSize {
				reply = greased
				if ce := log.Check(zap.DebugLevel, "greased response"); ce != nil {
					ce.Write(zap.Stringer("peer", items[i].peer))
				}
			}
		}

		// amplification protection: reply MUST NOT exceed request size on UDP
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
