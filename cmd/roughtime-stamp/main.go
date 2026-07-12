// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

// Command roughtime-stamp produces and verifies Roughtime document timestamps.
// Stamp mode hashes a file with SHA-256, binds the digest into a chained query
// across multiple witnesses, and writes the proof to disk as gzipped
// malfeasance-report JSON readable by roughtime.ParseProof. Verify mode
// re-validates a stored proof offline.
//
// Stamp:
//
//	go run ./cmd/roughtime-stamp -doc README.md -servers ecosystem.json -out README.md.proof
//
// Verify:
//
//	go run ./cmd/roughtime-stamp -mode verify -doc README.md -servers ecosystem.json -in README.md.proof
//
// All path flags are resolved relative to the process working directory.
//
// It uses IETF Ed25519 (drafts 05+) and experimental ML-DSA-44 witnesses. The
// SHA-256 seed requires a 32-byte nonce, so Google-Roughtime entries are
// skipped.
//
// Stamping requires >=2 distinct witness keys by design. The spec recommends
// >=3 for malfeasance detection, but two distinct witnesses are sufficient to
// bind a document to a corroborated time window.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/tannerryan/roughtime"
	"github.com/tannerryan/roughtime/internal/version"
)

var (
	// mode is the operation mode flag, either stamp or verify.
	mode = flag.String("mode", "stamp", "stamp or verify")
	// docPath is the document path flag.
	docPath = flag.String("doc", "", "document to timestamp")
	// serversFile is the ecosystem JSON path flag.
	serversFile = flag.String("servers", "ecosystem.json", "ecosystem JSON")
	// outPath is the proof output path flag for stamp mode.
	outPath = flag.String("out", "", "proof output path, overwritten if it exists (stamp mode)")
	// inPath is the proof input path flag for verify mode.
	inPath = flag.String("in", "", "proof input path (verify mode)")
	// timeout is the per-server timeout flag.
	timeout = flag.Duration("timeout", 2*time.Second, "per-server timeout")
	// retries is the per-server max retry attempts flag.
	retries = flag.Int("retries", 3, "max attempts per server (1 = no retry)")
	// showVersion is the version-print flag.
	showVersion = flag.Bool("version", false, "print version and exit")
)

// maxFileBytes caps ecosystem and proof file reads.
const maxFileBytes = 4 * 1024 * 1024

// main is the CLI entry point.
func main() {
	flag.Parse()
	if *showVersion {
		fmt.Printf("roughtime-stamp %s (github.com/tannerryan/roughtime)\n\n%s\n", version.Full(), version.Copyright)
		return
	}
	if err := validateFlags(); err != nil {
		fmt.Fprintf(os.Stderr, "roughtime-stamp: %s\n", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "roughtime-stamp: %s\n", err)
		os.Exit(1)
	}
}

// validateFlags checks CLI flag values and returns the first violation.
func validateFlags() error {
	if flag.NArg() > 0 {
		return fmt.Errorf("unexpected positional args: %v", flag.Args())
	}
	if *docPath == "" {
		return errors.New("-doc is required")
	}
	if *timeout <= 0 {
		return fmt.Errorf("-timeout %s must be > 0", *timeout)
	}
	if *retries < 1 {
		return fmt.Errorf("-retries %d must be >= 1", *retries)
	}
	switch *mode {
	case "stamp":
		if *outPath == "" {
			return errors.New("-out is required for -mode stamp")
		}
		if err := rejectSamePath("-out", *outPath, "-doc", *docPath); err != nil {
			return err
		}
		if err := rejectSamePath("-out", *outPath, "-servers", *serversFile); err != nil {
			return err
		}
	case "verify":
		if *inPath == "" {
			return errors.New("-in is required for -mode verify")
		}
	default:
		return fmt.Errorf("unknown -mode %q (want stamp or verify)", *mode)
	}
	return nil
}

// run dispatches to stamp or verify based on -mode.
func run(ctx context.Context) error {
	if *mode == "stamp" {
		return stamp(ctx)
	}
	return verify(ctx)
}

// stamp hashes the document, runs a chained query seeded with the digest, and
// writes the verified proof.
func stamp(ctx context.Context) error {
	servers, err := loadServers(*serversFile)
	if err != nil {
		return err
	}
	servers = filterCompatible(servers)
	if len(servers) < 2 {
		return fmt.Errorf("need >=2 compatible servers in %s, got %d", *serversFile, len(servers))
	}
	digest, docSize, err := hashDocument(ctx, *docPath)
	if err != nil {
		return err
	}

	c := &roughtime.Client{Timeout: *timeout, MaxAttempts: *retries}
	cr, err := c.QueryChainWithNonce(ctx, servers, digest)
	if err != nil {
		return fmt.Errorf("query chain: %w", err)
	}
	// a truncated chain from an interrupt must not be written as a success
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("interrupted before completing stamp: %w", err)
	}
	proof, err := cr.Proof()
	if err != nil {
		printFailures(cr.Results)
		return errors.New("no chain links produced; all servers failed")
	}
	if proof.Len() < 2 {
		printFailures(cr.Results)
		return fmt.Errorf("only %d witness responded; need >=2 for a multi-witness stamp", proof.Len())
	}
	// verify before persisting so we never write a proof verify mode would
	// reject
	if err := proof.Verify(); err != nil {
		printFailures(cr.Results)
		return fmt.Errorf("chain verify: %w", err)
	}
	// ensure the seed the library bound equals our digest, so the stamp always
	// passes verify mode's document-binding check
	if seed, err := proof.SeedNonce(); err != nil {
		return err
	} else if !bytes.Equal(seed, digest) {
		return fmt.Errorf("seed nonce %x != SHA-256(document) %x", seed, digest)
	}
	links, err := proof.Links()
	if err != nil {
		return fmt.Errorf("inspecting proof: %w", err)
	}
	// count distinct keys, not links: one key signing every link is not
	// independent corroboration
	witnesses := distinctKeys(links)
	if witnesses < 2 {
		printFailures(cr.Results)
		return fmt.Errorf("only %d distinct witness(es) responded; need >=2 for a multi-witness stamp", witnesses)
	}
	data, err := proof.MarshalGzip()
	if err != nil {
		return fmt.Errorf("serializing proof: %w", err)
	}
	parsed, err := roughtime.ParseProof(data)
	if err != nil {
		return fmt.Errorf("serialized proof does not parse: %w", err)
	}
	if err := parsed.Verify(); err != nil {
		return fmt.Errorf("serialized proof verify: %w", err)
	}
	if err := parsed.Trust(servers); err != nil {
		return fmt.Errorf("serialized proof trust: %w", err)
	}
	if parsedSeed, err := parsed.SeedNonce(); err != nil {
		return fmt.Errorf("serialized proof seed: %w", err)
	} else if !bytes.Equal(parsedSeed, digest) {
		return fmt.Errorf("serialized proof seed %x != SHA-256(document) %x", parsedSeed, digest)
	}
	if err := writeProofAtomic(*outPath, data); err != nil {
		return err
	}

	names := lookup(servers)
	fmt.Println("=== Roughtime Timestamp Receipt ===")
	fmt.Println()
	printDocument(*docPath, docSize, digest)
	printSeedLink(links[0], digest, names)
	printCorroborating(links[1:], names)
	printFailures(cr.Results)
	printAttestationWindow(links)

	fmt.Println("Receipt")
	fmt.Printf("  Saved to:         %s (%d bytes)\n", *outPath, len(data))
	fmt.Printf("  Verify offline:   roughtime-stamp -mode verify -doc %s -servers %s -in %s\n", *docPath, *serversFile, *outPath)
	fmt.Println()
	fmt.Printf("STAMPED: %s is attested by %d distinct witness keys to have\n", *docPath, witnesses)
	fmt.Println("existed no later than the upper bound above. Any modification to the")
	fmt.Println("document or receipt invalidates this attestation.")
	return nil
}

// verify re-validates a stored proof against the document, fully offline.
func verify(ctx context.Context) error {
	servers, err := loadServers(*serversFile)
	if err != nil {
		return err
	}
	raw, err := readBoundedFile(*inPath)
	if err != nil {
		return err
	}
	proof, err := roughtime.ParseProof(raw)
	if err != nil {
		return fmt.Errorf("parsing proof: %w", err)
	}
	if proof.Len() < 2 {
		return fmt.Errorf("proof has %d link(s); a multi-witness stamp requires >=2", proof.Len())
	}
	if err := proof.Verify(); err != nil {
		return fmt.Errorf("chain verify: %w", err)
	}
	if err := proof.Trust(servers); err != nil {
		return fmt.Errorf("trust: %w", err)
	}
	digest, docSize, err := hashDocument(ctx, *docPath)
	if err != nil {
		return err
	}
	seed, err := proof.SeedNonce()
	if err != nil {
		return err
	}
	if !bytes.Equal(seed, digest) {
		return fmt.Errorf("proof does not cover document: seed %x != SHA-256 %x", seed, digest)
	}
	links, err := proof.Links()
	if err != nil {
		return err
	}
	// distinct keys, not links: repeated keys are not independent witnesses
	witnesses := distinctKeys(links)
	if witnesses < 2 {
		return fmt.Errorf("proof has %d distinct witness(es); a multi-witness stamp requires >=2", witnesses)
	}

	names := lookup(servers)
	fmt.Println("=== Roughtime Timestamp Verification ===")
	fmt.Println()
	printDocument(*docPath, docSize, digest)

	fmt.Println("Receipt")
	fmt.Printf("  Path:             %s\n", *inPath)
	fmt.Printf("  On disk:          %d bytes\n", len(raw))
	fmt.Printf("  Witnesses:        %d\n", witnesses)
	fmt.Println()

	printSeedLink(links[0], digest, names)
	printCorroborating(links[1:], names)

	fmt.Println("Verification")
	printCheck("Signatures", fmt.Sprintf("all %d links signed by their listed public keys", proof.Len()))
	printCheck("Causal ordering", "no witness contradicts another's time window")
	printCheck("Nonce linkage", "each link's nonce derives from the previous reply")
	printCheck("Document binding", "seed nonce equals SHA-256(document)")
	printCheck("Trusted keys", fmt.Sprintf("all public keys present in %s", *serversFile))
	fmt.Println()

	printAttestationWindow(links)

	fmt.Printf("VALID: %s is attested by %d distinct witness keys to have\n", *docPath, witnesses)
	fmt.Println("existed no later than the upper bound above.")
	return nil
}

// hashDocument returns SHA-256(document) and the file size, rejecting
// non-regular files and honoring ctx.
func hashDocument(ctx context.Context, path string) ([]byte, int64, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, 0, fmt.Errorf("opening document: %w", err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, 0, fmt.Errorf("stat document: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, 0, fmt.Errorf("%s is not a regular file", path)
	}
	h := sha256.New()
	buf := make([]byte, 1024*1024)
	for {
		select {
		case <-ctx.Done():
			return nil, 0, ctx.Err()
		default:
		}
		n, err := f.Read(buf)
		if n > 0 {
			h.Write(buf[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, 0, fmt.Errorf("hashing document: %w", err)
		}
	}
	after, err := f.Stat()
	if err != nil {
		return nil, 0, fmt.Errorf("stat document after hashing: %w", err)
	}
	if after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) || after.Mode() != info.Mode() {
		return nil, 0, fmt.Errorf("%s changed while hashing", path)
	}
	pathInfo, err := os.Stat(filepath.Clean(path))
	if err != nil {
		return nil, 0, fmt.Errorf("stat document path after hashing: %w", err)
	}
	if !os.SameFile(after, pathInfo) {
		return nil, 0, fmt.Errorf("%s changed while hashing", path)
	}
	return h.Sum(nil), info.Size(), nil
}

// rejectSamePath rejects path pairs that name the same existing file.
func rejectSamePath(aName, aPath, bName, bPath string) error {
	aClean := filepath.Clean(aPath)
	bClean := filepath.Clean(bPath)
	aAbs, aErr := filepath.Abs(aClean)
	bAbs, bErr := filepath.Abs(bClean)
	if aErr == nil && bErr == nil && aAbs == bAbs {
		return fmt.Errorf("%s must not be the same path as %s", aName, bName)
	}
	aInfo, aStatErr := os.Stat(aClean)
	bInfo, bStatErr := os.Stat(bClean)
	if aStatErr == nil && bStatErr == nil && os.SameFile(aInfo, bInfo) {
		return fmt.Errorf("%s must not refer to the same file as %s", aName, bName)
	}
	return nil
}

// distinctKeys counts the unique witness public keys across links.
func distinctKeys(links []roughtime.ProofLink) int {
	seen := make(map[string]struct{}, len(links))
	for _, l := range links {
		seen[string(l.PublicKey)] = struct{}{}
	}
	return len(seen)
}

// loadServers reads and parses an ecosystem JSON file.
func loadServers(path string) ([]roughtime.Server, error) {
	data, err := readBoundedFile(path)
	if err != nil {
		return nil, err
	}
	return roughtime.ParseEcosystem(data)
}

// readBoundedFile reads up to maxFileBytes from a regular file, erroring on
// oversize input or non-regular paths.
func readBoundedFile(path string) ([]byte, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxFileBytes {
		return nil, fmt.Errorf("%s exceeds %d bytes", path, maxFileBytes)
	}
	return data, nil
}

// writeProofAtomic writes data to path via tmp+fsync+rename so a crash never
// leaves a half-written stamp.
func writeProofAtomic(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp.*")
	if err != nil {
		return fmt.Errorf("creating proof: %w", err)
	}
	tmp := f.Name()
	cleanup := func() { _ = f.Close(); _ = os.Remove(tmp) }
	if _, err := f.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("writing proof: %w", err)
	}
	if err := f.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("fsync proof: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("closing proof: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("renaming proof: %w", err)
	}
	// best-effort dir fsync to persist the rename across an OS crash
	if dir, err := os.Open(filepath.Dir(path)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

// filterCompatible drops Google-Roughtime entries and servers with unrecognized
// key lengths.
func filterCompatible(servers []roughtime.Server) []roughtime.Server {
	out := make([]roughtime.Server, 0, len(servers))
	for _, s := range servers {
		if strings.EqualFold(s.Version, "Google-Roughtime") {
			continue
		}
		if _, err := roughtime.SchemeOfKey(s.PublicKey); err != nil {
			continue
		}
		out = append(out, s)
	}
	return out
}

// lookup builds a public-key -> name map for display.
func lookup(servers []roughtime.Server) map[string]string {
	m := make(map[string]string, len(servers))
	for _, s := range servers {
		m[string(s.PublicKey)] = roughtime.SanitizeForDisplay(s.Name)
	}
	return m
}

// nameOf returns the ecosystem name for pk, falling back to a fingerprint.
func nameOf(pk []byte, names map[string]string) string {
	if n, ok := names[string(pk)]; ok && n != "" {
		return n
	}
	return fingerprint(pk)
}

// fingerprint is the first 8 bytes of pk in hex.
func fingerprint(pk []byte) string {
	if len(pk) >= 8 {
		return fmt.Sprintf("%x", pk[:8])
	}
	return fmt.Sprintf("%x", pk)
}
