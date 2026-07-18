// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

// Command roughtime-stamp creates document-bound, two-pass timestamp receipts
// from three endpoint-domain groups and verifies receipts without network I/O.
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
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/tannerryan/roughtime"
	"github.com/tannerryan/roughtime/internal/version"
)

var (
	// mode selects receipt creation or verification.
	mode = flag.String("mode", "stamp", "stamp or verify")
	// docPath is the document path flag.
	docPath = flag.String("doc", "", "document to timestamp")
	// serversFile is the trust-store ecosystem path.
	serversFile = flag.String("servers", "ecosystem.json", "ecosystem JSON")
	// outPath is the created proof path.
	outPath = flag.String("out", "", "proof output path, replaced atomically if it exists (stamp mode)")
	// inPath is the proof path to verify.
	inPath = flag.String("in", "", "proof input path (verify mode)")
	// timeout bounds each exchange attempt.
	timeout = flag.Duration("timeout", 2*time.Second, "timeout per attempt")
	// retries caps attempts per server.
	retries = flag.Int("retries", 3, "max attempts per server")
	// showVersion requests version output and exit.
	showVersion = flag.Bool("version", false, "print version and exit")
)

const (
	// maxFileBytes caps ecosystems and proofs read by the command.
	maxFileBytes = 4 * 1024 * 1024
	// stampWitnesses is the required endpoint-domain group count.
	stampWitnesses = 3
)

// main parses flags and runs the timestamp command.
func main() {
	flag.Parse()
	if *showVersion {
		fmt.Printf("roughtime-stamp %s (github.com/tannerryan/roughtime)\n\n%s\n", version.Full(), version.Copyright)
		return
	}
	if err := validateFlags(); err != nil {
		fmt.Fprintln(os.Stderr, "roughtime-stamp:", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "roughtime-stamp:", err)
		os.Exit(1)
	}
}

// validateFlags rejects invalid mode and path combinations.
func validateFlags() error {
	if flag.NArg() > 0 {
		return fmt.Errorf("unexpected positional args: %v", flag.Args())
	}
	if *docPath == "" {
		return errors.New("-doc is required")
	}
	if *timeout <= 0 || *retries < 1 {
		return errors.New("-timeout must be positive and -retries must be at least 1")
	}
	switch *mode {
	case "stamp":
		if *outPath == "" {
			return errors.New("-out is required for -mode stamp")
		}
		if *inPath != "" {
			return errors.New("-in is only valid for -mode verify")
		}
		if err := rejectSamePath("-out", *outPath, "-doc", *docPath); err != nil {
			return err
		}
		return rejectSamePath("-out", *outPath, "-servers", *serversFile)
	case "verify":
		if *inPath == "" {
			return errors.New("-in is required for -mode verify")
		}
		if *outPath != "" {
			return errors.New("-out is only valid for -mode stamp")
		}
		return nil
	default:
		return fmt.Errorf("unknown -mode %q (want stamp or verify)", *mode)
	}
}

// run dispatches to stamp or verify mode.
func run(ctx context.Context) error {
	if *mode == "stamp" {
		return stamp(ctx)
	}
	return verify(ctx)
}

// stamp creates and persists a document-bound receipt.
func stamp(ctx context.Context) error {
	servers, err := loadServers(*serversFile)
	if err != nil {
		return err
	}
	servers = filterCompatible(servers)
	witnesses := roughtime.SampleByOperator(servers, stampWitnesses)
	if len(witnesses) != stampWitnesses {
		return fmt.Errorf("need %d compatible endpoint-domain groups, got %d", stampWitnesses, len(witnesses))
	}
	digest, size, err := hashDocument(ctx, *docPath)
	if err != nil {
		return err
	}

	client := roughtime.Client{Timeout: *timeout, MaxAttempts: *retries}
	chain, err := client.QueryChainWithNonce(ctx, twoPassOrder(witnesses), digest)
	if err != nil {
		return fmt.Errorf("query chain: %w", err)
	}
	proof, err := chain.Proof()
	if err != nil || proof.Len() != 2*stampWitnesses {
		printFailures(chain.Results)
		completed := 0
		if proof != nil {
			completed = proof.Len()
		}
		return fmt.Errorf("completed %d of %d required witness queries", completed, 2*stampWitnesses)
	}
	data, err := proof.MarshalGzip()
	if err != nil {
		return fmt.Errorf("serializing proof: %w", err)
	}
	parsed, err := roughtime.ParseProof(data)
	if err != nil {
		return fmt.Errorf("checking serialized proof: %w", err)
	}
	if err := parsed.Trust(servers); err != nil {
		return fmt.Errorf("serialized proof trust: %w", err)
	}
	if err := parsed.Verify(); err != nil {
		return fmt.Errorf("serialized proof verify: %w", err)
	}
	links, err := parsed.Links()
	if err != nil {
		return err
	}
	seed, err := parsed.SeedNonce()
	if err != nil || !bytes.Equal(seed, digest) {
		return errors.New("serialized proof is not bound to the document")
	}
	profile := analyzeProof(links, servers)
	if !profile.twoPass || profile.passSize != stampWitnesses {
		return errors.New("proof does not contain two same-order passes across three endpoint-domain groups")
	}

	current, _, err := hashDocument(ctx, *docPath)
	if err != nil {
		return err
	}
	if !bytes.Equal(current, digest) {
		return errors.New("document changed before proof persistence")
	}
	if err := writeProofAtomic(ctx, *outPath, data); err != nil {
		return err
	}
	printReceipt(*docPath, size, digest, *outPath, len(data), links, profile)
	return nil
}

// verify validates a stored receipt against its document and trust store.
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
		return errors.New("proof requires at least two links")
	}
	if err := proof.Trust(servers); err != nil {
		return fmt.Errorf("trust: %w", err)
	}
	if err := proof.Verify(); err != nil {
		return fmt.Errorf("chain verify: %w", err)
	}
	links, err := proof.Links()
	if err != nil {
		return err
	}
	digest, size, err := hashDocument(ctx, *docPath)
	if err != nil {
		return err
	}
	seed, err := proof.SeedNonce()
	if err != nil || !bytes.Equal(seed, digest) {
		return errors.New("proof does not cover document")
	}
	if distinctKeys(links) < 2 {
		return errors.New("proof requires at least two distinct witnesses")
	}
	printVerification(*docPath, size, digest, *inPath, len(raw), links, analyzeProof(links, servers))
	return nil
}

// twoPassOrder repeats witnesses in the same order.
func twoPassOrder(witnesses []roughtime.Server) []roughtime.Server {
	return append(slices.Clone(witnesses), witnesses...)
}

// hashDocument returns a regular file's SHA-256 digest and size.
func hashDocument(ctx context.Context, path string) ([]byte, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, fmt.Errorf("opening document: %w", err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, 0, errors.New("document is not a regular file")
	}
	hash := sha256.New()
	buffer := make([]byte, 1024*1024)
	for {
		if err := ctx.Err(); err != nil {
			return nil, 0, err
		}
		n, readErr := f.Read(buffer)
		if n > 0 {
			_, _ = hash.Write(buffer[:n])
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return nil, 0, fmt.Errorf("hashing document: %w", readErr)
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
	return hash.Sum(nil), info.Size(), nil
}

// rejectSamePath rejects paths that name the same file.
func rejectSamePath(aName, aPath, bName, bPath string) error {
	aClean := filepath.Clean(aPath)
	bClean := filepath.Clean(bPath)
	a, errA := filepath.Abs(aClean)
	b, errB := filepath.Abs(bClean)
	if errA == nil && errB == nil && a == b {
		return fmt.Errorf("%s must not be the same path as %s", aName, bName)
	}
	aInfo, aErr := os.Stat(aClean)
	bInfo, bErr := os.Stat(bClean)
	if aErr == nil && bErr == nil && os.SameFile(aInfo, bInfo) {
		return fmt.Errorf("%s must not refer to the same file as %s", aName, bName)
	}
	return nil
}

// distinctKeys counts distinct witness root keys.
func distinctKeys(links []roughtime.ProofLink) int {
	keys := make(map[string]struct{}, len(links))
	for _, link := range links {
		keys[string(link.PublicKey)] = struct{}{}
	}
	return len(keys)
}

// proofProfile summarizes receipt structure and witness diversity.
type proofProfile struct {
	twoPass  bool
	passSize int
	groups   int
}

// analyzeProof identifies two-pass receipts and counts endpoint-domain groups.
func analyzeProof(links []roughtime.ProofLink, servers []roughtime.Server) proofProfile {
	endpointGroups := make(map[string]string, len(servers))
	for _, server := range servers {
		key := string(server.PublicKey)
		group := roughtime.OperatorKey(server)
		if previous, ok := endpointGroups[key]; ok && previous != group {
			endpointGroups[key] = ""
		} else if !ok {
			endpointGroups[key] = group
		}
	}
	profile := proofProfile{}
	seen := make(map[string]struct{})
	for _, link := range links {
		if group := endpointGroups[string(link.PublicKey)]; group != "" {
			seen[group] = struct{}{}
		}
	}
	profile.groups = len(seen)
	if len(links) < 2*stampWitnesses || len(links)%2 != 0 {
		return profile
	}
	n := len(links) / 2
	keys := make(map[string]struct{}, n)
	groups := make(map[string]struct{}, n)
	for i := range n {
		key := string(links[i].PublicKey)
		if key == "" || key != string(links[n+i].PublicKey) || endpointGroups[key] == "" {
			return profile
		}
		keys[key] = struct{}{}
		groups[endpointGroups[key]] = struct{}{}
	}
	if len(keys) == n && len(groups) == n {
		profile.twoPass = true
		profile.passSize = n
		profile.groups = n
	}
	return profile
}

// loadServers reads and parses a bounded ecosystem file.
func loadServers(path string) ([]roughtime.Server, error) {
	data, err := readBoundedFile(path)
	if err != nil {
		return nil, err
	}
	return roughtime.ParseEcosystem(data)
}

// readBoundedFile accepts files up to maxFileBytes.
func readBoundedFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxFileBytes {
		return nil, fmt.Errorf("%s exceeds %d bytes", display(path), maxFileBytes)
	}
	return data, nil
}

// writeProofAtomic durably replaces path without exposing partial contents.
func writeProofAtomic(ctx context.Context, path string, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	path = filepath.Clean(path)
	dirPath := filepath.Dir(path)
	f, err := os.CreateTemp(dirPath, filepath.Base(path)+".tmp.*")
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
		return fmt.Errorf("syncing proof: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := ctx.Err(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("renaming proof: %w", err)
	}
	dir, err := os.Open(dirPath)
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	return dir.Sync()
}

// filterCompatible retains distinct, non-Google servers usable as witnesses.
func filterCompatible(servers []roughtime.Server) []roughtime.Server {
	out := make([]roughtime.Server, 0, len(servers))
	seen := make(map[string]struct{}, len(servers))
	for _, server := range servers {
		if strings.EqualFold(server.Version, roughtime.VersionLabelGoogle) || server.Version == "3000600613" {
			continue
		}
		scheme, err := roughtime.SchemeOfKey(server.PublicKey)
		if err != nil {
			continue
		}
		if scheme == roughtime.SchemeMLDSA44 && !hasTransport(server.Addresses, "tcp") {
			continue
		}
		if limit, err := strconv.ParseUint(server.Version, 10, 32); err == nil {
			compatible := false
			for _, version := range roughtime.VersionsForScheme(scheme) {
				if uint64(version) <= limit {
					compatible = true
					break
				}
			}
			if !compatible {
				continue
			}
		}
		key := string(server.PublicKey)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, server)
	}
	return out
}

// hasTransport reports whether addresses includes transport.
func hasTransport(addresses []roughtime.Address, transport string) bool {
	return slices.ContainsFunc(addresses, func(address roughtime.Address) bool {
		return strings.EqualFold(address.Transport, transport)
	})
}

// display sanitizes untrusted terminal text.
func display(value string) string { return roughtime.SanitizeForDisplay(value) }

// printFailures prints failed witness queries.
func printFailures(results []roughtime.Result) {
	for _, result := range results {
		if result.Err != nil {
			fmt.Printf("  %s: %s\n", display(result.Server.Name), result.Err)
		}
	}
}
