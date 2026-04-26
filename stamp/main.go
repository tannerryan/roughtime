// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

// Command stamp produces and verifies Roughtime document timestamps. Stamp mode
// hashes a file with SHA-256, binds the digest into a chained query across
// multiple witnesses, and writes the proof to disk. Verify mode re-validates a
// stored proof offline.
//
// Stamp:
//
//	go run stamp/main.go -doc README.md -servers ecosystem.json -out README.md.proof
//
// Verify:
//
//	go run stamp/main.go -mode verify -doc README.md -servers ecosystem.json -in README.md.proof
//
// IETF Ed25519 (drafts 05+) and experimental ML-DSA-44 witnesses; the SHA-256
// seed requires a 32-byte nonce, so Google-Roughtime entries are skipped.
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
	mode        = flag.String("mode", "stamp", "stamp or verify")
	docPath     = flag.String("doc", "", "document to timestamp")
	serversFile = flag.String("servers", "ecosystem.json", "ecosystem JSON")
	outPath     = flag.String("out", "", "proof output path (stamp mode)")
	inPath      = flag.String("in", "", "proof input path (verify mode)")
	timeout     = flag.Duration("timeout", 2*time.Second, "per-server timeout")
	retries     = flag.Int("retries", 3, "max retry attempts per server")
	showVersion = flag.Bool("version", false, "print version and exit")
)

// maxFileBytes caps document and ecosystem file reads.
const maxFileBytes = 4 * 1024 * 1024

// tsFormat shows millisecond precision for attestation times.
const tsFormat = "2006-01-02T15:04:05.000Z"

func main() {
	flag.Parse()
	if *showVersion {
		fmt.Printf("roughtime-stamp %s (github.com/tannerryan/roughtime)\n\n%s\n", version.Version, version.Copyright)
		return
	}
	if err := validateFlags(); err != nil {
		fmt.Fprintf(os.Stderr, "stamp: %s\n", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "stamp: %s\n", err)
		os.Exit(1)
	}
}

func validateFlags() error {
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
	case "verify":
		if *inPath == "" {
			return errors.New("-in is required for -mode verify")
		}
	default:
		return fmt.Errorf("unknown -mode %q (want stamp or verify)", *mode)
	}
	return nil
}

func run(ctx context.Context) error {
	if *mode == "stamp" {
		return stamp(ctx)
	}
	return verify()
}

// stamp hashes the document, runs a chained query seeded with the digest, and
// writes the proof.
func stamp(ctx context.Context) error {
	digest, docSize, err := hashDocument(*docPath)
	if err != nil {
		return err
	}
	servers, err := loadServers(*serversFile)
	if err != nil {
		return err
	}
	servers = filterCompatible(servers)
	if len(servers) < 2 {
		return fmt.Errorf("need ≥2 compatible servers in %s, got %d", *serversFile, len(servers))
	}

	c := &roughtime.Client{Timeout: *timeout, Retries: *retries}
	cr, err := c.QueryChainWithNonce(ctx, servers, digest)
	if err != nil {
		return fmt.Errorf("query chain: %w", err)
	}
	proof, err := cr.Proof()
	if err != nil {
		printFailures(cr.Results)
		return errors.New("no chain links produced; all servers failed")
	}
	// stamp's contract is multi-witness corroboration; a 1-link chain has none
	if proof.Len() < 2 {
		printFailures(cr.Results)
		return fmt.Errorf("only %d witness responded; need >=2 for a multi-witness stamp", proof.Len())
	}
	data, err := proof.MarshalGzip()
	if err != nil {
		return fmt.Errorf("serializing proof: %w", err)
	}
	if err := writeProofAtomic(*outPath, data); err != nil {
		return err
	}
	links, err := proof.Links()
	if err != nil {
		return fmt.Errorf("inspecting proof: %w", err)
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
	fmt.Printf("  Verify offline:   roughtime-stamp -mode verify -doc %s -in %s\n", *docPath, *outPath)
	fmt.Println()
	fmt.Printf("The %d listed witnesses cryptographically attest that the document with\n", len(links))
	fmt.Println("the SHA-256 hash above existed at a time within the verified window. Any")
	fmt.Println("modification to the document or receipt invalidates this attestation.")
	return nil
}

// verify re-validates a stored proof against the document, fully offline.
func verify() error {
	digest, docSize, err := hashDocument(*docPath)
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
	servers, err := loadServers(*serversFile)
	if err != nil {
		return err
	}
	if err := proof.Trust(servers); err != nil {
		return fmt.Errorf("trust: %w", err)
	}
	seed, err := proof.SeedNonce()
	if err != nil {
		return err
	}
	if !bytes.Equal(seed, digest) {
		return fmt.Errorf("proof does not cover document: seed %x ≠ SHA-256 %x", seed, digest)
	}
	links, err := proof.Links()
	if err != nil {
		return err
	}

	names := lookup(servers)
	fmt.Println("=== Roughtime Timestamp Verification ===")
	fmt.Println()
	printDocument(*docPath, docSize, digest)

	fmt.Println("Receipt")
	fmt.Printf("  Path:             %s\n", *inPath)
	fmt.Printf("  On disk:          %d bytes\n", len(raw))
	fmt.Printf("  Witnesses:        %d\n", proof.Len())
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

	fmt.Printf("VALID: %s is attested by %d independent Roughtime witnesses to have\n", *docPath, proof.Len())
	fmt.Println("existed at a time within the verified window above.")
	return nil
}

// printCheck prints one OK-prefixed line in the verification stanza.
func printCheck(label, detail string) {
	fmt.Printf("  %-18s OK   %s\n", label, detail)
}

// printDocument prints the document path, size, and SHA-256.
func printDocument(path string, size int64, digest []byte) {
	fmt.Println("Document")
	fmt.Printf("  Path:             %s\n", path)
	fmt.Printf("  Size:             %d bytes\n", size)
	fmt.Printf("  SHA-256:          %x\n", digest)
	fmt.Println()
}

// printSeedLink prints the seed link's full crypto detail and confirms the
// nonce matches the document hash.
func printSeedLink(l roughtime.ProofLink, docDigest []byte, names map[string]string) {
	lo, hi := l.Window()
	fmt.Println("Document Binding (Link 0 — Seed)")
	fmt.Printf("  Witness:          %s\n", nameOf(l.PublicKey, names))
	fmt.Printf("  Wire version:     %s\n", l.Version.ShortString())
	fmt.Printf("  Public key:       %x\n", l.PublicKey)
	fmt.Printf("  Nonce:            %x\n", l.Nonce)
	if bytes.Equal(l.Nonce, docDigest) {
		fmt.Println("                    MATCHES SHA-256(document)")
	}
	fmt.Printf("  Midpoint (UTC):   %s\n", l.Midpoint.UTC().Format(tsFormat))
	fmt.Printf("  Radius:           ±%s\n", l.Radius)
	fmt.Printf("  Time window:      [%s, %s]\n", lo.UTC().Format(tsFormat), hi.UTC().Format(tsFormat))
	fmt.Println()
}

// printCorroborating prints the tabular summary of links 1..N.
func printCorroborating(links []roughtime.ProofLink, names map[string]string) {
	if len(links) == 0 {
		return
	}
	fmt.Printf("Corroborating Witnesses (%d)\n", len(links))
	fmt.Printf("  %-3s  %-30s  %-10s  %-16s  %-24s  %s\n",
		"#", "Witness", "Version", "Key (fp)", "Midpoint (UTC)", "Radius")
	for i, l := range links {
		fmt.Printf("  %-3d  %-30s  %-10s  %-16s  %-24s  ±%s\n",
			i+1,
			nameOf(l.PublicKey, names),
			l.Version.ShortString(),
			fingerprint(l.PublicKey),
			l.Midpoint.UTC().Format(tsFormat),
			l.Radius)
	}
	fmt.Println()
}

// printFailures prints the per-server error list, if any.
func printFailures(results []roughtime.Result) {
	var failed []roughtime.Result
	for _, r := range results {
		if r.Err != nil {
			failed = append(failed, r)
		}
	}
	if len(failed) == 0 {
		return
	}
	fmt.Printf("Failures (%d)\n", len(failed))
	for _, r := range failed {
		fmt.Printf("  %-30s  %s\n",
			roughtime.SanitizeForDisplay(r.Server.Name),
			roughtime.SanitizeForDisplay(r.Err.Error()))
	}
	fmt.Println()
}

// printAttestationWindow prints the [earliest, latest] bound and witness count.
func printAttestationWindow(links []roughtime.ProofLink) {
	earliest, latest := links[0].Window()
	boundIdx := 0
	for i, l := range links {
		if _, hi := l.Window(); hi.Before(latest) {
			latest = hi
			boundIdx = i
		}
	}
	keys := make(map[string]struct{}, len(links))
	for _, l := range links {
		keys[string(l.PublicKey)] = struct{}{}
	}
	fmt.Println("Verified Attestation Window")
	fmt.Printf("  No earlier than:  %s  (link 0 lower bound)\n", earliest.UTC().Format(tsFormat))
	fmt.Printf("  No later than:    %s  (link %d upper bound)\n", latest.UTC().Format(tsFormat), boundIdx)
	fmt.Printf("  Width:            %s\n", latest.Sub(earliest))
	fmt.Printf("  Witnesses:        %d independent keys\n", len(keys))
	fmt.Println()
}

// hashDocument returns SHA-256(document) and the file size. Non-regular files
// are rejected so FIFOs/devices can't hang the stream.
func hashDocument(path string) ([]byte, int64, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, 0, fmt.Errorf("opening document: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, 0, fmt.Errorf("stat document: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, 0, fmt.Errorf("%s is not a regular file", path)
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, 0, fmt.Errorf("hashing document: %w", err)
	}
	return h.Sum(nil), info.Size(), nil
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
	defer f.Close()
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

// writeProofAtomic writes data to path via tmp+fsync+rename so a kill or power
// loss never leaves a half-written stamp.
func writeProofAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("creating proof: %w", err)
	}
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
	if dir, err := os.Open(filepath.Dir(path)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

// filterCompatible drops Google-Roughtime entries (64-byte nonce) and
// unrecognized key lengths.
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

// lookup builds a public-key → name map for display.
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
