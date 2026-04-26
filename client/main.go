// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

// Command client queries one or more Roughtime servers and prints the
// authenticated timestamps.
//
// Single server:
//
//	go run client/main.go -addr time.txryan.com:2002 -pubkey iBVjxg/1j7y1+kQUTBYdTabxCppesU/07D4PMDJk2WA=
//
// Multiple servers:
//
//	go run client/main.go -servers ecosystem.json
//
// Single server from a JSON list:
//
//	go run client/main.go -servers ecosystem.json -name time.txryan.com
//
// The CLI is a thin wrapper over [github.com/tannerryan/roughtime], which
// exposes the same functionality as a Go library.
//
// Supports Google-Roughtime, IETF drafts 01-19, and an experimental ML-DSA-44
// post-quantum extension.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/tannerryan/roughtime"
	"github.com/tannerryan/roughtime/internal/version"
)

var (
	serversFile = flag.String("servers", "", "path to JSON server list")
	nameFilter  = flag.String("name", "", "query only the named server from the JSON list")
	addr        = flag.String("addr", "", "host:port of a single Roughtime server")
	pubkey      = flag.String("pubkey", "", "root public key (base64 or hex, with -addr); 32 bytes selects Ed25519, 1312 bytes selects ML-DSA-44")
	useTCP      = flag.Bool("tcp", false, "force TCP transport (ML-DSA-44 keys always use TCP)")
	timeout     = flag.Duration("timeout", 500*time.Millisecond, "read/write timeout per attempt")
	retries     = flag.Int("retries", 3, "max retry attempts per server (backoff 1s × 1.5^(n-1), cap 24h)")
	chainMode   = flag.Bool("chain", true, "chain queries sequentially: each nonce derives from the previous reply")
	all         = flag.Bool("all", false, "query every server in the ecosystem (default: random 3)")
	showVersion = flag.Bool("version", false, "print version and exit")
)

// defaultSampleSize is the random sample count when -all is unset.
const defaultSampleSize = 3

// maxEcosystemFileBytes caps ecosystem JSON; sized for MaxEcosystemServers
// ML-DSA-44 entries (~1.7 KiB base64 each).
const maxEcosystemFileBytes = 4 * 1024 * 1024

func main() {
	flag.Parse()
	if *showVersion {
		fmt.Printf("roughtime-client %s (github.com/tannerryan/roughtime)\n\n%s\n", version.Version, version.Copyright)
		return
	}
	if err := validateFlags(); err != nil {
		fmt.Fprintf(os.Stderr, "client: %s\n", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "client: %s\n", err)
		os.Exit(1)
	}
}

func validateFlags() error {
	if *timeout <= 0 {
		return fmt.Errorf("-timeout %s must be > 0", *timeout)
	}
	if *retries < 1 {
		return fmt.Errorf("-retries %d must be >= 1", *retries)
	}
	if *serversFile != "" && *addr != "" {
		return errors.New("-servers and -addr are mutually exclusive")
	}
	if *addr != "" && *pubkey == "" {
		return errors.New("-addr requires -pubkey")
	}
	if *pubkey != "" && *addr == "" {
		return errors.New("-pubkey requires -addr")
	}
	if *useTCP && *addr == "" && *serversFile == "" {
		return errors.New("-tcp requires -addr or -servers")
	}
	if *nameFilter != "" && *serversFile == "" {
		return errors.New("-name requires -servers")
	}
	if *all && *serversFile == "" {
		return errors.New("-all requires -servers")
	}
	if *all && *nameFilter != "" {
		return errors.New("-all and -name are mutually exclusive")
	}
	return nil
}

func run(ctx context.Context) error {
	servers, err := loadServers()
	if err != nil {
		return err
	}

	c := &roughtime.Client{Timeout: *timeout, Retries: *retries}

	if len(servers) == 1 {
		resp, err := c.Query(ctx, servers[0])
		if err != nil {
			return fmt.Errorf("%s: %w", roughtime.SanitizeForDisplay(servers[0].Name), err)
		}
		printSingle(resp)
		return nil
	}

	var results []roughtime.Result
	var proof *roughtime.Proof
	if *chainMode {
		// two passes cross-check every server in both directions
		cr, qcErr := c.QueryChain(ctx, slices.Concat(servers, servers))
		if qcErr != nil {
			// chain-construction failure aborts mid-run; per-row errors print
			// below
			fmt.Fprintf(os.Stderr, "client: chain aborted: %s\n", roughtime.SanitizeForDisplay(qcErr.Error()))
		}
		results = cr.Results
		// ignore the empty-chain error so a fully-failed run still prints
		// results
		proof, _ = cr.Proof()
	} else {
		results = c.QueryAll(ctx, servers)
	}
	return printTable(results, proof, servers)
}

// loadServers resolves the server list from flags.
func loadServers() ([]roughtime.Server, error) {
	if *serversFile != "" {
		servers, err := loadServersFile(*serversFile)
		if err != nil {
			return nil, err
		}
		if *useTCP {
			servers = filterTCPOnly(servers)
			if len(servers) == 0 {
				return nil, fmt.Errorf("no servers in %s have a tcp address", *serversFile)
			}
		}
		if *nameFilter != "" {
			for _, s := range servers {
				if s.Name == *nameFilter {
					return []roughtime.Server{s}, nil
				}
			}
			return nil, fmt.Errorf("server %q not found in %s", *nameFilter, *serversFile)
		}
		if !*all && len(servers) > defaultSampleSize {
			mrand.Shuffle(len(servers), func(i, j int) {
				servers[i], servers[j] = servers[j], servers[i]
			})
			servers = servers[:defaultSampleSize]
		}
		return servers, nil
	}
	if *addr != "" && *pubkey != "" {
		host, port, err := net.SplitHostPort(*addr)
		if err != nil {
			return nil, fmt.Errorf("invalid -addr %q: %w", roughtime.SanitizeForDisplay(*addr), err)
		}
		cleanAddr := net.JoinHostPort(host, port)
		pk, err := roughtime.DecodePublicKey(*pubkey)
		if err != nil {
			return nil, err
		}
		sch, err := roughtime.SchemeOfKey(pk)
		if err != nil {
			return nil, err
		}
		transport := "udp"
		if sch == roughtime.SchemeMLDSA44 || *useTCP {
			transport = "tcp"
		}
		return []roughtime.Server{{
			Name:      cleanAddr,
			PublicKey: pk,
			Addresses: []roughtime.Address{{Transport: transport, Address: cleanAddr}},
		}}, nil
	}
	return nil, errors.New("provide -servers <file> or -addr <host:port> -pubkey <base64-or-hex>")
}

// filterTCPOnly narrows each server's Addresses to TCP and drops servers with
// none.
func filterTCPOnly(servers []roughtime.Server) []roughtime.Server {
	out := make([]roughtime.Server, 0, len(servers))
	for _, s := range servers {
		tcp := make([]roughtime.Address, 0, len(s.Addresses))
		for _, a := range s.Addresses {
			if strings.EqualFold(a.Transport, "tcp") {
				tcp = append(tcp, a)
			}
		}
		if len(tcp) == 0 {
			continue
		}
		s.Addresses = tcp
		out = append(out, s)
	}
	return out
}

// loadServersFile reads and parses a JSON server list.
func loadServersFile(path string) ([]roughtime.Server, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("reading server list: %w", err)
	}
	defer f.Close()
	// read one past the cap so oversize is reported explicitly, not as JSON
	// truncation
	data, err := io.ReadAll(io.LimitReader(f, maxEcosystemFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading server list: %w", err)
	}
	if len(data) > maxEcosystemFileBytes {
		return nil, fmt.Errorf("server list %s exceeds %d bytes", path, maxEcosystemFileBytes)
	}
	return roughtime.ParseEcosystem(data)
}

// printSingle prints a vertical summary of one verified server response.
func printSingle(r *roughtime.Response) {
	safeName := roughtime.SanitizeForDisplay(r.Server.Name)
	displayAddr := roughtime.SanitizeForDisplay(r.Address.String())
	windowStart := r.Midpoint.Add(-r.Radius).UTC().Format(time.RFC3339)
	windowEnd := r.Midpoint.Add(r.Radius).UTC().Format(time.RFC3339)
	status := "out-of-sync"
	if r.InSync() {
		status = "in-sync"
	}
	// in -addr mode Name duplicates Address; skip the redundant line
	if !strings.HasSuffix(displayAddr, safeName) {
		fmt.Printf("Server:    %s\n", safeName)
	}
	fmt.Printf("Address:   %s\n", displayAddr)
	fmt.Printf("Version:   %s\n", r.Version)
	fmt.Printf("Midpoint:  %s\n", r.Midpoint.UTC().Format(time.RFC3339))
	fmt.Printf("Radius:    %s\n", r.Radius)
	fmt.Printf("Window:    [%s, %s]\n", windowStart, windowEnd)
	fmt.Printf("RTT:       %s\n", r.RTT.Round(time.Millisecond))
	fmt.Printf("Local:     %s\n", r.LocalNow.UTC().Format(time.RFC3339Nano))
	fmt.Printf("Drift:     %s\n", r.Drift().Round(time.Millisecond))
	fmt.Printf("Status:    %s\n", status)
}

// printTable prints the per-server table, drift consensus, and chain status.
func printTable(results []roughtime.Result, proof *roughtime.Proof, servers []roughtime.Server) error {
	nameW, addrW := 30, 30
	for _, s := range servers {
		nameW = max(nameW, len(s.Name))
		if len(s.Addresses) > 0 {
			// +6 accounts for the "tcp://" / "udp://" prefix from
			// Address.String
			addrW = max(addrW, len(s.Addresses[0].Address)+6)
		}
	}
	rowFmt := fmt.Sprintf("%%-%ds  %%-%ds  %%-9s  %%-20s  %%-8s  %%-6s  %%-8s  %%s\n", nameW, addrW)
	fmt.Printf(rowFmt, "NAME", "ADDRESS", "VERSION", "MIDPOINT", "RADIUS", "RTT", "DRIFT", "STATUS")
	errFmt := fmt.Sprintf("%%-%ds  %%-%ds  error: %%s\n", nameW, addrW)

	var deduped []roughtime.Result
	seen := make(map[string]bool) // dedupe chained two-pass
	var succeeded, failed int
	for _, r := range results {
		if r.Err != nil {
			displayAddr := roughtime.SanitizeForDisplay(r.Address.String())
			if displayAddr == "://" && len(r.Server.Addresses) > 0 {
				displayAddr = roughtime.SanitizeForDisplay(r.Server.Addresses[0].String())
			}
			fmt.Printf(errFmt, roughtime.SanitizeForDisplay(r.Server.Name), displayAddr, roughtime.SanitizeForDisplay(r.Err.Error()))
			failed++
			continue
		}
		resp := r.Response
		displayAddr := roughtime.SanitizeForDisplay(resp.Address.String())
		key := string(resp.Server.PublicKey)
		if !seen[key] {
			deduped = append(deduped, r)
			seen[key] = true
		}
		status := "out-of-sync"
		if resp.InSync() {
			status = "in-sync"
		}
		fmt.Printf(rowFmt,
			roughtime.SanitizeForDisplay(resp.Server.Name),
			displayAddr,
			resp.Version.ShortString(),
			resp.Midpoint.UTC().Format(time.RFC3339),
			"±"+resp.Radius.String(),
			resp.RTT.Round(time.Millisecond).String(),
			resp.Drift().Round(time.Millisecond).String(),
			status,
		)
		succeeded++
	}
	fmt.Printf("\n%d/%d servers responded\n", succeeded, succeeded+failed)
	printConsensus(deduped)
	if proof != nil {
		printChainStatus(proof)
	}
	if succeeded == 0 {
		return errors.New("no servers responded")
	}
	return nil
}

// printConsensus formats the [roughtime.Consensus] summary across results.
func printConsensus(results []roughtime.Result) {
	c := roughtime.Consensus(results)
	if c.Samples == 0 {
		return
	}
	consensus := time.Now().Add(c.Median).UTC().Format(time.RFC3339)
	fmt.Printf("Consensus drift:    %s (median of %d samples)\n",
		c.Median.Round(time.Millisecond), c.Samples)
	fmt.Printf("Consensus midpoint: %s\n", consensus)
	fmt.Printf("Drift spread:       %s (min=%s, max=%s)\n",
		(c.Max - c.Min).Round(time.Millisecond),
		c.Min.Round(time.Millisecond),
		c.Max.Round(time.Millisecond),
	)
}

// printChainStatus verifies the proof and prints the chain summary line.
func printChainStatus(p *roughtime.Proof) {
	if err := p.Verify(); err != nil {
		fmt.Printf("Chain:              FAILED: %s\n", err)
		return
	}
	fmt.Printf("Chain:              ok (%d links verified)\n", p.Len())
}
