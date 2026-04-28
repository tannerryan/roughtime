// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

// Command roughtime-client queries one or more Roughtime servers and prints the
// authenticated timestamps.
//
// Single server:
//
//	go run ./cmd/roughtime-client -addr time.txryan.com:2002 -pubkey iBVjxg/1j7y1+kQUTBYdTabxCppesU/07D4PMDJk2WA=
//
// Multiple servers:
//
//	go run ./cmd/roughtime-client -servers ecosystem.json
//
// Single server from a JSON list:
//
//	go run ./cmd/roughtime-client -servers ecosystem.json -name time.txryan.com
//
// The CLI is a thin wrapper over [github.com/tannerryan/roughtime], which
// exposes the same functionality as a Go library.
//
// Supports Google-Roughtime, IETF Roughtime drafts 01-19, and an experimental
// ML-DSA-44 post-quantum extension.
//
// Server selection from a JSON list defaults to a random sample of three; -all
// queries every server and -name pins to one. The three are mutually exclusive.
//
// Transport defaults to UDP and falls back to TCP when an address only lists
// TCP; -tcp forces TCP for Ed25519 servers, while ML-DSA-44 keys always use TCP
// regardless of the flag.
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

// CLI flags configuring server selection, transport, and retry behaviour.
var (
	serversFile = flag.String("servers", "", "path to JSON server list")
	nameFilter  = flag.String("name", "", "query only the named server from the JSON list")
	addr        = flag.String("addr", "", "host:port of a single Roughtime server")
	pubkey      = flag.String("pubkey", "", "root public key (base64 or hex, with -addr); 32 bytes selects Ed25519, 1312 bytes selects ML-DSA-44")
	useTCP      = flag.Bool("tcp", false, "force TCP transport for Ed25519 servers (ML-DSA-44 keys always use TCP)")
	timeout     = flag.Duration("timeout", 500*time.Millisecond, "read/write timeout per attempt")
	retries     = flag.Int("retries", 3, "max attempts per server (1 = single attempt; backoff 1s × 1.5^(n-1) between attempts, cap 24h)")
	chainMode   = flag.Bool("chain", true, "chain queries sequentially: each nonce is H(previous reply || fresh random salt)")
	all         = flag.Bool("all", false, "query every server in the ecosystem (default: random 3)")
	showVersion = flag.Bool("version", false, "print version and exit")
)

// defaultSampleSize is the number of servers randomly sampled from the
// ecosystem when neither -all nor -name is set.
const defaultSampleSize = 3

// maxEcosystemFileBytes caps the ecosystem JSON read at 4 MiB, fitting
// MaxEcosystemServers entries of base64-encoded ML-DSA-44 keys.
const maxEcosystemFileBytes = 4 * 1024 * 1024

// main parses flags, validates them, and runs the client under a
// signal-cancelable context.
func main() {
	flag.Parse()
	if *showVersion {
		fmt.Printf("roughtime-client %s (github.com/tannerryan/roughtime)\n\n%s\n", version.Full(), version.Copyright)
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
		// follow the 128+signum convention when interrupted by a signal
		if errors.Is(ctx.Err(), context.Canceled) {
			os.Exit(130)
		}
		os.Exit(1)
	}
}

// validateFlags rejects invalid or mutually exclusive flag combinations.
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

// run resolves the server list and dispatches Query, QueryChain, or QueryAll
// based on flags.
func run(ctx context.Context) error {
	servers, err := loadServers()
	if err != nil {
		return err
	}

	c := &roughtime.Client{Timeout: *timeout, MaxAttempts: *retries}

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
	var qcErr error
	if *chainMode {
		// two passes link every server twice so each appears with both a
		// preceding and a following neighbour in the chain
		var cr *roughtime.ChainResult
		cr, qcErr = c.QueryChain(ctx, slices.Concat(servers, servers))
		if qcErr != nil {
			// chain-construction failure aborts mid-run; per-row errors print
			// below
			msg := strings.TrimPrefix(qcErr.Error(), "roughtime: ")
			fmt.Fprintf(os.Stderr, "client: chain aborted: %s\n", roughtime.SanitizeForDisplay(msg))
		}
		results = cr.Results
		// ignore the empty-chain error so a fully-failed run still prints
		// results
		proof, _ = cr.Proof()
	} else {
		results = c.QueryAll(ctx, servers)
	}
	if err := printTable(results, proof, servers); err != nil {
		return err
	}
	return qcErr
}

// loadServers resolves the configured flags into the list of servers to query.
func loadServers() ([]roughtime.Server, error) {
	if *serversFile != "" {
		safeFile := roughtime.SanitizeForDisplay(*serversFile)
		servers, err := loadServersFile(*serversFile)
		if err != nil {
			return nil, err
		}
		if *nameFilter != "" {
			for _, s := range servers {
				if s.Name != *nameFilter {
					continue
				}
				if *useTCP {
					s.Addresses = tcpAddresses(s.Addresses)
					if len(s.Addresses) == 0 {
						return nil, fmt.Errorf("server %q in %s has no tcp address", roughtime.SanitizeForDisplay(*nameFilter), safeFile)
					}
				}
				return []roughtime.Server{s}, nil
			}
			return nil, fmt.Errorf("server %q not found in %s", roughtime.SanitizeForDisplay(*nameFilter), safeFile)
		}
		if *useTCP {
			servers = filterTCPOnly(servers)
			if len(servers) == 0 {
				return nil, fmt.Errorf("no servers in %s have a tcp address", safeFile)
			}
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
		tcp := tcpAddresses(s.Addresses)
		if len(tcp) == 0 {
			continue
		}
		s.Addresses = tcp
		out = append(out, s)
	}
	return out
}

// tcpAddresses returns the subset of addrs whose transport is TCP.
func tcpAddresses(addrs []roughtime.Address) []roughtime.Address {
	tcp := make([]roughtime.Address, 0, len(addrs))
	for _, a := range addrs {
		if strings.EqualFold(a.Transport, "tcp") {
			tcp = append(tcp, a)
		}
	}
	return tcp
}

// loadServersFile reads and parses an ecosystem JSON file capped at
// maxEcosystemFileBytes.
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
		return nil, fmt.Errorf("server list %s exceeds %d bytes", roughtime.SanitizeForDisplay(path), maxEcosystemFileBytes)
	}
	return roughtime.ParseEcosystem(data)
}
