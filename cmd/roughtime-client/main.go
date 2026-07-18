// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

// Command roughtime-client queries one server or a JSON ecosystem and prints
// authenticated timestamps. It supports Google-Roughtime, IETF drafts 05–19,
// and the experimental ML-DSA-44 extension.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/tannerryan/roughtime"
	"github.com/tannerryan/roughtime/internal/version"
)

var (
	// serversFile is the ecosystem path flag.
	serversFile = flag.String("servers", "", "path to JSON server list")
	// nameFilter selects one ecosystem entry.
	nameFilter = flag.String("name", "", "query only the named server from the JSON list")
	// addr is the direct server endpoint flag.
	addr = flag.String("addr", "", "host:port of a single Roughtime server")
	// pubkey is the direct server root-key flag.
	pubkey = flag.String("pubkey", "", "root public key (base64 or hex, with -addr); 32 bytes selects Ed25519, 1312 bytes selects ML-DSA-44")
	// useTCP forces TCP for Ed25519.
	useTCP = flag.Bool("tcp", false, "force TCP for IETF Ed25519 servers (Google-Roughtime is UDP-only; ML-DSA-44 always uses TCP)")
	// timeout bounds each exchange attempt.
	timeout = flag.Duration("timeout", time.Second, "read/write timeout per attempt")
	// retries caps attempts per server.
	retries = flag.Int("retries", 3, "max attempts per server (1 = single attempt; backoff 1s × 1.5^(n-1) between attempts, cap 24h)")
	// chainMode enables causal ecosystem queries.
	chainMode = flag.Bool("chain", true, "chain queries sequentially: each nonce derives from the previous reply and fresh random salt")
	// all disables default ecosystem sampling.
	all = flag.Bool("all", false, "query every transport-compatible ecosystem server (default: up to 5 endpoint-domain groups)")
	// showVersion requests version output and exit.
	showVersion = flag.Bool("version", false, "print version and exit")
)

// defaultSampleSize caps the default ecosystem sample.
const defaultSampleSize = 5

// main parses flags and runs the client.
func main() {
	flag.Parse()
	if *showVersion {
		fmt.Printf("roughtime-client %s (github.com/tannerryan/roughtime)\n\n%s\n", version.Full(), version.Copyright)
		return
	}
	if err := validateFlags(); err != nil {
		fmt.Fprintln(os.Stderr, "client:", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "client:", err)
		if errors.Is(ctx.Err(), context.Canceled) {
			os.Exit(130)
		}
		os.Exit(1)
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		os.Exit(130)
	}
}

// validateFlags rejects invalid or mutually exclusive flag combinations.
func validateFlags() error {
	if *timeout <= 0 {
		return fmt.Errorf("-timeout %s must be > 0", *timeout)
	}
	if flag.NArg() > 0 {
		return fmt.Errorf("unexpected positional args: %v", flag.Args())
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

// run dispatches the selected direct or ecosystem workflow.
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
		var cr *roughtime.ChainResult
		cr, qcErr = c.QueryChain(ctx, servers)
		if cr != nil {
			results = cr.Results
			// ignore the empty-chain error so a fully-failed run still prints
			// results
			proof, _ = cr.Proof()
		}
	} else {
		results = c.QueryAll(ctx, servers)
	}
	if err := printTable(results, proof); err != nil {
		return err
	}
	return qcErr
}

// loadServers resolves the configured flags into the list of servers to query.
func loadServers() ([]roughtime.Server, error) {
	if *serversFile != "" {
		safeFile := display(*serversFile, 256)
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
					if isGoogleServerVersion(s.Version) {
						return nil, fmt.Errorf("server %q is Google-Roughtime (UDP-only), incompatible with -tcp", roughtime.SanitizeForDisplay(*nameFilter))
					}
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
		if !*all {
			servers = roughtime.SampleByOperator(servers, defaultSampleSize)
		}
		return servers, nil
	}
	if *addr != "" && *pubkey != "" {
		host, port, err := net.SplitHostPort(*addr)
		if err != nil {
			return nil, fmt.Errorf("invalid -addr %q: %w", display(*addr, 256), err)
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
		// Google-Roughtime is UDP-only, so it can never answer over TCP
		if isGoogleServerVersion(s.Version) {
			continue
		}
		tcp := tcpAddresses(s.Addresses)
		if len(tcp) == 0 {
			continue
		}
		s.Addresses = tcp
		out = append(out, s)
	}
	return out
}

// isGoogleServerVersion recognizes the textual and numeric ecosystem labels.
func isGoogleServerVersion(value string) bool {
	return strings.EqualFold(value, roughtime.VersionLabelGoogle) || value == "3000600613"
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

// loadServersFile reads and parses a size-capped ecosystem JSON file.
func loadServersFile(path string) ([]roughtime.Server, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("reading server list: %w", err)
	}
	defer func() { _ = f.Close() }()
	// read one past the cap so oversize is reported explicitly, not as JSON
	// truncation
	data, err := io.ReadAll(io.LimitReader(f, roughtime.MaxEcosystemBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading server list: %w", err)
	}
	if len(data) > roughtime.MaxEcosystemBytes {
		return nil, fmt.Errorf("server list %s exceeds %d bytes", roughtime.SanitizeForDisplay(path), roughtime.MaxEcosystemBytes)
	}
	return roughtime.ParseEcosystem(data)
}
