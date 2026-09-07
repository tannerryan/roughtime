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
	"github.com/tannerryan/roughtime/internal/fileutil"
	"github.com/tannerryan/roughtime/internal/version"
	"github.com/tannerryan/roughtime/protocol"
)

var (
	// commandLine returns parse errors so they pass through the same terminal
	// sanitizer as validation and runtime errors.
	commandLine = flag.NewFlagSet("roughtime-client", flag.ContinueOnError)
	// serversFile is the ecosystem path flag.
	serversFile = commandLine.String("servers", "", "path to JSON server list")
	// nameFilter selects one ecosystem entry.
	nameFilter = commandLine.String("name", "", "query only the named server from the JSON list")
	// addr is the direct server endpoint flag.
	addr = commandLine.String("addr", "", "host:port of a single Roughtime server")
	// pubkey is the direct server root-key flag.
	pubkey = commandLine.String("pubkey", "", "root public key with -addr (base64 or hex, 32 bytes Ed25519 or 1312 bytes ML-DSA-44)")
	// useTCP forces TCP for Ed25519.
	useTCP = commandLine.Bool("tcp", false, "force TCP for IETF Ed25519 servers (Google-Roughtime is UDP-only, ML-DSA-44 is TCP-only)")
	// timeout bounds each exchange attempt.
	timeout = commandLine.Duration("timeout", time.Second, "read/write timeout per attempt")
	// retries caps attempts per server.
	retries = commandLine.Int("retries", 3, "max attempts per server (1 = no retries, backoff starts at 1s, grows by 1.5, caps at 24h)")
	// chainMode enables causal ecosystem queries.
	chainMode = commandLine.Bool("chain", true, "chain queries sequentially: each nonce derives from the previous reply and fresh random salt")
	// all disables default ecosystem sampling.
	all = commandLine.Bool("all", false, "query every transport-compatible ecosystem server (default: up to 5 endpoint-domain groups)")
	// twoPass requests a complete same-order two-pass measurement.
	twoPass = commandLine.Bool("two-pass", false, "require a complete two-pass same-order ecosystem chain (at least 3 endpoint groups and trust roots)")
	// standardSize selects the draft-19 message-size padding convention.
	standardSize = commandLine.Bool("standard-size", false, "send standard message-sized padding plus framing (default: legacy total-packet sizing)")
	// showVersion requests version output and exit.
	showVersion = commandLine.Bool("version", false, "print version and exit")
)

const (
	// defaultSampleSize caps the default ecosystem sample.
	defaultSampleSize = 5
	// maxCLIErrorRunes bounds sanitized top-level errors.
	maxCLIErrorRunes = 1024
)

// main parses flags and runs the client.
func main() {
	commandLine.SetOutput(io.Discard)
	if err := commandLine.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(os.Stderr, "Usage of roughtime-client:")
			commandLine.SetOutput(os.Stderr)
			commandLine.PrintDefaults()
			return
		}
		fmt.Fprintln(os.Stderr, "client:", terminalError(err))
		os.Exit(2)
	}
	if *showVersion {
		fmt.Printf("roughtime-client %s (github.com/tannerryan/roughtime)\n\n%s\n", version.Full(), version.Copyright)
		return
	}
	if err := validateFlags(); err != nil {
		fmt.Fprintln(os.Stderr, "client:", terminalError(err))
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "client:", terminalError(err))
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
	if commandLine.NArg() > 0 {
		return fmt.Errorf("unexpected positional args: %v", commandLine.Args())
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
	if *twoPass && *serversFile == "" {
		return errors.New("-two-pass requires -servers")
	}
	if *twoPass && !*chainMode {
		return errors.New("-two-pass requires -chain=true")
	}
	return nil
}

// run dispatches the selected direct or ecosystem workflow.
func run(ctx context.Context) error {
	servers, err := loadServers()
	if err != nil {
		return err
	}
	expectedProbes := 0
	if *twoPass {
		servers, err = twoPassServers(servers)
		if err != nil {
			return err
		}
		expectedProbes = len(servers)
	}

	c := newClient()

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
	if err := printTable(results, proof, expectedProbes); err != nil {
		return err
	}
	return qcErr
}

// newClient maps command flags to the high-level client without changing the
// legacy packet-size default.
func newClient() *roughtime.Client {
	return &roughtime.Client{
		Timeout:            *timeout,
		MaxAttempts:        *retries,
		StandardPacketSize: *standardSize,
	}
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
				s, err = roughtime.NormalizeServer(s)
				if err != nil {
					return nil, fmt.Errorf("server %q in %s is unusable: %w", roughtime.SanitizeForDisplay(*nameFilter), safeFile, err)
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
		servers = normalizeServers(servers)
		if len(servers) == 0 {
			return nil, fmt.Errorf("no compatible servers in %s", safeFile)
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

// normalizeServers filters incompatible entries and orders usable endpoints.
// Named queries report incompatibility as an error instead of skipping it.
func normalizeServers(servers []roughtime.Server) []roughtime.Server {
	out := make([]roughtime.Server, 0, len(servers))
	for _, s := range servers {
		normalized, err := roughtime.NormalizeServer(s)
		if err != nil {
			continue
		}
		out = append(out, normalized)
	}
	return out
}

// twoPassServers validates and expands a strict two-pass measurement. The
// second half repeats the exact normalized server order.
func twoPassServers(servers []roughtime.Server) ([]roughtime.Server, error) {
	groups := make(map[string]struct{}, len(servers))
	roots := make(map[string]struct{}, len(servers))
	for _, s := range servers {
		groups[roughtime.OperatorKey(s)] = struct{}{}
		roots[string(s.PublicKey)] = struct{}{}
	}
	if len(groups) < 3 {
		return nil, fmt.Errorf("-two-pass requires at least 3 endpoint-domain groups (got %d)", len(groups))
	}
	if len(roots) < 3 {
		return nil, fmt.Errorf("-two-pass requires at least 3 distinct trust roots (got %d)", len(roots))
	}
	if len(servers) > protocol.MaxChainLinks/2 {
		return nil, fmt.Errorf("-two-pass requires %d chain links, exceeding max %d", 2*len(servers), protocol.MaxChainLinks)
	}
	out := make([]roughtime.Server, 0, 2*len(servers))
	out = append(out, servers...)
	out = append(out, servers...)
	return out, nil
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
	f, err := fileutil.OpenRegular(path)
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

// terminalError sanitizes and bounds errors at the final stderr boundary.
func terminalError(err error) string {
	return display(err.Error(), maxCLIErrorRunes)
}
