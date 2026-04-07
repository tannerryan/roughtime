// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

// Command client queries one or more Roughtime servers and prints the
// authenticated timestamps. It demonstrates how to use the protocol package for
// client-side Roughtime operations.
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
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"slices"
	"time"

	"github.com/tannerryan/roughtime/protocol"
)

var (
	serversFile = flag.String("servers", "", "path to JSON server list")
	nameFilter  = flag.String("name", "", "query only the named server from the JSON list")
	addr        = flag.String("addr", "", "host:port of a single Roughtime server")
	pubkey      = flag.String("pubkey", "", "base64-encoded Ed25519 root public key (with -addr)")
	timeout     = flag.Duration("timeout", 5*time.Second, "UDP read/write timeout")
)

// serverConfig matches the JSON schema used by the Roughtime ecosystem.
type serverConfig struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	PublicKey string `json:"publicKey"`
	Addresses []struct {
		Protocol string `json:"protocol"`
		Address  string `json:"address"`
	} `json:"addresses"`
}

// serverList is the top-level JSON structure.
type serverList struct {
	Servers []serverConfig `json:"servers"`
}

// result holds the outcome of querying a single server.
type result struct {
	Name     string
	Address  string
	Midpoint time.Time
	Radius   time.Duration
	RTT      time.Duration
	Version  protocol.Version
	Err      error
}

// inSync reports whether the local clock falls within the server's uncertainty
// window. The bound is radius + RTT/2 because the server's observation could
// have happened anywhere during the round trip.
func (r result) inSync(localNow time.Time) bool {
	drift := r.Midpoint.Sub(localNow)
	if drift < 0 {
		drift = -drift
	}
	return drift <= r.Radius+r.RTT/2
}

// main parses flags and runs the client.
func main() {
	flag.Parse()
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "client: %s\n", err)
		os.Exit(1)
	}
}

// run queries the configured servers and prints results.
func run() error {
	servers, err := loadServers()
	if err != nil {
		return err
	}

	if len(servers) == 1 {
		r := queryServer(servers[0])
		if r.Err != nil {
			return fmt.Errorf("%s: %w", r.Name, r.Err)
		}
		printSingleResult(r)
		return nil
	}

	// Stream results as each server responds
	ch := make(chan result, len(servers))
	for _, srv := range servers {
		go func(srv serverConfig) {
			ch <- queryServer(srv)
		}(srv)
	}

	const rowFmt = "%-30s  %-30s  %-14s  %-20s  %-8s  %-10s  %-12s  %s\n"
	fmt.Printf(rowFmt, "NAME", "ADDRESS", "VERSION", "MIDPOINT", "RADIUS", "RTT", "DRIFT", "STATUS")

	var drifts []time.Duration
	var succeeded, failed int
	for range servers {
		r := <-ch
		if r.Err != nil {
			fmt.Printf("%-30s  %-30s  error: %s\n", r.Name, r.Address, r.Err)
			failed++
			continue
		}
		localNow := time.Now()
		drift := r.Midpoint.Sub(localNow)
		drifts = append(drifts, drift)
		status := "out-of-sync"
		if r.inSync(localNow) {
			status = "in-sync"
		}
		fmt.Printf(rowFmt,
			r.Name,
			r.Address,
			r.Version.ShortString(),
			r.Midpoint.UTC().Format(time.RFC3339),
			"±"+r.Radius.String(),
			r.RTT.Round(time.Millisecond).String(),
			drift.Round(time.Millisecond).String(),
			status,
		)
		succeeded++
	}

	fmt.Printf("\n%d/%d servers responded\n", succeeded, succeeded+failed)
	printConsensus(drifts)
	if succeeded == 0 {
		return fmt.Errorf("no servers responded")
	}
	return nil
}

// printSingleResult prints a verbose vertical summary of a single verified
// server response.
func printSingleResult(r result) {
	localNow := time.Now()
	windowStart := r.Midpoint.Add(-r.Radius).UTC().Format(time.RFC3339)
	windowEnd := r.Midpoint.Add(r.Radius).UTC().Format(time.RFC3339)
	status := "out-of-sync"
	if r.inSync(localNow) {
		status = "in-sync"
	}
	// In -addr mode Name and Address are identical; skip the redundant line.
	if r.Name != r.Address {
		fmt.Printf("Server:    %s\n", r.Name)
	}
	fmt.Printf("Address:   %s\n", r.Address)
	fmt.Printf("Version:   %s\n", r.Version)
	fmt.Printf("Midpoint:  %s\n", r.Midpoint.UTC().Format(time.RFC3339))
	fmt.Printf("Radius:    %s\n", r.Radius)
	fmt.Printf("Window:    [%s, %s]\n", windowStart, windowEnd)
	fmt.Printf("RTT:       %s\n", r.RTT.Round(time.Millisecond))
	fmt.Printf("Local:     %s\n", localNow.UTC().Format(time.RFC3339Nano))
	fmt.Printf("Drift:     %s\n", r.Midpoint.Sub(localNow).Round(time.Millisecond))
	fmt.Printf("Status:    %s\n", status)
}

// printConsensus prints the median drift, derived consensus midpoint, and drift
// spread across a set of per-server samples. No-op when empty.
func printConsensus(drifts []time.Duration) {
	if len(drifts) == 0 {
		return
	}
	median := medianDuration(drifts)
	lo, hi := slices.Min(drifts), slices.Max(drifts)
	consensus := time.Now().Add(median).UTC().Format(time.RFC3339)
	fmt.Printf("Consensus drift:    %s (median of %d samples)\n",
		median.Round(time.Millisecond), len(drifts))
	fmt.Printf("Consensus midpoint: %s\n", consensus)
	fmt.Printf("Drift spread:       %s (min=%s, max=%s)\n",
		(hi - lo).Round(time.Millisecond),
		lo.Round(time.Millisecond),
		hi.Round(time.Millisecond),
	)
}

// medianDuration returns the median of a slice of durations without mutating
// the input. For an even count it averages the two middle values.
func medianDuration(d []time.Duration) time.Duration {
	s := slices.Clone(d)
	slices.Sort(s)
	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

// loadServers returns the server list from flags.
func loadServers() ([]serverConfig, error) {
	if *serversFile != "" {
		servers, err := loadServersFile(*serversFile)
		if err != nil {
			return nil, err
		}
		if *nameFilter != "" {
			for _, s := range servers {
				if s.Name == *nameFilter {
					return []serverConfig{s}, nil
				}
			}
			return nil, fmt.Errorf("server %q not found in %s", *nameFilter, *serversFile)
		}
		return servers, nil
	}
	if *addr != "" && *pubkey != "" {
		return []serverConfig{{
			Name:      *addr,
			PublicKey: *pubkey,
			Addresses: []struct {
				Protocol string `json:"protocol"`
				Address  string `json:"address"`
			}{{Protocol: "udp", Address: *addr}},
		}}, nil
	}
	return nil, fmt.Errorf("provide -servers <file> or -addr <host:port> -pubkey <base64>")
}

// loadServersFile reads and parses a JSON server list.
func loadServersFile(path string) ([]serverConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading server list: %w", err)
	}
	var list serverList
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("parsing server list: %w", err)
	}
	if len(list.Servers) == 0 {
		return nil, fmt.Errorf("no servers in %s", path)
	}
	return list.Servers, nil
}

// ietfVersions lists all IETF versions to advertise in the VER tag. The server
// picks the highest mutually supported version.
var ietfVersions = []protocol.Version{
	protocol.VersionDraft12,
	protocol.VersionDraft11,
	protocol.VersionDraft10,
	protocol.VersionDraft08,
	protocol.VersionDraft07,
	protocol.VersionDraft06,
	protocol.VersionDraft05,
	protocol.VersionDraft01,
}

// queryServer queries a single Roughtime server. For IETF servers it sends all
// supported versions in one VER tag, letting the server pick the best match.
func queryServer(srv serverConfig) result {
	r := result{Name: srv.Name}

	if len(srv.Addresses) == 0 {
		r.Err = fmt.Errorf("no addresses")
		return r
	}
	r.Address = srv.Addresses[0].Address

	rootPK, err := base64.StdEncoding.DecodeString(srv.PublicKey)
	if err != nil {
		r.Err = fmt.Errorf("decoding public key: %w", err)
		return r
	}

	if srv.Version == "Google-Roughtime" {
		return queryOnce(srv.Name, r.Address, rootPK, []protocol.Version{protocol.VersionGoogle}, *timeout)
	}

	return queryOnce(srv.Name, r.Address, rootPK, ietfVersions, *timeout)
}

// queryOnce sends a single Roughtime request and verifies the response.
func queryOnce(name, address string, rootPK []byte, versions []protocol.Version, timeout time.Duration) result {
	r := result{Name: name, Address: address}

	nonce, request, err := protocol.CreateRequest(versions, rand.Reader)
	if err != nil {
		r.Err = fmt.Errorf("creating request: %w", err)
		return r
	}

	raddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		r.Err = fmt.Errorf("resolving %s: %w", address, err)
		return r
	}

	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		r.Err = fmt.Errorf("dialing %s: %w", address, err)
		return r
	}
	defer conn.Close()

	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	start := time.Now()
	if _, err := conn.Write(request); err != nil {
		r.Err = fmt.Errorf("sending: %w", err)
		return r
	}

	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		r.Err = fmt.Errorf("reading: %w", err)
		return r
	}
	r.RTT = time.Since(start)

	midpoint, radius, err := protocol.VerifyReply(versions, buf[:n], rootPK, nonce, request)
	if err != nil {
		r.Err = fmt.Errorf("verification: %w", err)
		return r
	}

	r.Midpoint = midpoint
	r.Radius = radius
	if ver, ok := protocol.ExtractVersion(buf[:n]); ok {
		r.Version = ver
	} else {
		r.Version = slices.Max(versions)
	}
	return r
}
