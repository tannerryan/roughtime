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
//	go run client/main.go -servers client/ecosystem.json
//
// Single server from a JSON list:
//
//	go run client/main.go -servers client/ecosystem.json -name time.txryan.com
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/tannerryan/roughtime/internal/version"
	"github.com/tannerryan/roughtime/protocol"
)

var (
	serversFile = flag.String("servers", "", "path to JSON server list")
	nameFilter  = flag.String("name", "", "query only the named server from the JSON list")
	addr        = flag.String("addr", "", "host:port of a single Roughtime server")
	pubkey      = flag.String("pubkey", "", "base64-encoded Ed25519 root public key (with -addr)")
	timeout     = flag.Duration("timeout", 5*time.Second, "UDP read/write timeout")
	chain       = flag.Bool("chain", true, "chain queries: derive each nonce from the previous reply")
	showVersion = flag.Bool("version", false, "print version and exit")
)

// serverConfig matches the JSON schema used by the Roughtime ecosystem.
type serverConfig struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	PublicKeyType string `json:"publicKeyType"`
	PublicKey     string `json:"publicKey"`
	Addresses     []struct {
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
	LocalNow time.Time
	Radius   time.Duration
	RTT      time.Duration
	Version  protocol.Version
	Err      error
}

// inSync reports whether the local clock falls within the server's uncertainty
// window. The bound is radius + RTT/2 because the server's observation could
// have happened anywhere during the round trip.
func (r result) inSync() bool {
	drift := r.Midpoint.Sub(r.LocalNow)
	if drift < 0 {
		drift = -drift
	}
	return drift <= r.Radius+r.RTT/2
}

// main parses flags and runs the client.
func main() {
	flag.Parse()
	if *showVersion {
		fmt.Printf("roughtime-client %s (github.com/tannerryan/roughtime)\n", version.Version)
		return
	}
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

	const rowFmt = "%-30s  %-30s  %-14s  %-20s  %-8s  %-10s  %-12s  %s\n"
	fmt.Printf(rowFmt, "NAME", "ADDRESS", "VERSION", "MIDPOINT", "RADIUS", "RTT", "DRIFT", "STATUS")

	var results []result
	var pchain *protocol.Chain
	if *chain {
		// Section 8.2: repeat the query sequence twice in the same order so
		// every server is checked against every other in both directions.
		results, pchain = queryChained(append(servers, servers...))
	} else {
		ch := make(chan result, len(servers))
		for _, srv := range servers {
			go func(srv serverConfig) {
				ch <- queryServer(srv)
			}(srv)
		}
		for range servers {
			results = append(results, <-ch)
		}
	}

	var drifts []time.Duration
	var succeeded, failed int
	for _, r := range results {
		if r.Err != nil {
			fmt.Printf("%-30s  %-30s  error: %s\n", r.Name, r.Address, r.Err)
			failed++
			continue
		}
		drift := r.Midpoint.Sub(r.LocalNow)
		drifts = append(drifts, drift)
		status := "out-of-sync"
		if r.inSync() {
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
	if pchain != nil && len(pchain.Links) > 0 {
		printChainStatus(pchain)
	}
	if succeeded == 0 {
		return fmt.Errorf("no servers responded")
	}
	return nil
}

// printSingleResult prints a verbose vertical summary of a single verified
// server response.
func printSingleResult(r result) {
	windowStart := r.Midpoint.Add(-r.Radius).UTC().Format(time.RFC3339)
	windowEnd := r.Midpoint.Add(r.Radius).UTC().Format(time.RFC3339)
	status := "out-of-sync"
	if r.inSync() {
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
	fmt.Printf("Local:     %s\n", r.LocalNow.UTC().Format(time.RFC3339Nano))
	fmt.Printf("Drift:     %s\n", r.Midpoint.Sub(r.LocalNow).Round(time.Millisecond))
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

// printChainStatus verifies the chain and prints the result.
func printChainStatus(c *protocol.Chain) {
	err := c.Verify()
	if err == nil {
		fmt.Printf("Chain:              ok (%d links verified)\n", len(c.Links))
	} else {
		fmt.Printf("Chain:              FAILED: %s\n", err)
	}
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

// loadServersFile reads and parses a JSON server list. The path is operator-
// supplied via a CLI flag and is normalized with filepath.Clean before reading.
// Unknown JSON fields are rejected so schema drift fails loudly.
func loadServersFile(path string) ([]serverConfig, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("reading server list: %w", err)
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	var list serverList
	if err := dec.Decode(&list); err != nil {
		return nil, fmt.Errorf("parsing server list: %w", err)
	}
	if len(list.Servers) == 0 {
		return nil, fmt.Errorf("no servers in %s", path)
	}
	return list.Servers, nil
}

// ietfVersions lists every IETF Roughtime version this client advertises in the
// VER tag, newest first. It is derived from protocol.SupportedVersions so
// adding a new draft to the protocol package automatically expands the client.
var ietfVersions = func() []protocol.Version {
	all := protocol.SupportedVersions()
	out := make([]protocol.Version, len(all))
	for i, v := range all {
		out[len(all)-1-i] = v
	}
	return out
}()

// decodePubKey accepts an Ed25519 root public key encoded as standard base64,
// URL base64, or lowercase hex (the three forms used by published Roughtime
// ecosystem feeds). It returns an error unless the result is exactly 32 bytes.
func decodePubKey(s string) ([]byte, error) {
	for _, dec := range []func(string) ([]byte, error){
		base64.StdEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		base64.RawURLEncoding.DecodeString,
		hex.DecodeString,
	} {
		if b, err := dec(s); err == nil && len(b) == ed25519.PublicKeySize {
			return b, nil
		}
	}
	return nil, fmt.Errorf("public key %q is not 32 bytes of base64 or hex", s)
}

// queryServer queries a single Roughtime server. For IETF servers it advertises
// every supported version in one VER tag and lets the server pick.
func queryServer(srv serverConfig) result {
	r := result{Name: srv.Name}

	if len(srv.Addresses) == 0 {
		r.Err = fmt.Errorf("no addresses")
		return r
	}
	r.Address = srv.Addresses[0].Address

	rootPK, err := decodePubKey(srv.PublicKey)
	if err != nil {
		r.Err = fmt.Errorf("decoding public key: %w", err)
		return r
	}

	if strings.EqualFold(srv.Version, "Google-Roughtime") {
		return queryOnce(srv.Name, r.Address, rootPK, []protocol.Version{protocol.VersionGoogle}, *timeout)
	}

	return queryOnce(srv.Name, r.Address, rootPK, ietfVersions, *timeout)
}

// queryChained queries servers sequentially using protocol.Chain, deriving each
// nonce from the previous response per Section 8.2. Results are returned in
// server order.
func queryChained(servers []serverConfig) ([]result, *protocol.Chain) {
	var c protocol.Chain
	results := make([]result, len(servers))

	for i, srv := range servers {
		r := &results[i]
		r.Name = srv.Name
		if len(srv.Addresses) == 0 {
			r.Err = fmt.Errorf("no addresses")
			continue
		}
		r.Address = srv.Addresses[0].Address

		rootPK, err := decodePubKey(srv.PublicKey)
		if err != nil {
			r.Err = fmt.Errorf("decoding public key: %w", err)
			continue
		}

		versions := ietfVersions
		if strings.EqualFold(srv.Version, "Google-Roughtime") {
			versions = []protocol.Version{protocol.VersionGoogle}
		}

		link, err := c.NextRequest(versions, rootPK, rand.Reader)
		if err != nil {
			r.Err = fmt.Errorf("creating chained request: %w", err)
			continue
		}

		reply, rtt, localNow, err := sendRequest(r.Address, link.Request, *timeout)
		if err != nil {
			r.Err = err
			continue
		}
		r.RTT = rtt
		r.LocalNow = localNow
		link.Response = reply

		parsed, err := protocol.ParseRequest(link.Request)
		if err != nil {
			r.Err = fmt.Errorf("parsing chained request: %w", err)
			continue
		}

		midpoint, radius, err := protocol.VerifyReply(versions, reply, rootPK, parsed.Nonce, link.Request)
		if err != nil {
			r.Err = fmt.Errorf("verification: %w", err)
			continue
		}

		// Append only after verification so a bad response doesn't poison the
		// nonce derivation for subsequent links.
		c.Append(link)

		r.Midpoint = midpoint
		r.Radius = radius
		if ver, ok := protocol.ExtractVersion(reply); ok {
			r.Version = ver
		} else {
			r.Version = slices.Max(versions)
		}
	}

	return results, &c
}

// sendRequest sends a raw Roughtime request packet and returns the reply, RTT,
// and the local time captured immediately after receiving the response.
func sendRequest(address string, request []byte, timeout time.Duration) (reply []byte, rtt time.Duration, localNow time.Time, err error) {
	raddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, 0, time.Time{}, fmt.Errorf("resolving %s: %w", address, err)
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, 0, time.Time{}, fmt.Errorf("dialing %s: %w", address, err)
	}
	defer conn.Close()

	if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return nil, 0, time.Time{}, fmt.Errorf("set write deadline: %w", err)
	}
	start := time.Now()
	if _, err := conn.Write(request); err != nil {
		return nil, 0, time.Time{}, fmt.Errorf("sending: %w", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, 0, time.Time{}, fmt.Errorf("set read deadline: %w", err)
	}
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, 0, time.Time{}, fmt.Errorf("reading: %w", err)
	}
	return buf[:n], time.Since(start), time.Now(), nil
}

// queryOnce sends one Roughtime request and verifies the response.
func queryOnce(name, address string, rootPK []byte, versions []protocol.Version, timeout time.Duration) result {
	r := result{Name: name, Address: address}

	srv := protocol.ComputeSRV(rootPK)
	nonce, request, err := protocol.CreateRequestWithSRV(versions, rand.Reader, srv)
	if err != nil {
		r.Err = fmt.Errorf("creating request: %w", err)
		return r
	}

	reply, rtt, localNow, err := sendRequest(address, request, timeout)
	if err != nil {
		r.Err = err
		return r
	}
	r.RTT = rtt
	r.LocalNow = localNow

	midpoint, radius, err := protocol.VerifyReply(versions, reply, rootPK, nonce, request)
	if err != nil {
		r.Err = fmt.Errorf("verification: %w", err)
		return r
	}

	r.Midpoint = midpoint
	r.Radius = radius
	if ver, ok := protocol.ExtractVersion(reply); ok {
		r.Version = ver
	} else {
		r.Version = slices.Max(versions)
	}
	return r
}
