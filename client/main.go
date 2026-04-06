// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

// Command client queries one or more Roughtime servers and prints the
// authenticated timestamps. It demonstrates how to use the protocol package for
// client-side Roughtime operations.
//
// Single server:
//
//	go run ./client -addr time.txryan.com:2002 -pubkey iBVjxg/1j7y1+kQUTBYdTabxCppesU/07D4PMDJk2WA=
//
// Multiple servers:
//
//	go run ./client -servers ecosystem.json
//
// Single server from a JSON list:
//
//	go run ./client -servers ecosystem.json -name time.txryan.com
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
	Midpoint time.Time
	Radius   time.Duration
	RTT      time.Duration
	Version  protocol.Version
	Err      error
}

// main parses flags and runs the client.
func main() {
	flag.Parse()
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
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
		localNow := time.Now()
		fmt.Printf("Server:    %s\n", r.Name)
		fmt.Printf("Version:   %s\n", r.Version)
		fmt.Printf("Midpoint:  %s\n", r.Midpoint.UTC().Format(time.RFC3339))
		fmt.Printf("Radius:    %s\n", r.Radius)
		fmt.Printf("RTT:       %s\n", r.RTT.Round(time.Millisecond))
		fmt.Printf("Local:     %s\n", localNow.UTC().Format(time.RFC3339Nano))
		fmt.Printf("Drift:     %s\n", r.Midpoint.Sub(localNow).Round(time.Millisecond))
		return nil
	}

	// Stream results as each server responds
	ch := make(chan result, len(servers))
	for _, srv := range servers {
		go func(srv serverConfig) {
			ch <- queryServer(srv)
		}(srv)
	}

	var succeeded, failed int
	for range servers {
		r := <-ch
		if r.Err != nil {
			fmt.Printf("%-30s  error: %s\n", r.Name, r.Err)
			failed++
			continue
		}
		localNow := time.Now()
		drift := r.Midpoint.Sub(localNow)
		fmt.Printf("%-30s  %-14s  %s  ±%-6s  rtt=%-8s  drift=%s\n",
			r.Name,
			r.Version.ShortString(),
			r.Midpoint.UTC().Format(time.RFC3339),
			r.Radius,
			r.RTT.Round(time.Millisecond),
			drift.Round(time.Millisecond),
		)
		succeeded++
	}

	fmt.Printf("\n%d/%d servers responded\n", succeeded, succeeded+failed)
	if succeeded == 0 {
		return fmt.Errorf("no servers responded")
	}
	return nil
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
	address := srv.Addresses[0].Address

	rootPK, err := base64.StdEncoding.DecodeString(srv.PublicKey)
	if err != nil {
		r.Err = fmt.Errorf("decoding public key: %w", err)
		return r
	}

	if srv.Version == "Google-Roughtime" {
		return queryOnce(srv.Name, address, rootPK, []protocol.Version{protocol.VersionGoogle}, *timeout)
	}

	return queryOnce(srv.Name, address, rootPK, ietfVersions, *timeout)
}

// queryOnce sends a single Roughtime request and verifies the response.
func queryOnce(name, address string, rootPK []byte, versions []protocol.Version, timeout time.Duration) result {
	r := result{Name: name}

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
