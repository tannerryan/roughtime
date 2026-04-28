// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

// Command roughtime-debug probes a Roughtime server to discover its supported
// protocol versions and prints a full diagnostic dump of the request, response,
// signatures, and delegation certificate.
//
// Usage:
//
//	go run ./cmd/roughtime-debug -addr time.txryan.com:2002 -pubkey iBVjxg/1j7y1+kQUTBYdTabxCppesU/07D4PMDJk2WA=
//
// Supports Google-Roughtime, IETF drafts, and an experimental ML-DSA-44
// post-quantum extension.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/tannerryan/roughtime"
	"github.com/tannerryan/roughtime/internal/version"
	"github.com/tannerryan/roughtime/protocol"
)

var (
	// addr is the host:port of the Roughtime server to probe.
	addr = flag.String("addr", "", "host:port of the Roughtime server")
	// pubkey is the root public key encoded as base64 or hex.
	pubkey = flag.String("pubkey", "", "root public key (base64 or hex); 32 raw bytes selects Ed25519, 1312 raw bytes selects ML-DSA-44")
	// useTCP forces TCP transport for the probe.
	useTCP = flag.Bool("tcp", false, "use TCP transport; ML-DSA-44 keys always use TCP")
	// timeout is the per-version probe deadline.
	timeout = flag.Duration("timeout", 500*time.Millisecond, "per-version probe timeout (consider raising for ML-DSA-44 over TCP)")
	// retries is the maximum number of attempts per version.
	retries = flag.Int("retries", 3, "max attempts per version (>=1)")
	// forceVer restricts probing to a single named version.
	forceVer = flag.String("ver", "", "probe only this version, case-sensitive (e.g. draft-12, Google, ml-dsa-44); dumps request/response even on failure")
	// showVersion prints the binary version and exits.
	showVersion = flag.Bool("version", false, "print version and exit")
)

// probeResult represents the outcome of a single per-version probe.
type probeResult struct {
	version   protocol.Version
	transport string // "udp" or "tcp"
	midpoint  time.Time
	localNow  time.Time
	radius    time.Duration
	rtt       time.Duration
	request   []byte
	reply     []byte
	nonce     []byte
	err       error
}

// main parses flags and runs the probe.
func main() {
	flag.Parse()
	if *showVersion {
		fmt.Printf("roughtime-debug %s (github.com/tannerryan/roughtime)\n\n%s\n", version.Full(), version.Copyright)
		return
	}
	if err := validateFlags(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "debug: %s: %s\n", *addr, err)
		os.Exit(1)
	}
}

// validateFlags checks that required flags are set and within range.
func validateFlags() error {
	if *addr == "" || *pubkey == "" {
		return fmt.Errorf("usage: roughtime-debug -addr <host:port> -pubkey <base64-or-hex>")
	}
	if *timeout <= 0 {
		return fmt.Errorf("-timeout %s must be > 0", *timeout)
	}
	if *retries < 1 {
		return fmt.Errorf("-retries %d must be >= 1", *retries)
	}
	return nil
}

// defaultProbeVersions returns the version list to probe for sch.
func defaultProbeVersions(sch roughtime.Scheme) []protocol.Version {
	versions := roughtime.VersionsForScheme(sch)
	if sch == roughtime.SchemeEd25519 {
		versions = append(versions, protocol.VersionGoogle)
	}
	return versions
}

// run executes the probe workflow against the configured server.
func run(ctx context.Context) error {
	rootPK, err := roughtime.DecodePublicKey(*pubkey)
	if err != nil {
		return fmt.Errorf("decoding public key: %w", err)
	}
	sch, err := roughtime.SchemeOfKey(rootPK)
	if err != nil {
		return err
	}
	probeVersions := defaultProbeVersions(sch)
	transport := "udp"
	if sch == roughtime.SchemeMLDSA44 || *useTCP {
		transport = "tcp"
	}
	if *forceVer != "" {
		v, err := protocol.ParseShortVersion(*forceVer)
		if err != nil {
			return err
		}
		pqKey := sch == roughtime.SchemeMLDSA44
		pqVer := v == protocol.VersionMLDSA44
		if pqKey != pqVer {
			return fmt.Errorf("-ver %s is incompatible with the supplied root key", *forceVer)
		}
		probeVersions = []protocol.Version{v}

		r := probe(ctx, rootPK, probeVersions[0], transport)
		fmt.Printf("=== Forced Version: %s ===\n", r.version)
		if r.err != nil {
			fmt.Printf("Probe error: %s\n\n", r.err)
		}
		printDiagnostic(r)
		if r.err != nil {
			return r.err
		}
		return nil
	}

	fmt.Printf("=== Version Probe: %s (%s) ===\n", *addr, transport)
	fmt.Printf("Timeout: %s\n", *timeout)
	var supported []protocol.Version
	var best *probeResult

	for _, ver := range probeVersions {
		r := probe(ctx, rootPK, ver, transport)
		status := "OK"
		if r.err != nil {
			status = r.err.Error()
		}
		fmt.Printf("  %-40s %s\n", ver.String(), status)

		if r.err != nil {
			continue
		}
		supported = append(supported, ver)
		// probeVersions is ordered newest-first, so the first OK is the best.
		if best == nil {
			best = &r
		}
	}

	fmt.Println()
	if len(supported) == 0 {
		return fmt.Errorf("no supported versions found")
	}

	shorts := make([]string, len(supported))
	for i, v := range supported {
		shorts[i] = v.ShortString()
	}
	fmt.Printf("Supported versions: %s\n", strings.Join(shorts, ", "))
	fmt.Printf("Negotiated:         %s\n", best.version)
	fmt.Println()

	printDiagnostic(*best)
	return nil
}

// probe sends a Roughtime request for a single version, retrying on failure.
func probe(ctx context.Context, rootPK []byte, ver protocol.Version, transport string) probeResult {
	r := probeResult{version: ver, transport: transport}
	versions := []protocol.Version{ver}

	srv := protocol.ComputeSRV(rootPK)
	nonce, request, err := protocol.CreateRequest(versions, rand.Reader, srv)
	if err != nil {
		r.err = fmt.Errorf("request: %w", err)
		return r
	}
	r.nonce = nonce
	r.request = request

	var midpoint time.Time
	var radius time.Duration
	for attempt := range *retries {
		if err := ctx.Err(); err != nil {
			r.err = err
			return r
		}
		var networkErr bool
		reply, rtt, localNow, sendErr := sendProbe(ctx, request, *timeout, transport)
		err = sendErr
		if err != nil {
			networkErr = true
		} else {
			// retain last reply so diagnostic dump works on verify failure.
			r.reply = reply
			r.rtt = rtt
			r.localNow = localNow
			midpoint, radius, err = protocol.VerifyReply(versions, reply, rootPK, nonce, request)
		}
		if err == nil {
			r.midpoint = midpoint
			r.radius = radius
			break
		}
		if attempt == *retries-1 {
			if !networkErr {
				err = fmt.Errorf("verify: %w", err)
			}
			r.err = err
			break
		}
	}
	return r
}

// sendProbe performs a single round trip over the chosen transport.
func sendProbe(ctx context.Context, request []byte, deadline time.Duration, transport string) (reply []byte, rtt time.Duration, localNow time.Time, err error) {
	ctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	if transport == "tcp" {
		return protocol.RoundTripTCP(ctx, *addr, request, deadline)
	}
	return protocol.RoundTripUDP(ctx, *addr, request, deadline)
}

// isIETF reports whether pkt carries the IETF "ROUGHTIM" framing header.
func isIETF(pkt []byte) bool {
	return len(pkt) >= 8 && bytes.Equal(pkt[:8], []byte("ROUGHTIM"))
}

// msgBody strips the ROUGHTIM header if present and returns the message body.
func msgBody(pkt []byte) []byte {
	if !isIETF(pkt) {
		return pkt
	}
	bodyLen, err := protocol.ParsePacketHeader(pkt)
	if err != nil {
		return nil
	}
	// bound first so int(bodyLen) cannot overflow on 32-bit GOARCH.
	if uint64(bodyLen) > uint64(len(pkt)-protocol.PacketHeaderSize) {
		return nil
	}
	return pkt[protocol.PacketHeaderSize : protocol.PacketHeaderSize+int(bodyLen)]
}

// decode parses Roughtime tag-value data and returns a tag map.
func decode(data []byte) map[uint32][]byte {
	tags, err := protocol.Decode(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "debug: decode: %s\n", err)
		return nil
	}
	return tags
}
