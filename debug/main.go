// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

// Command debug probes a Roughtime server to discover its supported protocol
// versions and prints a full diagnostic dump of the request, response,
// signatures, and delegation certificate.
//
// Usage:
//
//	go run debug/main.go -addr time.txryan.com:2002 -pubkey iBVjxg/1j7y1+kQUTBYdTabxCppesU/07D4PMDJk2WA=
//
// Supports Google-Roughtime, IETF drafts, and an experimental ML-DSA-44
// post-quantum extension.
package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/tannerryan/roughtime"
	"github.com/tannerryan/roughtime/internal/version"
	"github.com/tannerryan/roughtime/protocol"
)

var (
	addr        = flag.String("addr", "", "host:port of the Roughtime server")
	pubkey      = flag.String("pubkey", "", "root public key (base64 or hex); 32 bytes selects Ed25519, 1312 bytes selects ML-DSA-44")
	useTCP      = flag.Bool("tcp", false, "use TCP transport; ML-DSA-44 keys always use TCP")
	timeout     = flag.Duration("timeout", 500*time.Millisecond, "per-version probe timeout")
	retries     = flag.Int("retries", 3, "max retry attempts per version")
	forceVer    = flag.String("ver", "", "probe only this version (e.g. draft-12, Google, ml-dsa-44) and dump request/response even on failure")
	showVersion = flag.Bool("version", false, "print version and exit")
)

// probeVersions is resolved at runtime from the key scheme and -ver flag.
var probeVersions []protocol.Version

// transport is resolved at runtime from the key scheme and -tcp flag.
var transport = "udp"

type probeResult struct {
	version  protocol.Version
	midpoint time.Time
	localNow time.Time
	radius   time.Duration
	rtt      time.Duration
	request  []byte
	reply    []byte
	nonce    []byte
	err      error
}

func main() {
	flag.Parse()
	if *showVersion {
		fmt.Printf("roughtime-debug %s (github.com/tannerryan/roughtime)\n\n%s\n", version.Version, version.Copyright)
		return
	}
	if err := validateFlags(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "debug: %s: %s\n", *addr, err)
		os.Exit(1)
	}
}

func validateFlags() error {
	if *addr == "" || *pubkey == "" {
		return fmt.Errorf("usage: debug -addr <host:port> -pubkey <base64-or-hex>")
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
	if sch == roughtime.SchemeMLDSA44 {
		return []protocol.Version{protocol.VersionMLDSA44}
	}
	out := make([]protocol.Version, 0)
	for _, v := range protocol.Supported() {
		if v == protocol.VersionMLDSA44 {
			continue
		}
		out = append(out, v)
	}
	return out
}

// run probes all versions and prints diagnostics for the best one.
func run() error {
	rootPK, err := roughtime.DecodePublicKey(*pubkey)
	if err != nil {
		return fmt.Errorf("decoding public key: %w", err)
	}
	sch, err := roughtime.SchemeOfKey(rootPK)
	if err != nil {
		return err
	}
	probeVersions = defaultProbeVersions(sch)
	transport = "udp"
	if sch == roughtime.SchemeMLDSA44 || *useTCP {
		transport = "tcp"
	}
	if *forceVer != "" {
		v, err := protocol.ParseShortVersion(*forceVer)
		if err != nil {
			return err
		}
		probeVersions = []protocol.Version{v}
	}

	if *forceVer != "" {
		r := probe(rootPK, probeVersions[0])
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
		r := probe(rootPK, ver)
		status := "OK"
		if r.err != nil {
			status = r.err.Error()
		}
		fmt.Printf("  %-40s %s\n", ver.String(), status)

		if r.err != nil {
			continue
		}
		supported = append(supported, ver)
		// probeVersions is ordered newest-first, so the first OK is the best
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

// probe sends a Roughtime request for a single version, retrying on network and
// verification failures.
func probe(rootPK []byte, ver protocol.Version) probeResult {
	r := probeResult{version: ver}
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
		var networkErr bool
		reply, rtt, localNow, sendErr := sendProbe(request, *timeout)
		err = sendErr
		if err != nil {
			networkErr = true
		} else {
			// retain last reply so diagnostic dump works on verify failure
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

// sendProbe sends a single request over the resolved transport.
func sendProbe(request []byte, deadline time.Duration) (reply []byte, rtt time.Duration, localNow time.Time, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	if transport == "tcp" {
		return protocol.RoundTripTCP(ctx, *addr, request, deadline)
	}
	return protocol.RoundTripUDP(ctx, *addr, request, deadline)
}

// isIETF reports whether a packet begins with the ROUGHTIM magic.
func isIETF(pkt []byte) bool {
	return len(pkt) >= 8 && string(pkt[:8]) == "ROUGHTIM"
}

// msgBody strips the 12-byte ROUGHTIM header if present.
func msgBody(pkt []byte) []byte {
	if isIETF(pkt) {
		if len(pkt) < 12 {
			return nil
		}
		return pkt[12:]
	}
	return pkt
}

// decode wraps [protocol.Decode] and logs errors to stderr.
func decode(data []byte) map[uint32][]byte {
	tags, err := protocol.Decode(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "debug: decode: %s\n", err)
		return nil
	}
	return tags
}

// printDiagnostic prints the full diagnostic dump for a probe result.
func printDiagnostic(r probeResult) {
	reqTags := decode(msgBody(r.request))
	respTags := decode(msgBody(r.reply))

	printRequest(r, reqTags)
	printResponse(r, respTags)
	if r.err == nil {
		printVerified(r)
	}
	printResponseDetail(r, respTags)
	printSREP(r, respTags)
	printCert(r, respTags)
}

// printRequest prints request size, hex dump, and parsed tags.
func printRequest(r probeResult, tags map[uint32][]byte) {
	fmt.Printf("=== Request ===\n")
	fmt.Printf("Size: %d bytes\n", len(r.request))
	hexDump(r.request)

	if tags == nil {
		return
	}

	fmt.Println("\n--- Request Tags ---")
	printHex(tags, "VER", protocol.TagVER)
	printHex(tags, "SRV", protocol.TagSRV)
	printHex(tags, "NONC", protocol.TagNONC)
	printHex(tags, "TYPE", protocol.TagTYPE)
	if val, ok := tags[protocol.TagZZZZ]; ok {
		fmt.Printf("  ZZZZ: (%d bytes of padding)\n", len(val))
	}
	if val, ok := tags[protocol.TagPAD]; ok {
		fmt.Printf("  PAD:  (%d bytes of padding)\n", len(val))
	}
	fmt.Println()
}

// printResponse prints response size, hex dump, and parsed tags.
func printResponse(r probeResult, tags map[uint32][]byte) {
	fmt.Printf("=== Response ===\n")
	fmt.Printf("Size: %d bytes\n", len(r.reply))
	hexDump(r.reply)

	if tags == nil {
		return
	}

	fmt.Println("\n--- Response Tags ---")
	for _, e := range []struct {
		name string
		tag  uint32
	}{
		{"SIG", protocol.TagSIG}, {"VER", protocol.TagVER}, {"NONC", protocol.TagNONC}, {"PATH", protocol.TagPATH},
		{"SREP", protocol.TagSREP}, {"CERT", protocol.TagCERT}, {"INDX", protocol.TagINDX}, {"TYPE", protocol.TagTYPE},
	} {
		val, ok := tags[e.tag]
		if !ok {
			continue
		}
		switch {
		case e.name == "SREP" || e.name == "CERT":
			fmt.Printf("  %s: (%d bytes)\n", e.name, len(val))
		case e.name == "PATH" && len(val) == 0:
			fmt.Printf("  %s: (empty)\n", e.name)
		default:
			fmt.Printf("  %s: %s\n", e.name, hex.EncodeToString(val))
		}
	}
	fmt.Println()
}

// printVerified prints the verified result summary and amplification check.
func printVerified(r probeResult) {
	fmt.Printf("=== Verified Result ===\n")
	fmt.Printf("Round-trip time: %s\n", r.rtt)
	fmt.Printf("Midpoint:        %s\n", r.midpoint.UTC().Format(time.RFC3339))
	fmt.Printf("Radius:          %s\n", r.radius)
	fmt.Printf("Local time:      %s\n", r.localNow.UTC().Format(time.RFC3339Nano))
	fmt.Printf("Clock drift:     %s\n", r.midpoint.Sub(r.localNow).Round(time.Millisecond))
	switch {
	case transport != "udp":
		fmt.Printf("Amplification:   n/a (%s, reply %d, request %d)\n", transport, len(r.reply), len(r.request))
	case len(r.reply) <= len(r.request):
		fmt.Printf("Amplification:   ok (reply %d ≤ request %d)\n", len(r.reply), len(r.request))
	default:
		fmt.Printf("Amplification:   VIOLATED (reply %d > request %d)\n", len(r.reply), len(r.request))
	}
	fmt.Println()
}

// printResponseDetail prints decoded top-level response fields.
func printResponseDetail(r probeResult, tags map[uint32][]byte) {
	if tags == nil {
		return
	}

	fmt.Printf("=== Response Details ===\n")
	if vb, ok := tags[protocol.TagVER]; ok && len(vb) >= 4 {
		v := binary.LittleEndian.Uint32(vb)
		fmt.Printf("Version:         0x%08x (%s)\n", v, protocol.Version(v))
	} else if r.version == protocol.VersionGoogle {
		fmt.Printf("Version:         (none) (%s)\n", protocol.VersionGoogle)
	}
	if sig, ok := tags[protocol.TagSIG]; ok {
		fmt.Printf("Signature:       %s\n", hex.EncodeToString(sig))
	}
	if nonce, ok := tags[protocol.TagNONC]; ok {
		fmt.Printf("Nonce:           %s\n", hex.EncodeToString(nonce))
	}
	if indx, ok := tags[protocol.TagINDX]; ok && len(indx) == 4 {
		fmt.Printf("Merkle index:    %d\n", binary.LittleEndian.Uint32(indx))
	}
	if path, ok := tags[protocol.TagPATH]; ok {
		hs := 32
		if r.version == protocol.VersionGoogle {
			hs = 64
		}
		fmt.Printf("Merkle path:     %d node(s)\n", len(path)/hs)
	}
	fmt.Println()
}

// printSREP parses and prints the signed response contents.
func printSREP(r probeResult, tags map[uint32][]byte) {
	if tags == nil {
		return
	}
	srepBytes, ok := tags[protocol.TagSREP]
	if !ok {
		return
	}
	srep := decode(srepBytes)
	if srep == nil {
		return
	}

	fmt.Printf("=== Signed Response (SREP) ===\n")
	if root, ok := srep[protocol.TagROOT]; ok {
		fmt.Printf("Merkle root:     %s\n", hex.EncodeToString(root))
	}
	if midp, ok := srep[protocol.TagMIDP]; ok && len(midp) == 8 {
		raw := binary.LittleEndian.Uint64(midp)
		ts, _ := protocol.DecodeTimestamp(r.version, midp)
		fmt.Printf("Midpoint (raw):  %d (%s)\n", raw, ts.UTC().Format(time.RFC3339))
	}
	if radi, ok := srep[protocol.TagRADI]; ok && len(radi) == 4 {
		fmt.Printf("Radius (raw):    %d\n", binary.LittleEndian.Uint32(radi))
	}
	if ver, ok := srep[protocol.TagVER]; ok && len(ver) >= 4 {
		v := binary.LittleEndian.Uint32(ver)
		fmt.Printf("VER in SREP:     0x%08x (%s)\n", v, protocol.Version(v))
	}
	if vers, ok := srep[protocol.TagVERS]; ok && len(vers) >= 4 && len(vers)%4 == 0 {
		fmt.Printf("VERS in SREP:    ")
		for i := 0; i < len(vers); i += 4 {
			if i > 0 {
				fmt.Printf(", ")
			}
			v := binary.LittleEndian.Uint32(vers[i:])
			fmt.Printf("%s", protocol.Version(v).ShortString())
		}
		fmt.Println()
	}
	fmt.Println()
}

// printCert prints the delegation certificate and validates the midpoint
// window.
func printCert(r probeResult, tags map[uint32][]byte) {
	if tags == nil {
		return
	}
	certBytes, ok := tags[protocol.TagCERT]
	if !ok {
		return
	}
	certMsg := decode(certBytes)
	if certMsg == nil {
		return
	}

	fmt.Printf("=== Certificate ===\n")
	if sig, ok := certMsg[protocol.TagSIG]; ok {
		fmt.Printf("Signature:       %s\n", hex.EncodeToString(sig))
	}

	deleBytes, ok := certMsg[protocol.TagDELE]
	if !ok {
		return
	}
	dele := decode(deleBytes)
	if dele == nil {
		return
	}

	if pk, ok := dele[protocol.TagPUBK]; ok {
		fmt.Printf("Online key:      %s\n", hex.EncodeToString(pk))
	}

	verified := r.err == nil && !r.midpoint.IsZero()
	var mintTime, maxtTime time.Time
	var haveMint, haveMaxt bool
	if mint, ok := dele[protocol.TagMINT]; ok && len(mint) == 8 {
		mintTime, _ = protocol.DecodeTimestamp(r.version, mint)
		haveMint = true
		fmt.Printf("Not before:      %s\n", mintTime.UTC().Format(time.RFC3339))
	}
	if maxt, ok := dele[protocol.TagMAXT]; ok && len(maxt) == 8 {
		maxtTime, _ = protocol.DecodeTimestamp(r.version, maxt)
		haveMaxt = true
		fmt.Printf("Not after:       %s\n", maxtTime.UTC().Format(time.RFC3339))
		// prefer verified midpoint so a skewed local clock does not mislead
		ref := time.Now()
		if verified {
			ref = r.midpoint
		}
		if remaining := maxtTime.Sub(ref); remaining > 0 {
			fmt.Printf("Expires in:      %s\n", remaining.Round(time.Second))
		} else {
			fmt.Printf("Expired:         %s ago\n", (-remaining).Round(time.Second))
		}
	}

	if haveMint && haveMaxt {
		if !verified {
			fmt.Printf("Cert validity:   skipped (no verified midpoint)\n")
		} else if !r.midpoint.Before(mintTime) && !r.midpoint.After(maxtTime) {
			fmt.Printf("Cert validity:   ok (midpoint within window)\n")
		} else {
			fmt.Printf("Cert validity:   INVALID (midpoint outside [mint, maxt])\n")
		}
	}
}

// printHex prints a tag value as hex if present.
func printHex(tags map[uint32][]byte, name string, tag uint32) {
	val, ok := tags[tag]
	if !ok {
		return
	}
	if len(val) == 0 {
		fmt.Printf("  %s: (empty)\n", name)
	} else {
		fmt.Printf("  %s: %s\n", name, hex.EncodeToString(val))
	}
}

// hexDump prints data in the standard 16-bytes-per-line hex+ASCII format.
func hexDump(data []byte) {
	for off := 0; off < len(data); off += 16 {
		end := min(off+16, len(data))
		line := data[off:end]

		fmt.Printf("%08x  ", off)
		for i := range 16 {
			if i < len(line) {
				fmt.Printf("%02x ", line[i])
			} else {
				fmt.Printf("   ")
			}
			if i == 7 {
				fmt.Printf(" ")
			}
		}

		fmt.Printf(" |")
		for _, b := range line {
			if b >= 0x20 && b <= 0x7e {
				fmt.Printf("%c", b)
			} else {
				fmt.Printf(".")
			}
		}
		fmt.Printf("|\n")
	}
}
