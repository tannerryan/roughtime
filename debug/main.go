// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

// Command debug probes a Roughtime server to discover its supported protocol
// versions and prints a full diagnostic dump of the request, response,
// signatures, and delegation certificate.
//
// Usage:
//
//	go run ./debug -addr time.txryan.com:2002 \
//	              -pubkey iBVjxg/1j7y1+kQUTBYdTabxCppesU/07D4PMDJk2WA=
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/tannerryan/roughtime/protocol"
)

var (
	addr    = flag.String("addr", "", "host:port of the Roughtime server")
	pubkey  = flag.String("pubkey", "", "base64-encoded Ed25519 root public key")
	timeout = flag.Duration("timeout", 2*time.Second, "per-version probe timeout")
)

// probeResult holds the outcome of a single version probe.
type probeResult struct {
	Version  protocol.Version
	Midpoint time.Time
	Radius   time.Duration
	RTT      time.Duration
	Request  []byte
	Reply    []byte
	Nonce    []byte
	Err      error
}

// main parses flags and runs the debug probe.
func main() {
	flag.Parse()
	if *addr == "" || *pubkey == "" {
		fmt.Fprintf(os.Stderr, "usage: debug -addr <host:port> -pubkey <base64>\n")
		os.Exit(1)
	}
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
}

// probeVersions lists every distinct wire-group representative to probe.
var probeVersions = []protocol.Version{
	protocol.VersionDraft12,
	protocol.VersionDraft11,
	protocol.VersionDraft10,
	protocol.VersionDraft08,
	protocol.VersionDraft07,
	protocol.VersionDraft06,
	protocol.VersionDraft05,
	protocol.VersionDraft01,
	protocol.VersionGoogle,
}

// run probes all versions and prints diagnostics for the best one.
func run() error {
	rootPK, err := base64.StdEncoding.DecodeString(*pubkey)
	if err != nil {
		return fmt.Errorf("decoding public key: %w", err)
	}

	fmt.Printf("=== Version Probe: %s ===\n", *addr)
	var supported []protocol.Version
	var best *probeResult

	for _, ver := range probeVersions {
		r := probe(rootPK, ver)
		status := "OK"
		if r.Err != nil {
			status = r.Err.Error()
		}
		fmt.Printf("  %-40s %s\n", ver.String(), status)

		if r.Err == nil {
			supported = append(supported, ver)
			if best == nil {
				best = &r
			}
		}
	}

	fmt.Println()
	if len(supported) == 0 {
		return fmt.Errorf("no supported versions found")
	}

	fmt.Printf("Supported versions: ")
	for i, v := range supported {
		if i > 0 {
			fmt.Printf(", ")
		}
		fmt.Printf("%s", v.ShortString())
	}
	fmt.Println()
	fmt.Printf("Negotiated:         %s\n", best.Version)
	fmt.Println()

	printDiagnostic(*best)
	return nil
}

// probe sends a single Roughtime request for a specific version and verifies
// the response.
func probe(rootPK []byte, ver protocol.Version) probeResult {
	r := probeResult{Version: ver}
	versions := []protocol.Version{ver}

	nonce, request, err := protocol.CreateRequest(versions, rand.Reader)
	if err != nil {
		r.Err = fmt.Errorf("request: %w", err)
		return r
	}
	r.Nonce = nonce
	r.Request = request

	raddr, err := net.ResolveUDPAddr("udp", *addr)
	if err != nil {
		r.Err = fmt.Errorf("resolve: %w", err)
		return r
	}

	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		r.Err = fmt.Errorf("dial: %w", err)
		return r
	}
	defer conn.Close()

	_ = conn.SetWriteDeadline(time.Now().Add(*timeout))
	start := time.Now()
	if _, err := conn.Write(request); err != nil {
		r.Err = fmt.Errorf("send: %w", err)
		return r
	}

	_ = conn.SetReadDeadline(time.Now().Add(*timeout))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		r.Err = fmt.Errorf("read: %w", err)
		return r
	}
	r.RTT = time.Since(start)
	r.Reply = buf[:n]

	midpoint, radius, err := protocol.VerifyReply(versions, r.Reply, rootPK, nonce, request)
	if err != nil {
		r.Err = err
		return r
	}

	r.Midpoint = midpoint
	r.Radius = radius
	return r
}

// isIETF reports whether a packet begins with the ROUGHTIM magic.
func isIETF(pkt []byte) bool {
	return len(pkt) >= 8 && string(pkt[:8]) == "ROUGHTIM"
}

// msgBody strips the 12-byte ROUGHTIM header if present.
func msgBody(pkt []byte) []byte {
	if isIETF(pkt) {
		return pkt[12:]
	}
	return pkt
}

// decode is a safe wrapper around [protocol.Decode].
func decode(data []byte) map[uint32][]byte {
	tags, err := protocol.Decode(data)
	if err != nil {
		return nil
	}
	return tags
}

// printDiagnostic prints the full diagnostic dump for a verified probe result.
// It decodes the request and response once and passes the parsed tags to each
// output section.
func printDiagnostic(r probeResult) {
	reqTags := decode(msgBody(r.Request))
	respTags := decode(msgBody(r.Reply))

	printRequest(r, reqTags)
	printResponse(r, respTags)
	printVerified(r)
	printResponseDetail(r, respTags)
	printSREP(r, respTags)
	printCert(r, respTags)
}

// printRequest prints request size, hex dump, and parsed tags.
func printRequest(r probeResult, tags map[uint32][]byte) {
	fmt.Printf("=== Request ===\n")
	fmt.Printf("Size: %d bytes\n", len(r.Request))
	hexDump(r.Request)

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
	fmt.Printf("Size: %d bytes\n", len(r.Reply))
	hexDump(r.Reply)

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

// printVerified prints the verified result summary.
func printVerified(r probeResult) {
	localNow := time.Now()
	fmt.Printf("=== Verified Result ===\n")
	fmt.Printf("Round-trip time: %s\n", r.RTT)
	fmt.Printf("Midpoint:        %s\n", r.Midpoint.UTC().Format(time.RFC3339))
	fmt.Printf("Radius:          %s\n", r.Radius)
	fmt.Printf("Local time:      %s\n", localNow.UTC().Format("2006-01-02T15:04:05.000000Z"))
	fmt.Printf("Clock drift:     %s\n", r.Midpoint.Sub(localNow).Round(time.Millisecond))
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
	} else if r.Version == protocol.VersionGoogle {
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
		if len(r.Nonce) == 64 {
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
		ts, _ := protocol.DecodeTimestamp(r.Version, midp)
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

// printCert parses and prints the delegation certificate.
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
	if mint, ok := dele[protocol.TagMINT]; ok && len(mint) == 8 {
		ts, _ := protocol.DecodeTimestamp(r.Version, mint)
		fmt.Printf("Not before:      %s\n", ts.UTC().Format(time.RFC3339))
	}
	if maxt, ok := dele[protocol.TagMAXT]; ok && len(maxt) == 8 {
		ts, _ := protocol.DecodeTimestamp(r.Version, maxt)
		fmt.Printf("Not after:       %s\n", ts.UTC().Format(time.RFC3339))
		if remaining := time.Until(ts); remaining > 0 {
			fmt.Printf("Expires in:      %s\n", remaining.Round(time.Second))
		} else {
			fmt.Printf("Expired:         %s ago\n", (-remaining).Round(time.Second))
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

		// Offset
		fmt.Printf("%08x  ", off)

		// Hex bytes in two groups of 8
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

		// ASCII
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
