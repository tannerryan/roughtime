// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

// Command debug probes a Roughtime server to discover its supported protocol
// versions and prints a full diagnostic dump of the request, response,
// signatures, and delegation certificate.
//
// Usage:
//
//	go run debug/main.go -addr time.txryan.com:2002 \
//	                     -pubkey iBVjxg/1j7y1+kQUTBYdTabxCppesU/07D4PMDJk2WA=
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
	"slices"
	"strings"
	"time"

	"github.com/tannerryan/roughtime/internal/version"
	"github.com/tannerryan/roughtime/protocol"
)

var (
	addr        = flag.String("addr", "", "host:port of the Roughtime server")
	pubkey      = flag.String("pubkey", "", "base64-encoded Ed25519 root public key")
	timeout     = flag.Duration("timeout", 2*time.Second, "per-version probe timeout")
	showVersion = flag.Bool("version", false, "print version and exit")
)

// probeResult holds the outcome of a single version probe.
type probeResult struct {
	version  protocol.Version
	midpoint time.Time
	radius   time.Duration
	rtt      time.Duration
	request  []byte
	reply    []byte
	nonce    []byte
	err      error
}

// main parses flags and runs the debug probe.
func main() {
	flag.Parse()
	if *showVersion {
		fmt.Println("roughtime-debug", version.Version)
		return
	}
	if *addr == "" || *pubkey == "" {
		fmt.Fprintf(os.Stderr, "usage: debug -addr <host:port> -pubkey <base64>\n")
		os.Exit(1)
	}
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "debug: %s: %s\n", *addr, err)
		os.Exit(1)
	}
}

// probeVersions lists every distinct VER value, newest first.
var probeVersions = func() []protocol.Version {
	out := slices.Clone(protocol.SupportedVersions())
	slices.Reverse(out)
	return append(out, protocol.VersionGoogle)
}()

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

// probe sends a single Roughtime request for a specific version and verifies
// the response.
func probe(rootPK []byte, ver protocol.Version) probeResult {
	r := probeResult{version: ver}
	versions := []protocol.Version{ver}

	nonce, request, err := protocol.CreateRequest(versions, rand.Reader)
	if err != nil {
		r.err = fmt.Errorf("request: %w", err)
		return r
	}
	r.nonce = nonce
	r.request = request

	raddr, err := net.ResolveUDPAddr("udp", *addr)
	if err != nil {
		r.err = fmt.Errorf("resolve: %w", err)
		return r
	}

	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		r.err = fmt.Errorf("dial: %w", err)
		return r
	}
	defer conn.Close()

	if err := conn.SetWriteDeadline(time.Now().Add(*timeout)); err != nil {
		r.err = fmt.Errorf("set write deadline: %w", err)
		return r
	}
	start := time.Now()
	if _, err := conn.Write(request); err != nil {
		r.err = fmt.Errorf("send: %w", err)
		return r
	}

	if err := conn.SetReadDeadline(time.Now().Add(*timeout)); err != nil {
		r.err = fmt.Errorf("set read deadline: %w", err)
		return r
	}
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		r.err = fmt.Errorf("read: %w", err)
		return r
	}
	r.rtt = time.Since(start)
	r.reply = buf[:n]

	midpoint, radius, err := protocol.VerifyReply(versions, r.reply, rootPK, nonce, request)
	if err != nil {
		r.err = fmt.Errorf("verify: %w", err)
		return r
	}

	r.midpoint = midpoint
	r.radius = radius
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

// decode is a safe wrapper around [protocol.Decode] that prints decode errors
// to stderr instead of silently dropping malformed input.
func decode(data []byte) map[uint32][]byte {
	tags, err := protocol.Decode(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "debug: decode: %s\n", err)
		return nil
	}
	return tags
}

// printDiagnostic prints the full diagnostic dump for a verified probe result.
// It decodes the request and response once and passes the parsed tags to each
// output section.
func printDiagnostic(r probeResult) {
	reqTags := decode(msgBody(r.request))
	respTags := decode(msgBody(r.reply))

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

// printVerified prints the verified result summary, including the amplification
// check that Roughtime requires of every server response.
func printVerified(r probeResult) {
	localNow := time.Now()
	fmt.Printf("=== Verified Result ===\n")
	fmt.Printf("Round-trip time: %s\n", r.rtt)
	fmt.Printf("Midpoint:        %s\n", r.midpoint.UTC().Format(time.RFC3339))
	fmt.Printf("Radius:          %s\n", r.radius)
	fmt.Printf("Local time:      %s\n", localNow.UTC().Format(time.RFC3339Nano))
	fmt.Printf("Clock drift:     %s\n", r.midpoint.Sub(localNow).Round(time.Millisecond))
	if len(r.reply) <= len(r.request) {
		fmt.Printf("Amplification:   ok (reply %d ≤ request %d)\n", len(r.reply), len(r.request))
	} else {
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
		if len(r.nonce) == 64 {
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

// printCert parses and prints the delegation certificate, then checks whether
// the response midpoint falls within the certificate's validity window.
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
		if remaining := time.Until(maxtTime); remaining > 0 {
			fmt.Printf("Expires in:      %s\n", remaining.Round(time.Second))
		} else {
			fmt.Printf("Expired:         %s ago\n", (-remaining).Round(time.Second))
		}
	}

	if haveMint && haveMaxt {
		if !r.midpoint.Before(mintTime) && !r.midpoint.After(maxtTime) {
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
