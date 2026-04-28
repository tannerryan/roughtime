// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	"github.com/tannerryan/roughtime/protocol"
)

// tagPADIETF is the drafts 01-07 padding tag "PAD\0".
const tagPADIETF uint32 = 0x00444150

// radiusUsesMicroseconds reports whether RADI is encoded in microseconds for v.
func radiusUsesMicroseconds(v protocol.Version) bool {
	return v == protocol.VersionGoogle ||
		(v >= protocol.VersionDraft01 && v <= protocol.VersionDraft07)
}

// midpointUnit returns the encoding label for MIDP's raw uint64 at version v.
func midpointUnit(v protocol.Version) string {
	switch {
	case v == protocol.VersionGoogle:
		return "Unix-µs"
	case v >= protocol.VersionDraft01 && v <= protocol.VersionDraft07:
		return "MJD-µs"
	default:
		return "Unix-s"
	}
}

// printDiagnostic prints a full diagnostic dump of the probe result.
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

// printRequest prints the request bytes and decoded tag summary.
func printRequest(r probeResult, tags map[uint32][]byte) {
	fmt.Printf("=== Request ===\n")
	fmt.Printf("Size: %d bytes\n", len(r.request))
	hexDump(r.request)

	if tags == nil {
		return
	}

	fmt.Println("\n--- Request Tags ---")
	printVER(tags, protocol.TagVER)
	printHex(tags, "SRV", protocol.TagSRV)
	printHex(tags, "NONC", protocol.TagNONC)
	printTYPE(tags)
	if val, ok := tags[protocol.TagZZZZ]; ok {
		fmt.Printf("  ZZZZ: (%d bytes of padding)\n", len(val))
	}
	if val, ok := tags[protocol.TagPAD]; ok {
		fmt.Printf("  PAD:  (%d bytes of padding)\n", len(val))
	}
	if val, ok := tags[tagPADIETF]; ok {
		fmt.Printf("  PAD:  (%d bytes of padding, drafts 01-07)\n", len(val))
	}
	fmt.Println()
}

// printResponse prints the response bytes and decoded tag summary.
func printResponse(r probeResult, tags map[uint32][]byte) {
	fmt.Printf("=== Response ===\n")
	fmt.Printf("Size: %d bytes\n", len(r.reply))
	hexDump(r.reply)

	if tags == nil {
		return
	}

	fmt.Println("\n--- Response Tags ---")
	entries := []struct {
		name string
		tag  uint32
	}{
		{"SIG", protocol.TagSIG}, {"VER", protocol.TagVER}, {"NONC", protocol.TagNONC}, {"PATH", protocol.TagPATH},
		{"SREP", protocol.TagSREP}, {"CERT", protocol.TagCERT}, {"INDX", protocol.TagINDX}, {"TYPE", protocol.TagTYPE},
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].tag < entries[j].tag })
	hs := 32
	if r.version == protocol.VersionGoogle {
		hs = 64
	}
	for _, e := range entries {
		val, ok := tags[e.tag]
		if !ok {
			continue
		}
		switch e.name {
		case "SREP", "CERT":
			fmt.Printf("  %s: (%d bytes)\n", e.name, len(val))
		case "PATH":
			switch {
			case len(val) == 0:
				fmt.Printf("  %s: (empty)\n", e.name)
			case len(val)%hs != 0:
				fmt.Printf("  %s: %s (length %d not a multiple of %d)\n", e.name, hex.EncodeToString(val), len(val), hs)
			default:
				fmt.Printf("  %s: %s\n", e.name, hex.EncodeToString(val))
			}
		case "VER":
			if len(val) >= 4 {
				v := protocol.Version(binary.LittleEndian.Uint32(val))
				fmt.Printf("  %s: %s (%s)\n", e.name, hex.EncodeToString(val), v.ShortString())
			} else {
				fmt.Printf("  %s: %s\n", e.name, hex.EncodeToString(val))
			}
		case "TYPE":
			fmt.Printf("  %s: %s (%s)\n", e.name, hex.EncodeToString(val), describeType(val))
		default:
			fmt.Printf("  %s: %s\n", e.name, hex.EncodeToString(val))
		}
	}
	fmt.Println()
}

// printVerified prints the verified midpoint, radius, and amplification status.
func printVerified(r probeResult) {
	fmt.Printf("=== Verified Result ===\n")
	fmt.Printf("Round-trip time: %s\n", r.rtt)
	fmt.Printf("Midpoint:        %s\n", r.midpoint.UTC().Format(time.RFC3339))
	fmt.Printf("Radius:          %s\n", r.radius)
	fmt.Printf("Local time:      %s\n", r.localNow.UTC().Format(time.RFC3339Nano))
	fmt.Printf("Clock drift:     %s\n", r.midpoint.Sub(r.localNow.Add(-r.rtt/2)).Round(time.Millisecond))
	switch {
	case r.transport != "udp":
		fmt.Printf("Amplification:   n/a (%s, reply %d, request %d)\n", r.transport, len(r.reply), len(r.request))
	case len(r.reply) <= len(r.request):
		fmt.Printf("Amplification:   ok (reply %d <= request %d)\n", len(r.reply), len(r.request))
	default:
		fmt.Printf("Amplification:   VIOLATED (reply %d > request %d)\n", len(r.reply), len(r.request))
	}
	fmt.Println()
}

// printResponseDetail prints decoded fields from the top-level response tags.
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
		// Google uses full 64-byte SHA-512 nodes; IETF truncates to 32 bytes.
		hs := 32
		if r.version == protocol.VersionGoogle {
			hs = 64
		}
		fmt.Printf("Merkle path:     %d node(s)\n", len(path)/hs)
	}
	fmt.Println()
}

// printSREP prints decoded fields from the signed-response (SREP) tag.
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
	if nonce, ok := srep[protocol.TagNONC]; ok {
		fmt.Printf("NONC in SREP:    %s\n", hex.EncodeToString(nonce))
	}
	if midp, ok := srep[protocol.TagMIDP]; ok && len(midp) == 8 {
		raw := binary.LittleEndian.Uint64(midp)
		unit := midpointUnit(r.version)
		if ts, err := protocol.DecodeTimestamp(r.version, midp); err == nil {
			fmt.Printf("Midpoint (raw):  %d %s (%s)\n", raw, unit, ts.UTC().Format(time.RFC3339))
		} else {
			fmt.Printf("Midpoint (raw):  %d %s (decode failed: %s)\n", raw, unit, err)
		}
	}
	if radi, ok := srep[protocol.TagRADI]; ok && len(radi) == 4 {
		raw := binary.LittleEndian.Uint32(radi)
		// Google and drafts 01-07 encode RADI in µs; drafts 08+ in seconds.
		unit := "s"
		if radiusUsesMicroseconds(r.version) {
			unit = "µs"
		}
		fmt.Printf("Radius (raw):    %d %s\n", raw, unit)
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
		want := protocol.SchemeSignatureSize(r.version)
		if len(sig) != want {
			fmt.Printf("Signature:       %s (length %d, expected %d)\n", hex.EncodeToString(sig), len(sig), want)
		} else {
			fmt.Printf("Signature:       %s\n", hex.EncodeToString(sig))
		}
	}

	deleBytes, ok := certMsg[protocol.TagDELE]
	if !ok {
		fmt.Println("DELE:            missing")
		return
	}
	dele := decode(deleBytes)
	if dele == nil {
		fmt.Println("DELE:            decode failed")
		return
	}

	if pk, ok := dele[protocol.TagPUBK]; ok {
		fmt.Printf("Online key:      %s\n", hex.EncodeToString(pk))
	}

	verified := r.err == nil && !r.midpoint.IsZero()
	var mintTime, maxtTime time.Time
	var haveMint, haveMaxt bool
	if mint, ok := dele[protocol.TagMINT]; ok {
		switch {
		case len(mint) != 8:
			fmt.Printf("Not before:      (length %d, expected 8)\n", len(mint))
		default:
			t, err := protocol.DecodeTimestamp(r.version, mint)
			if err != nil {
				fmt.Printf("Not before:      decode failed: %s\n", err)
			} else {
				mintTime = t
				haveMint = true
				fmt.Printf("Not before:      %s\n", mintTime.UTC().Format(time.RFC3339))
			}
		}
	}
	if maxt, ok := dele[protocol.TagMAXT]; ok {
		switch {
		case len(maxt) != 8:
			fmt.Printf("Not after:       (length %d, expected 8)\n", len(maxt))
		default:
			t, err := protocol.DecodeTimestamp(r.version, maxt)
			if err != nil {
				fmt.Printf("Not after:       decode failed: %s\n", err)
			} else {
				maxtTime = t
				haveMaxt = true
				fmt.Printf("Not after:       %s\n", maxtTime.UTC().Format(time.RFC3339))
				// prefer verified midpoint so a skewed local clock does not
				// mislead.
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

// printHex prints a tag's value as hex, or "(empty)" if zero length.
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

// printVER prints a VER tag value with its parsed short version.
func printVER(tags map[uint32][]byte, tag uint32) {
	val, ok := tags[tag]
	if !ok {
		return
	}
	if len(val) >= 4 {
		v := protocol.Version(binary.LittleEndian.Uint32(val))
		fmt.Printf("  VER:  %s (%s)\n", hex.EncodeToString(val), v.ShortString())
	} else {
		fmt.Printf("  VER:  %s\n", hex.EncodeToString(val))
	}
}

// printTYPE prints the TYPE tag value with its decoded meaning.
func printTYPE(tags map[uint32][]byte) {
	val, ok := tags[protocol.TagTYPE]
	if !ok {
		return
	}
	fmt.Printf("  TYPE: %s (%s)\n", hex.EncodeToString(val), describeType(val))
}

// describeType returns a human-readable name for a TYPE tag value.
func describeType(val []byte) string {
	if len(val) != 4 {
		return fmt.Sprintf("length %d, expected 4", len(val))
	}
	switch binary.LittleEndian.Uint32(val) {
	case 0:
		return "request"
	case 1:
		return "response"
	default:
		return fmt.Sprintf("unknown %d", binary.LittleEndian.Uint32(val))
	}
}

// hexDump prints data as 16 bytes per line of hex with an ASCII gutter.
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
