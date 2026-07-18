// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"slices"
	"time"

	"github.com/tannerryan/roughtime/protocol"
)

// printDiagnostic prints one probe's request, response, and verified timing.
func printDiagnostic(r probeResult) {
	fmt.Printf("=== Request ===\nSize: %d bytes\n", len(r.request))
	printTags(decode(msgBody(r.request)))

	fmt.Printf("\n=== Response ===\nSize: %d bytes\n", len(r.reply))
	if len(r.reply) == 0 {
		fmt.Println("No response captured.")
		return
	}
	tags := decode(msgBody(r.reply))
	printTags(tags)
	if r.err != nil {
		fmt.Printf("Verification:    failed: %s\n", r.err)
		return
	}

	fmt.Println("\n=== Verified Result ===")
	fmt.Printf("Round-trip time: %s\n", r.rtt)
	fmt.Printf("Midpoint:        %s\n", r.midpoint.UTC().Format(time.RFC3339Nano))
	fmt.Printf("Radius:          %s\n", r.radius)
	fmt.Printf("Local time:      %s\n", r.localNow.UTC().Format(time.RFC3339Nano))
	fmt.Printf("Clock drift:     %s\n", r.midpoint.Sub(r.localNow.Add(-r.rtt/2)).Round(time.Millisecond))
	if r.transport == "udp" {
		status := "ok"
		if len(r.reply) > len(r.request) {
			status = "VIOLATED"
		}
		fmt.Printf("Amplification:   %s (reply %d, request %d)\n", status, len(r.reply), len(r.request))
	}
	printSREP(tags, r.plan.version)
	printCertificate(tags, r.plan.version, r.midpoint)
}

// printTags prints a compact tag-value summary.
func printTags(tags map[uint32][]byte) {
	if tags == nil {
		return
	}
	keys := make([]uint32, 0, len(tags))
	for tag := range tags {
		keys = append(keys, tag)
	}
	slices.Sort(keys)
	for _, tag := range keys {
		value := tags[tag]
		name := tagName(tag)
		switch tag {
		case protocol.TagVER:
			if len(value) == 4 {
				v := protocol.Version(binary.LittleEndian.Uint32(value))
				fmt.Printf("  %-5s %s (%s)\n", name+":", hex.EncodeToString(value), v.ShortString())
				continue
			}
		case protocol.TagTYPE:
			fmt.Printf("  %-5s %s (%s)\n", name+":", hex.EncodeToString(value), describeType(value))
			continue
		case protocol.TagZZZZ, protocol.TagPAD, 0x00444150:
			fmt.Printf("  %-5s %d bytes\n", name+":", len(value))
			continue
		case protocol.TagSREP, protocol.TagCERT:
			fmt.Printf("  %-5s %d-byte message\n", name+":", len(value))
			continue
		}
		if len(value) <= 64 {
			fmt.Printf("  %-5s %s\n", name+":", hex.EncodeToString(value))
		} else {
			fmt.Printf("  %-5s %d bytes\n", name+":", len(value))
		}
	}
}

// printSREP prints selected signed-response fields.
func printSREP(tags map[uint32][]byte, version protocol.Version) {
	srepBytes := tags[protocol.TagSREP]
	if srepBytes == nil {
		return
	}
	srep := decode(srepBytes)
	if srep == nil {
		return
	}
	fmt.Println("\n=== Signed Response ===")
	if midpoint, err := protocol.DecodeTimestamp(version, srep[protocol.TagMIDP]); err == nil {
		fmt.Printf("Midpoint:        %s\n", midpoint.UTC().Format(time.RFC3339Nano))
	}
	if values := srep[protocol.TagVERS]; len(values)%4 == 0 && len(values) > 0 {
		fmt.Print("VERS:            ")
		for i := 0; i < len(values); i += 4 {
			if i > 0 {
				fmt.Print(", ")
			}
			fmt.Print(protocol.Version(binary.LittleEndian.Uint32(values[i:])).ShortString())
		}
		fmt.Println()
	}
}

// printCertificate prints delegation key and validity fields.
func printCertificate(tags map[uint32][]byte, version protocol.Version, midpoint time.Time) {
	cert := decode(tags[protocol.TagCERT])
	if cert == nil {
		return
	}
	delegation := decode(cert[protocol.TagDELE])
	if delegation == nil {
		return
	}
	fmt.Println("\n=== Certificate ===")
	if key := delegation[protocol.TagPUBK]; key != nil {
		if len(key) > 64 {
			fmt.Printf("Online key:      %d bytes\n", len(key))
		} else {
			fmt.Printf("Online key:      %s\n", hex.EncodeToString(key))
		}
	}
	minimum, minErr := protocol.DecodeTimestamp(version, delegation[protocol.TagMINT])
	maximum, maxErr := protocol.DecodeTimestamp(version, delegation[protocol.TagMAXT])
	if minErr == nil {
		fmt.Printf("Not before:      %s\n", minimum.UTC().Format(time.RFC3339Nano))
	}
	if maxErr == nil {
		fmt.Printf("Not after:       %s\n", maximum.UTC().Format(time.RFC3339Nano))
	}
	if minErr == nil && maxErr == nil && !midpoint.IsZero() {
		valid := !midpoint.Before(minimum) && !midpoint.After(maximum)
		fmt.Printf("Cert validity:   %t\n", valid)
	}
}

// describeType formats a TYPE value.
func describeType(value []byte) string {
	if len(value) != 4 {
		return fmt.Sprintf("invalid length %d", len(value))
	}
	switch binary.LittleEndian.Uint32(value) {
	case 0:
		return "request"
	case 1:
		return "response"
	default:
		return "unknown"
	}
}

// tagName returns the conventional tag label or its hexadecimal value.
func tagName(tag uint32) string {
	switch tag {
	case protocol.TagSIG:
		return "SIG"
	case protocol.TagVER:
		return "VER"
	case protocol.TagSRV:
		return "SRV"
	case protocol.TagNONC:
		return "NONC"
	case protocol.TagDELE:
		return "DELE"
	case protocol.TagTYPE:
		return "TYPE"
	case protocol.TagPATH:
		return "PATH"
	case protocol.TagRADI:
		return "RADI"
	case protocol.TagPUBK:
		return "PUBK"
	case protocol.TagMIDP:
		return "MIDP"
	case protocol.TagSREP:
		return "SREP"
	case protocol.TagVERS:
		return "VERS"
	case protocol.TagROOT:
		return "ROOT"
	case protocol.TagCERT:
		return "CERT"
	case protocol.TagMINT:
		return "MINT"
	case protocol.TagMAXT:
		return "MAXT"
	case protocol.TagINDX:
		return "INDX"
	case protocol.TagZZZZ:
		return "ZZZZ"
	case protocol.TagPAD, 0x00444150:
		return "PAD"
	}
	return fmt.Sprintf("0x%08x", tag)
}
