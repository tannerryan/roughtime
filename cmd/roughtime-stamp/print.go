// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"

	"github.com/tannerryan/roughtime"
)

// printCheck prints one OK-prefixed line in the verification stanza.
func printCheck(label, detail string) {
	fmt.Printf("  %-18s OK   %s\n", label, detail)
}

// printDocument prints the document path, size, and SHA-256.
func printDocument(path string, size int64, digest []byte) {
	fmt.Println("Document")
	fmt.Printf("  Path:             %s\n", path)
	fmt.Printf("  Size:             %d bytes\n", size)
	fmt.Printf("  SHA-256:          %x\n", digest)
	fmt.Println()
}

// printSeedLink prints the seed link's crypto detail and confirms its nonce
// equals the document hash.
func printSeedLink(l roughtime.ProofLink, docDigest []byte, names map[string]string) {
	lo, hi := l.Window()
	fmt.Println("Document Binding (Link 0 — Seed)")
	fmt.Printf("  Witness:          %s\n", nameOf(l.PublicKey, names))
	fmt.Printf("  Wire version:     %s\n", l.Version.ShortString())
	fmt.Printf("  Key (fp):         %s\n", fingerprint(l.PublicKey))
	fmt.Printf("  Nonce:            %x\n", l.Nonce)
	if bytes.Equal(l.Nonce, docDigest) {
		fmt.Println("                    MATCHES SHA-256(document)")
	}
	fmt.Printf("  Midpoint (UTC):   %s\n", l.Midpoint.UTC().Format(tsFormat))
	fmt.Printf("  Radius:           ±%s\n", l.Radius)
	fmt.Printf("  Time window:      [%s, %s]\n", lo.UTC().Format(tsFormat), hi.UTC().Format(tsFormat))
	fmt.Println()
}

// printCorroborating prints the tabular summary of links 1..N with
// fingerprinted keys.
func printCorroborating(links []roughtime.ProofLink, names map[string]string) {
	if len(links) == 0 {
		return
	}
	fmt.Printf("Corroborating Witnesses (%d)\n", len(links))
	fmt.Printf("  %-3s  %-30s  %-10s  %-16s  %-24s  %s\n",
		"#", "Witness", "Version", "Key (fp)", "Midpoint (UTC)", "Radius")
	for i, l := range links {
		fmt.Printf("  %-3d  %-30s  %-10s  %-16s  %-24s  ±%s\n",
			i+1,
			nameOf(l.PublicKey, names),
			l.Version.ShortString(),
			fingerprint(l.PublicKey),
			l.Midpoint.UTC().Format(tsFormat),
			l.Radius)
	}
	fmt.Println()
}

// printFailures prints the per-server error list, if any.
func printFailures(results []roughtime.Result) {
	var failed []roughtime.Result
	for _, r := range results {
		if r.Err != nil {
			failed = append(failed, r)
		}
	}
	if len(failed) == 0 {
		return
	}
	fmt.Printf("Failures (%d)\n", len(failed))
	for _, r := range failed {
		fmt.Printf("  %-30s  %s\n",
			roughtime.SanitizeForDisplay(r.Server.Name),
			roughtime.SanitizeForDisplay(r.Err.Error()))
	}
	fmt.Println()
}

// printAttestationWindow prints the [earliest, latest] bound and witness count.
func printAttestationWindow(links []roughtime.ProofLink) {
	if len(links) == 0 {
		return
	}
	earliest, latest := links[0].Window()
	boundIdx := 0
	for i, l := range links {
		if _, hi := l.Window(); hi.Before(latest) {
			latest = hi
			boundIdx = i
		}
	}
	keys := make(map[string]struct{}, len(links))
	for _, l := range links {
		keys[string(l.PublicKey)] = struct{}{}
	}
	fmt.Println("Verified Attestation Window")
	fmt.Printf("  No earlier than:  %s  (link 0 lower bound)\n", earliest.UTC().Format(tsFormat))
	fmt.Printf("  No later than:    %s  (link %d upper bound)\n", latest.UTC().Format(tsFormat), boundIdx)
	fmt.Printf("  Width:            %s\n", latest.Sub(earliest))
	fmt.Printf("  Witnesses:        %d independent keys\n", len(keys))
	fmt.Println()
}
