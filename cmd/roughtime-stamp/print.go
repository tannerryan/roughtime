// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"slices"
	"time"

	"github.com/tannerryan/roughtime"
)

// printReceipt prints a newly created receipt summary.
func printReceipt(document string, size int64, digest []byte, proofPath string, proofSize int, links []roughtime.ProofLink, profile proofProfile) {
	fmt.Println("Roughtime timestamp created")
	fmt.Printf("Document:     %s (%d bytes)\n", display(document), size)
	fmt.Printf("SHA-256:      %x\n", digest)
	fmt.Printf("Proof:        %s (%d bytes)\n", display(proofPath), proofSize)
	fmt.Printf("Measurement:  two passes across %d endpoint-domain groups\n", profile.groups)
	printBound(links)
}

// printVerification prints a verified receipt summary.
func printVerification(document string, size int64, digest []byte, proofPath string, proofSize int, links []roughtime.ProofLink, profile proofProfile) {
	label := "legacy"
	if profile.twoPass {
		label = fmt.Sprintf("two-pass (%d endpoint-domain groups)", profile.groups)
	}
	fmt.Println("Roughtime timestamp valid")
	fmt.Printf("Document:     %s (%d bytes)\n", display(document), size)
	fmt.Printf("SHA-256:      %x\n", digest)
	fmt.Printf("Proof:        %s (%d bytes)\n", display(proofPath), proofSize)
	fmt.Printf("Measurement:  %s\n", label)
	printBound(links)
}

// printBound prints the earliest bound attested by a majority of witnesses.
func printBound(links []roughtime.ProofLink) {
	if len(links) == 0 {
		return
	}
	upper := witnessUpperBound(links)
	fmt.Printf("Upper bound:  %s\n", upper.UTC().Format(time.RFC3339Nano))
}

func witnessUpperBound(links []roughtime.ProofLink) time.Time {
	byRoot := make(map[string]time.Time, len(links))
	for _, link := range links {
		root := string(link.PublicKey)
		upper := link.Midpoint.Add(link.Radius)
		if previous, ok := byRoot[root]; !ok || upper.Before(previous) {
			byRoot[root] = upper
		}
	}
	bounds := make([]time.Time, 0, len(byRoot))
	for _, bound := range byRoot {
		bounds = append(bounds, bound)
	}
	slices.SortFunc(bounds, time.Time.Compare)
	return bounds[len(bounds)/2]
}
