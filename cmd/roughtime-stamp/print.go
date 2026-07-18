// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package main

import (
	"fmt"
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

// printBound prints the tightest attested upper bound.
func printBound(links []roughtime.ProofLink) {
	if len(links) == 0 {
		return
	}
	upper := links[0].Midpoint.Add(links[0].Radius)
	for _, link := range links[1:] {
		if candidate := link.Midpoint.Add(link.Radius); candidate.Before(upper) {
			upper = candidate
		}
	}
	fmt.Printf("Upper bound:  %s\n", upper.UTC().Format(time.RFC3339Nano))
}
